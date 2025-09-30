/**
 * 极简币安WebSocket行情客户端
 * 使用F-Stack + mbedTLS实现
 * 功能：连接币安WebSocket服务器，接收BTC/USDT深度行情数据
 */

 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <signal.h>
 #include <unistd.h>
 #include <sys/time.h>
 #include <arpa/inet.h>
 #include <errno.h>
 #include <netdb.h>
 #include <sys/socket.h>
 #include <fcntl.h>

 // F-Stack 头文件
 #include "ff_config.h"
 #include "ff_api.h"
 #include "ff_epoll.h"

 // mbedTLS 头文件
 #include "mbedtls/net_sockets.h"
 #include "mbedtls/ssl.h"
 #include "mbedtls/entropy.h"
 #include "mbedtls/ctr_drbg.h"
 #include "mbedtls/error.h"

 // 币安WebSocket配置
 #define BINANCE_HOST "stream.binance.com"
 #define BINANCE_PORT 9443
 #define BINANCE_PATH "/ws/btcusdt@ticker"  // 24小时价格变化统计
 #define BUFFER_SIZE 4096

 // 全局变量
 static volatile int g_running = 1;

 // 信号处理函数
 static void signal_handler(int sig) {
     printf("\n收到信号 %d，准备退出...\n", sig);
     g_running = 0;
 }

 // DNS解析函数
 static int resolve_hostname(const char *hostname, char *ip_str, size_t ip_str_size) {
     struct hostent *host_entry;
     struct in_addr addr;

     printf("正在解析域名 %s...\n", hostname);

     // 尝试DNS解析
     host_entry = gethostbyname(hostname);
     if (host_entry == NULL) {
         printf("DNS解析失败: %s\n", hostname);
         return -1;
     }

     // 获取第一个IP地址
     addr.s_addr = *((unsigned long *)host_entry->h_addr_list[0]);
     const char *ip = inet_ntoa(addr);

     if (strlen(ip) >= ip_str_size) {
         printf("IP地址字符串缓冲区太小\n");
         return -1;
     }

     strcpy(ip_str, ip);
     printf("解析到IP地址: %s\n", ip);

     return 0;
 }

 // WebSocket握手请求模板
 static const char *websocket_handshake =
     "GET %s HTTP/1.1\r\n"
     "Host: %s\r\n"
     "Upgrade: websocket\r\n"
     "Connection: Upgrade\r\n"
     "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
     "Sec-WebSocket-Version: 13\r\n"
     "User-Agent: FStack-WebSocket-Client/1.0\r\n"
     "\r\n";

 // 简化的WebSocket帧解析（仅处理文本帧）
 static int parse_websocket_frame(const unsigned char *buffer, int len,
                                unsigned char **payload, int *payload_len) {
     if (len < 2) {
         return -1;
     }

     // 解析帧头
     unsigned char first_byte = buffer[0];
     unsigned char second_byte = buffer[1];

     int fin = (first_byte >> 7) & 1;
     int opcode = first_byte & 0x0F;
     int masked = (second_byte >> 7) & 1;
     int len_field = second_byte & 0x7F;

     // 只处理文本帧(opcode=1)和完整帧(fin=1)
     if (opcode != 1 || !fin) {
         return -1;
     }

     int header_len = 2;
     uint64_t actual_len = len_field;

     // 处理扩展长度
     if (len_field == 126) {
         if (len < 4) return -1;
         actual_len = (buffer[2] << 8) | buffer[3];
         header_len += 2;
     } else if (len_field == 127) {
         // 忽略超长帧
         return -1;
     }

     // 处理掩码（服务器发送的帧通常不带掩码）
     if (masked) {
         header_len += 4;
     }

     if (len < header_len + actual_len) {
         return -1;  // 数据不完整
     }

     *payload = (unsigned char *)buffer + header_len;
     *payload_len = actual_len;

     return 0;
 }

 // 解析币安行情数据（简化版JSON解析）
 static void process_ticker_data(const unsigned char *data, int len) {
     // 将数据转为字符串
     char *json_str = malloc(len + 1);
     memcpy(json_str, data, len);
     json_str[len] = '\0';

     // 简单解析关键字段
     char *symbol = strstr(json_str, "\"s\":\"");
     char *price = strstr(json_str, "\"c\":\"");
     char *change = strstr(json_str, "\"P\":\"");
     char *volume = strstr(json_str, "\"v\":\"");

     printf("\n=== 币安行情数据 ===\n");

     if (symbol) {
         symbol += 5;  // 跳过 "s":"
         char *end = strchr(symbol, '"');
         if (end) {
             *end = '\0';
             printf("交易对: %s\n", symbol);
             *end = '"';  // 恢复原字符
         }
     }

     if (price) {
         price += 5;  // 跳过 "c":"
         char *end = strchr(price, '"');
         if (end) {
             *end = '\0';
             printf("当前价格: %s USDT\n", price);
             *end = '"';
         }
     }

     if (change) {
         change += 5;  // 跳过 "P":"
         char *end = strchr(change, '"');
         if (end) {
             *end = '\0';
             printf("24h涨跌幅: %s%%\n", change);
             *end = '"';
         }
     }

     if (volume) {
         volume += 5;  // 跳过 "v":"
         char *end = strchr(volume, '"');
         if (end) {
             *end = '\0';
             printf("24h成交量: %s BTC\n", volume);
             *end = '"';
         }
     }

     printf("==================\n");

     free(json_str);
 }

 // mbedTLS网络发送函数（适配F-Stack）
 static int fstack_net_send(void *ctx, const unsigned char *buf, size_t len) {
     int fd = ((mbedtls_net_context *)ctx)->fd;
     int ret = ff_send(fd, buf, len, 0);

     if (ret < 0) {
         if (errno == EAGAIN || errno == EWOULDBLOCK) {
             return MBEDTLS_ERR_SSL_WANT_WRITE;
         }
         return MBEDTLS_ERR_NET_SEND_FAILED;
     }

     return ret;
 }

 // mbedTLS网络接收函数（适配F-Stack）
 static int fstack_net_recv(void *ctx, unsigned char *buf, size_t len) {
     int fd = ((mbedtls_net_context *)ctx)->fd;
     int ret = ff_recv(fd, buf, len, 0);

     if (ret < 0) {
         if (errno == EAGAIN || errno == EWOULDBLOCK) {
             return MBEDTLS_ERR_SSL_WANT_READ;
         }
         return MBEDTLS_ERR_NET_RECV_FAILED;
     }

     if (ret == 0) {
         return MBEDTLS_ERR_NET_CONN_RESET;
     }

     return ret;
 }

 // F-Stack主循环函数
 static int fstack_loop(void *arg) {
     int sockfd = -1;
     int epfd = -1;
     int ret = -1;

     // mbedTLS上下文
     mbedtls_net_context server_fd;
     mbedtls_ssl_context ssl;
     mbedtls_ssl_config conf;
     mbedtls_entropy_context entropy;
     mbedtls_ctr_drbg_context ctr_drbg;

     // 初始化mbedTLS
     mbedtls_net_init(&server_fd);
     mbedtls_ssl_init(&ssl);
     mbedtls_ssl_config_init(&conf);
     mbedtls_entropy_init(&entropy);
     mbedtls_ctr_drbg_init(&ctr_drbg);

     printf("正在初始化SSL...\n");

     // 初始化随机数生成器
     const char *pers = "fstack_binance_client";
     if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                              (const unsigned char *)pers, strlen(pers)) != 0) {
         printf("随机数生成器初始化失败\n");
         goto cleanup;
     }

     // 配置SSL
     if (mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
                                    MBEDTLS_SSL_TRANSPORT_STREAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
         printf("SSL配置初始化失败\n");
         goto cleanup;
     }

     // 设置验证模式（生产环境应该验证证书）
     mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
     mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

     if (mbedtls_ssl_setup(&ssl, &conf) != 0) {
         printf("SSL设置失败\n");
         goto cleanup;
     }

     // 设置主机名（用于SNI）
     if (mbedtls_ssl_set_hostname(&ssl, BINANCE_HOST) != 0) {
         printf("设置主机名失败\n");
         goto cleanup;
     }

     // 创建F-Stack socket
     printf("正在创建socket连接...\n");
     sockfd = ff_socket(AF_INET, SOCK_STREAM, 0);
     if (sockfd < 0) {
         printf("创建socket失败: %d\n", errno);
         goto cleanup;
     }

     // 连接到币安服务器
     struct sockaddr_in server_addr;
     memset(&server_addr, 0, sizeof(server_addr));
     server_addr.sin_family = AF_INET;
     server_addr.sin_port = htons(BINANCE_PORT);

     // 使用DNS解析获取币安服务器IP地址
     char resolved_ip[INET_ADDRSTRLEN];
     if (resolve_hostname(BINANCE_HOST, resolved_ip, sizeof(resolved_ip)) < 0) {
         printf("无法解析币安服务器地址\n");
         goto cleanup;
     }

     if (inet_pton(AF_INET, resolved_ip, &server_addr.sin_addr) <= 0) {
         printf("IP地址转换失败\n");
         goto cleanup;
     }

    struct sockaddr_in my_addr;
    bzero(&my_addr, sizeof(my_addr));
    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons(8000);

    ret = ff_bind(sockfd, (struct linux_sockaddr *)&my_addr, sizeof(my_addr));
    if (ret < 0) {
        printf("ff_bind failed, sockfd:%d, errno:%d, %s\n", sockfd, errno, strerror(errno));
        exit(1);
    }else{
        printf("ff_bind success, sockfd:%d\n", sockfd);
    }

    server_addr.sin_addr.s_addr = inet_addr(resolved_ip);
	

     printf("正在连接到 %s:%d (IP: %s)...\n", BINANCE_HOST, BINANCE_PORT, resolved_ip);

     // 尝试直接阻塞连接
     printf("使用阻塞连接...\n");
     int connect_result = ff_connect(sockfd, (const struct linux_sockaddr *)&server_addr, sizeof(server_addr));
     if (connect_result < 0) {
         printf("连接失败: %d (%s)\n", errno, strerror(errno));
         goto cleanup;
     }

     printf("连接成功\n");
     int connection_established = 1;

     // 连接已建立，创建epoll用于后续数据接收
     epfd = ff_epoll_create(1);
     if (epfd < 0) {
         printf("创建epoll失败\n");
         goto cleanup;
     }

     struct epoll_event ev;
     ev.events = EPOLLIN;
     ev.data.fd = sockfd;
     if (ff_epoll_ctl(epfd, EPOLL_CTL_ADD, sockfd, &ev) < 0) {
         printf("添加epoll事件失败\n");
         goto cleanup;
     }

     printf("TCP连接成功\n");

     // 设置mbedTLS的网络上下文
     server_fd.fd = sockfd;
     mbedtls_ssl_set_bio(&ssl, &server_fd, fstack_net_send, fstack_net_recv, NULL);

     // 执行SSL握手
     printf("正在进行SSL握手...\n");
     while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
         if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
             char error_buf[100];
             mbedtls_strerror(ret, error_buf, sizeof(error_buf));
             printf("SSL握手失败: %s\n", error_buf);
             goto cleanup;
         }
     }

     printf("SSL握手成功\n");

     // 发送WebSocket握手请求
     char handshake_request[1024];
     snprintf(handshake_request, sizeof(handshake_request), websocket_handshake,
              BINANCE_PATH, BINANCE_HOST);

     printf("发送WebSocket握手请求...\n");
     if (mbedtls_ssl_write(&ssl, (unsigned char *)handshake_request,
                          strlen(handshake_request)) <= 0) {
         printf("发送WebSocket握手失败\n");
         goto cleanup;
     }

     // 接收握手响应
     unsigned char response[1024];
     int response_len = mbedtls_ssl_read(&ssl, response, sizeof(response) - 1);
     if (response_len <= 0) {
         printf("接收握手响应失败\n");
         goto cleanup;
     }

     response[response_len] = '\0';
     if (strstr((char *)response, "101 Switching Protocols") == NULL) {
         printf("WebSocket握手失败，响应: %s\n", response);
         goto cleanup;
     }

     printf("WebSocket握手成功\n");

     printf("开始接收行情数据...\n");

     // 主事件循环
     unsigned char buffer[BUFFER_SIZE];
     struct epoll_event events[1];

     while (g_running) {
         int nfds = ff_epoll_wait(epfd, events, 1, 1000);  // 1秒超时

         if (nfds < 0) {
             printf("epoll_wait失败\n");
             break;
         }

         if (nfds == 0) {
             continue;  // 超时，继续循环
         }

         if (events[0].events & EPOLLIN) {
             int bytes_read = mbedtls_ssl_read(&ssl, buffer, sizeof(buffer) - 1);

             if (bytes_read <= 0) {
                 if (bytes_read == MBEDTLS_ERR_SSL_WANT_READ) {
                     continue;
                 }
                 printf("读取数据失败: %d\n", bytes_read);
                 break;
             }

             // 解析WebSocket帧
             unsigned char *payload;
             int payload_len;
             if (parse_websocket_frame(buffer, bytes_read, &payload, &payload_len) == 0) {
                 process_ticker_data(payload, payload_len);
             }
         }
     }

     ret = 0;  // 正常退出

 cleanup:
     printf("正在清理资源...\n");

     if (epfd >= 0) {
         ff_close(epfd);
     }

     mbedtls_ssl_close_notify(&ssl);

     if (sockfd >= 0) {
         ff_close(sockfd);
     }

     mbedtls_net_free(&server_fd);
     mbedtls_ssl_free(&ssl);
     mbedtls_ssl_config_free(&conf);
     mbedtls_ctr_drbg_free(&ctr_drbg);
     mbedtls_entropy_free(&entropy);

     exit(0);

     return ret;
 }

 // --conf=xxx --proc-id=0 --proc-type=primary or secondary
 // --conf=config.ini --proc-id=0 --proc-type=primary or secondary
 int main(int argc, char *argv[]) {
     printf("F-Stack + mbedTLS 币安WebSocket客户端\n");
     printf("=====================================\n");

     // 注册信号处理函数
     signal(SIGINT, signal_handler);
     signal(SIGTERM, signal_handler);

     // 初始化F-Stack
     printf("正在初始化F-Stack...\n");

     if (ff_init(argc, argv) < 0) {
         fprintf(stderr, "F-Stack初始化失败！可能原因：PCI地址错误/大页未分配/核心绑定冲突\n");
         return -1;
     }

     printf("F-Stack初始化成功\n");

     // 添加默认路由 - F-Stack需要手动配置路由表
     printf("配置F-Stack路由表...\n");
     // 这里应该使用F-Stack的路由API，但如果没有，可能需要使用系统调用

     // 运行主循环
     ff_run(fstack_loop, NULL);
     int result = 0;

     // 清理F-Stack
     printf("正在清理F-Stack...\n");

     printf("程序退出\n");
     return result;
 }
