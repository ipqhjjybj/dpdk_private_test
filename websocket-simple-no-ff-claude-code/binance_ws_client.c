/**
 * 轻量级币安WebSocket行情客户端 (C语言版本)
 * 使用标准socket + mbedTLS实现
 * 功能：接收BTC/USDT实时行情数据
 */

 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <unistd.h>
 #include <signal.h>
 #include <sys/socket.h>
 #include <netinet/in.h>
 #include <arpa/inet.h>
 #include <netdb.h>
 #include <poll.h>
 #include <errno.h>
 
 // mbedTLS 头文件
 #include "mbedtls/net_sockets.h"
 #include "mbedtls/ssl.h"
 #include "mbedtls/entropy.h"
 #include "mbedtls/ctr_drbg.h"
 #include "mbedtls/error.h"
 
 // 币安WebSocket配置
 #define BINANCE_HOST "stream.binance.com"
 #define BINANCE_PORT 9443
 #define BINANCE_PATH "/ws/btcusdt@ticker"  // 24小时价格统计
 #define BUFFER_SIZE 4096
 #define MAX_RESPONSE_SIZE 1024
 
 // 全局控制变量
 static volatile int g_running = 1;
 
 // WebSocket握手请求模板
 static const char websocket_handshake[] = 
     "GET %s HTTP/1.1\r\n"
     "Host: %s\r\n"
     "Upgrade: websocket\r\n"
     "Connection: Upgrade\r\n"
     "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
     "Sec-WebSocket-Version: 13\r\n"
     "User-Agent: Simple-WebSocket-Client/1.0\r\n"
     "\r\n";
 
 // 信号处理函数
 void signal_handler(int sig) {
     printf("\n收到信号 %d，准备退出...\n", sig);
     g_running = 0;
 }
 
 // 简化的WebSocket帧解析（仅处理文本帧）
 int parse_websocket_frame(const unsigned char *buffer, int len, 
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
     int actual_len = len_field;
     
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
     
     return header_len + actual_len;
 }
 
 // 解析币安行情数据（简化版JSON解析）
 void process_ticker_data(const unsigned char *data, int len) {
     // 创建以null结尾的字符串
     char *json_str = (char*)malloc(len + 1);
     if (!json_str) return;
     
     memcpy(json_str, data, len);
     json_str[len] = '\0';
     
     // 简单解析关键字段
     char *symbol = strstr(json_str, "\"s\":\"");
     char *price = strstr(json_str, "\"c\":\"");
     char *change = strstr(json_str, "\"P\":\"");
     char *volume = strstr(json_str, "\"v\":\"");
     
     printf("\n=== 币安行情数据 ===\n");
     
     // 解析交易对
     if (symbol) {
         symbol += 5;  // 跳过 "s":"
         char *end = strchr(symbol, '"');
         if (end) {
             *end = '\0';
             printf("交易对: %s\n", symbol);
             *end = '"';  // 恢复原字符
         }
     }
     
     // 解析当前价格
     if (price) {
         price += 5;  // 跳过 "c":"
         char *end = strchr(price, '"');
         if (end) {
             *end = '\0';
             printf("当前价格: %s USDT\n", price);
             *end = '"';
         }
     }
     
     // 解析24小时涨跌幅
     if (change) {
         change += 5;  // 跳过 "P":"
         char *end = strchr(change, '"');
         if (end) {
             *end = '\0';
             printf("24h涨跌幅: %s%%\n", change);
             *end = '"';
         }
     }
     
     // 解析24小时成交量
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
 
 // 创建并连接TCP socket
 int create_socket_connection() {
     struct hostent *host_entry;
     struct sockaddr_in server_addr;
     int sockfd;
     
     // DNS解析
     printf("正在解析主机名 %s...\n", BINANCE_HOST);
     host_entry = gethostbyname(BINANCE_HOST);
     if (!host_entry) {
         printf("DNS解析失败: %s\n", BINANCE_HOST);
         return -1;
     }
     
     // 创建socket
     sockfd = socket(AF_INET, SOCK_STREAM, 0);
     if (sockfd < 0) {
         printf("创建socket失败: %s\n", strerror(errno));
         return -1;
     }
     
     // 设置服务器地址
     memset(&server_addr, 0, sizeof(server_addr));
     server_addr.sin_family = AF_INET;
     server_addr.sin_port = htons(BINANCE_PORT);
     memcpy(&server_addr.sin_addr.s_addr, host_entry->h_addr, host_entry->h_length);
     
     // 连接服务器
     printf("正在连接到 %s:%d...\n", BINANCE_HOST, BINANCE_PORT);
     if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
         printf("连接失败: %s\n", strerror(errno));
         close(sockfd);
         return -1;
     }
     
     printf("TCP连接成功\n");
     return sockfd;
 }
 
 // 执行SSL握手
 int perform_ssl_handshake(mbedtls_ssl_context *ssl, int sockfd) {
     mbedtls_net_context server_fd;
     mbedtls_ssl_config conf;
     mbedtls_entropy_context entropy;
     mbedtls_ctr_drbg_context ctr_drbg;
     const char *pers = "binance_ws_client";
     int ret;
     
     // 初始化mbedTLS
     mbedtls_net_init(&server_fd);
     mbedtls_ssl_init(ssl);
     mbedtls_ssl_config_init(&conf);
     mbedtls_entropy_init(&entropy);
     mbedtls_ctr_drbg_init(&ctr_drbg);
     
     printf("正在初始化SSL...\n");
     
     // 初始化随机数生成器
     if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char *)pers, strlen(pers))) != 0) {
         printf("随机数生成器初始化失败: %d\n", ret);
         goto cleanup;
     }
     
     // 配置SSL
     if ((ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
                                           MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
         printf("SSL配置失败: %d\n", ret);
         goto cleanup;
     }
     
     // 设置验证模式（生产环境建议开启证书验证）
     mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
     mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
     
     if ((ret = mbedtls_ssl_setup(ssl, &conf)) != 0) {
         printf("SSL设置失败: %d\n", ret);
         goto cleanup;
     }
     
     // 设置主机名（用于SNI）
     if ((ret = mbedtls_ssl_set_hostname(ssl, BINANCE_HOST)) != 0) {
         printf("设置主机名失败: %d\n", ret);
         goto cleanup;
     }
     
     // 设置网络上下文
     server_fd.fd = sockfd;
     mbedtls_ssl_set_bio(ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);
     
     // 执行SSL握手
     printf("正在进行SSL握手...\n");
     while ((ret = mbedtls_ssl_handshake(ssl)) != 0) {
         if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
             char error_buf[100];
             mbedtls_strerror(ret, error_buf, sizeof(error_buf));
             printf("SSL握手失败: %s\n", error_buf);
             goto cleanup;
         }
     }
     
     printf("SSL握手成功\n");
     return 0;
     
 cleanup:
     mbedtls_ssl_config_free(&conf);
     mbedtls_ctr_drbg_free(&ctr_drbg);
     mbedtls_entropy_free(&entropy);
     return -1;
 }
 
 // 执行WebSocket握手
 int perform_websocket_handshake(mbedtls_ssl_context *ssl) {
     char handshake_request[512];
     unsigned char response[MAX_RESPONSE_SIZE];
     int ret;
     
     // 构建握手请求
     snprintf(handshake_request, sizeof(handshake_request), websocket_handshake, 
              BINANCE_PATH, BINANCE_HOST);
     
     printf("发送WebSocket握手请求...\n");
     
     // 发送握手请求
     ret = mbedtls_ssl_write(ssl, (unsigned char *)handshake_request, strlen(handshake_request));
     if (ret <= 0) {
         printf("发送握手请求失败: %d\n", ret);
         return -1;
     }
     
     // 接收握手响应
     ret = mbedtls_ssl_read(ssl, response, sizeof(response) - 1);
     if (ret <= 0) {
         printf("接收握手响应失败: %d\n", ret);
         return -1;
     }
     
     response[ret] = '\0';
     
     // 检查握手响应
     if (strstr((char *)response, "101 Switching Protocols") == NULL) {
         printf("WebSocket握手失败，响应:\n%s\n", response);
         return -1;
     }
     
     printf("WebSocket握手成功\n");
     return 0;
 }
 
 // 主事件循环
 void run_client_loop(mbedtls_ssl_context *ssl, int sockfd) {
     unsigned char buffer[BUFFER_SIZE];
     struct pollfd fds[1];
     int ret;
     
     printf("开始接收行情数据...\n");
     
     fds[0].fd = sockfd;
     fds[0].events = POLLIN;
     
     while (g_running) {
         // 等待数据，超时1秒
         ret = poll(fds, 1, 1000);
         
         if (ret < 0) {
             if (errno == EINTR) continue;  // 被信号中断
             printf("poll错误: %s\n", strerror(errno));
             break;
         }
         
         if (ret == 0) {
             continue;  // 超时，继续等待
         }
         
         // 有数据可读
         if (fds[0].revents & POLLIN) {
             ret = mbedtls_ssl_read(ssl, buffer, sizeof(buffer) - 1);
             
             if (ret <= 0) {
                 if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
                     continue;
                 }
                 printf("读取数据失败: %d\n", ret);
                 break;
             }
             
             // 解析WebSocket帧
             unsigned char *payload;
             int payload_len;
             int frame_len = parse_websocket_frame(buffer, ret, &payload, &payload_len);
             
             if (frame_len > 0) {
                 process_ticker_data(payload, payload_len);
             }
         }
         
         // 检查错误事件
         if (fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) {
             printf("socket错误事件: %d\n", fds[0].revents);
             break;
         }
     }
 }
 
 // 清理SSL资源
 void cleanup_ssl(mbedtls_ssl_context *ssl) {
     mbedtls_ssl_free(ssl);
 }
 
 int main() {
     int sockfd = -1;
     mbedtls_ssl_context ssl;
     
     printf("轻量级币安WebSocket客户端 (C语言版本)\n");
     printf("=======================================\n");
     
     // 注册信号处理函数
     signal(SIGINT, signal_handler);
     signal(SIGTERM, signal_handler);
     
     // 1. 创建TCP连接
     sockfd = create_socket_connection();
     if (sockfd < 0) {
         return 1;
     }
     
     // 2. 执行SSL握手
     if (perform_ssl_handshake(&ssl, sockfd) < 0) {
         close(sockfd);
         return 1;
     }
     
     // 3. 执行WebSocket握手
     if (perform_websocket_handshake(&ssl) < 0) {
         cleanup_ssl(&ssl);
         close(sockfd);
         return 1;
     }
     
     // 4. 运行主循环
     run_client_loop(&ssl, sockfd);
     
     // 5. 清理资源
     printf("正在清理资源...\n");
     cleanup_ssl(&ssl);
     close(sockfd);
     
     printf("程序退出\n");
     return 0;
 }
 