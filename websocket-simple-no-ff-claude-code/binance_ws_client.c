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
 #include <sys/time.h>
 #include <time.h>
 
 // mbedTLS 头文件
 #include "mbedtls/net_sockets.h"
 #include "mbedtls/ssl.h"
 #include "mbedtls/entropy.h"
 #include "mbedtls/ctr_drbg.h"
 #include "mbedtls/error.h"
 
 // 币安WebSocket配置
 #define BINANCE_HOST "stream.binance.com"
 #define BINANCE_PORT 9443
 #define BINANCE_PATH "/ws/btcusdt@depth"  // 订单簿深度数据
 #define BUFFER_SIZE 16384  // 增加到16KB处理大的深度数据
 #define MAX_RESPONSE_SIZE 1024
 #define PING_INTERVAL_SEC 30  // 心跳间隔30秒（符合币安频率限制）
 #define ENABLE_PING 1  // 0=禁用ping，1=启用ping
 #define MAX_MESSAGES_PER_SEC 5  // 币安限制：每秒最多5个消息
 
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
 
 // 简化的WebSocket帧解析（处理文本帧和pong帧）
 int parse_websocket_frame(const unsigned char *buffer, int len, 
                          unsigned char **payload, int *payload_len) {
     if (len < 2) {
         printf("帧太短: %d字节\n", len);
         return -1;
     }
     
     // 解析帧头
     unsigned char first_byte = buffer[0];
     unsigned char second_byte = buffer[1];
     
     int fin = (first_byte >> 7) & 1;
     int opcode = first_byte & 0x0F;
     int masked = (second_byte >> 7) & 1;
     int len_field = second_byte & 0x7F;
     
     printf("帧调试: fin=%d, opcode=0x%X, masked=%d, len_field=%d\n", fin, opcode, masked, len_field);
     
     // 处理ping帧(opcode=9)和pong帧(opcode=10)需要解析完整帧
     if (opcode == 0x9 || opcode == 0xA) {
         if (opcode == 0x9) {
             printf("检测到ping帧: opcode=0x%X, fin=%d, masked=%d\n", opcode, fin, masked);
         } else {
             printf("检测到pong帧: opcode=0x%X, fin=%d, masked=%d\n", opcode, fin, masked);
         }
         // 继续解析以获取payload
     } else if (opcode != 1) {
         // 处理文本帧(opcode=1) - 移除fin检查，允许分片
         printf("不支持的opcode: 0x%X\n", opcode);
         return -1;
     }
     
     int header_len = 2;
     int actual_len = len_field;
     
     // 处理扩展长度
     if (len_field == 126) {
         if (len < 4) {
             printf("扩展长度帧不完整: 需要4字节，实际%d字节\n", len);
             return -1;
         }
         actual_len = (buffer[2] << 8) | buffer[3];
         header_len += 2;
         printf("扩展长度(126): %d字节\n", actual_len);
     } else if (len_field == 127) {
         if (len < 10) {
             printf("超长帧不完整: 需要10字节，实际%d字节\n", len);
             return -1;
         }
         // 读取64位长度（只取低32位）
         actual_len = (buffer[6] << 24) | (buffer[7] << 16) | (buffer[8] << 8) | buffer[9];
         header_len += 8;
         printf("超长帧(127): %d字节\n", actual_len);
     }
     
     // 处理掩码（服务器发送的帧通常不带掩码）
     if (masked) {
         header_len += 4;
     }
     
     if (len < header_len + actual_len) {
         printf("帧数据不完整: 需要%d字节，实际%d字节\n", header_len + actual_len, len);
         return -1;  // 数据不完整
     }
     
     printf("成功解析帧: header=%d字节, payload=%d字节\n", header_len, actual_len);
     
     *payload = (unsigned char *)buffer + header_len;
     *payload_len = actual_len;
     
     // 根据opcode返回不同值
     if (opcode == 0x9) {
         return 3;  // ping帧
     } else if (opcode == 0xA) {
         return 2;  // pong帧
     } else {
         return header_len + actual_len;  // 数据帧
     }
 }
 
 // 发送WebSocket ping帧 (客户端需要mask，币安兼容)
 int send_websocket_ping(mbedtls_ssl_context *ssl) {
     unsigned char ping_frame[6];
     
     // 生成随机mask key
     srand(time(NULL));
     unsigned char mask_key[4];
     for (int i = 0; i < 4; i++) {
         mask_key[i] = rand() & 0xFF;
     }
     
     ping_frame[0] = 0x89;  // FIN=1, RSV=000, opcode=9 (ping)
     ping_frame[1] = 0x80;  // MASK=1, payload length=0
     ping_frame[2] = mask_key[0];
     ping_frame[3] = mask_key[1]; 
     ping_frame[4] = mask_key[2];
     ping_frame[5] = mask_key[3];
     
     int ret = mbedtls_ssl_write(ssl, ping_frame, 6);
     if (ret != 6) {
         char error_buf[100];
         mbedtls_strerror(ret, error_buf, sizeof(error_buf));
         printf("发送ping帧失败: 发送了%d字节，期望6字节 (%s)\n", ret, error_buf);
         return -1;
     }
     
     printf("已发送币安ping帧 (时间: %ld)\n", time(NULL));
     return 0;
 }
 
 // 发送WebSocket pong帧回复服务器ping
 int send_websocket_pong(mbedtls_ssl_context *ssl, const unsigned char *ping_payload, int payload_len) {
     unsigned char pong_frame[256];
     int frame_len = 0;
     
     // 生成随机mask key
     srand(time(NULL));
     unsigned char mask_key[4];
     for (int i = 0; i < 4; i++) {
         mask_key[i] = rand() & 0xFF;
     }
     
     pong_frame[0] = 0x8A;  // FIN=1, RSV=000, opcode=10 (pong)
     
     if (payload_len == 0) {
         pong_frame[1] = 0x80;  // MASK=1, payload length=0
         frame_len = 2;
     } else if (payload_len < 126) {
         pong_frame[1] = 0x80 | payload_len;  // MASK=1, payload length
         frame_len = 2;
     } else {
         printf("pong payload过大: %d字节\n", payload_len);
         return -1;
     }
     
     // 添加mask key
     memcpy(pong_frame + frame_len, mask_key, 4);
     frame_len += 4;
     
     // 添加masked payload (如果有)
     for (int i = 0; i < payload_len; i++) {
         pong_frame[frame_len + i] = ping_payload[i] ^ mask_key[i % 4];
     }
     frame_len += payload_len;
     
     int ret = mbedtls_ssl_write(ssl, pong_frame, frame_len);
     if (ret != frame_len) {
         char error_buf[100];
         mbedtls_strerror(ret, error_buf, sizeof(error_buf));
         printf("发送pong帧失败: 发送了%d字节，期望%d字节 (%s)\n", ret, frame_len, error_buf);
         return -1;
     }
     
     printf("已回复pong帧 (payload: %d字节, 时间: %ld)\n", payload_len, time(NULL));
     return 0;
 }
 
 // 备用保活方法：发送订阅消息
 int send_keepalive_subscribe(mbedtls_ssl_context *ssl) {
     const char *subscribe_msg = "{\"method\":\"SUBSCRIBE\",\"params\":[\"btcusdt@depth\"],\"id\":1}";
     int msg_len = strlen(subscribe_msg);
     
     // 构建WebSocket文本帧 (带mask)
     unsigned char frame[256];
     unsigned char mask_key[4] = {0xAB, 0xCD, 0xEF, 0x12};
     int frame_len = 0;
     
     frame[0] = 0x81;  // FIN=1, opcode=1 (text)
     frame[1] = 0x80 | (msg_len & 0x7F);  // MASK=1, length
     frame_len = 2;
     
     // 添加mask key
     memcpy(frame + frame_len, mask_key, 4);
     frame_len += 4;
     
     // 添加masked payload
     for (int i = 0; i < msg_len; i++) {
         frame[frame_len + i] = subscribe_msg[i] ^ mask_key[i % 4];
     }
     frame_len += msg_len;
     
     int ret = mbedtls_ssl_write(ssl, frame, frame_len);
     if (ret <= 0) {
         printf("发送保活订阅失败: %d\n", ret);
         return -1;
     }
     
     printf("已发送保活订阅消息 (时间: %ld)\n", time(NULL));
     return 0;
 }
 
 // 获取当前时间戳（微秒）
 long long get_current_timestamp_us() {
     struct timeval tv;
     gettimeofday(&tv, NULL);
     return (long long)(tv.tv_sec) * 1000000 + (long long)(tv.tv_usec);
 }
 
 // 获取当前时间戳（毫秒）
 long long get_current_timestamp_ms() {
     return get_current_timestamp_us() / 1000;
 }
 
 // 解析JSON字段中的数字字符串
 long long parse_json_number(const char *json_str, const char *field) {
     const char *field_pos = strstr(json_str, field);
     if (!field_pos) return 0;
     
     // 跳过字段名和引号
     field_pos += strlen(field);
     if (*field_pos == '"') field_pos++;
     
     // 找到数字结束位置
     const char *end_pos = field_pos;
     while (*end_pos && *end_pos != '"' && *end_pos != ',' && *end_pos != '}') {
         end_pos++;
     }
     
     // 计算数字字符串长度
     int num_len = end_pos - field_pos;
     
     // 创建临时字符串
     char *temp_str = (char*)malloc(num_len + 1);
     if (!temp_str) return 0;
     
     memcpy(temp_str, field_pos, num_len);
     temp_str[num_len] = '\0';
     
     long long result = atoll(temp_str);
     
     free(temp_str);
     
     return result;
 }
 
 // 解析币安订单簿深度数据（简化版JSON解析）
 void process_depth_data(const unsigned char *data, int len) {
     // 创建以null结尾的字符串
     char *json_str = (char*)malloc(len + 1);
     if (!json_str) return;
     
     memcpy(json_str, data, len);
     json_str[len] = '\0';
     
     // 获取当前本地时间戳（微秒）
     long long current_time_us = get_current_timestamp_us();
     long long current_time_ms = current_time_us / 1000;
     
     // 解析币安服务器时间戳（毫秒）
     long long server_time = parse_json_number(json_str, "\"E\":");
     
     // 计算延迟（微秒精度）
     long long latency_us = current_time_us - (server_time * 1000);
     long long latency_ms = latency_us / 1000;
     
     // 简单解析深度数据关键字段
     char *symbol = strstr(json_str, "\"s\":\"");
     char *last_update_id = strstr(json_str, "\"lastUpdateId\":");
     char *bids = strstr(json_str, "\"bids\":");
     char *asks = strstr(json_str, "\"asks\":");
     
     printf("\n=== 币安深度数据 ===\n");
     
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
     
     // 解析最后更新ID
     if (last_update_id) {
         last_update_id += 15;  // 跳过 "lastUpdateId":
         char *end = strpbrk(last_update_id, ",}");
         if (end) {
             char saved = *end;
             *end = '\0';
             printf("最后更新ID: %s\n", last_update_id);
             *end = saved;
         }
     }
     
     // 显示买单和卖单信息
     if (bids) {
         printf("买单数据: 可用\n");
     }
     if (asks) {
         printf("卖单数据: 可用\n");
     }
     
     // 显示原始数据长度（深度数据通常较大）
     printf("数据长度: %d 字节\n", len);
     
     // 显示延迟信息
     printf("服务器时间: %lld ms\n", server_time);
     printf("本地时间: %lld.%03lld ms\n", current_time_ms, current_time_us % 1000);
     if (server_time > 0) {
         if (latency_us >= 0) {
             if (latency_us < 1000) {
                 printf("网络延迟: %lld μs\n", latency_us);
             } else {
                 printf("网络延迟: %lld.%03lld ms (%lld μs)\n", 
                        latency_ms, (latency_us % 1000), latency_us);
             }
         } else {
             printf("网络延迟: %lld.%03lld ms (时钟不同步)\n", 
                    latency_ms, (long long)labs(latency_us % 1000));
         }
     } else {
         printf("网络延迟: 无法计算 (未找到服务器时间戳)\n");
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
     int data_received = 0;
     int ping_sent = 0;
     int pong_received = 0;
     int server_ping_received = 0;  // 收到服务器ping计数
     int pong_sent = 0;  // 发送pong回复计数
     time_t last_ping_time = time(NULL);
     time_t connection_start = time(NULL);
     
     // 消息频率限制 (币安要求每秒最多5个消息)
     time_t rate_limit_window = time(NULL);
     int messages_in_window = 0;
     
     printf("开始接收行情数据...\n");
     if (ENABLE_PING) {
         printf("心跳已启用，间隔: %d秒\n", PING_INTERVAL_SEC);
     } else {
         printf("心跳已禁用，依赖数据流保活\n");
     }
     
     fds[0].fd = sockfd;
     fds[0].events = POLLIN;
     
     while (g_running) {
         // 检查消息频率限制窗口
         time_t current_time = time(NULL);
         if (current_time > rate_limit_window) {
             rate_limit_window = current_time;
             messages_in_window = 0;
         }
         
         // 检查是否需要发送心跳
         if (ENABLE_PING) {
             if (current_time - last_ping_time >= PING_INTERVAL_SEC) {
                 // 检查频率限制
                 if (messages_in_window < MAX_MESSAGES_PER_SEC) {
                     if (send_websocket_ping(ssl) == 0) {
                         last_ping_time = current_time;
                         ping_sent++;
                         messages_in_window++;
                         printf("消息频率: %d/%d (当前秒: %ld)\n", messages_in_window, MAX_MESSAGES_PER_SEC, current_time);
                     }
                 } else {
                     printf("达到频率限制，跳过ping发送 (%d/%d)\n", messages_in_window, MAX_MESSAGES_PER_SEC);
                 }
             }
         }
         
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
                 char error_buf[100];
                 mbedtls_strerror(ret, error_buf, sizeof(error_buf));
                 printf("读取数据失败: %d (%s)\n", ret, error_buf);
                 if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
                     printf("服务器主动关闭了SSL连接\n");
                 } else if (ret == MBEDTLS_ERR_NET_CONN_RESET) {
                     printf("网络连接被重置\n");
                 }
                 time_t connection_duration = time(NULL) - connection_start;
                 printf("连接统计信息:\n");
                 printf("  连接持续时间: %ld 秒\n", connection_duration);
                 printf("  已接收数据包: %d\n", data_received);
                 printf("  已发送ping: %d\n", ping_sent);
                 printf("  已收到pong: %d\n", pong_received);
                 printf("  收到服务器ping: %d\n", server_ping_received);
                 printf("  已发送pong回复: %d\n", pong_sent);
                 if (ping_sent > 0) {
                     printf("  心跳响应率: %.1f%%\n", (float)pong_received * 100.0 / ping_sent);
                 }
                 if (server_ping_received > 0) {
                     printf("  pong回复率: %.1f%%\n", (float)pong_sent * 100.0 / server_ping_received);
                 }
                 break;
             }
             
             // 解析WebSocket帧
             unsigned char *payload;
             int payload_len;
             printf("开始解析帧，缓冲区大小: %d字节\n", ret);
             int frame_len = parse_websocket_frame(buffer, ret, &payload, &payload_len);
             printf("帧解析完成，返回值: %d\n", frame_len);
             
             if (frame_len == 2) {
                 // 收到pong响应
                 pong_received++;
                 printf("收到心跳pong响应 (#%d) - 统计已更新\n", pong_received);
             } else if (frame_len == 3) {
                 // 收到服务器ping，必须回复pong
                 server_ping_received++;
                 printf("收到服务器ping (#%d) - 准备回复pong\n", server_ping_received);
                 printf("ping payload长度: %d字节\n", payload_len);
                 
                 // 检查频率限制后发送pong回复
                 if (messages_in_window < MAX_MESSAGES_PER_SEC) {
                     printf("尝试发送pong回复...\n");
                     int pong_result = send_websocket_pong(ssl, payload, payload_len);
                     printf("pong发送结果: %d\n", pong_result);
                     if (pong_result == 0) {
                         pong_sent++;
                         messages_in_window++;
                         printf("pong回复成功 (#%d)\n", pong_sent);
                     } else {
                         printf("pong发送失败，错误码: %d\n", pong_result);
                     }
                 } else {
                     printf("达到频率限制，延迟pong回复\n");
                 }
             } else if (frame_len > 0) {
                 // 正常数据帧
                 data_received++;
                 process_depth_data(payload, payload_len);
             } else {
                 // 其他类型的帧或解析失败
                 data_received++;
                 printf("收到其他类型帧: frame_len=%d\n", frame_len);
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
 
/*
 * 主函数 - 实现币安WebSocket客户端的主要逻辑流程
 * 包括连接建立、SSL握手、WebSocket握手、数据收发以及错误处理和重连机制
 */
 int main() {
    // 初始化套接字描述符，设置为-1表示未初始化状态
     int sockfd = -1;
    // 初始化SSL上下文结构体
     mbedtls_ssl_context ssl;
     int reconnect_count = 0;
     const int max_reconnects = 10;
     
     printf("轻量级币安WebSocket客户端 (C语言版本)\n");
     printf("=======================================\n");
     
     // 注册信号处理函数
     signal(SIGINT, signal_handler);
     signal(SIGTERM, signal_handler);
     
     while (g_running && reconnect_count < max_reconnects) {
         printf("\n=== 连接尝试 %d/%d ===\n", reconnect_count + 1, max_reconnects);
         
         // 1. 创建TCP连接
         sockfd = create_socket_connection();
         if (sockfd < 0) {
             reconnect_count++;
             printf("等待5秒后重试...\n");
             sleep(5);
             continue;
         }
         
         // 2. 执行SSL握手
         if (perform_ssl_handshake(&ssl, sockfd) < 0) {
             close(sockfd);
             reconnect_count++;
             printf("等待5秒后重试...\n");
             sleep(5);
             continue;
         }
         
         // 3. 执行WebSocket握手
         if (perform_websocket_handshake(&ssl) < 0) {
             cleanup_ssl(&ssl);
             close(sockfd);
             reconnect_count++;
             printf("等待5秒后重试...\n");
             sleep(5);
             continue;
         }
         
         printf("连接成功! 开始接收数据...\n");
         
         // 4. 运行主循环
         run_client_loop(&ssl, sockfd);
         
         // 5. 清理资源
         printf("连接断开，正在清理资源...\n");
         cleanup_ssl(&ssl);
         close(sockfd);
         
         // 如果是用户主动退出，不重连
         if (!g_running) {
             break;
         }
         
         reconnect_count++;
         if (reconnect_count < max_reconnects) {
             printf("等待5秒后重新连接...\n");
             sleep(5);
         }
     }
     
     if (reconnect_count >= max_reconnects) {
         printf("已达到最大重连次数 (%d)，程序退出\n", max_reconnects);
     } else {
         printf("程序正常退出\n");
     }
     
     return 0;
 }