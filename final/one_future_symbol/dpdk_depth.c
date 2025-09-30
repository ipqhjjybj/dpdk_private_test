/*
 * 通过 shell 执行
 * ./tcp_client --conf /etc/f-stack.conf --proc-type=primary &
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <assert.h>
#include <netdb.h>
#include <sys/time.h>
#include <time.h>
 
#include "ff_config.h"
#include "ff_api.h"

// mbedTLS 头文件
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
 
#define MAX_EVENTS 512
#define BUFFER_SIZE 4096

// 连接状态
typedef enum {
    STATE_TCP_CONNECTING,
    STATE_SSL_HANDSHAKE,
    STATE_WEBSOCKET_HANDSHAKE,
    STATE_WEBSOCKET_CONNECTED
} connection_state_t;

/* kevent set */
struct kevent kevSet[2];

/* events */
struct kevent events[MAX_EVENTS];
/* kq */
int kq;
int sockfd;

// SSL 上下文
mbedtls_net_context server_fd;
mbedtls_ssl_context ssl;
mbedtls_ssl_config conf;
mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;

// 连接状态
connection_state_t conn_state = STATE_TCP_CONNECTING;
int ssl_handshake_done = 0;
int websocket_handshake_sent = 0;

// Ping/Pong相关变量
time_t last_ping_time = 0;
#define PING_INTERVAL 30  // 每30秒发送一次ping

// 延迟记录文件
FILE *latency_file = NULL;

// 延迟统计
typedef struct {
    double total_latency;
    double min_latency;
    double max_latency;
    int count;
} latency_stats_t;

latency_stats_t latency_stats = {0.0, 999999.0, 0.0, 0};
#ifdef INET6
int sockfd6;
#endif

// 获取高精度时间戳（微秒）
static double get_timestamp_us() {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return ts.tv_sec * 1000000.0 + ts.tv_nsec / 1000.0;
}

// 解析币安时间戳（毫秒，需要转换为微秒）
static long long parse_binance_timestamp(const char *json_str) {
    char *event_time = strstr(json_str, "\"E\":");
    if (event_time) {
        event_time += 4; // 跳过 "E":
        return strtoll(event_time, NULL, 10);
    }
    return 0;
}

// 更新延迟统计
static void update_latency_stats(double latency_us) {
    latency_stats.total_latency += latency_us;
    latency_stats.count++;

    if (latency_us < latency_stats.min_latency) {
        latency_stats.min_latency = latency_us;
    }
    if (latency_us > latency_stats.max_latency) {
        latency_stats.max_latency = latency_us;
    }
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

// WebSocket握手请求 - 使用combine stream方式
static const char *websocket_handshake =
    "GET /stream?streams=btcusdt@depth@100ms HTTP/1.1\r\n"
    "Host: fstream.binance.com\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "User-Agent: FStack-Futures-Client/1.0\r\n"
    "\r\n";

// WebSocket帧类型定义
#define WS_OPCODE_CONTINUATION 0x0
#define WS_OPCODE_TEXT         0x1
#define WS_OPCODE_BINARY       0x2
#define WS_OPCODE_CLOSE        0x8
#define WS_OPCODE_PING         0x9
#define WS_OPCODE_PONG         0xA

// 发送WebSocket帧
static int send_websocket_frame(int opcode, const unsigned char *payload, int payload_len) {
    unsigned char frame[1024];
    int frame_len = 0;

    // 第一个字节：FIN=1, RSV=000, opcode
    frame[0] = 0x80 | (opcode & 0x0F);

    // 第二个字节：MASK=1（客户端必须掩码）+ payload长度
    if (payload_len < 126) {
        frame[1] = 0x80 | payload_len;
        frame_len = 2;
    } else if (payload_len < 65536) {
        frame[1] = 0x80 | 126;
        frame[2] = (payload_len >> 8) & 0xFF;
        frame[3] = payload_len & 0xFF;
        frame_len = 4;
    } else {
        printf("载荷过大，不支持\n");
        return -1;
    }

    // 生成掩码密钥（简单起见，使用固定掩码）
    unsigned char mask[4] = {0x12, 0x34, 0x56, 0x78};
    memcpy(frame + frame_len, mask, 4);
    frame_len += 4;

    // 复制并掩码载荷
    for (int i = 0; i < payload_len; i++) {
        frame[frame_len + i] = payload[i] ^ mask[i % 4];
    }
    frame_len += payload_len;

    // 通过SSL发送
    int ret = mbedtls_ssl_write(&ssl, frame, frame_len);
    return ret > 0 ? 0 : -1;
}

// 发送pong响应
static void send_pong_response(const unsigned char *ping_payload, int ping_payload_len) {
    printf("收到ping，发送pong响应\n");
    send_websocket_frame(WS_OPCODE_PONG, ping_payload, ping_payload_len);
}

// 发送ping请求
static void send_ping_request() {
    printf("发送ping请求到币安服务器\n");
    const unsigned char ping_payload[] = "ping";
    send_websocket_frame(WS_OPCODE_PING, ping_payload, strlen((char*)ping_payload));
}

// 简化的WebSocket帧解析
static int parse_websocket_frame(const unsigned char *buffer, int len,
                                unsigned char **payload, int *payload_len, int *opcode) {
    if (len < 2) return -1;

    unsigned char first_byte = buffer[0];
    unsigned char second_byte = buffer[1];

    int fin = (first_byte >> 7) & 1;
    int frame_opcode = first_byte & 0x0F;
    int masked = (second_byte >> 7) & 1;
    int len_field = second_byte & 0x7F;

    // 只处理完整帧(fin=1)
    if (!fin) return -1;

    int header_len = 2;
    uint64_t actual_len = len_field;

    // 处理扩展长度
    if (len_field == 126) {
        if (len < 4) return -1;
        actual_len = (buffer[2] << 8) | buffer[3];
        header_len += 2;
    } else if (len_field == 127) {
        return -1;  // 忽略超长帧
    }

    // 处理掩码（服务器发送的帧通常不带掩码）
    if (masked) header_len += 4;

    if (len < header_len + actual_len) return -1;

    *payload = (unsigned char *)buffer + header_len;
    *payload_len = actual_len;
    *opcode = frame_opcode;
    return 0;
}

// 处理币安合约深度数据 - combine stream格式
static void process_depth_data(const unsigned char *data, int len) {
    double receive_time = get_timestamp_us();

    char *json_str = malloc(len + 1);
    memcpy(json_str, data, len);
    json_str[len] = '\0';

    // 检查是否是combine stream格式（包含stream和data字段）
    char *stream = strstr(json_str, "\"stream\":\"");
    char *data_field = strstr(json_str, "\"data\":");

    char *data_json = json_str; // 默认使用原始JSON
    char stream_name[100] = "direct"; // 默认流名称

    if (stream && data_field) {
        // combine stream格式，提取stream名称
        stream += 10; // 跳过 "stream":"
        char *stream_end = strchr(stream, '"');
        if (stream_end) {
            int stream_len = stream_end - stream;
            strncpy(stream_name, stream, stream_len < 99 ? stream_len : 99);
            stream_name[stream_len < 99 ? stream_len : 99] = '\0';
        }

        // 使用data字段进行解析
        data_json = data_field + 7; // 跳过 "data":
    }

    // 解析币安事件时间戳
    long long binance_timestamp = parse_binance_timestamp(data_json);
    double latency_us = 0.0;

    if (binance_timestamp > 0) {
        // 币安时间戳是毫秒，转换为微秒进行计算
        latency_us = receive_time - ((double)binance_timestamp * 1000.0);
        update_latency_stats(latency_us);
    }

    // 解析深度数据的关键字段（在data字段内）
    char *symbol = strstr(data_json, "\"s\":\"");
    char *lastUpdateId = strstr(data_json, "\"lastUpdateId\":");
    char *updateId = strstr(data_json, "\"u\":");
    char *firstUpdateId = strstr(data_json, "\"U\":");

    // 解析更新ID用于文件记录
    long long update_id = 0;
    if (updateId) {
        char *temp_updateId = updateId + 4; // 跳过 "u":
        while (*temp_updateId == ' ') temp_updateId++;
        update_id = strtoll(temp_updateId, NULL, 10);
    }

    // 记录ID和延迟到文件
    if (latency_file && update_id > 0 && latency_us > 0) {
        fprintf(latency_file, "%lld,%.1f\n", update_id, latency_us);
        fflush(latency_file); // 立即写入文件
    }

    char *bids = strstr(data_json, "\"bids\":");
    char *asks = strstr(data_json, "\"asks\":");

    printf("\n=== 币安合约深度数据 ===\n");
    printf("Stream: %s\n", stream_name);

    if (symbol) {
        symbol += 5;
        char *end = strchr(symbol, '"');
        if (end) {
            *end = '\0';
            printf("交易对: %s\n", symbol);
            *end = '"';
        }
    }

    // 解析各种ID字段
    if (lastUpdateId) {
        lastUpdateId += 15; // 跳过 "lastUpdateId":
        // 跳过可能的空格
        while (*lastUpdateId == ' ') lastUpdateId++;
        char *end = strchr(lastUpdateId, ',');
        if (!end) end = strchr(lastUpdateId, '}');
        if (end) {
            char temp = *end;
            *end = '\0';
            printf("最后更新ID: %s\n", lastUpdateId);
            *end = temp;
        }
    }

    if (updateId) {
        updateId += 4; // 跳过 "u":
        // 跳过可能的空格
        while (*updateId == ' ') updateId++;
        char *end = strchr(updateId, ',');
        if (!end) end = strchr(updateId, '}');
        if (end) {
            char temp = *end;
            *end = '\0';
            printf("当前更新ID: %s\n", updateId);
            *end = temp;
        }
    }

    if (firstUpdateId) {
        firstUpdateId += 4; // 跳过 "U":
        // 跳过可能的空格
        while (*firstUpdateId == ' ') firstUpdateId++;
        char *end = strchr(firstUpdateId, ',');
        if (!end) end = strchr(firstUpdateId, '}');
        if (end) {
            char temp = *end;
            *end = '\0';
            printf("首个更新ID: %s\n", firstUpdateId);
            *end = temp;
        }
    }

    // 如果没有找到任何ID字段，输出JSON片段用于调试
    if (!lastUpdateId && !updateId && !firstUpdateId) {
        printf("DEBUG: 未找到ID字段，JSON片段: %.100s...\n", json_str);
    }

    // 解析最优买单价格 (bids数组第一个元素)
    if (bids) {
        char *first_bid = strstr(bids, "[[\"");
        if (first_bid) {
            first_bid += 3; // 跳过 [["
            char *price_end = strchr(first_bid, '"');
            if (price_end) {
                *price_end = '\0';
                printf("最优买价: %s USDT", first_bid);
                *price_end = '"';

                // 解析数量
                char *quantity_start = strstr(price_end + 1, "\"");
                if (quantity_start) {
                    quantity_start += 1;
                    char *quantity_end = strchr(quantity_start, '"');
                    if (quantity_end) {
                        *quantity_end = '\0';
                        printf(" (数量: %s)\n", quantity_start);
                        *quantity_end = '"';
                    }
                }
            }
        }
    }

    // 解析最优卖单价格 (asks数组第一个元素)
    if (asks) {
        char *first_ask = strstr(asks, "[[\"");
        if (first_ask) {
            first_ask += 3; // 跳过 [["
            char *price_end = strchr(first_ask, '"');
            if (price_end) {
                *price_end = '\0';
                printf("最优卖价: %s USDT", first_ask);
                *price_end = '"';

                // 解析数量
                char *quantity_start = strstr(price_end + 1, "\"");
                if (quantity_start) {
                    quantity_start += 1;
                    char *quantity_end = strchr(quantity_start, '"');
                    if (quantity_end) {
                        *quantity_end = '\0';
                        printf(" (数量: %s)\n", quantity_start);
                        *quantity_end = '"';
                    }
                }
            }
        }
    }

    // 计算买卖价差
    if (bids && asks) {
        char *bid_price_str = strstr(bids, "[[\"");
        char *ask_price_str = strstr(asks, "[[\"");

        if (bid_price_str && ask_price_str) {
            bid_price_str += 3;
            ask_price_str += 3;

            char *bid_end = strchr(bid_price_str, '"');
            char *ask_end = strchr(ask_price_str, '"');

            if (bid_end && ask_end) {
                *bid_end = '\0';
                *ask_end = '\0';

                double bid_price = atof(bid_price_str);
                double ask_price = atof(ask_price_str);
                double spread = ask_price - bid_price;
                double spread_bps = (spread / ask_price) * 10000; // 基点

                printf("买卖价差: %.2f USDT (%.2f基点)\n", spread, spread_bps);

                *bid_end = '"';
                *ask_end = '"';
            }
        }
    }

    // 显示网络延迟信息
    if (binance_timestamp > 0) {
        printf("网络延迟: %.1f μs (%.3f ms)\n", latency_us, latency_us / 1000.0);

        // 每10条消息显示一次统计信息
        if (latency_stats.count % 10 == 0) {
            double avg_latency = latency_stats.total_latency / latency_stats.count;
            printf("--- 延迟统计 (最近%d条消息) ---\n", latency_stats.count);
            printf("平均延迟: %.1f μs (%.3f ms)\n", avg_latency, avg_latency / 1000.0);
            printf("最小延迟: %.1f μs (%.3f ms)\n", latency_stats.min_latency, latency_stats.min_latency / 1000.0);
            printf("最大延迟: %.1f μs (%.3f ms)\n", latency_stats.max_latency, latency_stats.max_latency / 1000.0);
            printf("抖动范围: %.1f μs\n", latency_stats.max_latency - latency_stats.min_latency);
            printf("--------------------------------\n");
        }
    }

    printf("==================\n");
    free(json_str);
}

int loop(void *arg)
{
    /* Wait for events to happen */
    unsigned nevents = ff_kevent(kq, NULL, 0, events, MAX_EVENTS, NULL);
    unsigned i;
 
    for (i = 0; i < nevents; ++i) {
        struct kevent event = events[i];
        int clientfd = (int)event.ident;
 
        /* Handle disconnect */
        if (event.flags & EV_EOF) {
            /* Simply close socket */
            ff_close(clientfd);
			printf("#### close clientfd=%d\n",clientfd);
        }
 
		if (clientfd == sockfd) {
			// 处理不同的连接状态
			if (event.filter == EVFILT_WRITE) {
				if (conn_state == STATE_TCP_CONNECTING) {
					printf("TCP连接建立，开始SSL握手\n");
					conn_state = STATE_SSL_HANDSHAKE;
				}

				if (conn_state == STATE_SSL_HANDSHAKE && !ssl_handshake_done) {
					// 继续SSL握手
					int ret = mbedtls_ssl_handshake(&ssl);
					if (ret == 0) {
						printf("SSL握手成功\n");
							ssl_handshake_done = 1;
						conn_state = STATE_WEBSOCKET_HANDSHAKE;
					} else if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
						char error_buf[100];
						mbedtls_strerror(ret, error_buf, sizeof(error_buf));
						printf("SSL握手失败: %s\n", error_buf);
						return 0;
					}
				}

				if (conn_state == STATE_WEBSOCKET_HANDSHAKE && !websocket_handshake_sent) {
					printf("发送WebSocket握手请求\n");
					if (mbedtls_ssl_write(&ssl, (unsigned char *)websocket_handshake,
						strlen(websocket_handshake)) > 0) {
						websocket_handshake_sent = 1;
					}
				}
			}

			if (event.filter == EVFILT_READ) {
				if (conn_state == STATE_SSL_HANDSHAKE && !ssl_handshake_done) {
					// 继续SSL握手
					int ret = mbedtls_ssl_handshake(&ssl);
					if (ret == 0) {
						printf("SSL握手成功\n");
						ssl_handshake_done = 1;
						conn_state = STATE_WEBSOCKET_HANDSHAKE;
					} else if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
						char error_buf[100];
						mbedtls_strerror(ret, error_buf, sizeof(error_buf));
						printf("SSL握手失败: %s\n", error_buf);
						return 0;
					}
				} else if (conn_state == STATE_WEBSOCKET_HANDSHAKE) {
					// 读取WebSocket握手响应
					unsigned char buffer[BUFFER_SIZE];
					int bytes_read = mbedtls_ssl_read(&ssl, buffer, sizeof(buffer) - 1);
					if (bytes_read > 0) {
						buffer[bytes_read] = '\0';
						if (strstr((char *)buffer, "101 Switching Protocols")) {
							printf("WebSocket握手成功\n");
							conn_state = STATE_WEBSOCKET_CONNECTED;
							last_ping_time = time(NULL); // 初始化ping时间
						} else {
							printf("WebSocket握手失败: %s\n", buffer);
						}
					}
				} else if (conn_state == STATE_WEBSOCKET_CONNECTED) {
					// 读取WebSocket数据
					unsigned char buffer[BUFFER_SIZE];
					int bytes_read = mbedtls_ssl_read(&ssl, buffer, sizeof(buffer));
					if (bytes_read > 0) {
						// 解析WebSocket帧
						unsigned char *payload;
						int payload_len;
						int opcode;
						if (parse_websocket_frame(buffer, bytes_read, &payload, &payload_len, &opcode) == 0) {
							switch (opcode) {
								case WS_OPCODE_TEXT:
									// 处理文本数据（币安行情数据）
									process_depth_data(payload, payload_len);
									break;
								case WS_OPCODE_PING:
									// 处理ping请求，发送pong响应
									send_pong_response(payload, payload_len);
									break;
								case WS_OPCODE_PONG:
									// 收到pong响应
									printf("收到pong响应\n");
									break;
								case WS_OPCODE_CLOSE:
									printf("服务器关闭连接\n");
									return 0;
								default:
									printf("收到未知帧类型: 0x%02X\n", opcode);
									break;
							}
						}
					}

					// 检查是否需要发送ping
					time_t current_time = time(NULL);
					if (current_time - last_ping_time >= PING_INTERVAL) {
						send_ping_request();
						last_ping_time = current_time;
					}
				}
			}

    	}
    }
    return 0;
}
 
int main(int argc, char * argv[])
{
    printf("F-Stack + mbedTLS 币安合约WebSocket客户端 (深度数据 + 微秒级延迟测试)\n");
    printf("==========================================================================\n");
    printf("功能: 实时接收BTCUSDT合约订单簿深度数据并测试网络延迟\n");
    printf("连接方式: Combine Stream (便于后续扩展多品种订阅)\n");
    printf("更新频率: 100ms (高频数据推送)\n");
    printf("数据: 最优买价/卖价、数量、买卖价差、更新ID\n");
    printf("延迟精度: 微秒级(μs) - 币安服务器时间戳 vs 本地接收时间\n");
    printf("统计指标: 平均延迟、最小/最大延迟、抖动范围\n");
    printf("延迟记录: 保存到 latency.txt 文件 (格式: 更新ID,延迟微秒)\n");
    printf("==========================================================================\n\n");

    // 打开延迟记录文件
    latency_file = fopen("latency.txt", "w");
    if (latency_file) {
        printf("延迟记录文件 latency.txt 已创建\n");
        // 写入CSV头部
        fprintf(latency_file, "update_id,latency_us\n");
        fflush(latency_file);
    } else {
        printf("警告: 无法创建延迟记录文件 latency.txt\n");
    }

    ff_init(argc, argv);
 
    assert((kq = ff_kqueue()) > 0);
 
    sockfd = ff_socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        printf("ff_socket failed, sockfd:%d, errno:%d, %s\n", sockfd, errno, strerror(errno));
        exit(1);
    }
	
	struct sockaddr_in server_addr; 
	bzero(&server_addr, sizeof(server_addr)); 
	server_addr.sin_family = AF_INET; 
	// 动态解析币安合约服务器地址
	struct hostent *host_entry = gethostbyname("fstream.binance.com");
	if (host_entry == NULL) {
		printf("DNS解析失败\n");
		exit(1);
	}
	server_addr.sin_addr.s_addr = *((unsigned long *)host_entry->h_addr_list[0]);
	printf("解析到币安合约IP地址: %s\n", inet_ntoa(server_addr.sin_addr));
	server_addr.sin_port = htons(443); 
 
    struct sockaddr_in my_addr;
    bzero(&my_addr, sizeof(my_addr));
    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons(8000);
    my_addr.sin_addr.s_addr = inet_addr("172.35.33.174");
 
    int ret = ff_bind(sockfd, (struct linux_sockaddr *)&my_addr, sizeof(my_addr));
    if (ret < 0) {
        printf("ff_bind failed, sockfd:%d, errno:%d, %s\n", sockfd, errno, strerror(errno));
        exit(1);
    }else{
        printf("ff_bind success, sockfd:%d\n", sockfd);
    }

    // 初始化mbedTLS
    printf("初始化SSL...\n");
    mbedtls_net_init(&server_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    // 初始化随机数生成器
    const char *pers = "fstack_binance_client";
    if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                             (const unsigned char *)pers, strlen(pers)) != 0) {
        printf("随机数生成器初始化失败\n");
        exit(1);
    }

    // 配置SSL
    if (mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
                                   MBEDTLS_SSL_TRANSPORT_STREAM,
                                   MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
        printf("SSL配置初始化失败\n");
        exit(1);
    }

    // 设置验证模式（生产环境应该验证证书）
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

    if (mbedtls_ssl_setup(&ssl, &conf) != 0) {
        printf("SSL设置失败\n");
        exit(1);
    }

    // 设置主机名（用于SNI）
    if (mbedtls_ssl_set_hostname(&ssl, "fstream.binance.com") != 0) {
        printf("设置主机名失败\n");
        exit(1);
    }

    // 设置mbedTLS的网络上下文
    server_fd.fd = sockfd;
    mbedtls_ssl_set_bio(&ssl, &server_fd, fstack_net_send, fstack_net_recv, NULL);

	ret = ff_connect(sockfd,(struct linux_sockaddr *)&server_addr,sizeof(server_addr));
    if (ret < 0 && errno != EPERM) {
        printf("ff_connect failed, sockfd:%d, errno:%d, %s\n", sockfd, errno, strerror(errno));
        exit(1);
    } else {
        printf("TCP连接启动成功\n");
    }	
 
    EV_SET(&kevSet[0], sockfd, EVFILT_READ	, EV_ADD, 0, MAX_EVENTS, NULL);	
	EV_SET(&kevSet[1], sockfd, EVFILT_WRITE, EV_ADD, 0, MAX_EVENTS, NULL);
    /* Update kqueue */
    ff_kevent(kq, kevSet, 2, NULL, 0, NULL);
 
    ff_run(loop, NULL);

    // 清理资源
    if (latency_file) {
        fclose(latency_file);
        printf("延迟记录文件已关闭\n");
    }

    return 0;
}