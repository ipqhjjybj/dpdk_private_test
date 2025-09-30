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

// WebSocket握手请求
static const char *websocket_handshake =
    "GET /ws/btcusdt@ticker HTTP/1.1\r\n"
    "Host: stream.binance.com\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "User-Agent: FStack-WebSocket-Client/1.0\r\n"
    "\r\n";

// 简化的WebSocket帧解析
static int parse_websocket_frame(const unsigned char *buffer, int len,
                                unsigned char **payload, int *payload_len) {
    if (len < 2) return -1;

    unsigned char first_byte = buffer[0];
    unsigned char second_byte = buffer[1];

    int fin = (first_byte >> 7) & 1;
    int opcode = first_byte & 0x0F;
    int masked = (second_byte >> 7) & 1;
    int len_field = second_byte & 0x7F;

    // 只处理文本帧(opcode=1)和完整帧(fin=1)
    if (opcode != 1 || !fin) return -1;

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
    return 0;
}

// 处理币安行情数据
static void process_ticker_data(const unsigned char *data, int len) {
    double receive_time = get_timestamp_us();

    char *json_str = malloc(len + 1);
    memcpy(json_str, data, len);
    json_str[len] = '\0';

    // 解析币安事件时间戳
    long long binance_timestamp = parse_binance_timestamp(json_str);
    double latency_us = 0.0;

    if (binance_timestamp > 0) {
        // 币安时间戳是毫秒，转换为微秒进行计算
        latency_us = receive_time - ((double)binance_timestamp * 1000.0);
        update_latency_stats(latency_us);
    }

    // 简单解析关键字段
    char *symbol = strstr(json_str, "\"s\":\"");
    char *price = strstr(json_str, "\"c\":\"");
    char *change = strstr(json_str, "\"P\":\"");
    char *volume = strstr(json_str, "\"v\":\"");

    printf("\n=== 币安行情数据 ===\n");

    if (symbol) {
        symbol += 5;
        char *end = strchr(symbol, '"');
        if (end) {
            *end = '\0';
            printf("交易对: %s\n", symbol);
            *end = '"';
        }
    }

    if (price) {
        price += 5;
        char *end = strchr(price, '"');
        if (end) {
            *end = '\0';
            printf("当前价格: %s USDT\n", price);
            *end = '"';
        }
    }

    if (change) {
        change += 5;
        char *end = strchr(change, '"');
        if (end) {
            *end = '\0';
            printf("24h涨跌幅: %s%%\n", change);
            *end = '"';
        }
    }

    if (volume) {
        volume += 5;
        char *end = strchr(volume, '"');
        if (end) {
            *end = '\0';
            printf("24h成交量: %s BTC\n", volume);
            *end = '"';
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
						if (parse_websocket_frame(buffer, bytes_read, &payload, &payload_len) == 0) {
							process_ticker_data(payload, payload_len);
						}
					}
				}
			}

    	}
    }
    return 0;
}
 
int main(int argc, char * argv[])
{
    printf("F-Stack + mbedTLS 币安WebSocket客户端 (微秒级延迟测试)\n");
    printf("===============================================\n");
    printf("功能: 实时接收BTC/USDT行情并测试网络延迟\n");
    printf("延迟精度: 微秒级(μs) - 币安服务器时间戳 vs 本地接收时间\n");
    printf("统计指标: 平均延迟、最小/最大延迟、抖动范围\n");
    printf("===============================================\n\n");

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
	// 动态解析币安服务器地址
	struct hostent *host_entry = gethostbyname("stream.binance.com");
	if (host_entry == NULL) {
		printf("DNS解析失败\n");
		exit(1);
	}
	server_addr.sin_addr.s_addr = *((unsigned long *)host_entry->h_addr_list[0]);
	printf("解析到币安IP地址: %s\n", inet_ntoa(server_addr.sin_addr)); 
	server_addr.sin_port = htons(9443); 
 
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
    if (mbedtls_ssl_set_hostname(&ssl, "stream.binance.com") != 0) {
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
    return 0;
}