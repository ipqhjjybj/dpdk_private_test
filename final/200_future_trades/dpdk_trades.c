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

// WebSocket握手请求 - 使用combine stream方式订阅多品种trade数据
static const char *websocket_handshake =
    "GET /stream?streams=btcusdt@trade/ethusdt@trade/bchusdt@trade/xrpusdt@trade/ltcusdt@trade/trxusdt@trade/etcusdt@trade/linkusdt@trade/xlmusdt@trade/adausdt@trade/xmrusdt@trade/dashusdt@trade/zecusdt@trade/xtzusdt@trade/bnbusdt@trade/atomusdt@trade/ontusdt@trade/iotausdt@trade/batusdt@trade/vetusdt@trade/neousdt@trade/qtumusdt@trade/iostusdt@trade/thetausdt@trade/algousdt@trade/zilusdt@trade/kncusdt@trade/zrxusdt@trade/compusdt@trade/dogeusdt@trade/sxpusdt@trade/kavausdt@trade/bandusdt@trade/rlcusdt@trade/snxusdt@trade/dotusdt@trade/yfiusdt@trade/crvusdt@trade/trbusdt@trade/runeusdt@trade/sushiusdt@trade/egldusdt@trade/solusdt@trade/icxusdt@trade/storjusdt@trade/uniusdt@trade/avaxusdt@trade/enjusdt@trade/flmusdt@trade/ksmusdt@trade/nearusdt@trade/aaveusdt@trade/filusdt@trade/rsrusdt@trade/lrcusdt@trade/belusdt@trade/axsusdt@trade/zenusdt@trade/sklusdt@trade/grtusdt@trade/1inchusdt@trade/chzusdt@trade/sandusdt@trade/ankrusdt@trade/rvnusdt@trade/sfpusdt@trade/cotiusdt@trade/chrusdt@trade/manausdt@trade/aliceusdt@trade/hbarusdt@trade/oneusdt@trade/dentusdt@trade/celrusdt@trade/hotusdt@trade/mtlusdt@trade/ognusdt@trade/nknusdt@trade/1000shibusdt@trade/bakeusdt@trade/gtcusdt@trade/btcdomusdt@trade/iotxusdt@trade/c98usdt@trade/maskusdt@trade/atausdt@trade/dydxusdt@trade/1000xecusdt@trade/galausdt@trade/celousdt@trade/arusdt@trade/arpausdt@trade/ctsiusdt@trade/lptusdt@trade/ensusdt@trade/peopleusdt@trade/roseusdt@trade/duskusdt@trade/flowusdt@trade/imxusdt@trade/api3usdt@trade/gmtusdt@trade/apeusdt@trade/woousdt@trade/jasmyusdt@trade/opusdt@trade/injusdt@trade/stgusdt@trade/spellusdt@trade/1000luncusdt@trade/luna2usdt@trade/ldousdt@trade/icpusdt@trade/aptusdt@trade/qntusdt@trade/fetusdt@trade/fxsusdt@trade/hookusdt@trade/magicusdt@trade/tusdt@trade/highusdt@trade/minausdt@trade/astrusdt@trade/phbusdt@trade/gmxusdt@trade/cfxusdt@trade/stxusdt@trade/achusdt@trade/ssvusdt@trade/ckbusdt@trade/perpusdt@trade/truusdt@trade/lqtyusdt@trade/usdcusdt@trade/idusdt@trade/arbusdt@trade/joeusdt@trade/tlmusdt@trade/rdntusdt@trade/hftusdt@trade/xvsusdt@trade/ethbtc@trade/blurusdt@trade/eduusdt@trade/suiusdt@trade/1000pepeusdt@trade/1000flokiusdt@trade/umausdt@trade/nmrusdt@trade/mavusdt@trade/xvgusdt@trade/wldusdt@trade/pendleusdt@trade/arkmusdt@trade/agldusdt@trade/yggusdt@trade/dodoxusdt@trade/bntusdt@trade/oxtusdt@trade/seiusdt@trade/cyberusdt@trade/hifiusdt@trade/arkusdt@trade/bicousdt@trade/bigtimeusdt@trade/waxpusdt@trade/bsvusdt@trade/rifusdt@trade/polyxusdt@trade/gasusdt@trade/powrusdt@trade/tiausdt@trade/cakeusdt@trade/memeusdt@trade/twtusdt@trade/tokenusdt@trade/ordiusdt@trade/steemusdt@trade/ilvusdt@trade/ntrnusdt@trade/kasusdt@trade/beamxusdt@trade/1000bonkusdt@trade/pythusdt@trade/superusdt@trade/ustcusdt@trade/ongusdt@trade/ethwusdt@trade/jtousdt@trade/1000satsusdt@trade/auctionusdt@trade/1000ratsusdt@trade/aceusdt@trade/movrusdt@trade/nfpusdt@trade/btcusdc@trade/ethusdc@trade/bnbusdc@trade/solusdc@trade/xrpusdc@trade HTTP/1.1\r\n"
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

// 处理币安合约交易数据 - combine stream格式（仅提取ID和延迟）
static void process_trade_data(const unsigned char *data, int len) {
    double receive_time = get_timestamp_us();

    char *json_str = malloc(len + 1);
    memcpy(json_str, data, len);
    json_str[len] = '\0';

    // 检查是否是combine stream格式（包含stream和data字段）
    char *stream = strstr(json_str, "\"stream\":\"");
    char *data_field = strstr(json_str, "\"data\":");

    char *data_json = json_str; // 默认使用原始JSON
    char stream_name[50] = "unknown"; // 流名称

    if (stream && data_field) {
        // combine stream格式，提取stream名称
        stream += 10; // 跳过 "stream":"
        char *stream_end = strchr(stream, '"');
        if (stream_end) {
            int stream_len = stream_end - stream;
            strncpy(stream_name, stream, stream_len < 49 ? stream_len : 49);
            stream_name[stream_len < 49 ? stream_len : 49] = '\0';
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

    // 解析交易ID（尝试多个可能的字段）
    long long trade_id = 0;

    // 按优先级尝试不同的ID字段
    char *id_fields[] = {"\"a\":", "\"i\":", "\"id\":", "\"t\":"};
    int field_offsets[] = {4, 4, 5, 4}; // 对应字段名的长度
    int num_fields = sizeof(id_fields) / sizeof(id_fields[0]);

    for (int i = 0; i < num_fields && trade_id == 0; i++) {
        char *id_field = strstr(data_json, id_fields[i]);
        if (id_field) {
            char *temp_id = id_field + field_offsets[i];
            while (*temp_id == ' ') temp_id++;

            // 处理可能的引号包围的数字
            if (*temp_id == '"') {
                temp_id++; // 跳过开始引号
            }

            trade_id = strtoll(temp_id, NULL, 10);
            break;
        }
    }

    // 如果仍然没有找到有效ID，尝试输出JSON片段进行调试
    if (trade_id == 0) {
        // 只在前几次显示调试信息，避免刷屏
        static int debug_count = 0;
        if (debug_count < 3) {
            printf("DEBUG: 无法解析交易ID，JSON片段: %.200s...\n", data_json);
            debug_count++;
        }
    }

    // 记录交易ID和延迟到文件
    if (latency_file && trade_id > 0 && latency_us > 0) {
        fprintf(latency_file, "%lld,%.1f\n", trade_id, latency_us);
        fflush(latency_file); // 立即写入文件
    }

    // 简化输出 - 只显示关键信息
    printf("Trade - %s | ID: %lld | Latency: %.1f μs\n",
           stream_name, trade_id, latency_us);

    // 每50条消息显示一次延迟统计
    if (latency_stats.count % 50 == 0) {
        double avg_latency = latency_stats.total_latency / latency_stats.count;
        printf("=== 延迟统计 (%d条) ===\n", latency_stats.count);
        printf("平均: %.1f μs | 最小: %.1f μs | 最大: %.1f μs | 抖动: %.1f μs\n",
               avg_latency, latency_stats.min_latency,
               latency_stats.max_latency, latency_stats.max_latency - latency_stats.min_latency);
        printf("=======================\n");
    }
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
									// 处理文本数据（币安交易数据）
									process_trade_data(payload, payload_len);
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
    printf("F-Stack + mbedTLS 币安合约WebSocket客户端 (多品种交易数据 + 微秒级延迟测试)\n");
    printf("================================================================================\n");
    printf("功能: 实时接收200+个合约品种交易数据并测试网络延迟\n");
    printf("订阅品种: BTCUSDT, ETHUSDT, BCHUSDT, XRPUSDT等200+个热门合约\n");
    printf("数据类型: Trade交易数据 (实时成交记录)\n");
    printf("连接方式: Combine Stream (单连接多品种高效订阅)\n");
    printf("数据解析: 仅提取交易ID和延迟信息 (精简高性能)\n");
    printf("延迟精度: 微秒级(μs) - 币安服务器时间戳 vs 本地接收时间\n");
    printf("统计指标: 平均延迟、最小/最大延迟、抖动范围\n");
    printf("延迟记录: 保存到 latency.txt 文件 (格式: 交易ID,延迟微秒)\n");
    printf("================================================================================\n\n");

    // 打开延迟记录文件
    latency_file = fopen("latency.txt", "w");
    if (latency_file) {
        printf("延迟记录文件 latency.txt 已创建\n");
        // 写入CSV头部
        fprintf(latency_file, "trade_id,latency_us\n");
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