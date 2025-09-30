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

// 性能优化宏
#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

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

// SSL密钥日志文件（用于Wireshark解密）
FILE *keylog_file = NULL;

// 延迟统计
typedef struct {
    double total_latency;
    double min_latency;
    double max_latency;
    int count;
} latency_stats_t;

latency_stats_t latency_stats = {0.0, 999999.0, 0.0, 0};

// SSL解密性能统计
typedef struct {
    uint64_t total_time_ns;
    uint64_t min_time_ns;
    uint64_t max_time_ns;
    uint64_t count;
} decrypt_stats_t;

static decrypt_stats_t decrypt_stats = {0, UINT64_MAX, 0, 0};

// 获取纳秒级时间戳
static inline uint64_t get_decrypt_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

// 记录解密时间
static inline void record_decrypt_time(uint64_t decrypt_ns) {
    decrypt_stats.total_time_ns += decrypt_ns;
    decrypt_stats.count++;
    if (decrypt_ns < decrypt_stats.min_time_ns) {
        decrypt_stats.min_time_ns = decrypt_ns;
    }
    if (decrypt_stats.max_time_ns < decrypt_ns) {
        decrypt_stats.max_time_ns = decrypt_ns;
    }
}

// 打印解密统计
static void print_decrypt_stats(void) {
    if (decrypt_stats.count == 0) return;
    double avg_ns = (double)decrypt_stats.total_time_ns / decrypt_stats.count;
    printf("\n=== SSL解密性能统计 ===\n");
    printf("解密次数: %lu\n", decrypt_stats.count);
    printf("平均耗时: %.3f μs (%.0f ns)\n", avg_ns / 1000.0, avg_ns);
    printf("最小耗时: %.3f μs (%lu ns)\n", decrypt_stats.min_time_ns / 1000.0, decrypt_stats.min_time_ns);
    printf("最大耗时: %.3f μs (%lu ns)\n", decrypt_stats.max_time_ns / 1000.0, decrypt_stats.max_time_ns);
    printf("抖动范围: %.3f μs\n", (decrypt_stats.max_time_ns - decrypt_stats.min_time_ns) / 1000.0);
}

// 性能优化：预分配缓冲区
#define JSON_BUFFER_SIZE 65536
#define WRITE_BUFFER_SIZE (1024*1024)
#define BATCH_WRITE_COUNT 1000

static char json_buffer[JSON_BUFFER_SIZE];     // JSON解析缓冲区
static char write_buffer[WRITE_BUFFER_SIZE];   // 批量写入缓冲区
static int buffer_pos = 0;                     // 写入缓冲区位置
static int batch_count = 0;                    // 批量计数器

// WebSocket帧缓冲区（处理分片帧）
#define WS_FRAME_BUFFER_SIZE 131072  // 128KB
static unsigned char ws_frame_buffer[WS_FRAME_BUFFER_SIZE];
static int ws_buffer_len = 0;
static int ws_frame_expected_len = 0;

#ifdef INET6
int sockfd6;
#endif

// 获取高精度时间戳（微秒）- 修复：使用REALTIME与币安时间戳匹配
static double get_timestamp_us() {
    struct timespec ts;
    // 必须使用CLOCK_REALTIME与币安的UTC时间戳匹配
    clock_gettime(CLOCK_REALTIME, &ts);
    return ts.tv_sec * 1000000.0 + ts.tv_nsec / 1000.0;
}

// 修复：币安时间戳解析 - 回退到可靠版本
static long long parse_binance_timestamp_fast(const char *data, int len) {
    // 查找 "E": 字段
    for (int i = 0; i < len - 4; i++) {
        if (data[i] == '"' && data[i+1] == 'E' && data[i+2] == '"' && data[i+3] == ':') {
            i += 4;
            // 跳过空格
            while (i < len && data[i] == ' ') i++;

            // 解析数字
            long long result = 0;
            while (i < len && data[i] >= '0' && data[i] <= '9') {
                result = result * 10 + (data[i] - '0');
                i++;
            }
            return result;
        }
    }
    return 0;
}

// 修复：交易ID解析 - 回退到可靠版本
static long long parse_trade_id_fast(const char *data, int len) {
    // 按优先级查找交易ID字段
    const char *patterns[] = {"\"a\":", "\"i\":", "\"id\":", "\"t\":"};
    const int pattern_lens[] = {4, 4, 5, 4};

    for (int p = 0; p < 4; p++) {
        for (int i = 0; i < len - pattern_lens[p] - 1; i++) {
            if (memcmp(data + i, patterns[p], pattern_lens[p]) == 0) {
                i += pattern_lens[p];
                // 跳过空格和引号
                while (i < len && (data[i] == ' ' || data[i] == '"')) i++;

                // 解析数字
                long long result = 0;
                while (i < len && data[i] >= '0' && data[i] <= '9') {
                    result = result * 10 + (data[i] - '0');
                    i++;
                }
                if (result > 0) return result;
            }
        }
    }
    return 0;
}

// 批量写入延迟数据
static void write_latency_batch(long long trade_id, double latency_us) {
    if (!latency_file) return;

    // 写入到缓冲区
    int written = snprintf(write_buffer + buffer_pos, WRITE_BUFFER_SIZE - buffer_pos,
                          "%lld,%.1f\n", trade_id, latency_us);

    if (written > 0 && buffer_pos + written < WRITE_BUFFER_SIZE) {
        buffer_pos += written;
        batch_count++;

        // 达到批量阈值或缓冲区快满时写入
        if (batch_count >= BATCH_WRITE_COUNT || buffer_pos > WRITE_BUFFER_SIZE - 1000) {
            fwrite(write_buffer, 1, buffer_pos, latency_file);
            fflush(latency_file);
            buffer_pos = 0;
            batch_count = 0;
        }
    }
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

// SSL密钥导出回调函数（用于Wireshark解密TLS流量）
// 格式: CLIENT_RANDOM <64字节client_random的十六进制> <master_secret的十六进制>
// 兼容mbedTLS 3.x版本
#ifdef MBEDTLS_SSL_EXPORT_KEYS
static void ssl_export_keys_callback(void *p_expkey,
                                     mbedtls_ssl_key_export_type type,
                                     const unsigned char *secret,
                                     size_t secret_len,
                                     const unsigned char client_random[32],
                                     const unsigned char server_random[32],
                                     mbedtls_tls_prf_types tls_prf_type)
{
    (void)p_expkey;
    (void)server_random;
    (void)tls_prf_type;

    if (!keylog_file || !secret) return;

    const char *label = NULL;

    // 根据密钥类型选择标签
    switch (type) {
        case MBEDTLS_SSL_KEY_EXPORT_TLS12_MASTER_SECRET:
            label = "CLIENT_RANDOM";
            break;
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
        case MBEDTLS_SSL_KEY_EXPORT_TLS1_3_CLIENT_HANDSHAKE_TRAFFIC_SECRET:
            label = "CLIENT_HANDSHAKE_TRAFFIC_SECRET";
            break;
        case MBEDTLS_SSL_KEY_EXPORT_TLS1_3_SERVER_HANDSHAKE_TRAFFIC_SECRET:
            label = "SERVER_HANDSHAKE_TRAFFIC_SECRET";
            break;
        case MBEDTLS_SSL_KEY_EXPORT_TLS1_3_CLIENT_APPLICATION_TRAFFIC_SECRET:
            label = "CLIENT_TRAFFIC_SECRET_0";
            break;
        case MBEDTLS_SSL_KEY_EXPORT_TLS1_3_SERVER_APPLICATION_TRAFFIC_SECRET:
            label = "SERVER_TRAFFIC_SECRET_0";
            break;
#endif
        default:
            return;
    }

    fprintf(keylog_file, "%s ", label);

    // 写入client_random（32字节 = 64个十六进制字符）
    for (int i = 0; i < 32; i++) {
        fprintf(keylog_file, "%02x", client_random[i]);
    }
    fprintf(keylog_file, " ");

    // 写入secret（长度由secret_len指定）
    for (size_t i = 0; i < secret_len; i++) {
        fprintf(keylog_file, "%02x", secret[i]);
    }
    fprintf(keylog_file, "\n");
    fflush(keylog_file);
}
#endif

// 强制刷新批量写入缓冲区（程序退出时调用）
static void flush_latency_batch(void) {
    if (latency_file && buffer_pos > 0) {
        fwrite(write_buffer, 1, buffer_pos, latency_file);
        fflush(latency_file);
        buffer_pos = 0;
        batch_count = 0;
    }
}

// WebSocket握手请求 - 只订阅btcusdt的trade数据
static const char *websocket_handshake =
    "GET /stream?streams=btcusdt@trade HTTP/1.1\r\n"
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
    // 静默处理ping/pong（避免输出干扰）
    send_websocket_frame(WS_OPCODE_PONG, ping_payload, ping_payload_len);
}

// 发送ping请求
static void send_ping_request() {
    // 静默发送ping
    const unsigned char ping_payload[] = "ping";
    send_websocket_frame(WS_OPCODE_PING, ping_payload, strlen((char*)ping_payload));
}


// 高性能WebSocket帧解析（支持分片帧）
static int parse_websocket_frame_optimized(const unsigned char *buffer, int len,
                                         unsigned char **payload, int *payload_len, int *opcode) {
    if (len < 2) return -1;

    unsigned char first_byte = buffer[0];
    unsigned char second_byte = buffer[1];

    int fin = (first_byte >> 7) & 1;
    int frame_opcode = first_byte & 0x0F;
    int masked = (second_byte >> 7) & 1;
    int len_field = second_byte & 0x7F;

    int header_len = 2;
    uint64_t actual_len = len_field;

    // 处理扩展长度
    if (len_field == 126) {
        if (len < 4) return -1;
        actual_len = (buffer[2] << 8) | buffer[3];
        header_len += 2;
    } else if (len_field == 127) {
        if (len < 10) return -1;
        // 支持64位长度（只取低32位）
        actual_len = ((uint64_t)buffer[6] << 24) | ((uint64_t)buffer[7] << 16) |
                     ((uint64_t)buffer[8] << 8) | (uint64_t)buffer[9];
        header_len += 8;
    }

    // 处理掩码（服务器发送的帧通常不带掩码）
    if (masked) header_len += 4;

    // 检查是否有完整的帧
    if (len < header_len + actual_len) {
        // 帧不完整，保存期望长度
        ws_frame_expected_len = header_len + actual_len;
        return -2;  // 需要更多数据
    }

    *payload = (unsigned char *)buffer + header_len;
    *payload_len = actual_len;
    *opcode = frame_opcode;

    // 对于非最终帧，需要缓存
    if (!fin) {
        return -3;  // 非最终帧，需要组装
    }

    return header_len + actual_len;  // 返回帧的总长度
}

// 高性能处理币安合约交易数据 - 零拷贝、无malloc
static void process_trade_data(const unsigned char *data, int len) {
    double receive_time = get_timestamp_us();

    // 直接在原始数据上操作，避免拷贝
    const char *json_data = (const char *)data;
    char stream_name[50] = "unknown";

    // 修复：查找combine stream格式的data字段 - 使用可靠方法
    const char *data_start = json_data;

    // 查找 "data": 字段
    for (int i = 0; i < len - 7; i++) {
        if (memcmp(json_data + i, "\"data\":", 7) == 0) {
            data_start = json_data + i + 7;

            // 同时提取stream名称 - 向前搜索
            for (int j = 0; j < i - 10; j++) {
                if (memcmp(json_data + j, "\"stream\":\"", 10) == 0) {
                    int name_start = j + 10;
                    int name_len = 0;
                    while (name_start + name_len < len && json_data[name_start + name_len] != '"' && name_len < 49) {
                        stream_name[name_len] = json_data[name_start + name_len];
                        name_len++;
                    }
                    stream_name[name_len] = '\0';
                    break;
                }
            }
            break;
        }
    }

    // 使用高性能解析器
    long long binance_timestamp = parse_binance_timestamp_fast(data_start, len - (data_start - json_data));
    long long trade_id = parse_trade_id_fast(data_start, len - (data_start - json_data));

    double latency_us = 0.0;
    if (likely(binance_timestamp > 0)) {
        latency_us = receive_time - ((double)binance_timestamp * 1000.0);
        update_latency_stats(latency_us);
    } else {
        // 如果没有找到时间戳，说明解析失败
        printf("WARNING: Failed to parse binance timestamp\n");
    }

    // 使用批量写入替代即时fflush - 修复：允许负延迟进行调试
    if (likely(trade_id > 0)) {
        write_latency_batch(trade_id, latency_us);
    }

    // 调试输出 - 前几条消息显示原始数据
    if (latency_stats.count <= 5) {
        printf("DEBUG[%d]: binance_ts=%lld, receive_time=%.1f, trade_id=%lld, stream='%s'\n",
               latency_stats.count, binance_timestamp, receive_time, trade_id, stream_name);
        printf("DEBUG[%d]: binance_ts_us=%.1f, latency_raw=%.1f\n",
               latency_stats.count, (double)binance_timestamp * 1000.0,
               receive_time - ((double)binance_timestamp * 1000.0));
        printf("Raw JSON (first 200 chars): %.200s\n", json_data);
    }

    // 只在统计时显示交易信息（极大减少printf开销）
    // 每1000条消息显示一次统计和最新交易
    if (latency_stats.count % 1000 == 0 && latency_stats.count > 0) {
        double avg_latency = latency_stats.total_latency / latency_stats.count;
        printf("[%d] %s | ID: %lld | Lat: %.1fμs | Avg: %.1fμs | Min: %.1fμs | Max: %.1fμs | Jitter: %.1fμs\n",
               latency_stats.count, stream_name, trade_id, latency_us, avg_latency,
               latency_stats.min_latency, latency_stats.max_latency,
               latency_stats.max_latency - latency_stats.min_latency);
    }
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
			// 静默关闭连接
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
					// 高性能读取WebSocket数据
					unsigned char buffer[BUFFER_SIZE];

					// === 开始计时SSL解密 ===
					uint64_t decrypt_start = get_decrypt_ns();
					int bytes_read = mbedtls_ssl_read(&ssl, buffer, sizeof(buffer));
					uint64_t decrypt_end = get_decrypt_ns();

					if (bytes_read > 0) {
						// 将新数据添加到帧缓冲区
						if (ws_buffer_len + bytes_read <= WS_FRAME_BUFFER_SIZE) {
							memcpy(ws_frame_buffer + ws_buffer_len, buffer, bytes_read);
							ws_buffer_len += bytes_read;

							// 尝试解析完整帧
							int processed = 0;
							while (processed < ws_buffer_len) {
								unsigned char *payload;
								int payload_len;
								int opcode;
								int frame_len = parse_websocket_frame_optimized(
									ws_frame_buffer + processed,
									ws_buffer_len - processed,
									&payload, &payload_len, &opcode);

								if (frame_len > 0) {
									// 完整帧解析成功
									switch (opcode) {
										case WS_OPCODE_TEXT:
                                            // 记录解密耗时
                                            record_decrypt_time(decrypt_end - decrypt_start);

                                            // 每100次解密打印一次统计
                                            if (decrypt_stats.count % 100 == 0 && decrypt_stats.count > 0) {
                                                double avg_ns = (double)decrypt_stats.total_time_ns / decrypt_stats.count;
                                                printf("[解密统计 #%lu] 平均: %.3f μs, 最小: %.3f μs, 最大: %.3f μs\n",
                                                    decrypt_stats.count,
                                                    avg_ns / 1000.0,
                                                    decrypt_stats.min_time_ns / 1000.0,
                                                    decrypt_stats.max_time_ns / 1000.0);
                                            }
                                            // === 计时结束 ===
											process_trade_data(payload, payload_len);
											break;
										case WS_OPCODE_PING:
											send_pong_response(payload, payload_len);
											break;
										case WS_OPCODE_PONG:
											// 静默处理pong
											break;
										case WS_OPCODE_CLOSE:
											printf("服务器关闭连接\n");
											flush_latency_batch();
											return 0;
									}
									processed += frame_len;
								} else {
									// 不完整帧或错误，退出循环
									break;
								}
							}

							// 移除已处理的数据
							if (processed > 0) {
								memmove(ws_frame_buffer, ws_frame_buffer + processed,
								       ws_buffer_len - processed);
								ws_buffer_len -= processed;
							}
						} else {
							// 缓冲区满，重置
							printf("警告: WebSocket帧缓冲区满，重置\n");
							ws_buffer_len = 0;
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
    printf("服务器IP: 固定IP 54.64.217.188 (跳过DNS解析)\n");
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

    // 打开SSL密钥日志文件（用于Wireshark解密）
    keylog_file = fopen("sslkeylog.txt", "w");
    if (keylog_file) {
        printf("SSL密钥日志文件 sslkeylog.txt 已创建\n");
        printf("Wireshark使用方法: Edit -> Preferences -> Protocols -> TLS -> (Pre)-Master-Secret log filename\n");
    } else {
        printf("警告: 无法创建SSL密钥日志文件 sslkeylog.txt\n");
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
	// 使用固定的币安合约服务器IP地址
	server_addr.sin_addr.s_addr = inet_addr("54.64.217.188");
	printf("使用固定币安合约IP地址: %s\n", inet_ntoa(server_addr.sin_addr));
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

    // 启用SSL密钥导出（用于Wireshark解密）- mbedTLS 3.x需要在setup之后设置
    #ifdef MBEDTLS_SSL_EXPORT_KEYS
    mbedtls_ssl_set_export_keys_cb(&ssl, ssl_export_keys_callback, NULL);
    printf("SSL密钥导出已启用\n");
    #else
    printf("警告: mbedTLS未启用MBEDTLS_SSL_EXPORT_KEYS，无法导出密钥用于解密\n");
    #endif

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
    flush_latency_batch();  // 刷新剩余数据
    if (latency_file) {
        fclose(latency_file);
        printf("延迟记录文件已关闭\n");
    }
    if (keylog_file) {
        fclose(keylog_file);
        printf("SSL密钥日志文件已关闭\n");
    }

    // 打印SSL解密性能统计
    print_decrypt_stats();

    return 0;
}