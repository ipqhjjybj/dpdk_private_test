#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include <sys/time.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <limits.h>

#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/base64.h"
#include "mbedtls/x509_crt.h"

#define BINANCE_WS_HOST "54.64.217.188"
#define BINANCE_WS_PORT "443"
#define BUFFER_SIZE 16384
#define MAX_PAYLOAD_SIZE 8192
#define WS_MAGIC_STRING "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define PING_INTERVAL_SECONDS 180
#define RECONNECT_DELAY_SECONDS 5
#define MAX_RECONNECT_ATTEMPTS 10

// WebSocket opcodes
#define WS_OPCODE_CONTINUATION 0x0
#define WS_OPCODE_TEXT 0x1
#define WS_OPCODE_BINARY 0x2
#define WS_OPCODE_CLOSE 0x8
#define WS_OPCODE_PING 0x9
#define WS_OPCODE_PONG 0xA

typedef struct {
    mbedtls_net_context server_fd;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_x509_crt cacert;
    time_t last_ping_time;
    int running;
    FILE *latency_file;
    int reconnect_attempts;
    long long message_count;
    long long total_latency_us;
    int min_latency_us;
    int max_latency_us;
    char payload_buffer[MAX_PAYLOAD_SIZE];
    time_t last_ping_check;
} tls_context_t;

typedef struct {
    struct timeval timestamp;
    long long id;
    int latency_us;
} depth_update_t;

// 获取当前时间戳（微秒）
long long get_timestamp_us() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (long long)tv.tv_sec * 1000000 + tv.tv_usec;
}

// 计算延迟（使用服务器时间戳，精确到微秒）
int calculate_latency_from_server_us(long long server_timestamp_ms) {
    if (server_timestamp_ms <= 0) {
        return -1; // 无效的服务器时间戳
    }

    long long current_time_us = get_timestamp_us();
    long long server_timestamp_us = server_timestamp_ms * 1000; // 毫秒转微秒
    return (int)(current_time_us - server_timestamp_us);
}

// 生成WebSocket accept key
int generate_websocket_key(char *key_out, size_t key_len) {
    unsigned char random_bytes[16];
    size_t olen;

    // 生成16字节随机数
    for (int i = 0; i < 16; i++) {
        random_bytes[i] = rand() % 256;
    }

    // Base64编码
    return mbedtls_base64_encode((unsigned char*)key_out, key_len, &olen, random_bytes, 16);
}

// 发送WebSocket帧
int send_websocket_frame(tls_context_t *ctx, unsigned char opcode, const char *payload, int payload_len) {
    unsigned char frame[1024];
    int frame_len = 0;

    // 第一个字节: FIN=1, RSV=000, OPCODE
    frame[0] = 0x80 | (opcode & 0x0F);

    // 第二个字节和后续字节: MASK=1, payload length
    if (payload_len < 126) {
        frame[1] = 0x80 | payload_len;
        frame_len = 2;
    } else if (payload_len < 65536) {
        frame[1] = 0x80 | 126;
        frame[2] = (payload_len >> 8) & 0xFF;
        frame[3] = payload_len & 0xFF;
        frame_len = 4;
    } else {
        // 不支持超过64KB的payload
        return -1;
    }

    // 生成4字节mask key
    unsigned char mask[4];
    for (int i = 0; i < 4; i++) {
        mask[i] = rand() & 0xFF;
        frame[frame_len + i] = mask[i];
    }
    frame_len += 4;

    // 添加masked payload
    for (int i = 0; i < payload_len; i++) {
        frame[frame_len + i] = payload[i] ^ mask[i % 4];
    }
    frame_len += payload_len;

    // 发送帧
    int ret = mbedtls_ssl_write(&ctx->ssl, frame, frame_len);
    if (ret < 0) {
        printf("Failed to send WebSocket frame: -0x%x\n", -ret);
        return ret;
    }

    return 0;
}

// 发送pong帧
int send_pong(tls_context_t *ctx, const char *payload, int payload_len) {
    return send_websocket_frame(ctx, WS_OPCODE_PONG, payload, payload_len);
}

// 发送ping帧
int send_ping(tls_context_t *ctx) {
    return send_websocket_frame(ctx, WS_OPCODE_PING, "", 0);
}

// 发送订阅消息（combineStream方式）
int send_subscribe_message(tls_context_t *ctx) {
    // 构建订阅BTCUSDT depth的JSON消息
    const char* subscribe_msg =
        "{"
        "\"method\":\"SUBSCRIBE\","
        "\"params\":[\"btcusdt@depth@100ms\"],"
        "\"id\":1"
        "}";

    int ret = send_websocket_frame(ctx, WS_OPCODE_TEXT, subscribe_msg, strlen(subscribe_msg));

    return ret;
}

// 绑定CPU核心
int bind_to_cpu_core(int core_id) {
    cpu_set_t cpuset;
    pid_t pid = getpid();

    // 清空CPU集合
    CPU_ZERO(&cpuset);

    // 设置要绑定的CPU核心
    CPU_SET(core_id, &cpuset);

    // 执行CPU绑定
    if (sched_setaffinity(pid, sizeof(cpu_set_t), &cpuset) == -1) {
        perror("sched_setaffinity failed");
        return -1;
    }

    printf("Successfully bound process to CPU core %d\n", core_id);
    return 0;
}

// 内联优化的文件写入（现在直接在主循环中处理）

// 初始化TLS上下文
int init_tls_context(tls_context_t *ctx) {
    int ret;

    mbedtls_net_init(&ctx->server_fd);
    mbedtls_ssl_init(&ctx->ssl);
    mbedtls_ssl_config_init(&ctx->conf);
    mbedtls_entropy_init(&ctx->entropy);
    mbedtls_ctr_drbg_init(&ctx->ctr_drbg);
    mbedtls_x509_crt_init(&ctx->cacert);

    // 初始化随机数生成器
    ret = mbedtls_ctr_drbg_seed(&ctx->ctr_drbg, mbedtls_entropy_func, &ctx->entropy,
                                (const unsigned char *)"binance_ws_client", 17);
    if (ret != 0) {
        printf("mbedtls_ctr_drbg_seed failed: -0x%x\n", -ret);
        return ret;
    }

    // 配置SSL
    ret = mbedtls_ssl_config_defaults(&ctx->conf, MBEDTLS_SSL_IS_CLIENT,
                                      MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        printf("mbedtls_ssl_config_defaults failed: -0x%x\n", -ret);
        return ret;
    }

    mbedtls_ssl_conf_authmode(&ctx->conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_rng(&ctx->conf, mbedtls_ctr_drbg_random, &ctx->ctr_drbg);

    ret = mbedtls_ssl_setup(&ctx->ssl, &ctx->conf);
    if (ret != 0) {
        printf("mbedtls_ssl_setup failed: -0x%x\n", -ret);
        return ret;
    }

    ret = mbedtls_ssl_set_hostname(&ctx->ssl, BINANCE_WS_HOST);
    if (ret != 0) {
        printf("mbedtls_ssl_set_hostname failed: -0x%x\n", -ret);
        return ret;
    }

    // 初始化ping相关字段
    ctx->last_ping_time = 0;
    ctx->running = 0;
    ctx->latency_file = NULL;
    ctx->reconnect_attempts = 0;
    ctx->message_count = 0;
    ctx->total_latency_us = 0;
    ctx->min_latency_us = INT_MAX;
    ctx->max_latency_us = 0;
    ctx->last_ping_check = 0;

    return 0;
}

// 连接到Binance WebSocket
int connect_to_binance(tls_context_t *ctx) {
    int ret;

    printf("Connecting to %s:%s...\n", BINANCE_WS_HOST, BINANCE_WS_PORT);

    ret = mbedtls_net_connect(&ctx->server_fd, BINANCE_WS_HOST, BINANCE_WS_PORT, MBEDTLS_NET_PROTO_TCP);
    if (ret != 0) {
        printf("mbedtls_net_connect failed: -0x%x\n", -ret);
        return ret;
    }

    mbedtls_ssl_set_bio(&ctx->ssl, &ctx->server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    printf("Performing SSL handshake...\n");
    while ((ret = mbedtls_ssl_handshake(&ctx->ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            printf("mbedtls_ssl_handshake failed: -0x%x\n", -ret);
            return ret;
        }
    }

    printf("SSL handshake completed\n");
    return 0;
}

// 发送WebSocket握手请求
int websocket_handshake(tls_context_t *ctx) {
    char websocket_key[32];
    char handshake_request[8192]; // 增大缓冲区以容纳长URL
    char response[1024];
    int ret;

    // 生成WebSocket key
    if (generate_websocket_key(websocket_key, sizeof(websocket_key)) != 0) {
        printf("Failed to generate WebSocket key\n");
        return -1;
    }

    // 构建握手请求 - 订阅多品种trade流
    snprintf(handshake_request, sizeof(handshake_request),
        "GET /stream?streams=btcusdt@trade/ethusdt@trade/bchusdt@trade/xrpusdt@trade/ltcusdt@trade/trxusdt@trade/etcusdt@trade/linkusdt@trade/xlmusdt@trade/adausdt@trade/xmrusdt@trade/dashusdt@trade/zecusdt@trade/xtzusdt@trade/bnbusdt@trade/atomusdt@trade/ontusdt@trade/iotausdt@trade/batusdt@trade/vetusdt@trade/neousdt@trade/qtumusdt@trade/iostusdt@trade/thetausdt@trade/algousdt@trade/zilusdt@trade/kncusdt@trade/zrxusdt@trade/compusdt@trade/dogeusdt@trade/sxpusdt@trade/kavausdt@trade/bandusdt@trade/rlcusdt@trade/snxusdt@trade/dotusdt@trade/yfiusdt@trade/crvusdt@trade/trbusdt@trade/runeusdt@trade/sushiusdt@trade/egldusdt@trade/solusdt@trade/icxusdt@trade/storjusdt@trade/uniusdt@trade/avaxusdt@trade/enjusdt@trade/flmusdt@trade/ksmusdt@trade/nearusdt@trade/aaveusdt@trade/filusdt@trade/rsrusdt@trade/lrcusdt@trade/belusdt@trade/axsusdt@trade/zenusdt@trade/sklusdt@trade/grtusdt@trade/1inchusdt@trade/chzusdt@trade/sandusdt@trade/ankrusdt@trade/rvnusdt@trade/sfpusdt@trade/cotiusdt@trade/chrusdt@trade/manausdt@trade/aliceusdt@trade/hbarusdt@trade/oneusdt@trade/dentusdt@trade/celrusdt@trade/hotusdt@trade/mtlusdt@trade/ognusdt@trade/nknusdt@trade/1000shibusdt@trade/bakeusdt@trade/gtcusdt@trade/btcdomusdt@trade/iotxusdt@trade/c98usdt@trade/maskusdt@trade/atausdt@trade/dydxusdt@trade/1000xecusdt@trade/galausdt@trade/celousdt@trade/arusdt@trade/arpausdt@trade/ctsiusdt@trade/lptusdt@trade/ensusdt@trade/peopleusdt@trade/roseusdt@trade/duskusdt@trade/flowusdt@trade/imxusdt@trade/api3usdt@trade/gmtusdt@trade/apeusdt@trade/woousdt@trade/jasmyusdt@trade/opusdt@trade/injusdt@trade/stgusdt@trade/spellusdt@trade/1000luncusdt@trade/luna2usdt@trade/ldousdt@trade/icpusdt@trade/aptusdt@trade/qntusdt@trade/fetusdt@trade/fxsusdt@trade/hookusdt@trade/magicusdt@trade/tusdt@trade/highusdt@trade/minausdt@trade/astrusdt@trade/phbusdt@trade/gmxusdt@trade/cfxusdt@trade/stxusdt@trade/achusdt@trade/ssvusdt@trade/ckbusdt@trade/perpusdt@trade/truusdt@trade/lqtyusdt@trade/usdcusdt@trade/idusdt@trade/arbusdt@trade/joeusdt@trade/tlmusdt@trade/rdntusdt@trade/hftusdt@trade/xvsusdt@trade/ethbtc@trade/blurusdt@trade/eduusdt@trade/suiusdt@trade/1000pepeusdt@trade/1000flokiusdt@trade/umausdt@trade/nmrusdt@trade/mavusdt@trade/xvgusdt@trade/wldusdt@trade/pendleusdt@trade/arkmusdt@trade/agldusdt@trade/yggusdt@trade/dodoxusdt@trade/bntusdt@trade/oxtusdt@trade/seiusdt@trade/cyberusdt@trade/hifiusdt@trade/arkusdt@trade/bicousdt@trade/bigtimeusdt@trade/waxpusdt@trade/bsvusdt@trade/rifusdt@trade/polyxusdt@trade/gasusdt@trade/powrusdt@trade/tiausdt@trade/cakeusdt@trade/memeusdt@trade/twtusdt@trade/tokenusdt@trade/ordiusdt@trade/steemusdt@trade/ilvusdt@trade/ntrnusdt@trade/kasusdt@trade/beamxusdt@trade/1000bonkusdt@trade/pythusdt@trade/superusdt@trade/ustcusdt@trade/ongusdt@trade/ethwusdt@trade/jtousdt@trade/1000satsusdt@trade/auctionusdt@trade/1000ratsusdt@trade/aceusdt@trade/movrusdt@trade/nfpusdt@trade/btcusdc@trade/ethusdc@trade/bnbusdc@trade/solusdc@trade/xrpusdc@trade HTTP/1.1\r\n"
        "Host: fstream.binance.com\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: %s\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n",
        websocket_key);

    printf("Initiating WebSocket handshake...\n");

    ret = mbedtls_ssl_write(&ctx->ssl, (unsigned char*)handshake_request, strlen(handshake_request));
    if (ret < 0) {
        printf("mbedtls_ssl_write failed: -0x%x\n", -ret);
        return ret;
    }


    // 接收握手响应
    ret = mbedtls_ssl_read(&ctx->ssl, (unsigned char*)response, sizeof(response) - 1);
    if (ret < 0) {
        printf("mbedtls_ssl_read failed: -0x%x\n", -ret);
        return ret;
    }

    response[ret] = '\0';

    if (strstr(response, "101 Switching Protocols") == NULL) {
        printf("WebSocket handshake failed\n");
        return -1;
    }

    printf("WebSocket handshake successful\n");
    return 0;
}

// 优化的WebSocket帧解析（减少分支和计算）
static inline int parse_websocket_frame_fast(unsigned char *buffer, int len, char **payload, int *payload_len, int *opcode) {
    if (__builtin_expect(len < 2, 0)) return -1;

    unsigned char first_byte = buffer[0];
    unsigned char second_byte = buffer[1];

    *opcode = first_byte & 0x0F;
    int masked = (second_byte >> 7) & 1;
    int payload_length = second_byte & 0x7F;
    int header_size = 2;

    // 快速处理常见情况（小于126字节的payload）
    if (__builtin_expect(payload_length < 126, 1)) {
        // 大多数消息都是这种情况
    } else if (payload_length == 126) {
        if (__builtin_expect(len < 4, 0)) return -1;
        payload_length = (buffer[2] << 8) | buffer[3];
        header_size = 4;
    } else {
        if (__builtin_expect(len < 10, 0)) return -1;
        payload_length = (buffer[6] << 24) | (buffer[7] << 16) | (buffer[8] << 8) | buffer[9];
        header_size = 10;
    }

    if (masked) header_size += 4;
    if (__builtin_expect(len < header_size + payload_length, 0)) return -1;

    *payload = (char*)(buffer + header_size);
    *payload_len = payload_length;

    // 优化的mask解码（如果需要）
    if (__builtin_expect(masked, 0)) {
        unsigned char *mask = buffer + header_size - 4;
        char *p = *payload;
        // 按4字节块处理，提高效率
        int i;
        for (i = 0; i < (payload_length & ~3); i += 4) {
            *(uint32_t*)(p + i) ^= *(uint32_t*)mask;
        }
        // 处理剩余字节
        for (; i < payload_length; i++) {
            p[i] ^= mask[i & 3];
        }
    }

    return header_size + payload_length;
}

// 高性能JSON解析（专门为trade数据优化）
static inline long long parse_trade_id_fast(const char *json_data, int len) {
    // 直接搜索 "t": 模式，避免通用解析器开销
    const char *pos = json_data;
    const char *end = json_data + len;

    while (pos < end - 4) {
        if (*(uint32_t*)pos == 0x3a227422) { // "t": 的字节模式
            pos += 4;
            return strtoll(pos, NULL, 10);
        }
        pos++;
    }
    return -1;
}

static inline long long parse_event_time_fast(const char *json_data, int len) {
    // 直接搜索 "E": 模式
    const char *pos = json_data;
    const char *end = json_data + len;

    while (pos < end - 4) {
        if (*(uint32_t*)pos == 0x3a224522) { // "E": 的字节模式
            pos += 4;
            return strtoll(pos, NULL, 10);
        }
        pos++;
    }
    return -1;
}

// 快速检查是否为trade消息
static inline int is_trade_message_fast(const char *data, int len) {
    // 搜索 @trade 或 "t": 模式
    const char *pos = data;
    const char *end = data + len;

    while (pos < end - 6) {
        if (*(uint64_t*)pos == 0x656461727440) { // @trade 的部分字节模式
            return 1;
        }
        if (*(uint32_t*)pos == 0x3a227422) { // "t":
            return 1;
        }
        pos++;
    }
    return 0;
}

// 极速符号解析（仅用于统计输出）
static inline const char* get_symbol_for_stats() {
    static int counter = 0;
    // 简单轮换显示，避免每次都解析
    const char* symbols[] = {"MIXED", "MULTI", "TRADE", "STREAM"};
    return symbols[(counter++ / 1000) % 4];
}

// 统一的高性能数据提取
static inline void extract_trade_data_fast(const char *payload, int payload_len,
                                          long long *trade_id, long long *event_time) {
    // 先尝试直接解析，再尝试data字段内解析
    *trade_id = parse_trade_id_fast(payload, payload_len);
    *event_time = parse_event_time_fast(payload, payload_len);

    // 如果直接解析失败，尝试在data字段内搜索
    if (*trade_id == -1 || *event_time == -1) {
        const char *data_pos = strstr(payload, "\"data\":");
        if (data_pos != NULL) {
            int remaining_len = payload_len - (data_pos - payload);
            if (*trade_id == -1) {
                *trade_id = parse_trade_id_fast(data_pos, remaining_len);
            }
            if (*event_time == -1) {
                *event_time = parse_event_time_fast(data_pos, remaining_len);
            }
        }
    }
}

// 主循环：接收和处理trade数据
void receive_trade_updates(tls_context_t *ctx) {
    static unsigned char buffer[BUFFER_SIZE]; // 静态分配，避免栈开销
    char *payload;
    int payload_len;
    int opcode;
    int ret;
    depth_update_t update;

    printf("Trade data stream started...\n");
    time_t start_time = time(NULL);
    ctx->last_ping_time = start_time;
    ctx->last_ping_check = start_time;
    ctx->running = 1;

    while (ctx->running) {
        // 优化ping检查（减少time()系统调用）
        if (__builtin_expect((ctx->message_count & 4095) == 0, 0)) { // 每4096条消息检查一次
            time_t current_time = time(NULL);
            if (current_time - ctx->last_ping_time >= PING_INTERVAL_SECONDS) {
                if (send_ping(ctx) == 0) {
                    ctx->last_ping_time = current_time;
                }
            }
        }

        ret = mbedtls_ssl_read(&ctx->ssl, buffer, sizeof(buffer));
        if (ret < 0) {
            if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
                continue;
            }
            printf("mbedtls_ssl_read failed: -0x%x\n", -ret);
            break;
        }

        if (ret == 0) {
            printf("Connection closed by peer\n");
            break;
        }

        // 高性能帧解析
        int frame_size = parse_websocket_frame_fast(buffer, ret, &payload, &payload_len, &opcode);
        if (frame_size > 0) {
            switch (opcode) {
                case WS_OPCODE_CONTINUATION:
                    break;

                case WS_OPCODE_TEXT:
                case WS_OPCODE_BINARY:
                    // 高性能数据帧处理
                    if (__builtin_expect(payload_len > 0 && payload_len < MAX_PAYLOAD_SIZE, 1)) {
                        // 避兏不必要的null终止符，直接传递长度
                        if (__builtin_expect(!is_trade_message_fast(payload, payload_len), 0)) {
                            break;
                        }

                        // 立即获取时间戳
                        long long current_time_us = get_timestamp_us();

                        // 一次性提取所有需要的数据
                        long long trade_id, event_timestamp;
                        extract_trade_data_fast(payload, payload_len, &trade_id, &event_timestamp);

                        int latency_us = -1;
                        if (__builtin_expect(event_timestamp > 0, 1)) {
                            latency_us = (int)(current_time_us - event_timestamp * 1000);

                            // 快速更新统计
                            ctx->total_latency_us += latency_us;
                            if (__builtin_expect(latency_us < ctx->min_latency_us, 0)) {
                                ctx->min_latency_us = latency_us;
                            }
                            if (__builtin_expect(latency_us > ctx->max_latency_us, 0)) {
                                ctx->max_latency_us = latency_us;
                            }
                        }

                        ctx->message_count++;

                        // 批量写入文件
                        if (__builtin_expect(ctx->latency_file != NULL && latency_us >= 0, 1)) {
                            fprintf(ctx->latency_file, "%lld,%d\n", trade_id, latency_us);
                            if (__builtin_expect((ctx->message_count & 1023) == 0, 0)) { // 每1024条消息刷新
                                fflush(ctx->latency_file);
                            }
                        }

                        // 每1000条消息的统计输出
                        if (__builtin_expect((ctx->message_count % 1000) == 0, 0)) {
                            const char* symbol = get_symbol_for_stats();
                            int avg_latency = (int)(ctx->total_latency_us / ctx->message_count);

                            printf("[%lld] %s trades | Avg: %d us | Min: %d us | Max: %d us | Latest: %lld\n",
                                   ctx->message_count, symbol, avg_latency,
                                   ctx->min_latency_us, ctx->max_latency_us, trade_id);
                        }
                    }
                    break;

                case WS_OPCODE_PING:
                    send_pong(ctx, payload, payload_len);
                    break;

                case WS_OPCODE_PONG:
                    break;

                case WS_OPCODE_CLOSE:
                    printf("Connection closed by server\n");
                    ctx->running = 0;
                    break;

                default:
                    break;
            }
        }
    }
}

// 重置连接（不关闭文件和完全清理）
void reset_connection(tls_context_t *ctx) {
    printf("Resetting connection...\n");

    // 关闭当前连接
    mbedtls_ssl_close_notify(&ctx->ssl);
    mbedtls_net_free(&ctx->server_fd);
    mbedtls_ssl_free(&ctx->ssl);

    // 重新初始化SSL相关组件
    mbedtls_net_init(&ctx->server_fd);
    mbedtls_ssl_init(&ctx->ssl);

    int ret = mbedtls_ssl_setup(&ctx->ssl, &ctx->conf);
    if (ret != 0) {
        printf("mbedtls_ssl_setup failed during reset: -0x%x\n", -ret);
        return;
    }

    ret = mbedtls_ssl_set_hostname(&ctx->ssl, BINANCE_WS_HOST);
    if (ret != 0) {
        printf("mbedtls_ssl_set_hostname failed during reset: -0x%x\n", -ret);
    }
}

// 清理TLS上下文
void cleanup_tls_context(tls_context_t *ctx) {
    mbedtls_ssl_close_notify(&ctx->ssl);
    mbedtls_net_free(&ctx->server_fd);
    mbedtls_ssl_free(&ctx->ssl);
    mbedtls_ssl_config_free(&ctx->conf);
    mbedtls_entropy_free(&ctx->entropy);
    mbedtls_ctr_drbg_free(&ctx->ctr_drbg);
    mbedtls_x509_crt_free(&ctx->cacert);

    // 关闭延迟记录文件
    if (ctx->latency_file != NULL) {
        fclose(ctx->latency_file);
        ctx->latency_file = NULL;
    }
}

int main() {
    tls_context_t ctx;
    int ret;

    printf("Binance Futures WebSocket Trade Client (Multi-Symbol Stream)\n");
    printf("============================================================\n");

    // 绑定到CPU核心3
    if (bind_to_cpu_core(3) != 0) {
        printf("Warning: Failed to bind to CPU core 3, continuing anyway...\n");
    }

    // 初始化随机数种子
    srand(time(NULL));

    // 初始化TLS上下文
    if (init_tls_context(&ctx) != 0) {
        printf("Failed to initialize TLS context\n");
        return 1;
    }

    // 打开延迟记录文件
    ctx.latency_file = fopen("latency.txt", "w");
    if (ctx.latency_file == NULL) {
        printf("Warning: Failed to open latency.txt for writing\n");
    } else {
        printf("Latency data will be logged to latency.txt\n");
        // 写入表头
        fprintf(ctx.latency_file, "trade_id,latency_us\n");
        fflush(ctx.latency_file);
    }

    // 主循环：连接 -> 运行 -> 重连
    while (ctx.reconnect_attempts < MAX_RECONNECT_ATTEMPTS) {
        printf("\n=== Connection attempt %d ===\n", ctx.reconnect_attempts + 1);

        // 连接到Binance
        if (connect_to_binance(&ctx) != 0) {
            printf("Failed to connect to Binance (attempt %d/%d)\n",
                   ctx.reconnect_attempts + 1, MAX_RECONNECT_ATTEMPTS);
            ctx.reconnect_attempts++;

            if (ctx.reconnect_attempts < MAX_RECONNECT_ATTEMPTS) {
                printf("Waiting %d seconds before reconnecting...\n", RECONNECT_DELAY_SECONDS);
                sleep(RECONNECT_DELAY_SECONDS);
                reset_connection(&ctx);
                continue;
            } else {
                printf("Max reconnection attempts reached. Exiting.\n");
                break;
            }
        }

        // WebSocket握手
        if (websocket_handshake(&ctx) != 0) {
            printf("WebSocket handshake failed (attempt %d/%d)\n",
                   ctx.reconnect_attempts + 1, MAX_RECONNECT_ATTEMPTS);
            ctx.reconnect_attempts++;

            if (ctx.reconnect_attempts < MAX_RECONNECT_ATTEMPTS) {
                printf("Waiting %d seconds before reconnecting...\n", RECONNECT_DELAY_SECONDS);
                sleep(RECONNECT_DELAY_SECONDS);
                reset_connection(&ctx);
                continue;
            } else {
                printf("Max reconnection attempts reached. Exiting.\n");
                break;
            }
        }

        // Stream方式不需要单独发送订阅消息，已在握手时订阅

        printf("Connected successfully! Starting to receive data...\n");
        ctx.reconnect_attempts = 0; // 重置重连计数

        // 接收trade updates（这里会阻塞直到连接断开）
        receive_trade_updates(&ctx);

        printf("Connection lost. Attempting to reconnect...\n");
        ctx.reconnect_attempts++;

        if (ctx.reconnect_attempts < MAX_RECONNECT_ATTEMPTS) {
            printf("Waiting %d seconds before reconnecting...\n", RECONNECT_DELAY_SECONDS);
            sleep(RECONNECT_DELAY_SECONDS);
            reset_connection(&ctx);
        }
    }

    // 清理资源
    cleanup_tls_context(&ctx);

    printf("Client terminated\n");
    return 0;
}