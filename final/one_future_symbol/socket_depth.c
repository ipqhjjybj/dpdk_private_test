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

#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/base64.h"
#include "mbedtls/x509_crt.h"

#define BINANCE_WS_HOST "fstream.binance.com"
#define BINANCE_WS_PORT "443"
#define BUFFER_SIZE 8192
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
    printf("Sending pong response\n");
    return send_websocket_frame(ctx, WS_OPCODE_PONG, payload, payload_len);
}

// 发送ping帧
int send_ping(tls_context_t *ctx) {
    printf("Sending ping to server\n");
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

    printf("Sending subscription message for BTCUSDT depth...\n");
    int ret = send_websocket_frame(ctx, WS_OPCODE_TEXT, subscribe_msg, strlen(subscribe_msg));

    if (ret == 0) {
        printf("Successfully sent subscription for BTCUSDT@depth@100ms\n");
    } else {
        printf("Failed to send subscription message\n");
    }

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

// 记录延迟数据到文件
void log_latency_data(tls_context_t *ctx, long long update_id, int latency_us) {
    if (ctx->latency_file != NULL && latency_us >= 0) {
        fprintf(ctx->latency_file, "%lld,%d\n", update_id, latency_us);
        fflush(ctx->latency_file); // 立即写入文件
    }
}

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
    char handshake_request[1024];
    char response[1024];
    int ret;

    // 生成WebSocket key
    if (generate_websocket_key(websocket_key, sizeof(websocket_key)) != 0) {
        printf("Failed to generate WebSocket key\n");
        return -1;
    }

    // 构建握手请求 - 使用合约combineStream端点
    snprintf(handshake_request, sizeof(handshake_request),
        "GET /ws HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: %s\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n",
        BINANCE_WS_HOST, websocket_key);

    printf("Sending WebSocket handshake...\n");
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
    printf("WebSocket handshake response received:\n%s\n", response);

    if (strstr(response, "101 Switching Protocols") == NULL) {
        printf("WebSocket handshake failed\n");
        return -1;
    }

    printf("WebSocket handshake successful\n");
    return 0;
}

// 解析WebSocket帧
int parse_websocket_frame(unsigned char *buffer, int len, char **payload, int *payload_len, int *opcode) {
    if (len < 2) return -1;

    unsigned char first_byte = buffer[0];
    unsigned char second_byte = buffer[1];

    int fin = (first_byte >> 7) & 1;
    *opcode = first_byte & 0x0F;
    int masked = (second_byte >> 7) & 1;
    int payload_length = second_byte & 0x7F;

    int header_size = 2;

    if (payload_length == 126) {
        if (len < 4) return -1;
        payload_length = (buffer[2] << 8) | buffer[3];
        header_size = 4;
    } else if (payload_length == 127) {
        if (len < 10) return -1;
        // 简化处理，假设长度不超过32位
        payload_length = (buffer[6] << 24) | (buffer[7] << 16) | (buffer[8] << 8) | buffer[9];
        header_size = 10;
    }

    if (masked) {
        header_size += 4; // mask key
    }

    if (len < header_size + payload_length) {
        return -1; // 数据不完整
    }

    *payload = (char*)(buffer + header_size);
    *payload_len = payload_length;

    // 如果有mask，需要解码
    if (masked) {
        unsigned char *mask = buffer + header_size - 4;
        for (int i = 0; i < payload_length; i++) {
            (*payload)[i] ^= mask[i % 4];
        }
    }

    return header_size + payload_length;
}

// 通用JSON字段解析函数
long long parse_json_long_field(const char *json_data, const char *field_name) {
    char search_pattern[32];
    snprintf(search_pattern, sizeof(search_pattern), "\"%s\":", field_name);

    char *field_pos = strstr(json_data, search_pattern);
    if (field_pos == NULL) {
        return -1;
    }

    field_pos += strlen(search_pattern);
    return strtoll(field_pos, NULL, 10);
}

// 解析depth update并提取ID
long long parse_depth_update_id(const char *json_data) {
    return parse_json_long_field(json_data, "u");
}

// 解析币安服务器事件时间戳（毫秒）
long long parse_server_timestamp(const char *json_data) {
    return parse_json_long_field(json_data, "E");
}

// 主循环：接收和处理depth updates
void receive_depth_updates(tls_context_t *ctx) {
    unsigned char buffer[BUFFER_SIZE];
    char *payload;
    int payload_len;
    int opcode;
    int ret;
    depth_update_t update;

    printf("Starting to receive depth updates...\n");
    ctx->last_ping_time = time(NULL);
    ctx->running = 1;

    while (ctx->running) {
        // 检查是否需要发送ping
        time_t current_time = time(NULL);
        if (current_time - ctx->last_ping_time >= PING_INTERVAL_SECONDS) {
            if (send_ping(ctx) == 0) {
                ctx->last_ping_time = current_time;
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

        // 解析WebSocket帧
        int frame_size = parse_websocket_frame(buffer, ret, &payload, &payload_len, &opcode);
        if (frame_size > 0) {
            switch (opcode) {
                case WS_OPCODE_CONTINUATION:
                    // 继续帧，通常是分片数据的后续部分
                    printf("Received continuation frame (fragmented data)\n");
                    // 对于简单的实现，我们可以忽略continuation帧
                    // 完整的实现需要重组分片数据
                    break;

                case WS_OPCODE_TEXT:
                case WS_OPCODE_BINARY:
                    // 处理数据帧
                    if (payload_len > 0) {
                        payload[payload_len] = '\0'; // 确保字符串结束

                        // 检查是否是订阅确认消息
                        if (strstr(payload, "\"result\":null") && strstr(payload, "\"id\":1")) {
                            printf("Subscription confirmation received\n");
                            break;
                        }

                        // 检查是否包含depth数据
                        if (strstr(payload, "btcusdt@depth") == NULL && strstr(payload, "\"u\":") == NULL) {
                            printf("Received non-depth message: %.*s\n",
                                   (payload_len > 200) ? 200 : payload_len, payload);
                            break;
                        }

                        // 提取update ID
                        long long update_id = parse_depth_update_id(payload);

                        // 提取服务器时间戳
                        long long server_timestamp = parse_server_timestamp(payload);

                        // 计算真正的网络延迟（微秒精度）
                        int latency_us = calculate_latency_from_server_us(server_timestamp);

                        // 记录延迟数据到文件
                        log_latency_data(ctx, update_id, latency_us);

                        // 打印结果
                        if (latency_us >= 0) {
                            printf("Received BTCUSDT depth update - ID: %lld, Latency: %d us\n", update_id, latency_us);
                        } else {
                            printf("Received BTCUSDT depth update - ID: %lld, Latency: N/A (no server timestamp)\n", update_id);
                        }
                    }
                    break;

                case WS_OPCODE_PING:
                    // 收到ping，发送pong响应
                    printf("Received ping from server\n");
                    send_pong(ctx, payload, payload_len);
                    break;

                case WS_OPCODE_PONG:
                    // 收到pong响应
                    printf("Received pong from server\n");
                    break;

                case WS_OPCODE_CLOSE:
                    // 服务器要求关闭连接
                    printf("Received close frame from server\n");
                    ctx->running = 0;
                    break;

                default:
                    // 无效的opcode，可能是数据损坏或帧解析错误
                    printf("Received invalid opcode: 0x%x, frame may be corrupted\n", opcode);
                    // 可以选择跳过这个帧继续处理，或者断开连接
                    break;
            }
        } else if (frame_size == -1) {
            // 帧解析失败，可能是数据不完整
            printf("Frame parsing failed, may be incomplete data\n");
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

    printf("Binance Futures WebSocket Depth Client (CombineStream)\n");
    printf("======================================================\n");

    // 绑定到CPU核心1
    if (bind_to_cpu_core(1) != 0) {
        printf("Warning: Failed to bind to CPU core 1, continuing anyway...\n");
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
        fprintf(ctx.latency_file, "update_id,latency_us\n");
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

        // 发送订阅消息
        if (send_subscribe_message(&ctx) != 0) {
            printf("Failed to send subscription message (attempt %d/%d)\n",
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

        printf("Connected successfully! Starting to receive data...\n");
        ctx.reconnect_attempts = 0; // 重置重连计数

        // 接收depth updates（这里会阻塞直到连接断开）
        receive_depth_updates(&ctx);

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