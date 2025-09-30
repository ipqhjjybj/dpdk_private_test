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

#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/base64.h"
#include "mbedtls/x509_crt.h"

#define BINANCE_WS_HOST "stream.binance.com"
#define BINANCE_WS_PORT "9443"
#define BUFFER_SIZE 8192
#define WS_MAGIC_STRING "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

typedef struct {
    mbedtls_net_context server_fd;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_x509_crt cacert;
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

// 计算延迟
int calculate_latency_us(struct timeval start) {
    struct timeval end;
    gettimeofday(&end, NULL);
    return (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec);
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

    // 构建握手请求
    snprintf(handshake_request, sizeof(handshake_request),
        "GET /ws/btcusdt@depth HTTP/1.1\r\n"
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
int parse_websocket_frame(unsigned char *buffer, int len, char **payload, int *payload_len) {
    if (len < 2) return -1;

    unsigned char first_byte = buffer[0];
    unsigned char second_byte = buffer[1];

    int fin = (first_byte >> 7) & 1;
    int opcode = first_byte & 0x0F;
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

// 解析depth update并提取ID
long long parse_depth_update_id(const char *json_data) {
    char *id_pos = strstr(json_data, "\"u\":");
    if (id_pos == NULL) {
        return -1;
    }

    id_pos += 4; // 跳过 "u":
    return strtoll(id_pos, NULL, 10);
}

// 主循环：接收和处理depth updates
void receive_depth_updates(tls_context_t *ctx) {
    unsigned char buffer[BUFFER_SIZE];
    char *payload;
    int payload_len;
    int ret;
    struct timeval start_time;
    depth_update_t update;

    printf("Starting to receive depth updates...\n");

    while (1) {
        gettimeofday(&start_time, NULL);

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
        int frame_size = parse_websocket_frame(buffer, ret, &payload, &payload_len);
        if (frame_size > 0) {
            payload[payload_len] = '\0'; // 确保字符串结束

            // 提取update ID
            long long update_id = parse_depth_update_id(payload);

            // 计算延迟
            int latency = calculate_latency_us(start_time);

            // 打印结果
            printf("Received depth update - ID: %lld, Latency: %d us\n", update_id, latency);

            // 可选：打印原始数据（调试用）
            // printf("Raw data: %.*s\n", payload_len, payload);
        }
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
}

int main() {
    tls_context_t ctx;
    int ret;

    printf("Binance WebSocket Depth Update Client\n");
    printf("=====================================\n");

    // 初始化随机数种子
    srand(time(NULL));

    // 初始化TLS上下文
    if (init_tls_context(&ctx) != 0) {
        printf("Failed to initialize TLS context\n");
        return 1;
    }

    // 连接到Binance
    if (connect_to_binance(&ctx) != 0) {
        printf("Failed to connect to Binance\n");
        cleanup_tls_context(&ctx);
        return 1;
    }

    // WebSocket握手
    if (websocket_handshake(&ctx) != 0) {
        printf("WebSocket handshake failed\n");
        cleanup_tls_context(&ctx);
        return 1;
    }

    // 接收depth updates
    receive_depth_updates(&ctx);

    // 清理资源
    cleanup_tls_context(&ctx);

    printf("Client terminated\n");
    return 0;
}