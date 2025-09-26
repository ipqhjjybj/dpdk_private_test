#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include "ff_config.h"
#include "ff_api.h"
#include "ff_epoll.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

#define BINANCE_WSS "wss://stream.binance.com:9443/ws/btcusdt@depthUpdate"
#define HOST "stream.binance.com"
#define PORT 9443
#define PATH "/ws/btcusdt@depthUpdate"

static int interrupted = 0;

// 信号处理：退出程序
static void sigint_handler(int sig) {
    interrupted = 1;
}

// WebSocket 握手请求
static const char *ws_handshake = 
    "GET %s HTTP/1.1\r\n"
    "Host: %s:%d\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
    "Sec-WebSocket-Version: 13\r\n\r\n";

// 解析 WebSocket 帧（简化版，仅处理文本帧）
static int ws_parse_frame(const uint8_t *buf, int len, uint8_t **payload, int *payload_len) {
    if (len < 2) return -1;

    uint8_t fin = (buf[0] >> 7) & 1;
    uint8_t opcode = buf[0] & 0x0F;
    uint8_t mask = (buf[1] >> 7) & 1;
    uint64_t payload_len_ = buf[1] & 0x7F;
    int header_len = 2;

    // 仅处理文本帧和完整帧
    if (opcode != 0x01 || !fin) return -1;

    // 解析 payload 长度
    if (payload_len_ == 126) {
        payload_len_ = (buf[2] << 8) | buf[3];
        header_len += 2;
    } else if (payload_len_ == 127) {
        // 忽略超长帧（币安行情无需处理）
        return -1;
    }

    // 解析掩码（客户端发送的帧有掩码，服务器发送的无）
    uint8_t mask_key[4] = {0};
    if (mask) {
        memcpy(mask_key, buf + header_len, 4);
        header_len += 4;
    }

    // 提取 payload 并去掩码
    *payload = (uint8_t *)buf + header_len;
    *payload_len = payload_len_;
    if (mask) {
        for (int i = 0; i < *payload_len; i++) {
            (*payload)[i] ^= mask_key[i % 4];
        }
    }

    return 0;
}

// 处理币安行情数据（解析 JSON 中的价格和时间戳）
static void process_binance_data(const uint8_t *payload, int len) {
    const char *p = (const char *)payload;
    const char *price_str = strstr(p, "\"a\":[[\"");
    const char *time_str = strstr(p, "\"E\":");

    if (price_str && time_str) {
        // 提取价格（简化版，实际需更严谨的解析）
        price_str += 5;
        char price_buf[32] = {0};
        sscanf(price_str, "%31[^\"],", price_buf);

        // 提取时间戳
        time_str += 3;
        uint64_t event_time = atoll(time_str);

        printf("Price: %s, Event Time: %llu\n", price_buf, (unsigned long long)event_time);
    }
}

// F-Stack 主逻辑
static int fstack_main(void *arg) {
    int sockfd, epfd, n;
    struct epoll_event ev, events[10];
    mbedtls_ssl_context ssl;
    mbedtls_net_context server_fd;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_config conf;
    const char *pers = "binance_ws_client";

    // 1. 创建 F-Stack socket
    sockfd = ff_socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        fprintf(stderr, "ff_socket failed: %d\n", ff_errno);
        return -1;
    }

    // 2. 连接币安服务器（TCP 层）
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = ff_inet_addr(HOST); // F-Stack 的 DNS 解析需额外处理，这里简化用 IP

    if (ff_connect(sockfd, (struct linux_sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "ff_connect failed: %d\n", ff_errno);
        ff_close(sockfd);
        return -1;
    }

    // 3. 初始化 mbedtls 进行 TLS 握手（WSS 加密）
    mbedtls_net_init(&server_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, 
                             (const unsigned char *)pers, strlen(pers)) != 0) {
        fprintf(stderr, "mbedtls_ctr_drbg_seed failed\n");
        goto cleanup;
    }

    if (mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, 
                                   MBEDTLS_SSL_TRANSPORT_STREAM,
                                   MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
        fprintf(stderr, "mbedtls_ssl_config_defaults failed\n");
        goto cleanup;
    }

    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL); // 简化：不验证证书
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (mbedtls_ssl_setup(&ssl, &conf) != 0) {
        fprintf(stderr, "mbedtls_ssl_setup failed\n");
        goto cleanup;
    }

    // 将 F-Stack socket 绑定到 mbedtls
    server_fd.fd = sockfd;
    mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    // 执行 TLS 握手
    while ((n = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (n != MBEDTLS_ERR_SSL_WANT_READ && n != MBEDTLS_ERR_SSL_WANT_WRITE) {
            fprintf(stderr, "mbedtls_ssl_handshake failed: %d\n", n);
            goto cleanup;
        }
    }
    printf("TLS handshake success\n");

    // 4. 发送 WebSocket 握手请求
    char handshake_buf[512];
    snprintf(handshake_buf, sizeof(handshake_buf), ws_handshake, PATH, HOST, PORT);
    if (mbedtls_ssl_write(&ssl, (const unsigned char *)handshake_buf, strlen(handshake_buf)) <= 0) {
        fprintf(stderr, "WebSocket handshake failed\n");
        goto cleanup;
    }

    // 5. 验证握手响应（简化：仅检查 HTTP 101）
    uint8_t resp[1024];
    n = mbedtls_ssl_read(&ssl, resp, sizeof(resp) - 1);
    if (n <= 0 || strstr((char *)resp, "101 Switching Protocols") == NULL) {
        fprintf(stderr, "WebSocket upgrade failed\n");
        goto cleanup;
    }
    printf("WebSocket handshake success\n");

    // 6. 事件循环：接收并处理行情数据
    epfd = ff_epoll_create(0);
    ev.events = EPOLLIN;
    ev.data.fd = sockfd;
    ff_epoll_ctl(epfd, EPOLL_CTL_ADD, sockfd, &ev);

    uint8_t buf[8192];
    while (!interrupted) {
        n = ff_epoll_wait(epfd, events, 10, 1000); // 等待 1 秒超时
        if (n < 0) break;

        for (int i = 0; i < n; i++) {
            if (events[i].data.fd == sockfd && (events[i].events & EPOLLIN)) {
                // 读取 WebSocket 帧
                n = mbedtls_ssl_read(&ssl, buf, sizeof(buf) - 1);
                if (n <= 0) break;

                // 解析并处理帧
                uint8_t *payload;
                int payload_len;
                if (ws_parse_frame(buf, n, &payload, &payload_len) == 0) {
                    process_binance_data(payload, payload_len);
                }
            }
        }
    }

cleanup:
    // 清理资源
    mbedtls_ssl_close(&ssl);
    mbedtls_net_free(&server_fd);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_ssl_free(&ssl);
    ff_close(sockfd);
    ff_epoll_close(epfd);

    return 0;
}

int main(int argc, char **argv) {
    // 初始化 F-Stack
    if (ff_init(argc, argv) < 0) {
        fprintf(stderr, "F-Stack init failed\n");
        return -1;
    }

    // 注册信号处理
    signal(SIGINT, sigint_handler);

    // 启动 F-Stack 主循环
    int ret = ff_run(fstack_main, NULL);

    // 清理 F-Stack
    ff_cleanup();
    return ret;
}
    