#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <stdint.h>
#include <arpa/inet.h>
#include "ff_config.h"
#include "ff_api.h"
#include "ff_epoll.h"
#include "mbedtls/net.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"

#define BINANCE_HOST    "stream.binance.com"
#define BINANCE_PORT    9443
#define BINANCE_PATH    "/ws/btcusdt@depthUpdate"
#define MAX_BUFFER_SIZE 8192
#define HANDSHAKE_KEY   "dGhlIHNhbXBsZSBub25jZQ=="  // 标准测试key

// 全局退出标志
static volatile int running = 1;

// 信号处理函数
static void sig_handler(int signo) {
    if (signo == SIGINT) {
        printf("\n收到中断信号，准备退出...\n");
        running = 0;
    }
}

// WebSocket帧结构解析
typedef struct {
    uint8_t fin;         // 1位：是否为最后一帧
    uint8_t opcode;      // 4位：操作码(0x1表示文本帧)
    uint8_t mask;        // 1位：是否使用掩码
    uint64_t payload_len;// 7位/16位/64位： payload长度
    uint8_t mask_key[4]; // 掩码密钥(仅客户端发送帧有)
    const uint8_t *payload; // 数据指针
} ws_frame_t;

// 解析WebSocket帧头部
static int ws_parse_frame_header(const uint8_t *buf, size_t len, ws_frame_t *frame) {
    if (len < 2) return -1; // 至少需要2字节头部
    
    // 解析第一个字节
    frame->fin = (buf[0] >> 7) & 0x01;
    frame->opcode = buf[0] & 0x0F;
    
    // 解析第二个字节
    frame->mask = (buf[1] >> 7) & 0x01;
    frame->payload_len = buf[1] & 0x7F;
    
    size_t header_len = 2;
    
    // 处理不同长度的payload
    if (frame->payload_len == 126) {
        if (len < 4) return -1;
        frame->payload_len = (buf[2] << 8) | buf[3];
        header_len += 2;
    } else if (frame->payload_len == 127) {
        if (len < 10) return -1;
        // 64位长度(币安行情一般用不到，简化处理)
        return -1;
    }
    
    // 处理掩码
    if (frame->mask) {
        if (len < header_len + 4) return -1;
        memcpy(frame->mask_key, buf + header_len, 4);
        header_len += 4;
    }
    
    // 检查总长度是否足够
    if (len < header_len + frame->payload_len) return -1;
    
    // 设置payload指针
    frame->payload = buf + header_len;
    
    return header_len + frame->payload_len; // 返回整个帧的长度
}

// 对payload进行掩码解码
static void ws_apply_mask(uint8_t *data, size_t len, const uint8_t *mask_key) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= mask_key[i % 4];
    }
}

// 解析币安行情数据中的价格和时间戳
static void parse_binance_data(const uint8_t *data, size_t len) {
    if (len == 0) return;
    
    char *payload = (char *)malloc(len + 1);
    if (!payload) return;
    
    memcpy(payload, data, len);
    payload[len] = '\0';
    
    // 提取事件时间戳 "E":1620000000000
    char *e_ptr = strstr(payload, "\"E\":");
    // 提取卖一价 "a":[[价格,数量],...]
    char *a_ptr = strstr(payload, "\"a\":[[\"");
    
    if (e_ptr && a_ptr) {
        uint64_t event_time = atoll(e_ptr + 3);
        char *price_end = strchr(a_ptr + 5, '"');
        
        if (price_end) {
            *price_end = '\0';
            printf("事件时间: %llu, 卖一价: %s\n", 
                   (unsigned long long)event_time, a_ptr + 5);
        }
    }
    
    free(payload);
}

// 创建并发送WebSocket握手请求
static int ws_send_handshake(mbedtls_ssl_context *ssl) {
    char handshake[MAX_BUFFER_SIZE];
    int len = snprintf(handshake, MAX_BUFFER_SIZE,
        "GET %s HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: %s\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n",
        BINANCE_PATH, BINANCE_HOST, BINANCE_PORT, HANDSHAKE_KEY);
    
    if (len <= 0 || len >= MAX_BUFFER_SIZE) {
        fprintf(stderr, "创建握手请求失败\n");
        return -1;
    }
    
    // 发送握手请求
    int ret = mbedtls_ssl_write(ssl, (const uint8_t *)handshake, len);
    if (ret <= 0) {
        fprintf(stderr, "发送握手请求失败: %d\n", ret);
        return -1;
    }
    
    return 0;
}

// 验证WebSocket握手响应
static int ws_verify_handshake(mbedtls_ssl_context *ssl) {
    uint8_t buf[MAX_BUFFER_SIZE];
    int ret = mbedtls_ssl_read(ssl, buf, MAX_BUFFER_SIZE - 1);
    
    if (ret <= 0) {
        fprintf(stderr, "读取握手响应失败: %d\n", ret);
        return -1;
    }
    
    buf[ret] = '\0';
    
    // 检查是否包含101状态码
    if (strstr((char *)buf, "101 Switching Protocols") == NULL) {
        fprintf(stderr, "握手失败，响应: %s\n", buf);
        return -1;
    }
    
    return 0;
}

// F-Stack主逻辑
static int fstack_main(void *arg) {
    int epfd, sockfd, ret;
    struct epoll_event ev, events[10];
    uint8_t read_buf[MAX_BUFFER_SIZE];
    
    // 初始化mbedtls
    mbedtls_net_context server_fd;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "binance_ws_client";
    
    mbedtls_net_init(&server_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    
    // 初始化随机数生成器
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                    (const unsigned char *)pers, strlen(pers))) != 0) {
        fprintf(stderr, "随机数生成器初始化失败: %d\n", ret);
        goto cleanup;
    }
    
    // 创建F-Stack socket
    if ((sockfd = ff_socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        fprintf(stderr, "创建socket失败: %d\n", ff_errno);
        goto cleanup;
    }
    
    // 设置为非阻塞模式
    if (ff_fcntl(sockfd, F_SETFL, O_NONBLOCK) < 0) {
        fprintf(stderr, "设置非阻塞模式失败: %d\n", ff_errno);
        goto cleanup;
    }
    
    // 连接币安服务器
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(BINANCE_PORT);
    addr.sin_addr.s_addr = ff_inet_addr(BINANCE_HOST);
    
    if (ff_connect(sockfd, (struct linux_sockaddr *)&addr, sizeof(addr)) < 0) {
        // 非阻塞连接可能返回EINPROGRESS，属于正常情况
        if (ff_errno != EINPROGRESS && ff_errno != EWOULDBLOCK) {
            fprintf(stderr, "连接失败: %d\n", ff_errno);
            goto cleanup;
        }
    }
    
    // 配置SSL
    if ((ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
                                          MBEDTLS_SSL_TRANSPORT_STREAM,
                                          MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        fprintf(stderr, "SSL配置失败: %d\n", ret);
        goto cleanup;
    }
    
    // 不验证服务器证书(生产环境建议开启验证)
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    
    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
        fprintf(stderr, "SSL初始化失败: %d\n", ret);
        goto cleanup;
    }
    
    // 绑定F-Stack socket到mbedtls
    server_fd.fd = sockfd;
    mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);
    
    // 执行TLS握手
    printf("正在进行TLS握手...\n");
    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            fprintf(stderr, "TLS握手失败: %d\n", ret);
            goto cleanup;
        }
    }
    printf("TLS握手成功\n");
    
    // 执行WebSocket握手
    printf("正在进行WebSocket握手...\n");
    if (ws_send_handshake(&ssl) != 0) {
        goto cleanup;
    }
    
    if (ws_verify_handshake(&ssl) != 0) {
        goto cleanup;
    }
    printf("WebSocket握手成功，开始接收行情数据...\n");
    
    // 创建epoll实例
    if ((epfd = ff_epoll_create(0)) < 0) {
        fprintf(stderr, "创建epoll失败: %d\n", ff_errno);
        goto cleanup;
    }
    
    // 添加socket到epoll
    ev.events = EPOLLIN | EPOLLERR;
    ev.data.fd = sockfd;
    if (ff_epoll_ctl(epfd, EPOLL_CTL_ADD, sockfd, &ev) < 0) {
        fprintf(stderr, "epoll_ctl失败: %d\n", ff_errno);
        goto cleanup;
    }
    
    // 主事件循环
    while (running) {
        int nfds = ff_epoll_wait(epfd, events, 10, 1000); // 超时1秒
        
        if (nfds < 0) {
            if (ff_errno != EINTR) {
                fprintf(stderr, "epoll_wait失败: %d\n", ff_errno);
            }
            break;
        }
        
        for (int i = 0; i < nfds; i++) {
            if (events[i].data.fd == sockfd) {
                // 读取数据
                ret = mbedtls_ssl_read(&ssl, read_buf, MAX_BUFFER_SIZE);
                
                if (ret <= 0) {
                    if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                        fprintf(stderr, "读取数据失败: %d\n", ret);
                        running = 0;
                    }
                    continue;
                }
                
                // 解析WebSocket帧
                ws_frame_t frame;
                int frame_len = ws_parse_frame_header(read_buf, ret, &frame);
                
                if (frame_len <= 0) {
                    fprintf(stderr, "解析WebSocket帧失败\n");
                    continue;
                }
                
                // 处理文本帧
                if (frame.opcode == 0x01) {
                    uint8_t *payload = (uint8_t *)malloc(frame.payload_len);
                    if (payload) {
                        memcpy(payload, frame.payload, frame.payload_len);
                        
                        // 如果有掩码则解码
                        if (frame.mask) {
                            ws_apply_mask(payload, frame.payload_len, frame.mask_key);
                        }
                        
                        // 解析币安行情数据
                        parse_binance_data(payload, frame.payload_len);
                        free(payload);
                    }
                }
                // 忽略其他类型的帧
            }
        }
    }
    
cleanup:
    // 清理资源
    if (epfd >= 0) ff_epoll_close(epfd);
    if (sockfd >= 0) ff_close(sockfd);
    
    mbedtls_ssl_close(&ssl);
    mbedtls_net_free(&server_fd);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_ssl_free(&ssl);
    
    printf("资源已释放，程序退出\n");
    return 0;
}

int main(int argc, char **argv) {
    // 注册信号处理
    if (signal(SIGINT, sig_handler) == SIG_ERR) {
        fprintf(stderr, "无法注册信号处理函数\n");
        return 1;
    }
    
    // 初始化F-Stack
    if (ff_init(argc, argv) < 0) {
        fprintf(stderr, "F-Stack初始化失败\n");
        return 1;
    }
    
    // 运行F-Stack主逻辑
    int ret = ff_run(fstack_main, NULL);
    
    // 清理F-Stack
    ff_cleanup();
    
    return ret;
}
    