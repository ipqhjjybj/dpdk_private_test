#include <iostream>
#include <string>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <signal.h>
#include <thread>
#include <chrono>
#include <algorithm>

// mbedtls 3.x 正确头文件（替换旧版的 net.h）
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/error.h"

#define BINANCE_HOST    "stream.binance.com"
#define BINANCE_PORT    "9443"
#define BINANCE_PATH    "/ws/btcusdt@depthUpdate"
#define MAX_BUFFER_SIZE 8192
#define HANDSHAKE_KEY   "dGhlIHNhbXBsZSBub25jZQ=="

class BinanceWSClient {
private:
    int sockfd;
    bool running;
    mbedtls_net_context server_fd;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

public:
    BinanceWSClient() : sockfd(-1), running(false) {
        // 初始化mbedtls结构体
        mbedtls_net_init(&server_fd);
        mbedtls_ssl_init(&ssl);
        mbedtls_ssl_config_init(&conf);
        mbedtls_entropy_init(&entropy);
        mbedtls_ctr_drbg_init(&ctr_drbg);
    }

    ~BinanceWSClient() {
        cleanup();
    }

    bool connect() {
        int ret;
        const char *pers = "binance_ws_client";

        // 初始化随机数生成器
        if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                        (const unsigned char *)pers, strlen(pers))) != 0) {
            print_mbedtls_error("ctr_drbg_seed", ret);
            return false;
        }

        // 创建TCP连接
        std::cout << "连接到 " << BINANCE_HOST << ":" << BINANCE_PORT << std::endl;
        if ((ret = mbedtls_net_connect(&server_fd, BINANCE_HOST, BINANCE_PORT, MBEDTLS_NET_PROTO_TCP)) != 0) {
            print_mbedtls_error("net_connect", ret);
            return false;
        }
        sockfd = server_fd.fd;

        // 配置SSL
        if ((ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
                                              MBEDTLS_SSL_TRANSPORT_STREAM,
                                              MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
            print_mbedtls_error("ssl_config_defaults", ret);
            return false;
        }

        // 禁用证书验证（仅示例用，生产环境需启用）
        mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
        mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

        if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
            print_mbedtls_error("ssl_setup", ret);
            return false;
        }

        mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, nullptr);

        // TLS握手
        std::cout << "进行TLS握手..." << std::endl;
        while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
            if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                print_mbedtls_error("ssl_handshake", ret);
                return false;
            }
        }
        std::cout << "TLS握手成功" << std::endl;

        // WebSocket握手
        if (!perform_ws_handshake()) {
            return false;
        }

        running = true;
        return true;
    }

    void run() {
        if (!running) {
            std::cerr << "未建立连接，无法启动接收线程" << std::endl;
            return;
        }

        std::cout << "开始接收行情数据..." << std::endl;
        uint8_t buffer[MAX_BUFFER_SIZE];

        while (running) {
            int ret = mbedtls_ssl_read(&ssl, buffer, sizeof(buffer) - 1);
            if (ret <= 0) {
                if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                    print_mbedtls_error("ssl_read", ret);
                    running = false;
                }
                continue;
            }

            // 解析WebSocket帧
            parse_ws_frame(buffer, ret);
        }
    }

    void stop() {
        running = false;
    }

private:
    bool perform_ws_handshake() {
        // 构建握手请求
        std::string handshake = "GET " BINANCE_PATH " HTTP/1.1\r\n"
                                "Host: " BINANCE_HOST ":" BINANCE_PORT "\r\n"
                                "Upgrade: websocket\r\n"
                                "Connection: Upgrade\r\n"
                                "Sec-WebSocket-Key: " HANDSHAKE_KEY "\r\n"
                                "Sec-WebSocket-Version: 13\r\n\r\n";

        // 发送握手请求
        int ret = mbedtls_ssl_write(&ssl, (const unsigned char *)handshake.c_str(), handshake.size());
        if (ret <= 0) {
            print_mbedtls_error("ssl_write (handshake)", ret);
            return false;
        }

        // 验证握手响应
        uint8_t response[MAX_BUFFER_SIZE];
        ret = mbedtls_ssl_read(&ssl, response, sizeof(response) - 1);
        if (ret <= 0) {
            print_mbedtls_error("ssl_read (handshake response)", ret);
            return false;
        }
        response[ret] = '\0';

        if (std::string((char *)response).find("101 Switching Protocols") == std::string::npos) {
            std::cerr << "WebSocket握手失败: " << (char *)response << std::endl;
            return false;
        }

        std::cout << "WebSocket握手成功" << std::endl;
        return true;
    }

    void parse_ws_frame(const uint8_t *data, size_t len) {
        if (len < 2) return;

        // 解析帧头部
        bool fin = (data[0] & 0x80) != 0;
        uint8_t opcode = data[0] & 0x0F;
        bool masked = (data[1] & 0x80) != 0;
        uint64_t payload_len = data[1] & 0x7F;
        size_t header_len = 2;

        // 处理扩展的payload长度
        if (payload_len == 126) {
            if (len < 4) return;
            payload_len = (data[2] << 8) | data[3];
            header_len += 2;
        } else if (payload_len == 127) {
            // 忽略超长帧
            return;
        }

        // 处理掩码
        uint8_t mask_key[4] = {0};
        if (masked) {
            if (len < header_len + 4) return;
            memcpy(mask_key, data + header_len, 4);
            header_len += 4;
        }

        // 检查总长度
        if (len < header_len + payload_len) return;

        // 提取payload
        uint8_t *payload = new uint8_t[payload_len + 1];
        memcpy(payload, data + header_len, payload_len);
        payload[payload_len] = '\0';

        // 应用掩码（如果有）
        if (masked) {
            for (size_t i = 0; i < payload_len; i++) {
                payload[i] ^= mask_key[i % 4];
            }
        }

        // 处理文本帧
        if (opcode == 0x01) {
            parse_binance_data(payload, payload_len);
        }

        delete[] payload;
    }

    void parse_binance_data(const uint8_t *data, size_t len) {
        std::string json((char *)data, len);
        
        // 提取事件时间戳 "E":1620000000000
        size_t e_pos = json.find("\"E\":");
        // 提取卖一价 "a":[[价格,数量],...]
        size_t a_pos = json.find("\"a\":[[\"");

        if (e_pos != std::string::npos && a_pos != std::string::npos) {
            // 解析事件时间
            uint64_t event_time = std::stoull(json.substr(e_pos + 3));
            
            // 解析价格
            size_t price_end = json.find("\"", a_pos + 5);
            if (price_end != std::string::npos) {
                std::string price = json.substr(a_pos + 5, price_end - (a_pos + 5));
                std::cout << "事件时间: " << event_time << ", 卖一价: " << price << std::endl;
            }
        }
    }

    void print_mbedtls_error(const char *func, int err) {
        char err_buf[1024];
        mbedtls_strerror(err, err_buf, sizeof(err_buf));
        std::cerr << "[" << func << "] 错误: " << err << " - " << err_buf << std::endl;
    }

    void cleanup() {
        running = false;
        
        // 3.x版本用ssl_session_reset替代ssl_close
        mbedtls_ssl_session_reset(&ssl);  
        mbedtls_net_close(&server_fd);
        
        mbedtls_ssl_config_free(&conf);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        mbedtls_ssl_free(&ssl);
    }
};

// 全局客户端实例和信号处理
BinanceWSClient client;

void signal_handler(int signum) {
    std::cout << "\n收到退出信号..." << std::endl;
    client.stop();
}

int main() {
    // 注册信号处理
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // 连接到币安服务器
    if (!client.connect()) {
        std::cerr << "连接失败，程序退出" << std::endl;
        return 1;
    }

    // 运行接收循环
    client.run();

    std::cout << "程序正常退出" << std::endl;
    return 0;
}
