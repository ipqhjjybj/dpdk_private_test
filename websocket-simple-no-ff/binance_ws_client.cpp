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
#include <vector>

// mbedtls头文件
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/error.h"

// 配置参数
#define BINANCE_HOST    "stream.binance.com"
#define BINANCE_PORT    "9443"
#define BINANCE_PATH    "/ws/btcusdt@depthUpdate"  // 比特币/USDT深度更新
#define MAX_BUFFER_SIZE 16384  // 16KB缓冲区，足够处理币安行情
#define HANDSHAKE_KEY   "dGhlIHNhbXBsZSBub25jZQ=="  // WebSocket标准握手密钥

class BinanceWSClient {
private:
    bool running;
    mbedtls_net_context server_fd;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    // 分片帧处理
    std::vector<uint8_t> fragment_buffer;  // 用于拼接分片数据
    bool is_fragmented;                    // 是否正在处理分片帧
    uint8_t current_opcode;                // 当前帧类型

public:
    BinanceWSClient() : running(false), is_fragmented(false), current_opcode(0x00) {
        // 初始化mbedtls结构
        mbedtls_net_init(&server_fd);
        mbedtls_ssl_init(&ssl);
        mbedtls_ssl_config_init(&conf);
        mbedtls_entropy_init(&entropy);
        mbedtls_ctr_drbg_init(&ctr_drbg);
    }

    ~BinanceWSClient() {
        cleanup();
    }

    // 建立连接
    bool connect() {
        int ret;
        const char *pers = "binance_ws_client";

        // 初始化随机数生成器
        if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                        (const unsigned char *)pers, strlen(pers))) != 0) {
            print_mbedtls_error("随机数生成器初始化失败", ret);
            return false;
        }

        // 创建TCP连接
        std::cout << "[连接] 正在连接到 " << BINANCE_HOST << ":" << BINANCE_PORT << std::endl;
        if ((ret = mbedtls_net_connect(&server_fd, BINANCE_HOST, BINANCE_PORT, MBEDTLS_NET_PROTO_TCP)) != 0) {
            print_mbedtls_error("TCP连接失败", ret);
            return false;
        }

        // 配置SSL/TLS
        if ((ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
                                              MBEDTLS_SSL_TRANSPORT_STREAM,
                                              MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
            print_mbedtls_error("SSL配置失败", ret);
            return false;
        }

        // 配置TLS版本（币安要求TLS 1.2+）
        mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3); // TLS 1.2
        mbedtls_ssl_conf_max_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_4); // TLS 1.3
        
        // 禁用证书验证（仅示例用，生产环境需启用）
        mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
        mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

        // 设置SSL
        if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
            print_mbedtls_error("SSL初始化失败", ret);
            return false;
        }

        // 绑定I/O函数
        mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, nullptr);

        // 执行TLS握手
        std::cout << "[加密] 正在进行TLS握手..." << std::endl;
        while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
            if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                print_mbedtls_error("TLS握手失败", ret);
                return false;
            }
        }
        std::cout << "[加密] TLS握手成功" << std::endl;

        // 执行WebSocket握手
        if (!perform_ws_handshake()) {
            return false;
        }

        running = true;
        return true;
    }

    // 运行接收循环
    void run() {
        if (!running) {
            std::cerr << "[错误] 未建立连接，无法启动接收" << std::endl;
            return;
        }

        std::cout << "[接收] 开始接收行情数据（按Ctrl+C退出）..." << std::endl;
        uint8_t buffer[MAX_BUFFER_SIZE];

        while (running) {
            // 读取加密数据
            int ret = mbedtls_ssl_read(&ssl, buffer, sizeof(buffer) - 1);
            
            if (ret > 0) {
                // 成功读取到数据，解析WebSocket帧
                buffer[ret] = '\0';  // 确保字符串结束
                parse_ws_frames(buffer, ret);
            }
            // 处理非致命错误
            else if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                print_mbedtls_error("数据接收失败", ret);
                running = false;
            }
        }
    }

    // 停止客户端
    void stop() {
        running = false;
    }

private:
    // 执行WebSocket握手
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
            print_mbedtls_error("发送握手请求失败", ret);
            return false;
        }

        // 接收并验证握手响应
        uint8_t response[MAX_BUFFER_SIZE];
        ret = mbedtls_ssl_read(&ssl, response, sizeof(response) - 1);
        if (ret <= 0) {
            print_mbedtls_error("接收握手响应失败", ret);
            return false;
        }
        response[ret] = '\0';

        // 验证是否握手成功
        if (std::string((char *)response).find("101 Switching Protocols") == std::string::npos) {
            std::cerr << "[错误] WebSocket握手失败，响应: " << std::string((char *)response, 200) << std::endl;
            return false;
        }

        std::cout << "[协议] WebSocket握手成功" << std::endl;
        return true;
    }

    // 解析WebSocket帧（支持分片帧）
    void parse_ws_frames(const uint8_t *data, size_t len) {
        size_t pos = 0;
        
        // 循环处理所有帧（可能存在多个帧在一个数据包中）
        while (pos < len) {
            if (len - pos < 2) break;  // 至少需要2字节头部

            // 解析帧头部
            bool fin = (data[pos] & 0x80) != 0;
            uint8_t opcode = data[pos] & 0x0F;
            bool masked = (data[pos+1] & 0x80) != 0;
            uint64_t payload_len = data[pos+1] & 0x7F;
            size_t header_len = 2;
            pos += 2;

            // 处理扩展的payload长度
            if (payload_len == 126) {
                if (len - pos < 2) break;
                payload_len = (data[pos] << 8) | data[pos+1];
                header_len += 2;
                pos += 2;
            } else if (payload_len == 127) {
                if (len - pos < 8) break;
                // 64位长度（币安行情不常用，简化处理）
                payload_len = ((uint64_t)data[pos] << 56) | ((uint64_t)data[pos+1] << 48) |
                             ((uint64_t)data[pos+2] << 40) | ((uint64_t)data[pos+3] << 32) |
                             ((uint64_t)data[pos+4] << 24) | ((uint64_t)data[pos+5] << 16) |
                             ((uint64_t)data[pos+6] << 8) | data[pos+7];
                header_len += 8;
                pos += 8;
            }

            // 处理掩码
            uint8_t mask_key[4] = {0};
            if (masked) {
                if (len - pos < 4) break;
                memcpy(mask_key, data + pos, 4);
                header_len += 4;
                pos += 4;
            }

            // 检查payload是否完整
            if (len - pos < payload_len) break;

            // 提取payload
            const uint8_t *payload = data + pos;
            pos += payload_len;

            // 处理控制帧（关闭连接等）
            if (opcode >= 0x08) {
                handle_control_frame(opcode, payload, payload_len);
                continue;
            }

            // 处理数据帧（支持分片）
            handle_data_frame(fin, opcode, payload, payload_len, masked, mask_key);
        }
    }

    // 处理数据帧（支持分片拼接）
    void handle_data_frame(bool fin, uint8_t opcode, const uint8_t *payload, 
                          size_t payload_len, bool masked, const uint8_t *mask_key) {
        // 分配内存存储解码后的payload
        uint8_t *decoded = new uint8_t[payload_len + 1];
        memcpy(decoded, payload, payload_len);
        decoded[payload_len] = '\0';

        // 应用掩码（服务器发送的帧通常不掩码，但仍需处理）
        if (masked) {
            for (size_t i = 0; i < payload_len; i++) {
                decoded[i] ^= mask_key[i % 4];
            }
        }

        // 处理分片帧
        if (!is_fragmented) {
            // 新的分片序列开始
            if (opcode != 0x00) {  // 0x00是延续帧
                current_opcode = opcode;
                fragment_buffer.clear();
                is_fragmented = true;
            } else {
                // 无效的延续帧（没有起始帧）
                delete[] decoded;
                return;
            }
        }

        // 添加到分片缓冲区
        fragment_buffer.insert(fragment_buffer.end(), decoded, decoded + payload_len);
        delete[] decoded;

        // 如果是最后一帧，处理完整数据
        if (fin) {
            is_fragmented = false;
            
            // 只处理文本帧
            if (current_opcode == 0x01) {
                parse_binance_data(fragment_buffer.data(), fragment_buffer.size());
            }
            
            fragment_buffer.clear();
        }
    }

    // 处理控制帧
    void handle_control_frame(uint8_t opcode, const uint8_t *payload, size_t payload_len) {
        if (opcode == 0x08) {  // 关闭连接帧
            std::cout << "[协议] 收到关闭连接请求" << std::endl;
            running = false;
        } else if (opcode == 0x09) {  // PING帧
            std::cout << "[协议] 收到PING请求，发送PONG响应" << std::endl;
            send_pong(payload, payload_len);
        }
    }

    // 发送PONG响应
    void send_pong(const uint8_t *payload, size_t len) {
        // 构建PONG帧（控制帧格式）
        uint8_t frame[10 + len];
        frame[0] = 0x8A;  // FIN=1, opcode=0x0A(PONG)
        
        // 设置长度
        if (len <= 125) {
            frame[1] = len;
            memcpy(frame + 2, payload, len);
            mbedtls_ssl_write(&ssl, frame, 2 + len);
        } else if (len <= 65535) {
            frame[1] = 126;
            frame[2] = (len >> 8) & 0xFF;
            frame[3] = len & 0xFF;
            memcpy(frame + 4, payload, len);
            mbedtls_ssl_write(&ssl, frame, 4 + len);
        }
    }

    // 解析币安行情数据
    void parse_binance_data(const uint8_t *data, size_t len) {
        std::string json((char *)data, len);
        
        // 提取关键信息（使用简单字符串查找，避免依赖JSON库）
        // 事件时间戳 "E":1620000000000
        size_t e_pos = json.find("\"E\":");
        // 卖一价 "a":[[价格,数量],...]
        size_t a_pos = json.find("\"a\":[[\"");
        // 买一价 "b":[[价格,数量],...]
        size_t b_pos = json.find("\"b\":[[\"");

        if (e_pos != std::string::npos) {
            // 解析事件时间
            size_t e_end = json.find_first_of(",}", e_pos + 3);
            if (e_end != std::string::npos) {
                std::string e_str = json.substr(e_pos + 3, e_end - (e_pos + 3));
                uint64_t event_time = std::stoull(e_str);

                // 解析卖一价
                if (a_pos != std::string::npos) {
                    size_t a_end = json.find("\"", a_pos + 5);
                    if (a_end != std::string::npos) {
                        std::string ask_price = json.substr(a_pos + 5, a_end - (a_pos + 5));
                        
                        // 解析买一价
                        if (b_pos != std::string::npos) {
                            size_t b_end = json.find("\"", b_pos + 5);
                            if (b_end != std::string::npos) {
                                std::string bid_price = json.substr(b_pos + 5, b_end - (b_pos + 5));
                                
                                // 输出行情信息
                                std::cout << "[行情] 时间: " << event_time 
                                          << " | 买一: " << bid_price 
                                          << " | 卖一: " << ask_price << std::endl;
                            }
                        }
                    }
                }
            }
        }
    }

    // 打印mbedtls错误信息
    void print_mbedtls_error(const std::string &msg, int err) {
        char err_buf[1024];
        mbedtls_strerror(err, err_buf, sizeof(err_buf));
        std::cerr << "[错误] " << msg << ": " << err << " - " << err_buf << std::endl;
    }

    // 清理资源
    void cleanup() {
        running = false;
        mbedtls_ssl_session_reset(&ssl);  // 替代旧版的mbedtls_ssl_close
        mbedtls_net_close(&server_fd);
        
        mbedtls_ssl_config_free(&conf);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        mbedtls_ssl_free(&ssl);
    }
};

// 全局客户端实例
BinanceWSClient client;

// 信号处理函数（捕获Ctrl+C）
void signal_handler(int signum) {
    std::cout << "\n[退出] 收到退出信号，正在关闭连接..." << std::endl;
    client.stop();
}

int main() {
    // 注册信号处理
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // 连接到币安服务器
    if (!client.connect()) {
        std::cerr << "[退出] 连接失败，程序退出" << std::endl;
        return 1;
    }

    // 运行接收循环
    client.run();

    std::cout << "[退出] 程序已正常退出" << std::endl;
    return 0;
}
