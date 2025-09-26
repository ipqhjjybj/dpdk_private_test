#include <iostream>
#include <string>
#include <cstring>
#include <vector>
#include <csignal>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <poll.h>
#include <netdb.h>
#include <algorithm>
#include <sstream>

#include "mbedtls/net.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"

// 币安WebSocket行情地址
const std::string BINANCE_HOST = "stream.binance.com";
const std::string BINANCE_PATH = "/ws/btcusdt@depthUpdate";
const int BINANCE_PORT = 9443;

// 全局退出标志
static volatile bool running = true;

// 信号处理函数
void signal_handler(int signum) {
    running = false;
    std::cout << "\n收到退出信号，正在清理资源..." << std::endl;
}

// WebSocket帧结构
struct WebSocketFrame {
    bool fin;
    uint8_t opcode;
    bool masked;
    uint64_t payload_length;
    uint8_t mask_key[4];
    std::vector<uint8_t> payload;
};

class BinanceWSClient {
private:
    int sockfd;
    mbedtls_net_context server_fd;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char* pers = "binance_ws_client";

public:
    BinanceWSClient() : sockfd(-1) {
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

    // 初始化连接
    bool init() {
        // 1. 创建TCP socket
        if (!create_socket()) {
            return false;
        }

        // 2. 初始化随机数生成器
        if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                 reinterpret_cast<const unsigned char*>(pers), 
                                 strlen(pers)) != 0) {
            std::cerr << "初始化随机数生成器失败" << std::endl;
            return false;
        }

        // 3. 配置SSL
        if (mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
                                       MBEDTLS_SSL_TRANSPORT_STREAM,
                                       MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
            std::cerr << "配置SSL失败" << std::endl;
            return false;
        }

        // 不验证服务器证书(生产环境建议开启)
        mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
        mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

        if (mbedtls_ssl_setup(&ssl, &conf) != 0) {
            std::cerr << "设置SSL失败" << std::endl;
            return false;
        }

        // 绑定socket到mbedtls
        server_fd.fd = sockfd;
        mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

        // 4. 执行TLS握手
        std::cout << "正在进行TLS握手..." << std::endl;
        if (!perform_tls_handshake()) {
            return false;
        }

        // 5. 执行WebSocket握手
        std::cout << "正在进行WebSocket握手..." << std::endl;
        if (!perform_ws_handshake()) {
            return false;
        }

        return true;
    }

    // 运行客户端主循环
    void run() {
        std::cout << "开始接收行情数据..." << std::endl;
        
        std::vector<uint8_t> buffer(8192);
        struct pollfd fds[1];
        fds[0].fd = sockfd;
        fds[0].events = POLLIN;

        while (running) {
            int ret = poll(fds, 1, 1000); // 超时1秒
            
            if (ret < 0) {
                std::cerr << "poll错误: " << strerror(errno) << std::endl;
                break;
            }
            else if (ret == 0) {
                continue; // 超时，继续等待
            }

            // 有数据可读
            if (fds[0].revents & POLLIN) {
                ssize_t len = mbedtls_ssl_read(&ssl, buffer.data(), buffer.size());
                
                if (len <= 0) {
                    if (len != MBEDTLS_ERR_SSL_WANT_READ && len != MBEDTLS_ERR_SSL_WANT_WRITE) {
                        std::cerr << "读取数据失败: " << len << std::endl;
                        break;
                    }
                    continue;
                }

                // 解析WebSocket帧
                size_t pos = 0;
                while (pos < static_cast<size_t>(len)) {
                    WebSocketFrame frame;
                    size_t frame_size = parse_ws_frame(buffer.data() + pos, len - pos, frame);
                    
                    if (frame_size == 0) break; // 无法解析完整帧
                    
                    pos += frame_size;
                    
                    // 处理文本帧
                    if (frame.opcode == 0x01) {
                        process_message(frame.payload);
                    }
                    // 处理关闭帧
                    else if (frame.opcode == 0x08) {
                        std::cout << "收到关闭帧，退出" << std::endl;
                        running = false;
                        break;
                    }
                }
            }
        }
    }

private:
    // 创建并连接TCP socket
    bool create_socket() {
        // 获取主机地址
        struct hostent* host = gethostbyname(BINANCE_HOST.c_str());
        if (!host) {
            std::cerr << "无法解析主机名: " << BINANCE_HOST << std::endl;
            return false;
        }

        // 创建socket
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) {
            std::cerr << "创建socket失败: " << strerror(errno) << std::endl;
            return false;
        }

        // 设置socket地址
        struct sockaddr_in serv_addr;
        std::memset(&serv_addr, 0, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        std::memcpy(&serv_addr.sin_addr.s_addr, host->h_addr, host->h_length);
        serv_addr.sin_port = htons(BINANCE_PORT);

        // 连接服务器
        if (connect(sockfd, reinterpret_cast<struct sockaddr*>(&serv_addr), sizeof(serv_addr)) < 0) {
            std::cerr << "连接服务器失败: " << strerror(errno) << std::endl;
            close(sockfd);
            sockfd = -1;
            return false;
        }

        return true;
    }

    // 执行TLS握手
    bool perform_tls_handshake() {
        int ret;
        while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
            if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                std::cerr << "TLS握手失败: " << ret << std::endl;
                return false;
            }
        }
        std::cout << "TLS握手成功" << std::endl;
        return true;
    }

    // 执行WebSocket握手
    bool perform_ws_handshake() {
        // 构建握手请求
        std::string handshake = "GET " + BINANCE_PATH + " HTTP/1.1\r\n"
                              "Host: " + BINANCE_HOST + ":" + std::to_string(BINANCE_PORT) + "\r\n"
                              "Upgrade: websocket\r\n"
                              "Connection: Upgrade\r\n"
                              "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                              "Sec-WebSocket-Version: 13\r\n\r\n";

        // 发送握手请求
        int ret = mbedtls_ssl_write(&ssl, reinterpret_cast<const unsigned char*>(handshake.c_str()), 
                                   handshake.length());
        if (ret <= 0) {
            std::cerr << "发送握手请求失败: " << ret << std::endl;
            return false;
        }

        // 接收并验证握手响应
        std::vector<uint8_t> response(1024);
        ret = mbedtls_ssl_read(&ssl, response.data(), response.size() - 1);
        if (ret <= 0) {
            std::cerr << "接收握手响应失败: " << ret << std::endl;
            return false;
        }
        response[ret] = '\0';

        std::string resp_str(reinterpret_cast<char*>(response.data()));
        if (resp_str.find("101 Switching Protocols") == std::string::npos) {
            std::cerr << "WebSocket握手失败: " << resp_str << std::endl;
            return false;
        }

        std::cout << "WebSocket握手成功" << std::endl;
        return true;
    }

    // 解析WebSocket帧
    size_t parse_ws_frame(const uint8_t* data, size_t len, WebSocketFrame& frame) {
        if (len < 2) return 0;

        // 解析第一个字节
        frame.fin = (data[0] & 0x80) != 0;
        frame.opcode = data[0] & 0x0F;

        // 解析第二个字节
        frame.masked = (data[1] & 0x80) != 0;
        uint8_t payload_len_indicator = data[1] & 0x7F;

        size_t header_size = 2;
        frame.payload_length = 0;

        // 解析payload长度
        if (payload_len_indicator == 126) {
            if (len < 4) return 0;
            frame.payload_length = (data[2] << 8) | data[3];
            header_size += 2;
        }
        else if (payload_len_indicator == 127) {
            // 忽略超长帧
            return 0;
        }
        else {
            frame.payload_length = payload_len_indicator;
        }

        // 解析掩码
        if (frame.masked) {
            if (len < header_size + 4) return 0;
            std::memcpy(frame.mask_key, data + header_size, 4);
            header_size += 4;
        }

        // 检查帧是否完整
        if (len < header_size + frame.payload_length) return 0;

        // 提取payload
        frame.payload.resize(frame.payload_length);
        std::memcpy(frame.payload.data(), data + header_size, frame.payload_length);

        // 应用掩码
        if (frame.masked) {
            for (size_t i = 0; i < frame.payload_length; ++i) {
                frame.payload[i] ^= frame.mask_key[i % 4];
            }
        }

        return header_size + frame.payload_length;
    }

    // 处理收到的消息
    void process_message(const std::vector<uint8_t>& payload) {
        std::string msg(reinterpret_cast<const char*>(payload.data()), payload.size());
        
        // 提取价格和时间戳（简化解析）
        size_t price_pos = msg.find("\"a\":[[\"");
        size_t time_pos = msg.find("\"E\":");
        
        if (price_pos != std::string::npos && time_pos != std::string::npos) {
            // 提取价格
            size_t price_end = msg.find("\"", price_pos + 5);
            std::string price = msg.substr(price_pos + 5, price_end - (price_pos + 5));
            
            // 提取时间戳
            size_t time_end = msg.find(",", time_pos + 3);
            std::string time_str = msg.substr(time_pos + 3, time_end - (time_pos + 3));
            uint64_t event_time = std::stoull(time_str);
            
            std::cout << "事件时间: " << event_time << ", 卖一价: " << price << std::endl;
        }
    }

    // 清理资源
    void cleanup() {
        if (sockfd != -1) {
            close(sockfd);
            sockfd = -1;
        }
        
        mbedtls_ssl_close(&ssl);
        mbedtls_net_free(&server_fd);
        mbedtls_ssl_config_free(&conf);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        mbedtls_ssl_free(&ssl);
    }
};

int main() {
    // 注册信号处理
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // 创建并初始化客户端
    BinanceWSClient client;
    if (!client.init()) {
        std::cerr << "客户端初始化失败" << std::endl;
        return 1;
    }

    // 运行客户端
    client.run();

    std::cout << "程序已退出" << std::endl;
    return 0;
}
