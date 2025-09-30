#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#include <sys/time.h>

// F-Stack头文件
#include "ff_config.h"
#include "ff_api.h"
#include "ff_epoll.h"

// 配置参数
#define SERVER_PORT 8080
#define BUFFER_SIZE 1024
#define MAX_EVENTS 16
#define CONNECT_TIMEOUT 5000  // 连接超时(毫秒)

// 全局变量
int sockfd = -1;
int epfd = -1;
struct epoll_event ev, events[MAX_EVENTS];
const char *server_ip;
const char *send_data = "Hello from F-Stack TCP client!";

// 获取当前时间戳（毫秒）
static uint64_t ff_get_time_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

// F-Stack清理函数声明
void ff_cleanup(void){
    
}

// 事件处理函数
static int handle_events(void *arg) {
    int nevents = ff_epoll_wait(epfd, events, MAX_EVENTS, 100);
    if (nevents < 0) {
        printf("epoll_wait error: %s\n", strerror(errno));
        return -1;
    }

    for (int i = 0; i < nevents; i++) {
        if (events[i].data.fd == sockfd) {
            // 处理连接事件
            if (events[i].events & EPOLLOUT) {
                int error = 0;
                socklen_t len = sizeof(error);
                
                // 获取连接状态
                if (ff_getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
                    printf("getsockopt error: %s\n", strerror(errno));
                    return -1;
                }

                if (error == 0) {
                    printf("成功连接到 %s:%d\n", server_ip, SERVER_PORT);
                    
                    // 连接成功，发送数据
                    ssize_t sent = ff_write(sockfd, send_data, strlen(send_data));
                    if (sent < 0) {
                        printf("发送数据失败: %s\n", strerror(errno));
                        return -1;
                    }
                    printf("已发送 %zd 字节数据: %s\n", sent, send_data);
                    
                    // 修改事件监听：等待接收数据
                    ev.events = EPOLLIN | EPOLLERR;
                    if (ff_epoll_ctl(epfd, EPOLL_CTL_MOD, sockfd, &ev) < 0) {
                        printf("epoll_ctl MOD error: %s\n", strerror(errno));
                        return -1;
                    }
                } else {
                    printf("连接失败: %s\n", strerror(error));
                    return -1;
                }
            }
            // 处理接收数据事件
            else if (events[i].events & EPOLLIN) {
                char buffer[BUFFER_SIZE];
                ssize_t recv_len = ff_read(sockfd, buffer, BUFFER_SIZE - 1);
                
                if (recv_len > 0) {
                    buffer[recv_len] = '\0';
                    printf("收到服务器响应 (%zd 字节): %s\n", recv_len, buffer);
                    
                    // 接收完成，关闭连接
                    printf("关闭连接\n");
                    return 1; // 退出事件循环
                } else if (recv_len == 0) {
                    printf("服务器已关闭连接\n");
                    return 1;
                } else {
                    printf("接收数据失败: %s\n", strerror(errno));
                    return -1;
                }
            }
            // 处理错误事件
            else if (events[i].events & EPOLLERR) {
                printf(" socket 错误事件\n");
                return -1;
            }
        }
    }
    
    return 0;
}

// 主循环函数
static int main_loop(void *arg) {
    uint64_t start_time = ff_get_time_ms();
    
    while (1) {
        // 检查连接超时
        if (ff_get_time_ms() - start_time > CONNECT_TIMEOUT) {
            printf("连接超时 (%d ms)\n", CONNECT_TIMEOUT);
            return -1;
        }
        
        int ret = handle_events(arg);
        if (ret != 0) {
            return ret;
        }
    }
}

int main(int argc, char *argv[]) {
    struct sockaddr_in server_addr;

    // 检查参数
    if (argc != 2) {
        fprintf(stderr, "用法: %s <服务器IP地址>\n", argv[0]);
        fprintf(stderr, "示例: %s 172.35.43.121\n", argv[0]);
        fprintf(stderr, "注意: F-Stack不支持127.0.0.1，请使用实际网络IP\n");
        exit(EXIT_FAILURE);
    }
    server_ip = argv[1];

    // 检查是否使用了不支持的localhost地址
    if (strcmp(server_ip, "127.0.0.1") == 0 || strcmp(server_ip, "localhost") == 0) {
        fprintf(stderr, "错误: F-Stack不支持连接到127.0.0.1或localhost\n");
        fprintf(stderr, "请使用实际的网络IP地址，例如: 172.35.43.121\n");
        exit(EXIT_FAILURE);
    }

    // 初始化F-Stack
    if (ff_init(argc, argv) < 0) {
        fprintf(stderr, "F-Stack初始化失败\n");
        exit(EXIT_FAILURE);
    }
    printf("F-Stack初始化成功\n");

    // 创建socket
    sockfd = ff_socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        fprintf(stderr, "创建socket失败: %s\n", strerror(errno));
        ff_cleanup();
        exit(EXIT_FAILURE);
    }
    printf("创建socket成功 (fd: %d)\n", sockfd);

    // 设置非阻塞模式
    int flags = ff_fcntl(sockfd, F_GETFL, 0);
    if (flags < 0) {
        fprintf(stderr, "fcntl F_GETFL失败: %s\n", strerror(errno));
        ff_close(sockfd);
        ff_cleanup();
        exit(EXIT_FAILURE);
    }
    if (ff_fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) < 0) {
        fprintf(stderr, "fcntl F_SETFL失败: %s\n", strerror(errno));
        ff_close(sockfd);
        ff_cleanup();
        exit(EXIT_FAILURE);
    }

    // 初始化服务器地址
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    
    // 转换IP地址
    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
        fprintf(stderr, "无效的IP地址: %s\n", server_ip);
        ff_close(sockfd);
        ff_cleanup();
        exit(EXIT_FAILURE);
    }

    // 创建epoll实例
    epfd = ff_epoll_create(0);
    if (epfd < 0) {
        fprintf(stderr, "epoll_create失败: %s\n", strerror(errno));
        ff_close(sockfd);
        ff_cleanup();
        exit(EXIT_FAILURE);
    }

    // 发起非阻塞连接
    int ret = ff_connect(sockfd, (struct linux_sockaddr *)&server_addr, sizeof(server_addr));
    if (ret < 0 && errno != EINPROGRESS) {
        // 非EINPROGRESS错误才是真正的失败（非阻塞连接会返回这个错误）
        fprintf(stderr, "连接失败: %s\n", strerror(errno));
        ff_close(sockfd);
        ff_close(epfd);
        ff_cleanup();
        exit(EXIT_FAILURE);
    }
    printf("正在连接到 %s:%d...\n", server_ip, SERVER_PORT);

    // 将socket添加到epoll
    ev.events = EPOLLOUT | EPOLLERR;  // 监听写事件(连接完成)和错误事件
    ev.data.fd = sockfd;
    if (ff_epoll_ctl(epfd, EPOLL_CTL_ADD, sockfd, &ev) < 0) {
        fprintf(stderr, "epoll_ctl ADD失败: %s\n", strerror(errno));
        ff_close(sockfd);
        ff_close(epfd);
        ff_cleanup();
        exit(EXIT_FAILURE);
    }

    // 运行主循环
    ff_run(main_loop, NULL);

    // 清理资源
    ff_close(sockfd);
    ff_close(epfd);
    ff_cleanup();

    return 0;
}
