#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/epoll.h>

#define SERVER_PORT 8080
#define BUFFER_SIZE 1024
#define MAX_EVENTS 10
#define CONNECT_TIMEOUT 5000  // 5秒连接超时

// 设置 socket 为非阻塞模式
int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        perror("fcntl F_GETFL failed");
        return -1;
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        perror("fcntl F_SETFL failed");
        return -1;
    }
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "用法: %s <服务器IP>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    const char *server_ip = argv[1];

    // 1. 创建 TCP socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("socket 创建失败");
        exit(EXIT_FAILURE);
    }

    // 2. 设置为非阻塞模式
    if (set_nonblocking(sockfd) == -1) {
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // 3. 初始化服务器地址
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
        perror("无效的服务器IP");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // 4. 创建 epoll 实例（事件驱动核心）
    int epfd = epoll_create1(0);
    if (epfd == -1) {
        perror("epoll_create1 失败");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // 5. 发起非阻塞连接（立即返回，不会阻塞）
    int connect_ret = connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    if (connect_ret == -1 && errno != EINPROGRESS) {
        // 只有非 EINPROGRESS 的错误才是真正失败（非阻塞连接预期返回 EINPROGRESS）
        perror("connect 失败");
        close(sockfd);
        close(epfd);
        exit(EXIT_FAILURE);
    }
    printf("正在非阻塞连接到 %s:%d...\n", server_ip, SERVER_PORT);

    // 6. 将 socket 加入 epoll 监听（关注连接完成事件 EPOLLOUT）
    struct epoll_event ev, events[MAX_EVENTS];
    ev.events = EPOLLOUT | EPOLLERR;  // 监听写事件（连接完成）和错误
    ev.data.fd = sockfd;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, sockfd, &ev) == -1) {
        perror("epoll_ctl 添加失败");
        close(sockfd);
        close(epfd);
        exit(EXIT_FAILURE);
    }

    // 7. 事件循环（核心逻辑）
    int running = 1;
    const char *send_msg = "Hello from non-blocking TCP client!";
    uint64_t start_time = time(NULL);  // 记录连接开始时间（用于超时判断）

    while (running) {
        // 等待事件就绪（超时 100ms，避免永久阻塞）
        int nfds = epoll_wait(epfd, events, MAX_EVENTS, 100);
        if (nfds == -1) {
            perror("epoll_wait 失败");
            break;
        }

        // 检查连接超时
        if (time(NULL) - start_time > CONNECT_TIMEOUT) {
            fprintf(stderr, "连接超时（%d秒）\n", CONNECT_TIMEOUT);
            running = 0;
            break;
        }

        // 处理就绪事件
        for (int i = 0; i < nfds; i++) {
            if (events[i].data.fd == sockfd) {
                // 处理连接完成事件（EPOLLOUT）
                if (events[i].events & EPOLLOUT) {
                    int error = 0;
                    socklen_t err_len = sizeof(error);
                    // 获取连接结果（非阻塞连接的关键：通过 getsockopt 检查是否成功）
                    if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &err_len) == -1) {
                        perror("getsockopt 失败");
                        running = 0;
                        break;
                    }
                    if (error != 0) {
                        fprintf(stderr, "连接失败: %s\n", strerror(error));
                        running = 0;
                        break;
                    }

                    // 连接成功，发送数据
                    printf("连接成功！发送数据...\n");
                    ssize_t sent = send(sockfd, send_msg, strlen(send_msg), 0);
                    if (sent == -1) {
                        perror("send 失败");
                        running = 0;
                        break;
                    }
                    printf("已发送 %zd 字节: %s\n", sent, send_msg);

                    // 修改 epoll 监听事件：等待服务器响应（EPOLLIN）
                    ev.events = EPOLLIN | EPOLLERR;
                    if (epoll_ctl(epfd, EPOLL_CTL_MOD, sockfd, &ev) == -1) {
                        perror("epoll_ctl 修改失败");
                        running = 0;
                        break;
                    }
                }
                // 处理接收数据事件（EPOLLIN）
                else if (events[i].events & EPOLLIN) {
                    char buffer[BUFFER_SIZE];
                    ssize_t recv_len = recv(sockfd, buffer, BUFFER_SIZE - 1, 0);
                    if (recv_len > 0) {
                        buffer[recv_len] = '\0';
                        printf("收到服务器响应（%zd 字节）: %s\n", recv_len, buffer);
                        running = 0;  // 接收完成，退出循环
                        break;
                    } else if (recv_len == 0) {
                        printf("服务器已关闭连接\n");
                        running = 0;
                        break;
                    } else {
                        perror("recv 失败");
                        running = 0;
                        break;
                    }
                }
                // 处理错误事件
                else if (events[i].events & EPOLLERR) {
                    fprintf(stderr, "socket 发生错误\n");
                    running = 0;
                    break;
                }
            }
        }
    }

    // 清理资源
    close(sockfd);
    close(epfd);
    printf("程序退出\n");
    return 0;
}