#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/event.h>  // macOS/BSD 中的事件通知机制（替代 epoll）
#include <time.h>

#define SERVER_PORT 8080
#define BUFFER_SIZE 1024
#define MAX_EVENTS 10
#define CONNECT_TIMEOUT 5  // 连接超时（秒）

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

    // 4. 创建 kqueue 实例（替代 epoll）
    int kq = kqueue();
    if (kq == -1) {
        perror("kqueue 创建失败");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // 5. 发起非阻塞连接
    int connect_ret = connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    if (connect_ret == -1 && errno != EINPROGRESS && errno != EALREADY) {
        // 非阻塞连接预期返回 EINPROGRESS（正在连接）或 EALREADY（已发起连接）
        perror("connect 失败");
        close(sockfd);
        close(kq);
        exit(EXIT_FAILURE);
    }
    printf("正在非阻塞连接到 %s:%d...\n", server_ip, SERVER_PORT);

    // 6. 向 kqueue 注册事件（关注可写事件，用于检测连接完成）
    struct kevent change;
    EV_SET(&change, sockfd, EVFILT_WRITE, EV_ADD | EV_ENABLE, 0, 0, NULL);
    if (kevent(kq, &change, 1, NULL, 0, NULL) == -1) {
        perror("kevent 注册事件失败");
        close(sockfd);
        close(kq);
        exit(EXIT_FAILURE);
    }

    // 7. 事件循环（核心逻辑）
    int running = 1;
    const char *send_msg = "Hello from non-blocking TCP client!";
    time_t start_time = time(NULL);  // 记录连接开始时间（用于超时判断）

    while (running) {
        struct kevent event;
        // 等待事件（超时 100ms）
        int nevents = kevent(kq, NULL, 0, &event, 1, &(struct timespec){0, 100000000});
        if (nevents == -1) {
            perror("kevent 等待事件失败");
            break;
        }

        // 检查连接超时
        if (time(NULL) - start_time > CONNECT_TIMEOUT) {
            fprintf(stderr, "连接超时（%d秒）\n", CONNECT_TIMEOUT);
            running = 0;
            break;
        }

        // 处理就绪事件
        if (nevents > 0 && event.ident == sockfd) {
            // 连接完成事件（可写事件触发）
            if (event.filter == EVFILT_WRITE) {
                int error = 0;
                socklen_t err_len = sizeof(error);
                // 获取连接结果
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

                // 移除可写事件监听，添加可读事件监听（等待服务器响应）
                EV_SET(&change, sockfd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
                kevent(kq, &change, 1, NULL, 0, NULL);

                EV_SET(&change, sockfd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, NULL);
                if (kevent(kq, &change, 1, NULL, 0, NULL) == -1) {
                    perror("kevent 注册可读事件失败");
                    running = 0;
                    break;
                }
            }
            // 接收数据事件（可读事件触发）
            else if (event.filter == EVFILT_READ) {
                char buffer[BUFFER_SIZE];
                ssize_t recv_len = recv(sockfd, buffer, BUFFER_SIZE - 1, 0);
                if (recv_len > 0) {
                    buffer[recv_len] = '\0';
                    printf("收到服务器响应（%zd 字节）: %s\n", recv_len, buffer);
                    running = 0;  // 接收完成，退出
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
        }
    }

    // 清理资源
    close(sockfd);
    close(kq);
    printf("程序退出\n");
    return 0;
}
    