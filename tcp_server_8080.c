/* 
 * 传统TCP服务器示例
 * 功能：监听8080端口，接收客户端连接并回声回复消息
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

#define PORT 8080
#define BUFFER_SIZE 1024
#define MAX_QUEUE 5  // 最大等待连接队列

// 客户端处理函数
void *handle_client(void *arg) {
    int client_fd = *(int *)arg;
    free(arg);  // 释放传递的文件描述符内存

    char buffer[BUFFER_SIZE];
    struct sockaddr_in client_addr;
    socklen_t len = sizeof(client_addr);
    
    // 获取客户端地址信息
    getpeername(client_fd, (struct sockaddr*)&client_addr, &len);
    printf("客户端 %s:%d 已连接\n", 
           inet_ntoa(client_addr.sin_addr), 
           ntohs(client_addr.sin_port));

    // 循环接收并回复消息
    while (1) {
        // 清空缓冲区并接收消息
        memset(buffer, 0, BUFFER_SIZE);
        ssize_t recv_len = recv(client_fd, buffer, BUFFER_SIZE - 1, 0);
        
        if (recv_len < 0) {
            perror("接收消息失败");
            break;
        } else if (recv_len == 0) {
            printf("客户端 %s:%d 断开连接\n",
                   inet_ntoa(client_addr.sin_addr),
                   ntohs(client_addr.sin_port));
            break;
        }

        // 打印收到的消息
        printf("收到 %s:%d 的消息: %s\n",
               inet_ntoa(client_addr.sin_addr),
               ntohs(client_addr.sin_port),
               buffer);

        // 回声回复（将收到的消息原样返回）
        if (send(client_fd, buffer, recv_len, 0) < 0) {
            perror("发送消息失败");
            break;
        }

        // 若客户端发送"exit"则断开连接
        if (strncmp(buffer, "exit", 4) == 0) {
            printf("客户端 %s:%d 请求断开连接\n",
                   inet_ntoa(client_addr.sin_addr),
                   ntohs(client_addr.sin_port));
            break;
        }
    }

    // 关闭客户端连接
    close(client_fd);
    return NULL;
}

int main() {
    int server_fd;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);

    // 1. 创建TCP套接字
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("创建套接字失败");
        exit(EXIT_FAILURE);
    }

    // 2. 设置套接字选项（允许重用端口）
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("设置套接字选项失败");
        exit(EXIT_FAILURE);
    }

    // 3. 配置服务器地址
    address.sin_family = AF_INET;         // IPv4
    address.sin_addr.s_addr = INADDR_ANY; // 监听所有网络接口
    address.sin_port = htons(PORT);       // 端口转换为网络字节序

    // 4. 绑定套接字到端口
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("绑定端口失败");
        exit(EXIT_FAILURE);
    }

    // 5. 开始监听连接
    if (listen(server_fd, MAX_QUEUE) < 0) {
        perror("监听失败");
        exit(EXIT_FAILURE);
    }

    printf("服务器启动成功，监听端口 %d...\n", PORT);
    printf("请使用客户端连接，或按 Ctrl+C 退出\n");

    // 6. 循环接受客户端连接
    while (1) {
        // 接受新连接
        int *client_fd = malloc(sizeof(int));
        if ((*client_fd = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            perror("接受连接失败");
            free(client_fd);
            continue;
        }

        // 创建线程处理客户端
        pthread_t thread_id;
        if (pthread_create(&thread_id, NULL, handle_client, client_fd) != 0) {
            perror("创建线程失败");
            close(*client_fd);
            free(client_fd);
            continue;
        }

        // 分离线程，自动释放资源
        pthread_detach(thread_id);
    }

    // 实际不会执行到这里，因为上面是无限循环
    close(server_fd);
    return 0;
}
    