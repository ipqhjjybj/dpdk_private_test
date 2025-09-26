/*
 * TCP客户端示例：连接到8080端口
 * 功能：创建TCP连接，发送消息并接收响应
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT 8080
#define BUFFER_SIZE 1024

int main(int argc, char *argv[]) {
    int sockfd;
    struct sockaddr_in serv_addr;
    char buffer[BUFFER_SIZE];
    const char *message = "Hello from TCP client";

    // 检查参数：需要服务器IP地址
    if (argc != 2) {
        fprintf(stderr, "用法: %s <服务器IP地址>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // 1. 创建TCP套接字
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("创建套接字失败");
        exit(EXIT_FAILURE);
    }

    // 2. 设置服务器地址结构
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;       // IPv4
    serv_addr.sin_port = htons(PORT);     // 8080端口（转换为网络字节序）

    // 将IPv4地址从点分十进制转换为二进制格式
    if (inet_pton(AF_INET, argv[1], &serv_addr.sin_addr) <= 0) {
        perror("无效的服务器IP地址");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // 3. 连接到服务器的8080端口
    printf("尝试连接到 %s:%d...\n", argv[1], PORT);
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("连接失败");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    printf("成功连接到 %s:%d\n", argv[1], PORT);

    // 4. 发送消息到服务器
    if (send(sockfd, message, strlen(message), 0) < 0) {
        perror("发送消息失败");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    printf("已发送消息: %s\n", message);

    // 5. 接收服务器响应
    memset(buffer, 0, BUFFER_SIZE);
    ssize_t valread = read(sockfd, buffer, BUFFER_SIZE - 1);
    if (valread < 0) {
        perror("接收响应失败");
        close(sockfd);
        exit(EXIT_FAILURE);
    } else if (valread == 0) {
        printf("服务器已关闭连接\n");
    } else {
        printf("收到服务器响应: %s\n", buffer);
    }

    // 6. 关闭套接字
    close(sockfd);
    printf("连接已关闭\n");

    return 0;
}
    