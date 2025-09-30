#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <fcntl.h>

#include "ff_config.h"
#include "ff_api.h"
#include "ff_epoll.h"

#define SERVER_IP "101.32.223.170"

#define SERVER_PORT 12345
#define BUFFER_SIZE 256
#define MAX_EVENTS 10

static struct epoll_event ev, events[MAX_EVENTS];
int epfd;
int sockfd;
//#define STANDARD
int loop(void *arg)
{
    int nfds;
    char send_buf[] = "Hello, Server!";
    char recv_buf[BUFFER_SIZE];
    #ifdef STANDARD
    nfds = epoll_wait(epfd, events, MAX_EVENTS, -1);
    #else
    nfds = ff_epoll_wait(epfd, events, MAX_EVENTS, -1);
    #endif
    if (nfds < 0) {
        printf("ff_epoll_wait failed\n");
    } else if(nfds != 0){
        printf("got events, nfds %d\n", nfds);
    }

    for (int i = 0; i < nfds; ++i) {
        if (events[i].events & EPOLLOUT) {
            printf("before write\n");
            #ifdef STANDARD
            if (write(sockfd, send_buf, strlen(send_buf)) < 0) {
                #else
            if (ff_write(sockfd, send_buf, strlen(send_buf)) < 0) {
                #endif
                printf("ff_write failed: %s\n", strerror(errno));
            } else {
                ev.events = EPOLLIN;
                printf("write a buffer\n");
                #ifdef STANDARD
                epoll_ctl(epfd, EPOLL_CTL_MOD, sockfd, &ev);
                #else
                ff_epoll_ctl(epfd, EPOLL_CTL_MOD, sockfd, &ev);
                #endif
            }
            } else if (events[i].events & EPOLLIN) {
                #ifdef STANDARD
                int len = read(sockfd, recv_buf, BUFFER_SIZE - 1);
                #else
                int len = ff_read(sockfd, recv_buf, BUFFER_SIZE - 1);
                #endif
                if (len > 0) {
                    recv_buf[len] = '\0'; // 添加字符串结束符
                    printf("Received from server: %s\n", recv_buf);
                } else {
                    if (len < 0) {
                        printf("ff_read failed: %s\n", strerror(errno));
                    } else {
                        printf("Connection closed by server\n");
                    }
                }
                #ifdef STANDARD
                close(sockfd);
                #else
                ff_close(sockfd);
                #endif
                break;
            }
            } else if (events[i].events & (EPOLLHUP | EPOLLERR)) {
                printf("epoll error\n");
                #ifdef STANDARD
                close(sockfd);
                #else
                ff_close(sockfd);
                #endif
                break;
            }
    }
}

int main(int argc, char *argv[]) {
    int nfds;
    struct sockaddr_in server_addr;
    int on = 1;

    #ifdef STANDARD
    #else
    ff_init(argc, argv);
    #endif

    #ifdef STANDARD
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    #else
    sockfd = ff_socket(AF_INET, SOCK_STREAM, 0);
    #endif
    if (sockfd < 0) {
        printf("ff_socket failed\n");
        return -1;
    }

    #ifdef STANDARD
    ioctl(sockfd, FIONBIO, &on);
    #else
    ff_ioctl(sockfd, FIONBIO, &on);
    #endif

memset(&server_addr, 0, sizeof(server_addr));
server_addr.sin_family = AF_INET;
server_addr.sin_port = htons(SERVER_PORT);
server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);
printf("just before ff_connect\n");
#ifndef STANDARD
//sleep(10);
#endif
#ifdef STANDARD
if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
#else
if (ff_connect(sockfd, (struct linux_sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
#endif
if (errno != EINPROGRESS) {
printf("ff_connect failed: %s\n", strerror(errno));
#ifdef STANDARD
close(sockfd);
#else
ff_close(sockfd);
#endif
return -1;
} else {
printf("EINPROGRESS\n");
}
}

printf("end ff_connect\n");
#ifdef STANDARD
epfd = epoll_create(1);
#else
epfd = ff_epoll_create(1);
#endif
if (epfd < 0) {
printf("ff_epoll_create failed\n");

#ifdef STANDARD
close(sockfd);
#else
ff_close(sockfd);
#endif
return -1;
}

ev.events = EPOLLOUT | EPOLLIN;
ev.data.fd = sockfd;
#ifdef STANDARD
if (epoll_ctl(epfd, EPOLL_CTL_ADD, sockfd, &ev) < 0) {
    #else
    if (ff_epoll_ctl(epfd, EPOLL_CTL_ADD, sockfd, &ev) < 0) {
    #endif
    printf("ff_epoll_ctl failed\n");
    #ifdef STANDARD
    close(sockfd);
    #else
    ff_close(sockfd);
    #endif
    return -1;
    }

    #ifdef STANDARD
    while (1) {
    loop(NULL);
    }
    #else
    ff_run(loop, NULL);
    #endif
    #if 0
    while (1) {
    #ifdef STANDARD
    nfds = epoll_wait(epfd, events, MAX_EVENTS, -1);
    #else
    nfds = ff_epoll_wait(epfd, events, MAX_EVENTS, -1);
    #endif
    if (nfds < 0) {
    printf("ff_epoll_wait failed\n");
    if(nfds != 0) printf("got events, nfds %d\n", nfds);

        for (int i = 0; i < nfds; ++i) {
            if (events[i].events & EPOLLOUT) {
                printf("before write\n");
    #ifdef STANDARD
    if (write(sockfd, send_buf, strlen(send_buf)) < 0) {
    #else
    if (ff_write(sockfd, send_buf, strlen(send_buf)) < 0) {
    #endif
    printf("ff_write failed: %s\n", strerror(errno));
    } else {
    ev.events = EPOLLIN;
    printf("write a buffer\n");
    #ifdef STANDARD
    epoll_ctl(epfd, EPOLL_CTL_MOD, sockfd, &ev);
    #else
    ff_epoll_ctl(epfd, EPOLL_CTL_MOD, sockfd, &ev);
    #endif
    }
    } else if (events[i].events & EPOLLIN) {
    #ifdef STANDARD
    int len = read(sockfd, recv_buf, BUFFER_SIZE - 1);
    #else
    int len = ff_read(sockfd, recv_buf, BUFFER_SIZE - 1);
    #endif
    if (len > 0) {
    recv_buf[len] = '\0'; // 添加字符串结束符
    printf("Received from server: %s\n", recv_buf);
    } else {
    if (len < 0) {
    printf("ff_read failed: %s\n", strerror(errno));
    } else {
    printf("Connection closed by server\n");
    }
    #ifdef STANDARD
    close(sockfd);
    #else
    ff_close(sockfd);
    #endif
    goto cleanup;
    }
    } else if (events[i].events & (EPOLLHUP | EPOLLERR)) {
    printf("epoll error\n");
    #ifdef STANDARD
    close(sockfd);
    #else
    ff_close(sockfd);
    #endif
    goto cleanup;
    }
    }
    }
    }

    cleanup:
    #ifdef STANDARD
    close(epfd);
    #else
    ff_close(epfd);
    #endif
    #endif
    return 0;
}