/*
 * 通过 shell 执行
 * ./tcp_client --conf /etc/f-stack.conf --proc-type=primary &
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <assert.h>
 
#include "ff_config.h"
#include "ff_api.h"
 
#define MAX_EVENTS 512
 
/* kevent set */
struct kevent kevSet[2];
 
int send_once = 0;
/* events */
struct kevent events[MAX_EVENTS];
/* kq */
int kq;
int sockfd;
#ifdef INET6
int sockfd6;
#endif


int loop(void *arg)
{
    /* Wait for events to happen */
    unsigned nevents = ff_kevent(kq, NULL, 0, events, MAX_EVENTS, NULL);
    unsigned i;
 
    for (i = 0; i < nevents; ++i) {
        struct kevent event = events[i];
        int clientfd = (int)event.ident;
 
        /* Handle disconnect */
        if (event.flags & EV_EOF) {
            /* Simply close socket */
            ff_close(clientfd);
			printf("#### close clientfd=%d\n",clientfd);
        }
 
		if (clientfd == sockfd) {
	 		if (event.filter == EVFILT_READ) {
	            char buf[8000];
	            size_t readlen = ff_read(clientfd, buf, sizeof(buf));
				if(readlen > 0){
					printf("#### client recv data:%s\n",buf);
				}
	        }
			
			if (event.filter == EVFILT_WRITE) {
                if(send_once == 0){
                    char wr_buf[1000]="GET / HTTP/1.1\r\nHost: httpbin.org\r\n\r\n";
                    printf("#### client send data:%s\n",wr_buf);
                    ff_write(clientfd, wr_buf, strlen(wr_buf));		
                    send_once = 1;
                }
	        }
		
    	}
    }
}
 
int main(int argc, char * argv[])
{
    ff_init(argc, argv);
 
    assert((kq = ff_kqueue()) > 0);
 
    sockfd = ff_socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        printf("ff_socket failed, sockfd:%d, errno:%d, %s\n", sockfd, errno, strerror(errno));
        exit(1);
    }
	
	struct sockaddr_in server_addr; 
	bzero(&server_addr, sizeof(server_addr)); 
	server_addr.sin_family = AF_INET; 
	server_addr.sin_addr.s_addr = inet_addr("54.92.125.174"); 
	server_addr.sin_port = htons(9443); 
 
    struct sockaddr_in my_addr;
    bzero(&my_addr, sizeof(my_addr));
    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons(8000);
    my_addr.sin_addr.s_addr = inet_addr("172.35.33.174");
 
    int ret = ff_bind(sockfd, (struct linux_sockaddr *)&my_addr, sizeof(my_addr));
    if (ret < 0) {
        printf("ff_bind failed, sockfd:%d, errno:%d, %s\n", sockfd, errno, strerror(errno));
        exit(1);
    }else{
        printf("ff_bind success, sockfd:%d\n", sockfd);
    }
	
	ret = ff_connect(sockfd,(struct linux_sockaddr *)&server_addr,sizeof(server_addr));
    if (ret < 0 && errno != EPERM) {
        printf("ff_connect failed, sockfd:%d, errno:%d, %s\n", sockfd, errno, strerror(errno));
        exit(1);
    }	
 
    EV_SET(&kevSet[0], sockfd, EVFILT_READ	, EV_ADD, 0, MAX_EVENTS, NULL);	
	EV_SET(&kevSet[1], sockfd, EVFILT_WRITE, EV_ADD, 0, MAX_EVENTS, NULL);
    /* Update kqueue */
    ff_kevent(kq, kevSet, 2, NULL, 0, NULL);
 
    ff_run(loop, NULL);
    return 0;
}