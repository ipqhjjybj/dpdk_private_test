// 原 socket 创建函数
static int lws_socket(int domain, int type, int protocol) {
    return socket(domain, type, protocol);
}

// 原连接函数
static int lws_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    return connect(sockfd, addr, addrlen);
}

// 替换为 F-Stack 的 socket 创建
static int lws_socket(int domain, int type, int protocol) {
    // F-Stack 的 socket 接口（注意参数可能需要适配）
    return ff_socket(domain, type, protocol);
}

// 替换为 F-Stack 的连接接口
static int lws_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    // F-Stack 的 connect 接口（注意结构体兼容性）
    return ff_connect(sockfd, (struct linux_sockaddr *)addr, addrlen);
}


// 原创建 epoll 实例
static int lws_epoll_create(void) {
    return epoll_create1(EPOLL_CLOEXEC);
}

// 原添加事件
static int lws_epoll_ctl_add(int epfd, int fd, struct epoll_event *ev) {
    return epoll_ctl(epfd, EPOLL_CTL_ADD, fd, ev);
}


// 替换为 F-Stack 的 epoll 创建
static int lws_epoll_create(void) {
    return ff_epoll_create(0);  // F-Stack 的 epoll 创建接口
}

// 替换为 F-Stack 的事件添加
static int lws_epoll_ctl_add(int epfd, int fd, struct epoll_event *ev) {
    return ff_epoll_ctl(epfd, EPOLL_CTL_ADD, fd, ev);  // F-Stack 的 epoll 控制接口
}

// 替换事件等待函数
static int lws_epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout_ms) {
    return ff_epoll_wait(epfd, events, maxevents, timeout_ms);  // F-Stack 的事件等待
}


// 替换接收函数
static ssize_t lws_recv(int sockfd, void *buf, size_t len, int flags) {
    return ff_recv(sockfd, buf, len, flags);
}

// 替换发送函数
static ssize_t lws_send(int sockfd, const void *buf, size_t len, int flags) {
    return ff_send(sockfd, buf, len, flags);
}




// 下面不用修改
// 自定义 WebSocket 协议回调（与原版 libwebsockets 用法一致）
static int ws_protocol_callback(struct lws *wsi, enum lws_callback_reasons reason,
    void *user, void *in, size_t len) {
    switch (reason) {
        case LWS_CALLBACK_CLIENT_CONNECTED:
        lwsl_info("WebSocket 连接成功\n");
        break;
        case LWS_CALLBACK_CLIENT_RECEIVE:
        lwsl_info("收到数据: %.*s\n", (int)len, (char *)in);
        break;
        // ... 其他事件处理
        default:
        break;
    }
    return 0;
}

// 协议定义（与原版一致）
static const struct lws_protocols protocols[] = {
    {
        "my-protocol",  // 协议名称
        ws_protocol_callback,  // 回调函数
        0,  // 用户数据大小
        1024,  // 接收缓冲区大小
    },
    { NULL, NULL, 0, 0 }  // 结束标记
};