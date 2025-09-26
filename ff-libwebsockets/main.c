// 引入 F-Stack 头文件
#include "ff_config.h"
#include "ff_api.h"
#include "ff_epoll.h"

// libwebsockets 相关头文件
#include <libwebsockets.h>

// F-Stack 主函数（被 ff_run 调用）
static int fstack_main(void *arg) {
    // 这里放 libwebsockets 的初始化和事件循环逻辑
    struct lws_context_creation_info info;
    struct lws_context *context;
    
    memset(&info, 0, sizeof(info));
    info.port = CONTEXT_PORT_NO_LISTEN;  // 客户端模式
    info.protocols = protocols;  // 自定义协议（见下文）
    // ... 其他 libwebsockets 配置

    // 创建 libwebsockets 上下文
    context = lws_create_context(&info);
    if (!context) {
        lwsl_err("创建 lws 上下文失败\n");
        return -1;
    }

    // 启动 libwebsockets 事件循环（需改造内部逻辑）
    while (1) {
        // 替换 lws_service 为适配 F-Stack 的事件处理
        lws_service(context, 100);  // 100ms 超时
    }

    lws_context_destroy(context);
    return 0;
}

// 程序入口
int main(int argc, char **argv) {
    // 初始化 F-Stack（读取配置文件等）
    if (ff_init(argc, argv) < 0) {
        fprintf(stderr, "F-Stack 初始化失败\n");
        return -1;
    }

    // 启动 F-Stack 主循环，执行 fstack_main
    ff_run(fstack_main, NULL);

    // 清理 F-Stack 资源
    ff_cleanup();
    return 0;
}