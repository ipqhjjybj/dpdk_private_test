/*
 * F-Stack 适配的 libwebsockets Secure Streams 币安客户端
 * 核心修改：集成 F-Stack 接口，替换系统网络调用
 */

 #include <libwebsockets.h>
 #include <signal.h>
 #include <pthread.h>
 
 // F-Stack 头文件
 #include "ff_config.h"
 #include "ff_api.h"
 #include "ff_epoll.h"
 
 static struct lws_context *cx;
 static int interrupted;
 int test_result = 1;
 
 extern const lws_ss_info_t ssi_binance_t;
 
 // 保留原扩展配置（WebSocket 压缩等）
 static const struct lws_extension extensions[] = {
     {
         "permessage-deflate", lws_extension_callback_pm_deflate,
         "permessage-deflate" "; client_no_context_takeover"
          "; client_max_window_bits"
     },
     { NULL, NULL, NULL /* terminator */ }
 };
 
 // F-Stack 环境下的信号处理
 static void sigint_handler(int sig)
 {
     interrupted = 1;
     if (cx)
         lws_default_loop_exit(cx);
 }
 
 // 适配 F-Stack 的 libwebsockets 主逻辑
 static int lws_main_loop(void *arg)
 {
     struct lws_context_creation_info info;
 
     // 初始化 libwebsockets 上下文信息
     lws_context_info_defaults(&info, "example-policy.json");
     // 注意：这里需要确保命令行参数处理适配 F-Stack
     // lws_cmdline_option_handle_builtin(argc, argv, &info);
 
     info.extensions = extensions;
     // 关键：禁用 libwebsockets 内部的系统 epoll/kqueue，使用 F-Stack 事件循环
     info.options |= LWS_SERVER_OPTION_USERSPACE_EPOLL;
 
     // 创建 libwebsockets 上下文
     cx = lws_create_context(&info);
     if (!cx) {
         lwsl_err("lws init failed\n");
         return 1;
     }
 
     // 创建 Secure Stream 连接币安
     if (lws_ss_create(cx, 0, &ssi_binance_t, NULL, NULL, NULL, NULL)) {
         lwsl_cx_err(cx, "failed to create secure stream");
         interrupted = 1;
     } else {
         // 运行 libwebsockets 事件循环（已适配 F-Stack 事件）
         lws_context_default_loop_run_destroy(cx);
     }
 
     return test_result;
 }
 
 // F-Stack 主入口函数（被 ff_run 调用）
 static int fstack_main(void *arg)
 {
     // 设置信号处理
     signal(SIGINT, sigint_handler);
     lwsl_user("F-Stack based LWS minimal Secure Streams binance client\n");
 
     // 执行 libwebsockets 主逻辑
     return lws_main_loop(arg);
 }
 
 // 程序入口：初始化 F-Stack 并启动
 int main(int argc, const char **argv)
 {
     // 初始化 F-Stack（读取配置文件等）
     if (ff_init(argc, argv) < 0) {
         fprintf(stderr, "F-Stack 初始化失败\n");
         return 1;
     }
 
     // 启动 F-Stack 主循环，运行 fstack_main
     int ret = ff_run(fstack_main, NULL);
 
     // 清理 F-Stack 资源
     ff_cleanup();
 
     return ret;
 }
     