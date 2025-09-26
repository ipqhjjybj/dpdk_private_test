/*
 * F-Stack 适配的 libwebsockets Secure Streams 币安数据处理模块
 * 功能：接收币安 WebSocket 行情（depthUpdate）、计算延迟与价格统计、1Hz 输出结果
 * 核心改造：
 * 1. 替换系统时间接口为 F-Stack 高效接口（避免内核调用）
 * 2. 保持 SS 上层业务逻辑完全兼容
 * 3. 适配 F-Stack 用户态网络环境
 */

 #include <libwebsockets.h>
 #include <string.h>
 #include <signal.h>
 #include <ctype.h>
 
 // -------------------------- F-Stack 头文件引入（关键依赖） --------------------------
 #include "ff_config.h"   // F-Stack 配置头文件
 #include "ff_api.h"      // F-Stack 核心 API（socket/epoll 等）
 #include "ff_time.h"     // F-Stack 时间接口（微秒级计时）
 
 // -------------------------- 全局变量与结构体定义（与原逻辑兼容） --------------------------
 int test_result = 1;  // 测试结果标记（0=成功，1=未完成）
 
 // 统计范围结构体（延迟/价格的 min/max/avg 计算）
 typedef struct range {
     uint64_t        sum;        // 总和
     uint64_t        lowest;     // 最小值
     uint64_t        highest;    // 最大值
     unsigned int    samples;    // 样本数
 } range_t;
 
 // SS 用户数据结构体（绑定 SS 上下文与业务数据）
 LWS_SS_USER_TYPEDEF
     lws_sorted_usec_list_t    sul_hz;       // 1Hz 统计输出定时器
     range_t                   e_lat_range;   // 事件延迟统计（从币安推送时间到本地接收时间）
     range_t                   price_range;   // 价格统计（卖一价 "a" 字段）
 } binance_t;
 
 
 // -------------------------- 基础工具函数（保留原逻辑） --------------------------
 /**
  * 重置统计范围（每次 1Hz 输出后清零）
  */
 static void
 range_reset(range_t *r)
 {
     r->sum = r->highest = 0;
     r->lowest = 999999999999ull;  // 初始值设为极大值
     r->samples = 0;
 }
 
 /**
  * 价格转换：币安字符串格式（如 "45678.12"）→ 分（整数，避免浮点误差）
  */
 static uint64_t
 pennies(const char *s)
 {
     uint64_t price = (uint64_t)atoll(s) * 100;  // 整数部分转分
     const char *dot = strchr(s, '.');          // 查找小数点
 
     // 处理小数部分（保留 2 位，不足补 0）
     if (dot && isdigit(dot[1])) {
         price += (uint64_t)(dot[1] - '0') * 10;  // 小数点后第 1 位
         if (isdigit(dot[2]))
             price += (uint64_t)(dot[2] - '0');   // 小数点后第 2 位
     }
 
     return price;
 }
 
 
 // -------------------------- F-Stack 时间接口改造（核心优化） --------------------------
 /**
  * 获取当前微秒时间（替换系统 gettimeofday，避免内核态调用）
  * @return 微秒级时间戳（uint64_t）
  */
 static uint64_t
 get_us_timeofday(void)
 {
     // F-Stack 提供的用户态时间接口，比系统调用快一个数量级
     return ff_get_time_us();
 }
 
 
 // -------------------------- 1Hz 统计输出回调（保留原逻辑） --------------------------
 /**
  * 定时器回调：每秒输出一次延迟和价格统计结果
  */
 static void
 sul_hz_cb(lws_sorted_usec_list_t *sul)
 {
     binance_t *bin = lws_container_of(sul, binance_t, sul_hz);  // 从定时器获取用户数据
 
     // 重新调度：1 秒后再次执行（维持 1Hz 频率）
     lws_sul_schedule(
         lws_ss_get_context(bin->ss),  // 获取 SS 上下文
         0,                            // 优先级（默认 0）
         &bin->sul_hz,                 // 定时器对象
         sul_hz_cb,                    // 回调函数
         LWS_US_PER_SEC                // 间隔（1 秒 = 1e6 微秒）
     );
 
     // 输出价格统计（若有样本）
     if (bin->price_range.samples) {
         lwsl_ss_user(
             lws_ss_from_user(bin),    // SS 日志标识
             "price: min: %llu¢, max: %llu¢, avg: %llu¢, (%d prices/s)",
             (unsigned long long)bin->price_range.lowest,
             (unsigned long long)bin->price_range.highest,
             (unsigned long long)(bin->price_range.sum / bin->price_range.samples),
             bin->price_range.samples
         );
     }
 
     // 输出延迟统计（若有样本）
     if (bin->e_lat_range.samples) {
         lwsl_ss_user(
             lws_ss_from_user(bin),
             "elatency: min: %llums, max: %llums, avg: %llums, (%d msg/s)",
             (unsigned long long)(bin->e_lat_range.lowest / 1000),  // 微秒 → 毫秒
             (unsigned long long)(bin->e_lat_range.highest / 1000),
             (unsigned long long)((bin->e_lat_range.sum / bin->e_lat_range.samples) / 1000),
             bin->e_lat_range.samples
         );
     }
 
     // 重置统计（为下一秒做准备）
     range_reset(&bin->e_lat_range);
     range_reset(&bin->price_range);
 
     test_result = 0;  // 标记测试成功（有统计数据即表示正常运行）
 }
 
 
 // -------------------------- SS 数据接收回调（行情解析核心逻辑） --------------------------
 /**
  * SS 接收回调：处理币安推送的 WebSocket 行情数据
  * @param userobj  用户数据（binance_t 实例）
  * @param in       接收的数据缓冲区
  * @param len      数据长度
  * @param flags    接收标志（如 LWS_SS_FLAG_FINAL = 数据完整）
  * @return         SS 状态码（LWSSSSRET_OK = 正常）
  */
 static lws_ss_state_return_t
 binance_rx(void *userobj, const uint8_t *in, size_t len, int flags)
 {
     binance_t *bin = (binance_t *)userobj;
     uint64_t latency_us, now_us;  // 延迟（微秒）、当前时间
     char numbuf[16] = {0};        // 临时字符串缓冲区（存储解析后的数字）
     uint64_t price;               // 转换后的价格（分）
     const char *p;                // JSON 字段指针
     size_t alen;                  // JSON 字段值长度
 
     // 1. 获取当前时间（F-Stack 微秒级接口）
     now_us = get_us_timeofday();
 
     // 2. 过滤非 depthUpdate 事件（只处理深度更新行情）
     p = lws_json_simple_find((const char *)in, len, "\"depthUpdate\"", &alen);
     if (!p)
         return LWSSSSRET_OK;  // 非目标事件，直接返回
 
     // 3. 解析事件时间戳 "E"（币安服务器推送时间，毫秒级）
     p = lws_json_simple_find((const char *)in, len, "\"E\":", &alen);
     if (!p) {
         lwsl_err("%s: 未找到 JSON 字段 \"E\"（事件时间戳）\n", __func__);
         return LWSSSSRET_OK;
     }
     lws_strnncpy(numbuf, p, alen, sizeof(numbuf) - 1);  // 复制字段值（避免溢出）
     // 计算延迟：本地时间（微秒） - 币安时间（毫秒 → 微秒）
     latency_us = now_us - ((uint64_t)atoll(numbuf) * LWS_US_PER_MS);
 
     // 4. 更新延迟统计
     if (latency_us < bin->e_lat_range.lowest)
         bin->e_lat_range.lowest = latency_us;
     if (latency_us > bin->e_lat_range.highest)
         bin->e_lat_range.highest = latency_us;
     bin->e_lat_range.sum += latency_us;
     bin->e_lat_range.samples++;
 
     // 5. 解析卖一价 "a"（JSON 路径："a":[[价格, 数量], ...]）
     p = lws_json_simple_find((const char *)in, len, "\"a\":[[\"", &alen);
     if (!p)
         return LWSSSSRET_OK;  // 无价格字段，直接返回
     lws_strnncpy(numbuf, p, alen, sizeof(numbuf) - 1);  // 复制价格字符串
     price = pennies(numbuf);  // 转换为分（整数）
 
     // 6. 更新价格统计
     if (price < bin->price_range.lowest)
         bin->price_range.lowest = price;
     if (price > bin->price_range.highest)
         bin->price_range.highest = price;
     bin->price_range.sum += price;
     bin->price_range.samples++;
 
     return LWSSSSRET_OK;  // 处理完成，继续接收下一条数据
 }
 
 
 // -------------------------- SS 状态回调（连接生命周期管理） --------------------------
 /**
  * SS 状态回调：处理连接状态变化（连接/断开/错误等）
  * @param userobj  用户数据（binance_t 实例）
  * @param h_src    状态源（内部使用）
  * @param state    当前 SS 状态（如 LWSSSCS_CONNECTED = 已连接）
  * @param ack      发送确认序号（内部使用）
  * @return         SS 状态码（LWSSSSRET_OK = 正常）
  */
 static lws_ss_state_return_t
 binance_state(void *userobj, void *h_src, lws_ss_constate_t state,
               lws_ss_tx_ordinal_t ack)
 {
     binance_t *bin = (binance_t *)userobj;
 
     // 输出当前状态（调试用）
     lwsl_ss_info(
         bin->ss,
         "SS 状态变化: %s, 确认序号: 0x%x",
         lws_ss_state_name(state),  // 状态名（如 "CONNECTED"）
         (unsigned int)ack
     );
 
     switch (state) {
         // 连接成功：初始化定时器和统计
         case LWSSSCS_CONNECTED:
             // 启动 1Hz 统计定时器
             lws_sul_schedule(
                 lws_ss_get_context(bin->ss),
                 0,
                 &bin->sul_hz,
                 sul_hz_cb,
                 LWS_US_PER_SEC
             );
             // 重置统计数据
             range_reset(&bin->e_lat_range);
             range_reset(&bin->price_range);
             return LWSSSSRET_OK;
 
         // 连接断开：取消定时器
         case LWSSSCS_DISCONNECTED:
             lws_sul_cancel(&bin->sul_hz);  // 停止 1Hz 统计
             break;
 
         // 其他状态（如连接中/错误）：无需特殊处理
         default:
             break;
     }
 
     return LWSSSSRET_OK;
 }
 
 
 // -------------------------- SS 信息结构体定义（绑定回调与用户数据） --------------------------
 // 定义 SS 协议信息：将回调函数与用户数据类型绑定
 LWS_SS_INFO("binance", binance_t)
     .rx        = binance_rx,    // 数据接收回调（核心行情解析）
     .state     = binance_state, // 状态变化回调（连接管理）
 ;