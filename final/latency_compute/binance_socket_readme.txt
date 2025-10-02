● 根据修改后的代码，现在记录两种延迟：

  1. 端到端延迟 (latency.txt)

  - 起点: 服务器生成事件的时间 (event_timestamp)
  - 终点: 应用层处理时间 (current_time_us)
  - 包含: 服务器处理 + 网络传输 + 网卡接收 + 内核网络栈 + TLS解密 + WebSocket解析 + 应用处理

  2. 内核到应用层延迟 (kernel_latency.txt)

  - 起点: TCP包到达网卡的时间 (kernel_time_us - 通过 SO_TIMESTAMP 获取)
  - 终点: 应用层处理时间 (current_time_us)
  - 包含: 内核网络栈处理 + TLS解密 + WebSocket帧解析 + 应用层处理

  关键代码位置:
  - binance_ws_client.c:560 - 获取内核时间戳
  - binance_ws_client.c:601 - 获取应用层时间戳
  - binance_ws_client.c:625 - 计算内核延迟 = 应用层时间 - 内核时间

  所以 kernel_latency 就是你要的"TCP包从网卡到应用程序"的延迟。

