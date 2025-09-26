# F-Stack + mbedTLS 币安WebSocket客户端

这是一个使用F-Stack和mbedTLS实现的极简币安WebSocket行情客户端，用于接收BTC/USDT实时行情数据。

## 功能特点

- **高性能网络栈**: 使用F-Stack绕过内核网络栈，提供极高的网络性能
- **安全连接**: 使用mbedTLS实现TLS/SSL加密连接
- **极简设计**: 代码简洁，易于理解和修改
- **实时行情**: 接收币安WebSocket实时价格数据
- **资源管理**: 完善的资源清理和错误处理

## 系统要求

### 硬件要求
- x86_64架构CPU
- 至少2GB内存
- 支持DPDK的网卡

### 软件要求
- Linux系统 (Ubuntu 18.04+ 或 CentOS 7+)
- GCC 7.0+
- F-Stack 1.21+
- DPDK 20.11+
- mbedTLS 3.0+

## 安装依赖

### 1. 安装DPDK
```bash
# 下载DPDK
wget http://fast.dpdk.org/rel/dpdk-20.11.tar.xz
tar xf dpdk-20.11.tar.xz
cd dpdk-20.11

# 编译安装
meson build
cd build
ninja
sudo ninja install
```

### 2. 安装F-Stack
```bash
# 下载F-Stack
git clone https://github.com/F-Stack/f-stack.git
cd f-stack

# 编译安装
make
sudo make install
```

### 3. 安装mbedTLS
```bash
# 下载mbedTLS
wget https://github.com/Mbed-TLS/mbedtls/archive/v3.4.0.tar.gz
tar xf v3.4.0.tar.gz
cd mbedtls-3.4.0

# 编译安装
make
sudo make install
```

## 编译程序

### 1. 检查依赖
```bash
make check-deps
```

### 2. 编译
```bash
# 默认编译
make

# 或指定路径编译
make FSTACK_DIR=/opt/fstack MBEDTLS_DIR=/opt/mbedtls

# 调试版本
make debug-build

# 发布版本  
make release-build
```

### 3. 查看编译信息
```bash
make debug
```

## 系统配置

### 1. 配置Huge Pages
```bash
# 设置2MB huge pages
echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

# 或在启动参数中添加
# hugepagesz=2M hugepages=1024
```

### 2. 绑定网卡到DPDK驱动
```bash
# 查看网卡状态
dpdk-devbind.py --status

# 绑定网卡（替换为实际网卡PCI地址）
sudo dpdk-devbind.py --bind=uio_pci_generic 0000:01:00.0
```

### 3. 配置F-Stack
编辑 `f-stack.conf` 文件，根据实际网络环境调整：
- IP地址和网关
- CPU核心分配
- 内存配置

## 运行程序

### 1. 基本运行
```bash
sudo ./binance_ws_client --conf=f-stack.conf
```

### 2. 指定配置文件
```bash
sudo ./binance_ws_client --conf=/path/to/your/config.conf
```

### 3. 查看帮助
```bash
make help
```

## 输出示例

程序成功运行时会显示类似以下输出：

```
F-Stack + mbedTLS 币安WebSocket客户端
=====================================
正在初始化F-Stack...
F-Stack初始化成功
正在初始化SSL...
正在创建socket连接...
正在连接到 stream.binance.com:9443...
TCP连接成功
正在进行SSL握手...
SSL握手成功
发送WebSocket握手请求...
WebSocket握手成功
开始接收行情数据...

=== 币安行情数据 ===
交易对: BTCUSDT
当前价格: 43250.50 USDT
24h涨跌幅: +2.45%
24h成交量: 15234.56 BTC
==================
```

## 代码结构

```
ff-websockets-claude-code/
├── binance_ws_client.c    # 主程序源码
├── Makefile              # 编译脚本
├── f-stack.conf          # F-Stack配置文件
└── README.md            # 本文档
```

### 主要函数说明

- `main()`: 程序入口，初始化F-Stack
- `fstack_loop()`: F-Stack主循环，处理网络连接
- `fstack_net_send/recv()`: mbedTLS网络适配函数
- `parse_websocket_frame()`: WebSocket帧解析
- `process_ticker_data()`: 行情数据处理

## 自定义修改

### 1. 更换交易对
修改 `BINANCE_PATH` 宏定义：
```c
#define BINANCE_PATH "/ws/ethusdt@ticker"  // 改为ETH/USDT
```

### 2. 添加更多数据处理
在 `process_ticker_data()` 函数中添加更多字段解析：
```c
// 解析更多字段
char *high = strstr(json_str, "\"h\":\"");
char *low = strstr(json_str, "\"l\":\"");
```

### 3. 修改网络配置
编辑 `f-stack.conf` 文件调整网络参数。

## 故障排除

### 常见问题

1. **编译错误**: 检查依赖库是否正确安装
   ```bash
   make check-deps
   ```

2. **运行时错误**: 检查系统配置
   - Huge pages是否配置
   - 网卡是否正确绑定
   - 权限是否足够（需要root权限）

3. **连接失败**: 检查网络配置
   - 防火墙设置
   - DNS解析
   - 网络连通性

### 调试方法

1. **启用调试输出**:
   ```bash
   make debug-build
   ```

2. **使用GDB调试**:
   ```bash
   sudo gdb ./binance_ws_client
   ```

3. **查看系统日志**:
   ```bash
   dmesg | tail -20
   ```

## 性能优化

### 1. CPU绑定
在配置文件中设置合适的CPU核心：
```ini
lcore_mask=0x3  # 使用前两个核心
```

### 2. 内存优化
调整内存分配：
```ini
memory=2048  # 增加到2GB
```

### 3. 网卡队列
配置多队列网卡：
```ini
nb_ports=1
```

## 扩展功能

基于此代码可以扩展以下功能：

1. **多交易对支持**: 同时订阅多个交易对
2. **数据存储**: 将行情数据存储到数据库
3. **策略交易**: 基于行情数据实现交易策略
4. **监控告警**: 添加价格监控和告警功能
5. **负载均衡**: 支持多个WebSocket连接

## 许可证

本项目基于MIT许可证开源。

## 支持

如有问题或建议，请提交Issue或Pull Request。
