# DPDK Private Test - WebSocket与TCP Socket通信示例

这个项目演示了如何使用TCP socket连接WebSocket服务器，包含完整的WebSocket协议实现和测试工具。

## 项目结构

```
dpdk_private_test/
├── README.md                    # 项目文档
├── requirements.txt             # Python依赖包
├── socket_client.py            # 原始TCP客户端示例
├── socket_server.py            # 原始TCP服务器示例
├── websocket_server.py         # WebSocket服务器实现
├── tcp_websocket_client.py     # TCP客户端连接WebSocket服务器
└── test_websocket_connection.py # 测试工具
```

## 功能特性

### WebSocket服务器 (`websocket_server.py`)
- 支持多客户端并发连接
- JSON消息处理和广播
- 心跳检测机制
- 用户加入/离开通知
- 支持ping/pong、聊天、客户端列表等消息类型

### TCP WebSocket客户端 (`tcp_websocket_client.py`)
- 原生TCP socket实现WebSocket协议
- 完整的WebSocket握手过程
- 数据帧的编码和解码
- 支持掩码处理（客户端要求）
- 交互式聊天界面

### 测试工具 (`test_websocket_connection.py`)
- 自动化测试模式
- 交互式测试模式
- 服务器独立运行模式

## 安装依赖

```bash
pip install -r requirements.txt
```

## 使用方法

### 方法1: 使用测试工具（推荐）

```bash
python test_websocket_connection.py
```

选择测试模式：
1. **自动测试**: 自动启动服务器并运行预定义的测试用例
2. **交互式测试**: 启动服务器并提供交互式聊天界面
3. **仅启动服务器**: 只启动WebSocket服务器，可以用其他客户端连接

### 方法2: 分别启动服务器和客户端

**启动WebSocket服务器:**
```bash
python websocket_server.py
```
服务器将在 `ws://localhost:8765` 启动

**启动TCP WebSocket客户端:**
```bash
python tcp_websocket_client.py
```

### 方法3: 使用原始TCP通信

**启动TCP服务器:**
```bash
python socket_server.py
```

**启动TCP客户端:**
```bash
python socket_client.py
```

## 消息格式

### 支持的消息类型

1. **Ping消息**:
   ```json
   {"type": "ping"}
   ```

2. **聊天消息**:
   ```json
   {
     "type": "chat",
     "message": "你的消息内容",
     "timestamp": "2024-01-01T12:00:00"
   }
   ```

3. **获取客户端列表**:
   ```json
   {"type": "get_clients"}
   ```

4. **普通文本消息**:
   直接输入文本，会自动包装为聊天消息

## 技术实现细节

### WebSocket协议实现

本项目完全使用原生TCP socket实现WebSocket协议，包括：

1. **握手过程**:
   - HTTP升级请求
   - Sec-WebSocket-Key生成和验证
   - SHA-1哈希计算

2. **数据帧格式**:
   - 支持文本帧和二进制帧
   - 掩码处理（客户端到服务器）
   - 长度编码（7位、16位、64位）

3. **控制帧**:
   - Ping/Pong心跳检测
   - 连接关闭处理

### 服务器特性

- **异步处理**: 使用asyncio支持高并发
- **广播消息**: 向所有连接的客户端广播消息
- **用户管理**: 跟踪用户连接状态
- **错误处理**: 优雅处理连接断开和异常

## 测试示例

### 自动测试输出示例:
```
=== 开始测试TCP WebSocket客户端 ===
1. 测试连接...
正在连接到 localhost:8765...
WebSocket密钥: dGhlIHNhbXBsZSBub25jZQ==
发送握手请求...
✅ 连接成功

2. 测试发送消息...
发送测试消息 1: Hello WebSocket Server!
✅ 消息发送成功
收到响应: {"type": "echo", "original_message": "Hello WebSocket Server!", ...}

🎉 所有测试通过!
```

### 交互式测试示例:
```
=== WebSocket交互式会话开始 ===
输入消息发送到服务器，输入'quit'退出
请输入消息 (输入'quit'退出): Hello World!
发送聊天消息: {"type":"chat","message":"Hello World!","timestamp":"2024-01-01T12:00:00"}

[12:00:01] 服务器消息: {"type": "chat_response", "original_message": "Hello World!", ...}
```

## 注意事项

1. **防火墙**: 确保端口8765未被防火墙阻止
2. **依赖**: 需要Python 3.7+和websockets库
3. **网络**: 默认监听localhost，如需外部访问请修改host配置
4. **并发**: WebSocket服务器支持多客户端，TCP服务器使用线程处理

## 故障排除

### 常见问题:

1. **连接被拒绝**: 确保WebSocket服务器已启动
2. **握手失败**: 检查WebSocket协议实现和密钥计算
3. **消息乱码**: 确保使用UTF-8编码
4. **连接断开**: 检查网络稳定性和心跳机制

### 调试建议:

1. 查看服务器日志输出
2. 使用网络抓包工具分析协议
3. 检查防火墙和网络配置
4. 验证消息格式和编码

## 扩展功能

可以基于此项目扩展以下功能：
- SSL/TLS加密支持
- 用户认证和授权
- 消息持久化存储
- 负载均衡和集群支持
- 更多消息类型和协议扩展
