import asyncio
import websockets
import json
from datetime import datetime

# 存储所有连接的客户端
connected_clients = set()

async def register_client(websocket):
    """注册新客户端"""
    connected_clients.add(websocket)
    print(f"新客户端连接，当前在线: {len(connected_clients)}")
    try:
        await websocket.wait_closed()
    finally:
        connected_clients.remove(websocket)
        print(f"客户端断开，当前在线: {len(connected_clients)}")

async def broadcast_message(message, sender=None):
    """向所有客户端广播消息（排除发送者）"""
    if not connected_clients:
        return
    # 确保消息是字符串格式
    if isinstance(message, dict):
        message = json.dumps(message)
    # 发送给所有连接的客户端
    for client in connected_clients:
        if client != sender:
            try:
                await client.send(message)
            except websockets.exceptions.ConnectionClosed:
                pass

async def handle_client(websocket):
    """处理客户端消息"""
    # 注册客户端
    asyncio.create_task(register_client(websocket))
    
    # 发送欢迎消息
    welcome_msg = {
        "type": "system",
        "message": "欢迎连接到 WebSocket 服务器",
        "timestamp": datetime.now().isoformat()
    }
    await websocket.send(json.dumps(welcome_msg))
    
    # 接收客户端消息
    try:
        async for message in websocket:
            print(f"收到消息: {message}")
            
            # 尝试解析 JSON 消息
            try:
                data = json.loads(message)
                # 处理不同类型的消息
                if data.get("type") == "chat":
                    # 构建聊天消息（添加时间戳和发送者标识）
                    chat_msg = {
                        "type": "chat",
                        "user": data.get("user", "匿名"),
                        "message": data.get("message", ""),
                        "timestamp": datetime.now().isoformat()
                    }
                    # 广播给所有客户端
                    await broadcast_message(chat_msg, sender=websocket)
                elif data.get("type") == "ping":
                    # 回复 pong
                    pong_msg = {
                        "type": "pong",
                        "timestamp": datetime.now().isoformat()
                    }
                    await websocket.send(json.dumps(pong_msg))
            except json.JSONDecodeError:
                # 非 JSON 消息直接广播
                await broadcast_message({
                    "type": "text",
                    "message": message,
                    "timestamp": datetime.now().isoformat()
                }, sender=websocket)
    except websockets.exceptions.ConnectionClosed:
        print("客户端连接已关闭")

async def start_server():
    """启动 WebSocket 服务器"""
    async with websockets.serve(handle_client, "localhost", 8765):
        print("WebSocket 服务器已启动，地址: ws://localhost:8765")
        await asyncio.Future()  # 保持服务器运行

if __name__ == "__main__":
    asyncio.run(start_server())
    