import asyncio
import websockets
import json
import sys
from datetime import datetime

async def receive_messages(websocket):
    """接收服务器消息的协程"""
    try:
        while True:
            message = await websocket.recv()
            try:
                data = json.loads(message)
                # 格式化输出不同类型的消息
                if data.get("type") == "chat":
                    print(f"\n[{data['timestamp']}] {data['user']}: {data['message']}")
                elif data.get("type") == "system":
                    print(f"\n[系统消息] {data['message']}")
                elif data.get("type") == "pong":
                    print(f"\n[服务器响应] Pong 收到 ({data['timestamp']})")
                else:
                    print(f"\n[收到消息] {json.dumps(data, indent=2)}")
            except json.JSONDecodeError:
                print(f"\n[收到原始消息] {message}")
            # 提示用户输入
            print("请输入消息 (输入 'quit' 退出，'ping' 发送心跳): ", end="", flush=True)
    except websockets.exceptions.ConnectionClosed:
        print("\n与服务器的连接已关闭")

async def send_messages(websocket, username):
    """发送消息的协程"""
    try:
        while True:
            message = input("请输入消息 (输入 'quit' 退出，'ping' 发送心跳): ")
            if message.lower() == 'quit':
                # 发送关闭连接请求
                close_msg = {
                    "type": "close",
                    "message": "客户端主动退出"
                }
                await websocket.send(json.dumps(close_msg))
                break
            elif message.lower() == 'ping':
                # 发送 ping 请求
                ping_msg = {
                    "type": "ping",
                    "timestamp": datetime.now().isoformat()
                }
                await websocket.send(json.dumps(ping_msg))
                print("已发送 Ping 请求")
            else:
                # 发送聊天消息
                chat_msg = {
                    "type": "chat",
                    "user": username,
                    "message": message,
                    "timestamp": datetime.now().isoformat()
                }
                await websocket.send(json.dumps(chat_msg))
    except Exception as e:
        print(f"发送消息出错: {e}")

async def websocket_client(username):
    """WebSocket 客户端主函数"""
    uri = "ws://localhost:8765"
    try:
        async with websockets.connect(uri) as websocket:
            print(f"已连接到 WebSocket 服务器: {uri}")
            print("可以开始发送消息了 (输入 'quit' 退出)")
            
            # 同时运行接收和发送协程
            receive_task = asyncio.create_task(receive_messages(websocket))
            send_task = asyncio.create_task(send_messages(websocket, username))
            
            # 等待任一任务结束
            done, pending = await asyncio.wait(
                [receive_task, send_task],
                return_when=asyncio.FIRST_COMPLETED
            )
            
            # 取消未完成的任务
            for task in pending:
                task.cancel()
                
    except ConnectionRefusedError:
        print("无法连接到服务器，请确保服务器已启动")
    except Exception as e:
        print(f"客户端出错: {e}")

if __name__ == "__main__":
    # 获取用户名（从命令行参数或默认值）
    username = sys.argv[1] if len(sys.argv) > 1 else f"用户{datetime.now().microsecond % 1000}"
    asyncio.run(websocket_client(username))
    