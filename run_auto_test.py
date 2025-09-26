#!/usr/bin/env python3
"""
自动运行测试的脚本，无需用户交互
"""

import subprocess
import time
import sys
import json
from datetime import datetime

def run_websocket_server():
    """在子进程中运行WebSocket服务器"""
    try:
        print("启动WebSocket服务器...")
        process = subprocess.Popen([
            sys.executable, "websocket_server.py"
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        # 等待服务器启动
        time.sleep(3)
        
        return process
    except Exception as e:
        print(f"启动WebSocket服务器失败: {e}")
        return None

def test_tcp_websocket_client():
    """测试TCP WebSocket客户端"""
    try:
        from tcp_websocket_client import WebSocketClient
        
        print("\n=== 开始测试TCP WebSocket客户端 ===")
        
        # 创建客户端
        client = WebSocketClient()
        
        # 连接测试
        print("1. 测试连接...")
        if not client.connect():
            print("❌ 连接失败")
            return False
        
        print("✅ 连接成功")
        
        # 发送测试消息
        print("\n2. 测试发送消息...")
        
        test_messages = [
            "Hello WebSocket Server!",
            json.dumps({"type": "ping"}),
            json.dumps({"type": "get_clients"}),
            json.dumps({
                "type": "chat",
                "message": "这是一条测试聊天消息",
                "timestamp": datetime.now().isoformat()
            })
        ]
        
        for i, message in enumerate(test_messages, 1):
            print(f"发送测试消息 {i}: {message}")
            
            if client.send_message(message):
                print("✅ 消息发送成功")
                
                # 接收响应
                response = client.receive_message()
                if response:
                    print(f"收到响应: {response[:100]}...")  # 只显示前100个字符
                else:
                    print("⚠️  未收到响应")
            else:
                print("❌ 消息发送失败")
            
            time.sleep(0.5)
        
        print("\n3. 测试完成，断开连接...")
        client.disconnect()
        print("✅ 测试成功完成")
        
        return True
        
    except Exception as e:
        print(f"❌ 测试过程中出错: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """主函数"""
    print("=== WebSocket自动测试 ===")
    
    # 启动服务器
    server_process = run_websocket_server()
    if not server_process:
        print("无法启动WebSocket服务器")
        return
    
    try:
        # 运行测试
        success = test_tcp_websocket_client()
        
        if success:
            print("\n🎉 所有测试通过!")
        else:
            print("\n❌ 测试失败")
            
    finally:
        # 停止服务器
        print("\n停止WebSocket服务器...")
        server_process.terminate()
        server_process.wait()
        print("服务器已停止")

if __name__ == "__main__":
    main()
