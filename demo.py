#!/usr/bin/env python3
"""
WebSocket连接演示脚本
展示如何使用TCP socket连接WebSocket服务器
"""

import time
import json
from tcp_websocket_client import WebSocketClient

def demo_websocket_connection():
    """演示WebSocket连接"""
    print("=== WebSocket TCP连接演示 ===\n")
    
    # 创建客户端
    client = WebSocketClient()
    
    try:
        # 连接到服务器
        print("步骤1: 连接到WebSocket服务器")
        if not client.connect():
            print("❌ 无法连接到服务器，请确保WebSocket服务器正在运行")
            print("   运行命令: python websocket_server.py")
            return
        
        print("✅ 成功连接到WebSocket服务器\n")
        
        # 演示不同类型的消息
        demo_messages = [
            {
                "description": "发送普通文本消息",
                "message": "Hello, WebSocket Server!"
            },
            {
                "description": "发送Ping消息",
                "message": json.dumps({"type": "ping"})
            },
            {
                "description": "获取在线客户端数量",
                "message": json.dumps({"type": "get_clients"})
            },
            {
                "description": "发送聊天消息",
                "message": json.dumps({
                    "type": "chat",
                    "message": "这是一条来自TCP客户端的聊天消息",
                    "timestamp": "2025-09-25T12:00:00"
                })
            }
        ]
        
        for i, demo in enumerate(demo_messages, 2):
            print(f"步骤{i}: {demo['description']}")
            print(f"发送: {demo['message']}")
            
            # 发送消息
            if client.send_message(demo['message']):
                print("✅ 消息发送成功")
                
                # 接收响应
                response = client.receive_message()
                if response:
                    try:
                        # 尝试格式化JSON响应
                        response_obj = json.loads(response)
                        print(f"收到响应: {json.dumps(response_obj, ensure_ascii=False, indent=2)}")
                    except json.JSONDecodeError:
                        print(f"收到响应: {response}")
                else:
                    print("⚠️  未收到响应")
            else:
                print("❌ 消息发送失败")
            
            print()  # 空行分隔
            time.sleep(1)
        
        print("步骤6: 断开连接")
        client.disconnect()
        print("✅ 连接已断开")
        
        print("\n🎉 演示完成!")
        print("\n说明:")
        print("- 本演示使用原生TCP socket实现WebSocket协议")
        print("- 包含完整的握手过程和数据帧处理")
        print("- 支持文本消息、JSON消息和控制帧")
        print("- 客户端自动处理掩码和帧格式")
        
    except Exception as e:
        print(f"❌ 演示过程中出错: {e}")
        client.disconnect()

def main():
    """主函数"""
    print("WebSocket TCP连接演示")
    print("=" * 50)
    print("本演示将展示如何使用TCP socket连接WebSocket服务器")
    print("请确保WebSocket服务器正在运行 (python websocket_server.py)")
    print()
    
    input("按回车键开始演示...")
    print()
    
    demo_websocket_connection()

if __name__ == "__main__":
    main()
