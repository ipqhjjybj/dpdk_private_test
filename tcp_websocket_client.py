#!/usr/bin/env python3
"""
TCP客户端连接WebSocket服务器
通过原始TCP socket实现WebSocket协议握手和通信
"""

import socket
import base64
import hashlib
import struct
import json
import threading
import time
from datetime import datetime

class WebSocketClient:
    """WebSocket客户端实现，使用原始TCP socket"""
    
    WEBSOCKET_MAGIC_STRING = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    
    def __init__(self, host="localhost", port=8765):
        self.host = host
        self.port = port
        self.socket = None
        self.connected = False
        self.running = False
        
    def generate_websocket_key(self):
        """生成WebSocket握手密钥"""
        import random
        key = base64.b64encode(bytes([random.randint(0, 255) for _ in range(16)])).decode()
        return key
    
    def create_handshake_request(self, websocket_key):
        """创建WebSocket握手请求"""
        request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {websocket_key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"User-Agent: TCP-WebSocket-Client/1.0\r\n"
            f"\r\n"
        )
        return request.encode('utf-8')
    
    def verify_handshake_response(self, response, websocket_key):
        """验证WebSocket握手响应"""
        try:
            response_str = response.decode('utf-8')
            lines = response_str.split('\r\n')
            
            # 检查状态行
            if not lines[0].startswith('HTTP/1.1 101'):
                print(f"握手失败，状态行: {lines[0]}")
                return False
            
            # 计算期望的Accept值
            accept_key = base64.b64encode(
                hashlib.sha1((websocket_key + self.WEBSOCKET_MAGIC_STRING).encode()).digest()
            ).decode()
            
            # 检查Accept头
            for line in lines[1:]:
                if line.lower().startswith('sec-websocket-accept:'):
                    server_accept = line.split(':', 1)[1].strip()
                    if server_accept == accept_key:
                        return True
                    else:
                        print(f"Accept密钥不匹配，期望: {accept_key}, 收到: {server_accept}")
                        return False
            
            print("响应中未找到Sec-WebSocket-Accept头")
            return False
            
        except Exception as e:
            print(f"验证握手响应时出错: {e}")
            return False
    
    def connect(self):
        """连接到WebSocket服务器"""
        try:
            # 创建TCP socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(10)
            
            print(f"正在连接到 {self.host}:{self.port}...")
            self.socket.connect((self.host, self.port))
            
            # 生成WebSocket密钥
            websocket_key = self.generate_websocket_key()
            print(f"WebSocket密钥: {websocket_key}")
            
            # 发送握手请求
            handshake_request = self.create_handshake_request(websocket_key)
            print("发送握手请求...")
            print(handshake_request.decode('utf-8'))
            
            self.socket.send(handshake_request)
            
            # 接收握手响应
            response = self.socket.recv(4096)
            print("收到握手响应:")
            print(response.decode('utf-8'))
            
            # 验证握手响应
            if self.verify_handshake_response(response, websocket_key):
                print("WebSocket握手成功!")
                self.connected = True
                self.socket.settimeout(None)  # 移除超时限制
                return True
            else:
                print("WebSocket握手失败!")
                return False
                
        except Exception as e:
            print(f"连接失败: {e}")
            return False
    
    def create_websocket_frame(self, payload, opcode=1):
        """创建WebSocket数据帧"""
        # opcode: 1 = 文本帧, 2 = 二进制帧, 8 = 关闭帧, 9 = ping帧, 10 = pong帧
        
        payload_bytes = payload.encode('utf-8') if isinstance(payload, str) else payload
        payload_length = len(payload_bytes)
        
        # 第一个字节: FIN(1) + RSV(000) + OPCODE(4位)
        first_byte = 0x80 | opcode  # FIN=1, opcode
        
        # 第二个字节和后续长度字节
        if payload_length < 126:
            length_bytes = struct.pack('!B', 0x80 | payload_length)  # MASK=1, length
        elif payload_length < 65536:
            length_bytes = struct.pack('!BH', 0x80 | 126, payload_length)  # MASK=1, 126, length
        else:
            length_bytes = struct.pack('!BQ', 0x80 | 127, payload_length)  # MASK=1, 127, length
        
        # 生成掩码密钥（客户端必须使用掩码）
        import random
        mask_key = struct.pack('!I', random.randint(0, 0xFFFFFFFF))
        
        # 应用掩码
        masked_payload = bytearray(payload_bytes)
        for i in range(len(masked_payload)):
            masked_payload[i] ^= mask_key[i % 4]
        
        # 组装帧
        frame = struct.pack('!B', first_byte) + length_bytes + mask_key + bytes(masked_payload)
        return frame
    
    def parse_websocket_frame(self, data):
        """解析WebSocket数据帧"""
        if len(data) < 2:
            return None, None
        
        # 第一个字节
        first_byte = data[0]
        fin = (first_byte & 0x80) != 0
        opcode = first_byte & 0x0F
        
        # 第二个字节
        second_byte = data[1]
        masked = (second_byte & 0x80) != 0
        payload_length = second_byte & 0x7F
        
        offset = 2
        
        # 扩展长度
        if payload_length == 126:
            if len(data) < offset + 2:
                return None, None
            payload_length = struct.unpack('!H', data[offset:offset+2])[0]
            offset += 2
        elif payload_length == 127:
            if len(data) < offset + 8:
                return None, None
            payload_length = struct.unpack('!Q', data[offset:offset+8])[0]
            offset += 8
        
        # 掩码密钥
        if masked:
            if len(data) < offset + 4:
                return None, None
            mask_key = data[offset:offset+4]
            offset += 4
        
        # 负载数据
        if len(data) < offset + payload_length:
            return None, None
        
        payload = data[offset:offset+payload_length]
        
        # 如果有掩码，解除掩码
        if masked:
            unmasked_payload = bytearray(payload)
            for i in range(len(unmasked_payload)):
                unmasked_payload[i] ^= mask_key[i % 4]
            payload = bytes(unmasked_payload)
        
        return opcode, payload
    
    def send_message(self, message):
        """发送消息到WebSocket服务器"""
        if not self.connected:
            print("未连接到服务器")
            return False
        
        try:
            frame = self.create_websocket_frame(message)
            self.socket.send(frame)
            return True
        except Exception as e:
            print(f"发送消息失败: {e}")
            return False
    
    def receive_message(self):
        """接收WebSocket消息"""
        if not self.connected:
            return None
        
        try:
            # 接收数据
            data = self.socket.recv(4096)
            if not data:
                return None
            
            opcode, payload = self.parse_websocket_frame(data)
            
            if opcode == 1:  # 文本帧
                return payload.decode('utf-8')
            elif opcode == 2:  # 二进制帧
                return payload
            elif opcode == 8:  # 关闭帧
                print("服务器发送关闭帧")
                return None
            elif opcode == 9:  # ping帧
                # 发送pong响应
                pong_frame = self.create_websocket_frame(payload, opcode=10)
                self.socket.send(pong_frame)
                return "PING"
            elif opcode == 10:  # pong帧
                return "PONG"
            else:
                print(f"收到未知opcode: {opcode}")
                return None
                
        except Exception as e:
            print(f"接收消息失败: {e}")
            return None
    
    def listen_for_messages(self):
        """监听服务器消息的线程函数"""
        while self.running and self.connected:
            try:
                message = self.receive_message()
                if message is None:
                    break
                
                if message == "PING":
                    print("收到PING，已回复PONG")
                    continue
                elif message == "PONG":
                    print("收到PONG响应")
                    continue
                
                print(f"\n[{datetime.now().strftime('%H:%M:%S')}] 服务器消息: {message}")
                print("请输入消息 (输入'quit'退出): ", end='', flush=True)
                
            except Exception as e:
                if self.running:
                    print(f"监听消息时出错: {e}")
                break
    
    def start_interactive_session(self):
        """启动交互式会话"""
        if not self.connected:
            print("请先连接到服务器")
            return
        
        self.running = True
        
        # 启动消息监听线程
        listen_thread = threading.Thread(target=self.listen_for_messages)
        listen_thread.daemon = True
        listen_thread.start()
        
        print("\n=== WebSocket交互式会话开始 ===")
        print("输入消息发送到服务器，输入'quit'退出")
        print("支持发送JSON格式的消息，例如: {\"type\":\"ping\"}")
        
        try:
            while self.running:
                message = input("请输入消息 (输入'quit'退出): ")
                
                if message.lower() == 'quit':
                    break
                
                if not message.strip():
                    continue
                
                # 尝试解析为JSON，如果失败则作为普通文本发送
                try:
                    json.loads(message)  # 验证是否为有效JSON
                    print(f"发送JSON消息: {message}")
                except json.JSONDecodeError:
                    # 包装为聊天消息
                    chat_message = {
                        "type": "chat",
                        "message": message,
                        "timestamp": datetime.now().isoformat()
                    }
                    message = json.dumps(chat_message, ensure_ascii=False)
                    print(f"发送聊天消息: {message}")
                
                if not self.send_message(message):
                    print("发送失败，可能连接已断开")
                    break
                
        except KeyboardInterrupt:
            print("\n收到中断信号，正在退出...")
        finally:
            self.running = False
            self.disconnect()
    
    def disconnect(self):
        """断开连接"""
        self.running = False
        if self.connected and self.socket:
            try:
                # 发送关闭帧
                close_frame = self.create_websocket_frame("", opcode=8)
                self.socket.send(close_frame)
            except:
                pass
        
        if self.socket:
            self.socket.close()
        
        self.connected = False
        print("连接已断开")

def main():
    """主函数"""
    print("=== TCP WebSocket客户端 ===")
    
    # 创建客户端实例
    client = WebSocketClient()
    
    try:
        # 连接到服务器
        if client.connect():
            # 开始交互式会话
            client.start_interactive_session()
        else:
            print("无法连接到WebSocket服务器")
    
    except Exception as e:
        print(f"程序出错: {e}")
    finally:
        client.disconnect()

if __name__ == "__main__":
    main()
