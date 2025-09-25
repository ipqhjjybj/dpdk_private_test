import socket

def start_client(host='127.0.0.1', port=8080):
    """启动Socket客户端"""
    # 创建TCP socket对象
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        # 连接服务器
        client_socket.connect((host, port))
        print(f"已连接到服务器 {host}:{port}")
        
        while True:
            # 输入要发送的消息
            message = input("请输入要发送的消息(输入'quit'退出): ")
            
            if message.lower() == 'quit':
                break
                
            # 发送消息到服务器
            client_socket.sendall(message.encode('utf-8'))
            
            # 接收服务器回复
            response = client_socket.recv(1024)
            if not response:
                print("服务器已断开连接")
                break
                
            print(f"服务器回复: {response.decode('utf-8')}")
            
    except Exception as e:
        print(f"客户端错误: {e}")
    finally:
        client_socket.close()
        print("连接已关闭")

if __name__ == "__main__":
    start_client()

