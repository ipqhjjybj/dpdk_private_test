import socket
import threading

def handle_client(client_socket, client_address):
    """处理客户端连接的函数"""
    print(f"新连接: {client_address}")
    
    try:
        # 接收客户端发送的数据
        while True:
            data = client_socket.recv(1024)  # 一次最多接收1024字节
            if not data:
                print(f"客户端 {client_address} 断开连接")
                break
                
            message = data.decode('utf-8')
            print(f"收到来自 {client_address} 的消息: {message}")
            
            # 回复客户端
            response = f"服务器已收到: {message}"
            client_socket.sendall(response.encode('utf-8'))
            
    except Exception as e:
        print(f"与 {client_address} 通信出错: {e}")
    finally:
        client_socket.close()

def start_server(host='0.0.0.0', port=8080):
    """启动Socket服务器"""
    # 创建TCP socket对象
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        # 绑定地址和端口
        server_socket.bind((host, port))
        print(f"服务器绑定到 {host}:{port}")
        
        # 开始监听，最多允许5个排队连接
        server_socket.listen(5)
        print("服务器开始监听...")
        
        while True:
            # 接受客户端连接
            client_socket, client_address = server_socket.accept()
            
            # 创建线程处理客户端，主线程继续等待新连接
            client_thread = threading.Thread(
                target=handle_client,
                args=(client_socket, client_address)
            )
            client_thread.start()
            
    except Exception as e:
        print(f"服务器错误: {e}")
    finally:
        server_socket.close()

if __name__ == "__main__":
    start_server()

