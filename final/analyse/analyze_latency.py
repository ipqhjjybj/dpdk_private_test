"""
分析币安交易数据的网络延迟
对比交易所E时间戳与本地TCP包到达时间
"""

import subprocess
import json
import sys
from datetime import datetime

def extract_trades_with_latency(pcap_file, keylog_file):
    """使用tshark提取WebSocket交易数据并计算延迟"""

    cmd = [
        'tshark',
        '-r', pcap_file,
        '-o', f'tls.keylog_file:{keylog_file}',
        '-Y', 'websocket',
        '-T', 'fields',
        '-e', 'frame.number',
        '-e', 'frame.time_epoch',  # TCP包到达时间（本地时间戳）
        '-e', 'websocket.payload.text',
        '-E', 'separator=|'
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        if not result.stdout:
            print(f"[!] 无输出数据", file=sys.stderr)
            return

        lines = result.stdout.strip().split('\n')

        print(f"{'='*120}")
        print(f"币安BTCUSDT交易数据 - 网络延迟分析")
        print(f"{'='*120}")
        print(f"{'Cnt':>4s} | {'Frame':>5s} | {'TradeID':>12s} | {'Price':>12s} | {'Qty':>8s} | "
              f"{'Side':4s} | {'Exchange(E)':>17s} | {'TCPArrival':>17s} | {'Latency(ms)':>12s}")
        print(f"{'-'*120}")

        trade_count = 0
        latencies = []

        for line in lines:
            if not line:
                continue

            parts = line.split('|')
            if len(parts) < 3:
                continue

            frame_num = parts[0]
            frame_time_epoch = parts[1]  # TCP包到达时间（秒，带小数）
            payload_text = parts[2] if len(parts) > 2 else ''

            if not payload_text or not frame_time_epoch:
                continue

            # TCP包到达时间（转换为毫秒）
            try:
                tcp_arrival_ms = float(frame_time_epoch) * 1000.0
            except:
                continue

            # 解析可能包含多个JSON对象的行
            json_objects = []

            if '},{' in payload_text:
                # 多个JSON对象
                parts_json = payload_text.split('},{')
                for i, part in enumerate(parts_json):
                    if i == 0:
                        part = part + '}'
                    elif i == len(parts_json) - 1:
                        part = '{' + part
                    else:
                        part = '{' + part + '}'
                    try:
                        json_objects.append(json.loads(part))
                    except:
                        pass
            else:
                # 单个JSON对象
                try:
                    json_objects.append(json.loads(payload_text))
                except:
                    pass

            # 显示每个交易
            for obj in json_objects:
                if 'data' in obj:
                    trade_count += 1
                    data = obj['data']

                    trade_id = data.get('t', 'N/A')
                    price = data.get('p', 'N/A')
                    quantity = data.get('q', 'N/A')
                    exchange_timestamp_ms = data.get('E', None)  # 交易所E时间戳（毫秒）
                    is_buyer_maker = data.get('m', False)
                    side = 'SELL' if is_buyer_maker else 'BUY'

                    if exchange_timestamp_ms is None:
                        continue

                    # 计算延迟（TCP到达时间 - 交易所时间戳）
                    # 正值表示TCP包到达晚于交易所时间（正常网络延迟）
                    # 负值表示本地时钟比交易所快
                    latency_ms = tcp_arrival_ms - exchange_timestamp_ms

                    latencies.append(latency_ms)

                    # 格式化时间戳显示
                    exchange_time_str = f"{exchange_timestamp_ms:.3f}"
                    tcp_time_str = f"{tcp_arrival_ms:.3f}"

                    # 延迟显示（带颜色标记）
                    if latency_ms < 0:
                        latency_str = f"{latency_ms:>11.3f}*"  # 负延迟标记*
                    else:
                        latency_str = f"{latency_ms:>12.3f}"

                    print(f"{trade_count:4d} | {frame_num:>5s} | {str(trade_id):>12s} | "
                          f"{str(price):>12s} | {str(quantity):>8s} | "
                          f"{side:4s} | {exchange_time_str:>17s} | {tcp_time_str:>17s} | {latency_str}")

        # 统计信息
        if latencies:
            avg_latency = sum(latencies) / len(latencies)
            min_latency = min(latencies)
            max_latency = max(latencies)

            # 计算正延迟的统计（排除负值）
            positive_latencies = [l for l in latencies if l >= 0]
            if positive_latencies:
                avg_positive = sum(positive_latencies) / len(positive_latencies)
                min_positive = min(positive_latencies)
                max_positive = max(positive_latencies)
            else:
                avg_positive = min_positive = max_positive = 0

            print(f"\n{'='*120}")
            print(f"延迟统计（总共 {trade_count} 条交易）")
            print(f"{'='*120}")
            print(f"所有延迟:")
            print(f"  平均延迟: {avg_latency:>10.3f} ms")
            print(f"  最小延迟: {min_latency:>10.3f} ms")
            print(f"  最大延迟: {max_latency:>10.3f} ms")
            print(f"  抖动范围: {max_latency - min_latency:>10.3f} ms")

            if positive_latencies:
                print(f"\n仅正延迟 ({len(positive_latencies)} 条):")
                print(f"  平均延迟: {avg_positive:>10.3f} ms")
                print(f"  最小延迟: {min_positive:>10.3f} ms")
                print(f"  最大延迟: {max_positive:>10.3f} ms")

            negative_count = len([l for l in latencies if l < 0])
            if negative_count > 0:
                print(f"\n注意: {negative_count} 条记录显示负延迟（标记*），可能是本地时钟不同步")

            print(f"\n说明:")
            print(f"  - Exchange(E): 币安交易所事件时间戳（毫秒）")
            print(f"  - TCPArrival: 本地收到TCP包的时间戳（毫秒）")
            print(f"  - Latency: TCP到达时间 - 交易所时间 = 网络传输延迟")
            print(f"  - 正值: 正常网络延迟")
            print(f"  - 负值*: 可能时钟不同步或交易所时间戳更新延迟")
            print(f"{'='*120}")

    except subprocess.TimeoutExpired:
        print("[!] tshark执行超时", file=sys.stderr)
    except Exception as e:
        print(f"[!] 错误: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    pcap_file = '/tmp/cpu0_0.pcap'
    keylog_file = '/home/ec2-user/binance_dpdk/sslkeylog.txt'

    import os
    if not os.path.exists(pcap_file):
        print(f"[!] PCAP文件不存在: {pcap_file}")
        sys.exit(1)

    if not os.path.exists(keylog_file):
        print(f"[!] 密钥文件不存在: {keylog_file}")
        sys.exit(1)

    extract_trades_with_latency(pcap_file, keylog_file)