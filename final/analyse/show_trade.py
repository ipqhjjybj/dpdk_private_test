#!/usr/bin/env python3
"""
从解密的PCAP中提取并显示币安交易数据
"""

import subprocess
import json
import sys

def extract_trades(pcap_file, keylog_file):
    """使用tshark提取WebSocket交易数据"""

    cmd = [
        'tshark',
        '-r', pcap_file,
        '-o', f'tls.keylog_file:{keylog_file}',
        '-Y', 'websocket',
        '-T', 'fields',
        '-e', 'frame.number',
        '-e', 'frame.time_epoch',
        '-e', 'websocket.payload.text',
        '-E', 'separator=|'
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        # 即使有警告也继续处理（returncode可能非0但有输出）
        if not result.stdout:
            print(f"[!] 无输出数据", file=sys.stderr)
            if result.stderr:
                print(f"[!] tshark警告: {result.stderr[:200]}", file=sys.stderr)
            return

        lines = result.stdout.strip().split('\n')

        print(f"{'='*100}")
        print(f"币安BTCUSDT交易数据（从加密PCAP解密）")
        print(f"{'='*100}\n")

        trade_count = 0

        for line in lines:
            if not line:
                continue

            parts = line.split('|')
            if len(parts) < 3:
                continue

            frame_num = parts[0]
            frame_time = parts[1]
            payload_text = parts[2] if len(parts) > 2 else ''

            if not payload_text:
                continue

            # 解析可能包含多个JSON对象的行
            # 有些WebSocket帧包含多个交易
            json_objects = []

            # 尝试分割多个JSON对象
            if '},{' in payload_text:
                # 多个JSON对象
                parts = payload_text.split('},{')
                for i, part in enumerate(parts):
                    if i == 0:
                        part = part + '}'
                    elif i == len(parts) - 1:
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
                    timestamp = data.get('E', 'N/A')
                    is_buyer_maker = data.get('m', False)
                    side = 'SELL' if is_buyer_maker else 'BUY'

                    print(f"[{trade_count:4d}] Frame#{frame_num:4s} | "
                          f"TradeID: {str(trade_id):>12s} | "
                          f"Price: {str(price):>12s} | "
                          f"Qty: {str(quantity):>8s} | "
                          f"{side:4s} | "
                          f"Time: {str(timestamp)}")

        print(f"\n{'='*100}")
        print(f"总共 {trade_count} 条交易记录")
        print(f"{'='*100}")

    except subprocess.TimeoutExpired:
        print("[!] tshark执行超时", file=sys.stderr)
    except Exception as e:
        print(f"[!] 错误: {e}", file=sys.stderr)

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

    extract_trades(pcap_file, keylog_file)