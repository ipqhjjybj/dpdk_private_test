#!/usr/bin/env python3
import pandas as pd
import numpy as np

def compare_latency_files():
    # 读取两个文件
    dpdk_file = "/home/ec2-user/binance_dpdk/latency.txt"
    socket_file = "/home/ec2-user/binance_socket/latency.txt"

    try:
        # 读取DPDK数据
        dpdk_df = pd.read_csv(dpdk_file)
        print(f"DPDK文件读取成功，共{len(dpdk_df)}条记录")

        # 读取Socket数据
        socket_df = pd.read_csv(socket_file)
        print(f"Socket文件读取成功，共{len(socket_df)}条记录")

        # 合并数据，找到相同的trade_id
        merged_df = pd.merge(dpdk_df, socket_df, on='trade_id', suffixes=('_dpdk', '_socket'))

        print(f"找到{len(merged_df)}个相同的trade_id")

        if len(merged_df) < 500:
            print(f"警告：只找到{len(merged_df)}个相同的trade_id，少于要求的500个")
        else:
            print(f"✓ 找到{len(merged_df)}个相同的trade_id，满足500个的要求")

        if len(merged_df) == 0:
            print("没有找到相同的trade_id，无法进行比较")
            return

        # 计算延迟差异
        merged_df['latency_diff'] = merged_df['latency_us_socket'] - merged_df['latency_us_dpdk']
        merged_df['dpdk_faster'] = merged_df['latency_diff'] > 0

        # 统计结果
        dpdk_wins = (merged_df['latency_diff'] > 0).sum()
        socket_wins = (merged_df['latency_diff'] < 0).sum()
        equal = (merged_df['latency_diff'] == 0).sum()

        print("\n=== 延迟对比结果 ===")
        print(f"DPDK更快的次数: {dpdk_wins} ({dpdk_wins/len(merged_df)*100:.1f}%)")
        print(f"Socket更快的次数: {socket_wins} ({socket_wins/len(merged_df)*100:.1f}%)")
        print(f"延迟相同的次数: {equal} ({equal/len(merged_df)*100:.1f}%)")

        print(f"\n=== 延迟统计 ===")
        print(f"DPDK平均延迟: {merged_df['latency_us_dpdk'].mean():.2f} us")
        print(f"Socket平均延迟: {merged_df['latency_us_socket'].mean():.2f} us")
        print(f"平均延迟差异: {merged_df['latency_diff'].mean():.2f} us (正值表示Socket更慢)")

        print(f"\n=== 中位数比较 ===")
        print(f"DPDK中位数延迟: {merged_df['latency_us_dpdk'].median():.2f} us")
        print(f"Socket中位数延迟: {merged_df['latency_us_socket'].median():.2f} us")
        print(f"中位数延迟差异: {merged_df['latency_diff'].median():.2f} us (正值表示Socket更慢)")

        print(f"\n=== 分位数统计 (DPDK) ===")
        print(f"MIN:  {merged_df['latency_us_dpdk'].min():.2f} us")
        print(f"P50:  {merged_df['latency_us_dpdk'].quantile(0.50):.2f} us")
        print(f"P95:  {merged_df['latency_us_dpdk'].quantile(0.95):.2f} us")
        print(f"P99:  {merged_df['latency_us_dpdk'].quantile(0.99):.2f} us")
        print(f"MAX:  {merged_df['latency_us_dpdk'].max():.2f} us")

        print(f"\n=== 分位数统计 (Socket) ===")
        print(f"MIN:  {merged_df['latency_us_socket'].min():.2f} us")
        print(f"P50:  {merged_df['latency_us_socket'].quantile(0.50):.2f} us")
        print(f"P95:  {merged_df['latency_us_socket'].quantile(0.95):.2f} us")
        print(f"P99:  {merged_df['latency_us_socket'].quantile(0.99):.2f} us")
        print(f"MAX:  {merged_df['latency_us_socket'].max():.2f} us")

        print(f"\n=== 延迟差异分位数 ===")
        print(f"MIN:  {merged_df['latency_diff'].min():.2f} us")
        print(f"P50:  {merged_df['latency_diff'].quantile(0.50):.2f} us")
        print(f"P95:  {merged_df['latency_diff'].quantile(0.95):.2f} us")
        print(f"P99:  {merged_df['latency_diff'].quantile(0.99):.2f} us")
        print(f"MAX:  {merged_df['latency_diff'].max():.2f} us")

        # 显示最大的几个差异
        print(f"\n=== 延迟差异最大的10个样本 ===")
        top_diff = merged_df.nlargest(10, 'latency_diff')[['trade_id', 'latency_us_dpdk', 'latency_us_socket', 'latency_diff']]
        print(top_diff.to_string(index=False))

        # 保存结果到文件
        output_file = "/home/ec2-user/latency_comparison.csv"
        merged_df.to_csv(output_file, index=False)
        print(f"\n详细对比结果已保存到: {output_file}")

        # 结论
        if dpdk_wins > socket_wins:
            print(f"\n🏆 结论: DPDK的延迟更低，在{len(merged_df)}个样本中有{dpdk_wins}次更快")
        elif socket_wins > dpdk_wins:
            print(f"\n🏆 结论: Socket的延迟更低，在{len(merged_df)}个样本中有{socket_wins}次更快")
        else:
            print(f"\n🤝 结论: 两种方法的延迟表现相当")

    except FileNotFoundError as e:
        print(f"文件未找到: {e}")
    except Exception as e:
        print(f"处理过程中出错: {e}")

if __name__ == "__main__":
    compare_latency_files()