#!/usr/bin/env python3
import sys
import numpy as np

def analyze_latency(filename):
    latencies = []

    # Read latency data from file
    with open(filename, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('trade_id'):
                continue
            parts = line.split(',')
            if len(parts) == 2:
                latency = float(parts[1])
                latencies.append(latency)

    if not latencies:
        print("No latency data found")
        return

    latencies = np.array(latencies)

    # Calculate statistics
    min_val = np.min(latencies)
    max_val = np.max(latencies)
    mean_val = np.mean(latencies)
    median_val = np.median(latencies)
    p50 = np.percentile(latencies, 50)
    p95 = np.percentile(latencies, 95)
    p99 = np.percentile(latencies, 99)
    p999 = np.percentile(latencies, 99.9)

    # Print results
    print(f"Latency Analysis (microseconds)")
    print(f"=" * 40)
    print(f"Total samples: {len(latencies)}")
    print(f"Min:           {min_val:.2f}")
    print(f"Max:           {max_val:.2f}")
    print(f"Mean:          {mean_val:.2f}")
    print(f"Median (P50):  {median_val:.2f}")
    print(f"P95:           {p95:.2f}")
    print(f"P99:           {p99:.2f}")
    print(f"P99.9:         {p999:.2f}")

if __name__ == "__main__":
    filename = sys.argv[1] if len(sys.argv) > 1 else "latency.txt"
    analyze_latency(filename)