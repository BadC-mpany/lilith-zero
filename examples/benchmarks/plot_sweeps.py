#!/usr/bin/env python3
"""
Plots parameter sweep results for Lilith-Zero.
Generates line charts showing how latency, throughput, and error rates depend on concurrency (VUs).
"""

import glob
import json
import os
import re
import matplotlib.pyplot as plt

def parse_sweep_files():
    results_dir = "examples/benchmarks/results"
    pattern = os.path.join(results_dir, "sweep_vu*_*.json")
    files = glob.glob(pattern)

    data_points = []
    for f in files:
        filename = os.path.basename(f)
        # Match sweep_vu{VU}_{mode}.json
        match = re.match(r"sweep_vu(\d+)_(random|static)\.json", filename)
        if not match:
            continue
        vus = int(match.group(1))
        mode = match.group(2)

        try:
            with open(f, 'r') as fh:
                run_data = json.load(fh)
            
            summary = run_data.get("summary", {})
            metrics = run_data.get("metrics", {})
            http_dur = metrics.get("http_req_duration", {})

            data_points.append({
                "vus": vus,
                "mode": mode,
                "throughput": summary.get("throughput_req_sec", 0.0),
                "error_rate": summary.get("error_rate_pct", 0.0),
                "avg": http_dur.get("avg", 0.0),
                "med": http_dur.get("med", 0.0),
                "p95": http_dur.get("p95", 0.0),
                "p99": http_dur.get("p99", 0.0)
            })
        except Exception as e:
            print(f"[!] Error parsing {filename}: {e}")

    return data_points

def main():
    points = parse_sweep_files()
    if not points:
        print("[!] No sweep data points found. Make sure to run run_sweeps.py first.")
        return

    # Sort data points for plotting
    static_pts = sorted([p for p in points if p["mode"] == "static"], key=lambda x: x["vus"])
    random_pts = sorted([p for p in points if p["mode"] == "random"], key=lambda x: x["vus"])

    os.makedirs("examples/benchmarks/results", exist_ok=True)

    # Style configuration
    plt.style.use('seaborn-v0_8-whitegrid' if 'seaborn-v0_8-whitegrid' in plt.style.available else 'default')
    fig_width, fig_height = 8, 5.5

    # ----------------------------------------------------
    # Plot 1: Concurrency (VUs) vs Latency & Error Rate
    # ----------------------------------------------------
    fig, ax1 = plt.subplots(figsize=(fig_width, fig_height))

    # Color palette
    static_p99_color = '#d32f2f'  # Dark red
    static_med_color = '#ef5350'  # Light red
    random_p99_color = '#1976d2'  # Dark blue
    random_med_color = '#42a5f5'  # Light blue

    # Left axis: Latencies
    if static_pts:
        vus_static = [p["vus"] for p in static_pts]
        med_static = [p["med"] for p in static_pts]
        p99_static = [p["p99"] for p in static_pts]
        ax1.plot(vus_static, p99_static, color=static_p99_color, marker='o', linestyle='-', linewidth=2, label='Static Session P99')
        ax1.plot(vus_static, med_static, color=static_med_color, marker='s', linestyle='--', linewidth=1.5, label='Static Session Med')

    if random_pts:
        vus_random = [p["vus"] for p in random_pts]
        med_random = [p["med"] for p in random_pts]
        p99_random = [p["p99"] for p in random_pts]
        ax1.plot(vus_random, p99_random, color=random_p99_color, marker='o', linestyle='-', linewidth=2, label='Random Session P99')
        ax1.plot(vus_random, med_random, color=random_med_color, marker='s', linestyle='--', linewidth=1.5, label='Random Session Med')

    ax1.set_xlabel('Concurrency (Virtual Users - VUs)', fontsize=11, fontweight='bold')
    ax1.set_ylabel('Latency (ms)', fontsize=11, fontweight='bold')
    ax1.tick_params(axis='y')
    ax1.grid(True, linestyle=':', alpha=0.6)

    # 900ms limit threshold line
    ax1.axhline(y=900, color='#ff9800', linestyle=':', linewidth=2, label='Max Latency SLA Target (900ms)')

    # Right axis: Error Rate
    ax2 = ax1.twinx()
    if static_pts:
        err_static = [p["error_rate"] for p in static_pts]
        ax2.plot(vus_static, err_static, color='#7b1fa2', marker='x', linestyle=':', alpha=0.6, label='Static Session Errors')
    if random_pts:
        err_random = [p["error_rate"] for p in random_pts]
        ax2.plot(vus_random, err_random, color='#9c27b0', marker='x', linestyle=':', alpha=0.6, label='Random Session Errors')

    ax2.set_ylabel('Error Rate (%)', color='#7b1fa2', fontsize=11, fontweight='bold')
    ax2.tick_params(axis='y', labelcolor='#7b1fa2')
    ax2.set_ylim(-5, 105)

    # Combine legends
    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(lines1 + lines2, labels1 + labels2, loc='upper left', frameon=True, facecolor='white', edgecolor='none', shadow=True)

    plt.title('Lilith-Zero: Latency & Error Rate vs Concurrency Sweep', fontsize=12, fontweight='bold', pad=15)
    plt.tight_layout()
    
    out_img1 = "examples/benchmarks/results/concurrency_sweep.png"
    plt.savefig(out_img1, dpi=200)
    plt.close()
    print(f"[+] Saved concurrency sweep plot to: {out_img1}")

    # ----------------------------------------------------
    # Plot 2: Throughput (RPS) vs Latency & Error Rate
    # ----------------------------------------------------
    fig, ax1 = plt.subplots(figsize=(fig_width, fig_height))

    static_t_pts = sorted(static_pts, key=lambda x: x["throughput"]) if static_pts else []
    random_t_pts = sorted(random_pts, key=lambda x: x["throughput"]) if random_pts else []

    if static_t_pts:
        t_static = [p["throughput"] for p in static_t_pts]
        med_static = [p["med"] for p in static_t_pts]
        p99_static = [p["p99"] for p in static_t_pts]
        ax1.plot(t_static, p99_static, color=static_p99_color, marker='o', linestyle='-', linewidth=2, label='Static Session P99')
        ax1.plot(t_static, med_static, color=static_med_color, marker='s', linestyle='--', linewidth=1.5, label='Static Session Med')

    if random_t_pts:
        t_random = [p["throughput"] for p in random_t_pts]
        med_random = [p["med"] for p in random_t_pts]
        p99_random = [p["p99"] for p in random_t_pts]
        ax1.plot(t_random, p99_random, color=random_p99_color, marker='o', linestyle='-', linewidth=2, label='Random Session P99')
        ax1.plot(t_random, med_random, color=random_med_color, marker='s', linestyle='--', linewidth=1.5, label='Random Session Med')

    ax1.set_xlabel('Throughput (Requests per Second - RPS)', fontsize=11, fontweight='bold')
    ax1.set_ylabel('Latency (ms)', fontsize=11, fontweight='bold')
    ax1.grid(True, linestyle=':', alpha=0.6)

    # 900ms limit threshold line
    ax1.axhline(y=900, color='#ff9800', linestyle=':', linewidth=2, label='Max Latency SLA Target (900ms)')

    # Right axis: Error Rate
    ax2 = ax1.twinx()
    if static_t_pts:
        t_static = [p["throughput"] for p in static_t_pts]
        err_static = [p["error_rate"] for p in static_t_pts]
        ax2.plot(t_static, err_static, color='#7b1fa2', marker='x', linestyle=':', alpha=0.6, label='Static Session Errors')
    if random_t_pts:
        t_random = [p["throughput"] for p in random_t_pts]
        err_random = [p["error_rate"] for p in random_t_pts]
        ax2.plot(t_random, err_random, color='#9c27b0', marker='x', linestyle=':', alpha=0.6, label='Random Session Errors')

    ax2.set_ylabel('Error Rate (%)', color='#7b1fa2', fontsize=11, fontweight='bold')
    ax2.tick_params(axis='y', labelcolor='#7b1fa2')
    ax2.set_ylim(-5, 105)

    # Combine legends
    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(lines1 + lines2, labels1 + labels2, loc='upper left', frameon=True, facecolor='white', edgecolor='none', shadow=True)

    plt.title('Lilith-Zero: Throughput vs Latency Curve', fontsize=12, fontweight='bold', pad=15)
    plt.tight_layout()

    out_img2 = "examples/benchmarks/results/throughput_vs_latency.png"
    plt.savefig(out_img2, dpi=200)
    plt.close()
    print(f"[+] Saved throughput sweep plot to: {out_img2}")

if __name__ == "__main__":
    main()
