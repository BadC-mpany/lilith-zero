
"""
Lilith Zero Performance & Overhead Benchmark.
Google-grade minimalistic measurement suite.

Measures:
- Startup Latency (Cold/Warm)
- RPC Overhead (p50, p95, p99)
- Throughput (Requests/sec)
- Memory Footprint (RSS)
"""

import asyncio
import json
import os
import sys
import time
import statistics
import psutil
import subprocess
from typing import Dict, Any, List, Optional

# Add SDK to path
repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(repo_root, "sdk", "src"))

from lilith_zero import Lilith

# Configuration
BINARY_PATH = os.environ.get("LILITH_ZERO_BINARY_PATH")
UPSTREAM_SCRIPT = os.path.join(repo_root, "tests", "resources", "manual_server.py")
UPSTREAM_CMD = f"{sys.executable} -u {UPSTREAM_SCRIPT}"
ITERATIONS = 100
CONCURRENCY = 10

class BenchResult:
    def __init__(self, name: str):
        self.name = name
        self.latencies: List[float] = []
        self.start_time: float = 0
        self.end_time: float = 0
        self.memory_rss: float = 0
        self.subprocess_memory_rss: float = 0

    def stats(self):
        if not self.latencies:
            return "N/A"
        l = [lat * 1000 for lat in self.latencies] # ms
        return (f"p50: {statistics.median(l):.2f}ms, "
                f"p95: {statistics.quantiles(l, n=20)[18]:.2f}ms, "
                f"avg: {statistics.mean(l):.2f}ms")

async def measure_startup(runs=5):
    print(f"[*] Measuring Startup Latency ({runs} runs)...")
    latencies = []
    for _ in range(runs):
        start = time.perf_counter()
        async with Lilith(UPSTREAM_CMD, binary=BINARY_PATH) as client:
            latencies.append(time.perf_counter() - start)
    
    l_ms = [l * 1000 for l in latencies]
    print(f"    - Avg Startup: {statistics.mean(l_ms):.1f}ms (min: {min(l_ms):.1f}ms)")

async def run_rpc_bench(name: str, use_lilith: bool):
    print(f"[*] Benchmarking {name}...")
    res = BenchResult(name)
    
    if use_lilith:
        async with Lilith(UPSTREAM_CMD, binary=BINARY_PATH) as client:
            # Warm up
            await client.list_tools()
            
            # Measure Latency
            for _ in range(ITERATIONS):
                start = time.perf_counter()
                await client.list_tools()
                res.latencies.append(time.perf_counter() - start)
            
            # Measure Memory
            proc = psutil.Process(os.getpid())
            res.memory_rss = proc.memory_info().rss / (1024 * 1024)
            
            if client._process:
                try:
                    l_proc = psutil.Process(client._process.pid)
                    res.subprocess_memory_rss = l_proc.memory_info().rss / (1024 * 1024)
                except: pass
    else:
        # Direct MCP Baseline
        import shlex
        import platform
        is_posix = platform.system() != "Windows"
        args = shlex.split(UPSTREAM_CMD, posix=is_posix)
        
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        try:
            # MCP Initialize sequence (mimic enough for manual_server)
            async def rpc_call(method, params):
                req = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
                body = json.dumps(req).encode()
                proc.stdin.write(f"Content-Length: {len(body)}\r\n\r\n".encode() + body)
                await proc.stdin.drain()
                
                # Read response
                line = await proc.stdout.readline()
                while line.strip(): line = await proc.stdout.readline()
                content = await proc.stdout.read(1024) # manual_server response is small
                return json.loads(content)

            # Warm up
            await rpc_call("tools/list", {})

            for _ in range(ITERATIONS):
                start = time.perf_counter()
                await rpc_call("tools/list", {})
                res.latencies.append(time.perf_counter() - start)
            
            p = psutil.Process(proc.pid)
            res.subprocess_memory_rss = p.memory_info().rss / (1024 * 1024)
        finally:
            proc.kill()
            await proc.wait()

    return res

async def measure_throughput():
    print(f"[*] Measuring Throughput (Concurrency={CONCURRENCY})...")
    async with Lilith(UPSTREAM_CMD, binary=BINARY_PATH) as client:
        start = time.perf_counter()
        tasks = []
        for _ in range(ITERATIONS):
            tasks.append(client.list_tools())
        
        # Run in chunks of CONCURRENCY
        for i in range(0, len(tasks), CONCURRENCY):
            await asyncio.gather(*tasks[i:i+CONCURRENCY])
            
        duration = time.perf_counter() - start
        rps = ITERATIONS / duration
        print(f"    - Throughput: {rps:.1f} req/s")

async def main():
    print("="*60)
    print(" LILITH ZERO - PERFORMANCE BENCHMARK ")
    print("="*60)
    
    if not BINARY_PATH:
        print("ERROR: LILITH_ZERO_BINARY_PATH not set.")
        return

    # Baseline
    res_base = await run_rpc_bench("Baseline (Direct MCP)", use_lilith=False)
    
    # Lilith
    res_lilith = await run_rpc_bench("Lilith (Hardened)", use_lilith=True)
    
    print("\n" + "="*60)
    print(f"{'Metric':<20} | {'Baseline':<18} | {'Lilith':<18} | {'Overhead'}")
    print("-"*60)
    
    base_p50 = statistics.median(res_base.latencies) * 1000
    lilith_p50 = statistics.median(res_lilith.latencies) * 1000
    overhead = lilith_p50 - base_p50
    
    print(f"{'RPC Latency (p50)':<20} | {base_p50:>16.2f}ms | {lilith_p50:>16.2f}ms | {overhead:>7.2f}ms")
    
    base_mem = res_base.subprocess_memory_rss
    lilith_mem = res_lilith.subprocess_memory_rss
    print(f"{'Process Memory':<20} | {base_mem:>16.2f}MB | {lilith_mem:>16.2f}MB | {lilith_mem - base_mem:>7.2f}MB")
    
    print("="*60)
    
    # Startup (optional, only for Lilith)
    await measure_startup()
    
    # Throughput
    await measure_throughput()
    
    print("="*60)
    print("Benchmark Complete.")

if __name__ == "__main__":
    asyncio.run(main())
