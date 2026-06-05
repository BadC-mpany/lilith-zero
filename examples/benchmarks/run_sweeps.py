#!/usr/bin/env python3
"""
Parameter sweep orchestrator for Lilith-Zero.
Loops through VUs (1, 5, 10, 20, 50, 100) and LILITH_RANDOM_CONV (true, false),
running k6 load tests against either a local or remote target.
"""

import argparse
import os
import socket
import subprocess
import sys
import time

def wait_for_port(port, timeout=10.0):
    start = time.time()
    while time.time() - start < timeout:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect(('127.0.0.1', port))
                return True
        except socket.error:
            time.sleep(0.2)
    return False

def main():
    parser = argparse.ArgumentParser(description="Run parameter sweeps for Lilith-Zero.")
    parser.add_argument("--binary", default="lilith-zero/target/release/lilith-zero", help="Path to lilith-binary")
    parser.add_argument("--url", default="http://localhost:8080/analyze-tool-execution", help="Target webhook URL")
    parser.add_argument("--duration", default="10s", help="Duration for each k6 run")
    parser.add_argument("--vus", default="1,5,10,20,50,100", help="Comma-separated VU values to sweep")
    parser.add_argument("--agent-id", default="5be3e14e-2e46-f111-bec6-7c1e52344333,77236ced-1146-f111-bec6-7ced8d71fac9,universal", help="LILITH_AGENT_ID list")
    parser.add_argument("--random-only", action="store_true", help="Only run randomized session mode, skip static (useful for infrastructure ceiling tests)")
    args = parser.parse_args()

    vus = [int(v.strip()) for v in args.vus.split(",") if v.strip()]
    random_modes = [True] if args.random_only else [True, False]

    is_local = "localhost" in args.url or "127.0.0.1" in args.url
    server_proc = None

    # Step 1: Start local server if target is local
    if is_local:
        print(f"[*] Starting local Lilith-Zero server from: {args.binary}")
        if not os.path.exists(args.binary):
            # Try workspace root relative
            alt_path = "target/release/lilith-zero"
            if os.path.exists(alt_path):
                args.binary = alt_path
            else:
                print(f"[!] Error: Binary not found at {args.binary}. Please compile with 'cargo build --release -p lilith-zero'")
                sys.exit(1)

        policy_dir = "examples/copilot_studio/policies"
        if not os.path.exists(policy_dir):
            print(f"[!] Error: Policy dir not found at {policy_dir}")
            sys.exit(1)

        # Make sure session storage dir exists
        session_dir = "examples/benchmarks/results/sessions_sweep"
        os.makedirs(session_dir, exist_ok=True)

        env = os.environ.copy()
        env["LILITH_ZERO_SESSION_STORAGE_DIR"] = session_dir
        env["LILITH_EXPOSE_TIMING"] = "true"

        # Spawn local webhook daemon
        server_proc = subprocess.Popen(
            [args.binary, "serve", "--bind", "127.0.0.1:8080", "--policy", policy_dir, "--auth-mode", "none"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=env
        )

        print("[*] Waiting for port 8080 to become available...")
        if not wait_for_port(8080):
            print("[!] Error: Local server failed to bind to port 8080 in time.")
            server_proc.terminate()
            sys.exit(1)
        print("[+] Local server started successfully.")

    # Create results folder
    os.makedirs("examples/benchmarks/results", exist_ok=True)

    # Step 2: Sweep loop
    try:
        for vu in vus:
            for rand_mode in random_modes:
                mode_str = "random" if rand_mode else "static"
                sweep_name = f"sweep_vu{vu}_{mode_str}"
                print(f"\n==================================================")
                print(f" Running Sweep: VUs={vu}, Mode={mode_str.upper()}")
                print(f"==================================================")

                k6_env = os.environ.copy()
                k6_env["LILITH_URL"] = args.url
                k6_env["LILITH_VUS"] = str(vu)
                k6_env["LILITH_DURATION"] = args.duration
                k6_env["LILITH_RANDOM_CONV"] = "true" if rand_mode else "false"
                k6_env["LILITH_AGENT_ID"] = args.agent_id
                k6_env["LILITH_SWEEP_NAME"] = sweep_name

                # Run k6 in examples/benchmarks/ dir
                cmd = ["k6", "run", "webhook_load_test.js"]
                cwd = "examples/benchmarks"

                proc = subprocess.run(cmd, env=k6_env, cwd=cwd)
                if proc.returncode != 0:
                    print(f"[!] Warning: k6 run returned non-zero code {proc.returncode}")

    finally:
        # Step 3: Cleanup
        if server_proc:
            print("\n[*] Terminating local Lilith-Zero server...")
            server_proc.terminate()
            try:
                server_proc.wait(timeout=3.0)
            except subprocess.TimeoutExpired:
                server_proc.kill()
            print("[+] Local server stopped.")

    print("\n[+] Parameter sweep completed.")

if __name__ == "__main__":
    main()
