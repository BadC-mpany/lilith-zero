#!/usr/bin/env python3
# Copyright 2026 BadCompany
# Licensed under the Apache License, Version 2.0 (the "License");
# http://www.apache.org/licenses/LICENSE-2.0

import argparse
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from typing import List, Dict, Any

# Regex to parse the stderr timing line outputted when LILITH_EXPOSE_TIMING=true
TIMING_REGEX = re.compile(
    r"lilith_timing:\s+lock_acquire_ms=([\d\.]+)\s+state_load_ms=([\d\.]+)\s+core_eval_ms=([\d\.]+)\s+state_save_ms=([\d\.]+)"
)

def calculate_percentile(data: List[float], percentile: float) -> float:
    if not data:
        return 0.0
    sorted_data = sorted(data)
    k = (len(sorted_data) - 1) * percentile
    f = int(k)
    c = f + 1
    if c < len(sorted_data):
        return sorted_data[f] + (sorted_data[c] - sorted_data[f]) * (k - f)
    else:
        return sorted_data[f]

def run_benchmark(
    binary_path: str,
    policy_path: str,
    format_arg: str,
    iterations: int,
    payload_allowed_path: str,
    payload_denied_path: str,
):
    print("=" * 80)
    print(f"LILITH ZERO CLI HOOK BENCHMARK")
    print(f"Binary:     {binary_path}")
    print(f"Policy:     {policy_path}")
    print(f"Format:     {format_arg}")
    print(f"Iterations: {iterations}")
    print("=" * 80)

    # Resolve paths
    binary_path = os.path.abspath(binary_path)
    policy_path = os.path.abspath(policy_path)
    payload_allowed_path = os.path.abspath(payload_allowed_path)
    payload_denied_path = os.path.abspath(payload_denied_path)

    if not os.path.exists(binary_path):
        print(f"Error: Binary not found at {binary_path}")
        return

    # Load payloads
    with open(payload_allowed_path, "r") as f:
        allowed_json = json.load(f)
    with open(payload_denied_path, "r") as f:
        denied_json = json.load(f)

    # Prepare temp directory for session files to isolate runs and prevent disk clutter
    temp_session_dir = tempfile.mkdtemp(prefix="lilith_bench_")
    print(f"Isolated session storage: {temp_session_dir}")

    # Set up environment variables
    env = os.environ.copy()
    env["LILITH_ZERO_SESSION_STORAGE_DIR"] = temp_session_dir
    env["LILITH_EXPOSE_TIMING"] = "true"

    # Latency tracking categories
    metrics = {
        "lock_acquire": [],
        "state_load": [],
        "core_eval": [],
        "state_save": [],
        "total_process": [],
        "overhead": [],
    }

    successes = 0
    failures = 0
    test_details = []
    start_benchmark_time = time.perf_counter()

    try:
        for i in range(iterations):
            # Interleave allowed and denied requests
            is_allowed = i % 2 == 0
            payload = allowed_json if is_allowed else denied_json
            
            # Inject a fresh session ID or a static one to test cross-process safety
            # CLI hooks are usually executed per-session. We randomize session ID to avoid lock contention
            session_id = f"cli-session-{i // 2}"
            payload_copy = payload.copy()
            payload_copy["session_id"] = session_id
            payload_copy["sessionId"] = session_id

            # Prepare command
            cmd = [
                binary_path,
                "hook",
                "--policy",
                policy_path,
                "--format",
                format_arg,
            ]
            if format_arg == "copilot":
                cmd.extend(["--event", "preToolUse"])

            # Run process
            input_bytes = json.dumps(payload_copy).encode("utf-8")
            start_time = time.perf_counter()
            proc = subprocess.run(
                cmd,
                input=input_bytes,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
            )
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0

            # Verify decision correctness
            stdout_str = proc.stdout.decode("utf-8", errors="ignore")
            stderr_str = proc.stderr.decode("utf-8", errors="ignore")

            correct = False
            if format_arg == "claude":
                # Exit code 0 for allow, 2 for deny
                expected_code = 0 if is_allowed else 2
                correct = proc.returncode == expected_code
            elif format_arg == "copilot":
                # JSON on stdout containing permissionDecision
                try:
                    out_json = json.loads(stdout_str)
                    decision = out_json.get("permissionDecision")
                    expected_dec = "allow" if is_allowed else "deny"
                    correct = decision == expected_dec
                except Exception:
                    correct = False

            if correct:
                successes += 1
            else:
                failures += 1
                detail = f"Iteration {i} Mismatch (Expected {'allow' if is_allowed else 'deny'}, Got exit_code={proc.returncode})"
                print(f"  \033[31mFAIL\033[0m [{elapsed_ms/1000.0:8.3f}s] CLI Hook: {detail}")
                test_details.append(f"  - Iteration {i}: {detail}")

            # Parse timing breakdown from stderr
            match = TIMING_REGEX.search(stderr_str)
            if match:
                lock_acq = float(match.group(1))
                state_ld = float(match.group(2))
                core_ev = float(match.group(3))
                state_sv = float(match.group(4))
                
                metrics["lock_acquire"].append(lock_acq)
                metrics["state_load"].append(state_ld)
                metrics["core_eval"].append(core_ev)
                metrics["state_save"].append(state_sv)
                metrics["total_process"].append(elapsed_ms)
                
                # Overhead = Total Process Time - sum(internal engine execution times)
                internal_sum = lock_acq + state_ld + core_ev + state_sv
                metrics["overhead"].append(elapsed_ms - internal_sum)
            else:
                # If timing output wasn't matched, just capture total process time
                metrics["total_process"].append(elapsed_ms)

            if (i + 1) % max(1, iterations // 10) == 0:
                print(f"  \033[36mINFO\033[0m Progress: {i + 1}/{iterations} runs complete...")

    finally:
        # Clean up isolated session files
        shutil.rmtree(temp_session_dir)

    total_duration = time.perf_counter() - start_benchmark_time

    # Nextest-style Summary Bottom
    print("-" * 80)
    print(f"\033[1mSummary:\033[0m \033[32m{successes} passed\033[0m, \033[31m{failures} failed\033[0m, \033[33m0 skipped\033[0m in {total_duration:.3f}s")
    print("-" * 80)

    if failures > 0:
        print("\n\033[31;1mFailures:\033[0m")
        for detail in test_details:
            print(detail)
        print("-" * 80)

    # Print summary table
    print("\n" + "=" * 80)
    print("BENCHMARK EXECUTION RESULTS")
    print("=" * 80)

    # Helper function to print a row of statistics
    def format_row(name: str, values: List[float]) -> str:
        if not values:
            return f"| {name:<23} | N/A     | N/A     | N/A     | N/A     | N/A     |"
        avg_val = sum(values) / len(values)
        med_val = calculate_percentile(values, 0.5)
        p95_val = calculate_percentile(values, 0.95)
        p99_val = calculate_percentile(values, 0.99)
        max_val = max(values)
        return (
            f"| {name:<23} | "
            f"{avg_val:7.2f} | "
            f"{med_val:7.2f} | "
            f"{p95_val:7.2f} | "
            f"{p99_val:7.2f} | "
            f"{max_val:7.2f} |"
        )

    print(f"| {'Metric Phase':<23} | {'Avg (ms)':<7} | {'Med (ms)':<7} | {'P95 (ms)':<7} | {'P99 (ms)':<7} | {'Max (ms)':<7} |")
    print("|" + "-" * 25 + "|" + "-" * 9 + "|" + "-" * 9 + "|" + "-" * 9 + "|" + "-" * 9 + "|" + "-" * 9 + "|")
    print(format_row("Session Lock Acquire", metrics["lock_acquire"]))
    print(format_row("Session State Load", metrics["state_load"]))
    print(format_row("Security Policy Eval", metrics["core_eval"]))
    print(format_row("Session State Save", metrics["state_save"]))
    print(format_row("Binary Startup/IO", metrics["overhead"]))
    print(format_row("Total Process Execution", metrics["total_process"]))
    print("=" * 80)

    # Export reports
    results_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")
    os.makedirs(results_dir, exist_ok=True)

    report_json_path = os.path.join(results_dir, f"hook_benchmark_report_{format_arg}.json")
    report_md_path = os.path.join(results_dir, f"hook_benchmark_report_{format_arg}.md")

    def get_phase_stats(values: List[float]) -> Dict[str, float]:
        if not values:
            return {"avg": 0.0, "med": 0.0, "p95": 0.0, "p99": 0.0, "max": 0.0}
        return {
            "avg": sum(values) / len(values),
            "med": calculate_percentile(values, 0.5),
            "p95": calculate_percentile(values, 0.95),
            "p99": calculate_percentile(values, 0.99),
            "max": max(values)
        }

    # Save JSON report
    report_data = {
        "summary": {
            "total_runs": iterations,
            "successes": successes,
            "failures": failures,
            "accuracy_pct": (successes / iterations) * 100.0 if iterations else 0.0,
            "duration_sec": total_duration
        },
        "metrics": {
            "lock_acquire": get_phase_stats(metrics["lock_acquire"]),
            "state_load": get_phase_stats(metrics["state_load"]),
            "core_eval": get_phase_stats(metrics["core_eval"]),
            "state_save": get_phase_stats(metrics["state_save"]),
            "overhead": get_phase_stats(metrics["overhead"]),
            "total_process": get_phase_stats(metrics["total_process"])
        }
    }

    with open(report_json_path, "w") as f:
        json.dump(report_data, f, indent=2)

    # Save Markdown report
    md_lines = [
        f"# Lilith Zero: CLI Hook ({format_arg}) Latency Benchmark Report",
        "",
        "## Execution Summary",
        f"- **Total Invocations**: {iterations}",
        f"- **Correct Decisions**: {successes}",
        f"- **Mismatches**: {failures}",
        f"- **Policy Enforcement Accuracy**: {(successes/iterations)*100:.2f}%",
        f"- **Total Benchmark Duration**: {total_duration:.3f}s",
        f"- **Status**: {'✓ PASS' if failures == 0 else '✗ FAIL'}",
        "",
        "## Latency Metrics Breakdown (ms)",
        "",
        f"| {'Metric Phase':<23} | {'Avg (ms)':<7} | {'Med (ms)':<7} | {'P95 (ms)':<7} | {'P99 (ms)':<7} | {'Max (ms)':<7} |",
        "|---|---|---|---|---|---|",
    ]

    def md_row(name: str, key: str) -> str:
        stats = report_data["metrics"][key]
        return f"| {name} | {stats['avg']:.2f} | {stats['med']:.2f} | {stats['p95']:.2f} | {stats['p99']:.2f} | {stats['max']:.2f} |"

    md_lines.extend([
        md_row("Session Lock Acquire", "lock_acquire"),
        md_row("Session State Load", "state_load"),
        md_row("Security Policy Eval", "core_eval"),
        md_row("Session State Save", "state_save"),
        md_row("Binary Startup/IO Overhead", "overhead"),
        md_row("Total Process Execution", "total_process"),
    ])

    with open(report_md_path, "w") as f:
        f.write("\n".join(md_lines) + "\n")

    print(f"\nReports saved successfully to:")
    print(f" - Markdown: \033[36m{report_md_path}\033[0m")
    print(f" - JSON:     \033[36m{report_json_path}\033[0m")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Lilith Zero CLI Hook Benchmarking Suite")
    parser.add_argument(
        "--binary",
        default="lilith-zero/target/release/lilith-zero",
        help="Path to the compiled lilith-zero binary",
    )
    parser.add_argument(
        "--policy",
        default="examples/benchmarks/benchmark_policy.yaml",
        help="Path to the policy configuration file",
    )
    parser.add_argument(
        "--format",
        default="all",
        choices=["claude", "copilot", "all"],
        help="Format mode to run hook in (or 'all' to run both sequential)",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=200,
        help="Number of hook invocations to benchmark",
    )
    parser.add_argument(
        "--payload-allowed",
        default=None,
        help="JSON file for allowed request payload",
    )
    parser.add_argument(
        "--payload-denied",
        default=None,
        help="JSON file for denied request payload",
    )
    args = parser.parse_args()

    formats = ["claude", "copilot"] if args.format == "all" else [args.format]

    for fmt in formats:
        p_allowed = args.payload_allowed
        if p_allowed is None:
            p_allowed = f"examples/shared_payloads/hook_{fmt}_allowed.json"

        p_denied = args.payload_denied
        if p_denied is None:
            p_denied = f"examples/shared_payloads/hook_{fmt}_denied.json"

        run_benchmark(
            binary_path=args.binary,
            policy_path=args.policy,
            format_arg=fmt,
            iterations=args.iterations,
            payload_allowed_path=p_allowed,
            payload_denied_path=p_denied,
        )
