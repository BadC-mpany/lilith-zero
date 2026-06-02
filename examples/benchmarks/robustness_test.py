#!/usr/bin/env python3
# Copyright 2026 BadCompany
# Licensed under the Apache License, Version 2.0 (the "License");
# http://www.apache.org/licenses/LICENSE-2.0

import argparse
import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
from typing import Dict, Any

def run_proc(cmd: list, input_str: str, env: dict) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        input=input_str.encode("utf-8") if input_str else b"",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )

def test_fail_closed_on_invalid_inputs(binary_path: str, policy_path: str, env: dict) -> bool:
    print("\n--- Running Test: Fail-Closed on Invalid Inputs ---")
    cmd = [binary_path, "hook", "--policy", policy_path, "--format", "claude"]
    
    # 1. Empty input
    proc = run_proc(cmd, "", env)
    if proc.returncode == 0:
        print("FAIL: Empty input was allowed (exit code 0)")
        return False
    print(f"PASS: Empty input rejected with code {proc.returncode}")

    # 2. Malformed JSON
    proc = run_proc(cmd, "{ \"session_id\": \"123\"", env)
    if proc.returncode == 0:
        print("FAIL: Malformed JSON was allowed (exit code 0)")
        return False
    print(f"PASS: Malformed JSON rejected with code {proc.returncode}")

    # 3. Missing hook_event_name
    bad_payload = json.dumps({"session_id": "test-session", "tool_name": "some_tool"})
    proc = run_proc(cmd, bad_payload, env)
    if proc.returncode == 0:
        print("FAIL: Missing hook_event_name was allowed (exit code 0)")
        return False
    print(f"PASS: Missing hook_event_name rejected with code {proc.returncode}")

    return True

def test_lock_contention(binary_path: str, policy_path: str, env: dict) -> bool:
    print("\n--- Running Test: Lock Contention / Session Safety ---")
    # We will spawn multiple threads that call hook concurrently on the SAME session ID.
    # Because of fs2 flock, the runs must be serialized safely, and there should be no file corruptions.
    session_id = "shared-contention-session"
    num_threads = 8
    errors = []

    payload = {
        "session_id": session_id,
        "hook_event_name": "PreToolUse",
        "tool_name": "allowed_tool",
    }
    input_str = json.dumps(payload)
    cmd = [binary_path, "hook", "--policy", policy_path, "--format", "claude"]

    def worker():
        try:
            proc = run_proc(cmd, input_str, env)
            if proc.returncode != 0:
                errors.append(f"Thread failed with exit code {proc.returncode}, Stderr: {proc.stderr.decode()}")
        except Exception as e:
            errors.append(f"Thread raised exception: {e}")

    threads = [threading.Thread(target=worker) for _ in range(num_threads)]
    
    start_time = time.perf_counter()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    duration = (time.perf_counter() - start_time) * 1000.0

    print(f"Executed {num_threads} concurrent hook processes in {duration:.2f}ms")

    if errors:
        for err in errors:
            print(f"FAIL: {err}")
        return False

    # Check if the final session state file is valid JSON
    session_file = os.path.join(env["LILITH_ZERO_SESSION_STORAGE_DIR"], f"{session_id}.json")
    if not os.path.exists(session_file):
        print(f"FAIL: Session file {session_file} does not exist")
        return False

    try:
        with open(session_file, "r") as f:
            state = json.load(f)
        print(f"PASS: Session file is intact and contains valid JSON.")
    except Exception as e:
        print(f"FAIL: Failed to parse session file: {e}")
        return False

    return True

def test_taint_persistence_workflow(binary_path: str, cedar_policy_path: str, env: dict) -> bool:
    print("\n--- Running Test: Taint Accumulation & Persistence Workflow (Cedar) ---")
    session_id = "taint-workflow-session"
    cmd = [binary_path, "hook", "--policy", cedar_policy_path, "--format", "claude"]

    def call_hook(tool_name: str, event: str = "PreToolUse") -> int:
        payload = {
            "session_id": session_id,
            "hook_event_name": event,
            "tool_name": tool_name,
        }
        proc = run_proc(cmd, json.dumps(payload), env)
        return proc.returncode

    # 1. allowed_tool should be permitted on a fresh session
    code = call_hook("allowed_tool")
    if code != 0:
        print(f"FAIL: allowed_tool failed initially with code {code}")
        return False
    print("PASS: allowed_tool permitted initially")

    # 2. check_untrusted_tool should be permitted because session is clean (no taints)
    code = call_hook("check_untrusted_tool")
    if code != 0:
        print(f"FAIL: check_untrusted_tool failed with code {code} before taint added")
        return False
    print("PASS: check_untrusted_tool permitted before taint")

    # 3. taint_source_tool should be permitted and add UNTRUSTED_DATA taint
    code = call_hook("taint_source_tool")
    if code != 0:
        print(f"FAIL: taint_source_tool failed with code {code}")
        return False
    print("PASS: taint_source_tool permitted (taint UNTRUSTED_DATA added)")

    # Verify taint is inside the session file
    session_file = os.path.join(env["LILITH_ZERO_SESSION_STORAGE_DIR"], f"{session_id}.json")
    with open(session_file, "r") as f:
        state = json.load(f)
    active_taints = state.get("taints", [])
    if "UNTRUSTED_DATA" not in active_taints:
        print(f"FAIL: UNTRUSTED_DATA taint not persisted. Active taints: {active_taints}")
        return False
    print(f"PASS: UNTRUSTED_DATA taint successfully persisted in session state file")

    # 4. check_untrusted_tool should now be BLOCKED (exit code 2) because of the taint
    code = call_hook("check_untrusted_tool")
    if code != 2:
        print(f"FAIL: check_untrusted_tool was not blocked! Got code {code}, expected 2")
        return False
    print("PASS: check_untrusted_tool successfully blocked due to taint presence")

    # 5. remove_taint_tool should clear the taint
    code = call_hook("remove_taint_tool")
    if code != 0:
        print(f"FAIL: remove_taint_tool failed with code {code}")
        return False
    print("PASS: remove_taint_tool permitted (taint UNTRUSTED_DATA cleared)")

    # 6. check_untrusted_tool should be permitted again
    code = call_hook("check_untrusted_tool")
    if code != 0:
        print(f"FAIL: check_untrusted_tool remains blocked after taint clear. Got code {code}")
        return False
    print("PASS: check_untrusted_tool permitted again after taint removal")

    return True

def run_all(binary_path: str, policy_path: str, cedar_policy_path: str):
    temp_dir = tempfile.mkdtemp(prefix="lilith_robustness_")
    env = os.environ.copy()
    env["LILITH_ZERO_SESSION_STORAGE_DIR"] = temp_dir
    
    success = True
    try:
        # Test 1: Fail closed
        if not test_fail_closed_on_invalid_inputs(binary_path, policy_path, env):
            success = False

        # Test 2: Lock Contention
        if not test_lock_contention(binary_path, policy_path, env):
            success = False

        # Test 3: Cedar Taint Persistence
        if not test_taint_persistence_workflow(binary_path, cedar_policy_path, env):
            success = False

    finally:
        shutil.rmtree(temp_dir)

    print("\n" + "=" * 80)
    if success:
        print("ALL ROBUSTNESS AND PERSISTENCE TESTS PASSED SUCCESSFULLY!")
    else:
        print("ROBUSTNESS VERIFICATION DETECTED FAILURE CASES.")
    print("=" * 80)
    return 0 if success else 1

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Lilith Zero Robustness & Failure Injection Suite")
    parser.add_argument(
        "--binary",
        default="lilith-zero/target/release/lilith-zero",
        help="Path to the compiled lilith-zero binary",
    )
    parser.add_argument(
        "--policy",
        default="lilith-zero/tests/fixtures/policy_test.yaml",
        help="Path to the policy test YAML file",
    )
    parser.add_argument(
        "--cedar-policy",
        default="lilith-zero/tests/fixtures/taint_persistence.cedar",
        help="Path to the test Cedar policy file",
    )
    args = parser.parse_args()

    exit(run_all(args.binary, args.policy, args.cedar_policy))
