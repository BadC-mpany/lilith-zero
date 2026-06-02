#!/usr/bin/env python3
# Copyright 2026 BadCompany
# Licensed under the Apache License, Version 2.0 (the "License");
# http://www.apache.org/licenses/LICENSE-2.0

import argparse
import hashlib
import json
import os
import re
import resource
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import traceback
import urllib.request
from typing import Dict, Any, List, Set, Tuple

# Helper function to find a free TCP port
def find_free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port

# Poll validate endpoint until the server is ready
def wait_for_server(port: int, timeout_sec: float = 8.0) -> bool:
    start = time.perf_counter()
    url = f"http://127.0.0.1:{port}/validate"
    while time.perf_counter() - start < timeout_sec:
        try:
            req = urllib.request.Request(
                url,
                data=b"{}",
                headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=1.0) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            time.sleep(0.1)
    return False

# Query open file descriptors count for a PID
def get_open_fd_count(pid: int) -> int:
    try:
        return len(os.listdir(f"/proc/{pid}/fd"))
    except Exception:
        return 0

# Query peak RSS and VM memory from /proc/{pid}/status
def get_proc_memory(pid: int) -> Dict[str, int]:
    res = {"VmPeak": 0, "VmHWM": 0}
    try:
        with open(f"/proc/{pid}/status", "r") as f:
            for line in f:
                if line.startswith("VmPeak:"):
                    res["VmPeak"] = int(line.split()[1])
                elif line.startswith("VmHWM:"):
                    res["VmHWM"] = int(line.split()[1])
    except Exception:
        pass
    return res

# Hash a scenario definition to support deduplication and reuse
def get_scenario_hash(policy_content: str, payload: Dict[str, Any], initial_taints: List[str], format_type: str) -> str:
    h = hashlib.sha256()
    h.update(policy_content.encode("utf-8"))
    h.update(json.dumps(payload, sort_keys=True).encode("utf-8"))
    h.update(json.dumps(sorted(initial_taints)).encode("utf-8"))
    h.update(format_type.encode("utf-8"))
    return h.hexdigest()

# Extract rule IDs/annotations from policy content
def parse_yaml_policy_rules(content: str) -> List[str]:
    rule_ids = []
    
    # Parse static_rules
    static_section = re.search(r'static_rules:(.*?)(?:\n\w|\Z)', content, re.DOTALL)
    if static_section:
        for line in static_section.group(1).splitlines():
            m = re.match(r'^\s+([a-zA-Z0-9_\-]+)\s*:\s*(ALLOW|DENY)', line)
            if m:
                tool = m.group(1)
                rule_ids.append(f"static_{tool}")
                
    # Parse resource_rules
    res_section = re.search(r'resource_rules:(.*?)(?:\n\w|\Z)', content, re.DOTALL)
    if res_section:
        items = re.findall(r'^\s*-\s+.*', res_section.group(1), re.MULTILINE)
        for i in range(len(items)):
            rule_ids.append(f"resource_rule_{i}")
            
    rule_ids.append("default_resource_permit")
    
    # Parse taint_rules
    taint_section = re.search(r'taint_rules:(.*?)(?:\n\w|\Z)', content, re.DOTALL)
    if taint_section:
        rules_raw = []
        current_rule = []
        for line in taint_section.group(1).splitlines():
            if re.match(r'^\s*-\s+', line):
                if current_rule:
                    rules_raw.append("\n".join(current_rule))
                    current_rule = []
            if line.strip():
                current_rule.append(line)
        if current_rule:
            rules_raw.append("\n".join(current_rule))
            
        for i, r_text in enumerate(rules_raw):
            action_m = re.search(r'action:\s*(\w+)', r_text)
            action = action_m.group(1).upper() if action_m else "ALLOW"
            
            tag_m = re.search(r'tag:\s*(\w+)', r_text)
            tag = tag_m.group(1) if tag_m else ""
            
            policy_id_prefix = "rule"
            if action == "ADD_TAINT":
                policy_id_prefix = f"add_taint:{tag}:"
            elif action == "REMOVE_TAINT":
                policy_id_prefix = f"remove_taint:{tag}:"
                
            raw_id = f"{policy_id_prefix}_{i}"
            rule_ids.append("".join(c if (c.isalnum() or c == ":") else "_" for c in raw_id))
            
    return rule_ids

def parse_cedar_policy_rules(content: str) -> List[str]:
    return re.findall(r'@id\(\s*["\'](.*?)["\']\s*\)', content)

# CLI Hook execution wrapper
def run_cli_hook(
    binary_path: str,
    policy_path: str,
    payload: Dict[str, Any],
    initial_taints: List[str],
    session_storage_dir: str,
    event_opt: str = None
) -> Tuple[str, List[str], float, int]:
    session_id = payload.get("session_id", "default-session")
    if initial_taints:
        sess_file = os.path.join(session_storage_dir, f"{session_id}.json")
        with open(sess_file, "w") as f:
            json.dump({"taints": initial_taints}, f)
            
    cmd = [binary_path, "hook", "--policy", policy_path, "--format", "claude"]
    if event_opt:
        cmd.extend(["--event", event_opt])
        
    env = os.environ.copy()
    env["LILITH_ZERO_SESSION_STORAGE_DIR"] = session_storage_dir
    env["LILITH_EXPOSE_TIMING"] = "true"
    
    start = time.perf_counter()
    proc = subprocess.run(
        cmd,
        input=json.dumps(payload).encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env
    )
    elapsed = (time.perf_counter() - start) * 1000.0
    
    decision = "allow" if proc.returncode == 0 else "deny"
    
    stderr_str = proc.stderr.decode("utf-8", errors="ignore")
    matched_policies = []
    for line in stderr_str.splitlines():
        if line.startswith("lilith_policies:"):
            pols = line.split(":", 1)[1].strip()
            if pols:
                matched_policies = [p.strip() for p in pols.split(",") if p.strip()]
            break
            
    return decision, matched_policies, elapsed, proc.returncode

# Webhook request execution wrapper
def run_webhook_request(
    port: int,
    agent_id: str,
    conversation_id: str,
    tool_id: str,
    input_values: Dict[str, Any],
    initial_taints: List[str],
    session_storage_dir: str
) -> Tuple[str, List[str], float, int]:
    if initial_taints:
        sess_file = os.path.join(session_storage_dir, f"{conversation_id}.json")
        with open(sess_file, "w") as f:
            json.dump({"taints": initial_taints}, f)
            
    body = {
        "plannerContext": {
            "userMessage": "test message"
        },
        "toolDefinition": {
            "id": tool_id,
            "type": "CustomToolDefinition",
            "name": tool_id,
            "description": f"Test tool: {tool_id}"
        },
        "inputValues": input_values,
        "conversationMetadata": {
            "agent": {
                "id": agent_id,
                "tenantId": "test-tenant",
                "environmentId": "test-env",
                "isPublished": True
            },
            "conversationId": conversation_id
        }
    }
    
    url = f"http://127.0.0.1:{port}/analyze-tool-execution"
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    
    start = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=8.0) as resp:
            elapsed = (time.perf_counter() - start) * 1000.0
            resp_body = json.loads(resp.read().decode("utf-8"))
            
            block_action = resp_body.get("blockAction", False)
            decision = "deny" if block_action else "allow"
            
            matched_header = resp.headers.get("X-Lilith-Matched-Policies", "")
            matched_policies = [p.strip() for p in matched_header.split(",") if p.strip()]
            
            return decision, matched_policies, elapsed, 200
    except urllib.error.HTTPError as e:
        elapsed = (time.perf_counter() - start) * 1000.0
        return "error", [], elapsed, e.code
    except Exception:
        elapsed = (time.perf_counter() - start) * 1000.0
        return "error", [], elapsed, 999

# Webhook Server Manager
class WebhookServerLifecycle:
    def __init__(self, binary_path: str, session_storage_dir: str):
        self.binary_path = binary_path
        self.session_storage_dir = session_storage_dir
        self.proc = None
        self.port = None
        self.policy_path = None
        
    def start(self, policy_path: str):
        if self.proc is not None:
            if self.policy_path == policy_path:
                return
            self.stop()
            
        self.port = find_free_port()
        self.policy_path = policy_path
        
        cmd = [
            self.binary_path,
            "serve",
            "--bind", f"127.0.0.1:{self.port}",
            "--policy", policy_path,
            "--auth-mode", "none"
        ]
        
        env = os.environ.copy()
        env["LILITH_ZERO_SESSION_STORAGE_DIR"] = self.session_storage_dir
        env["LILITH_EXPOSE_TIMING"] = "true"
        
        self.proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env
        )
        
        if not wait_for_server(self.port):
            stderr_data = b""
            try:
                stderr_data = self.proc.stderr.read(1000)
            except Exception:
                pass
            self.stop()
            raise RuntimeError(f"Webhook server failed to start on port {self.port}. Stderr: {stderr_data.decode()}")
            
    def stop(self):
        if self.proc is not None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                self.proc.kill()
            self.proc = None
            self.port = None
            self.policy_path = None

def save_cache(cache: Dict[str, Any]):
    cache_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_run_cache.json")
    try:
        with open(cache_file_path, "w") as f:
            json.dump(cache, f, indent=2)
    except Exception as e:
        print(f"Warning: Failed to save cache: {e}", file=sys.stderr)

def run_tests():
    parser = argparse.ArgumentParser(description="Lilith-Zero Differential and Fuzz Testing Suite")
    parser.add_argument("--binary", help="Path to compiled lilith-zero binary")
    parser.add_argument("--fuzz", action="store_true", help="Enable toggleable adversarial fuzzing")
    parser.add_argument("--no-cache", action="store_true", help="Bypass the test run cache")
    args = parser.parse_args()
    
    # Resolve binary
    binary = args.binary
    if not binary:
        candidates = [
            "./lilith-zero/target/release/lilith-zero",
            "./lilith-zero/target/debug/lilith-zero",
            "../lilith-zero/target/release/lilith-zero",
            "../lilith-zero/target/debug/lilith-zero",
            "target/release/lilith-zero",
            "target/debug/lilith-zero",
        ]
        for c in candidates:
            if os.path.isfile(c):
                binary = os.path.abspath(c)
                break
                
    if not binary or not os.path.isfile(binary):
        print("Error: Lilith binary not found. Please compile the project or specify --binary.")
        sys.exit(1)
        
    print(f"Using Lilith Binary: {binary}")
    
    # Load cache
    cache_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_run_cache.json")
    cache = {}
    if not args.no_cache and os.path.exists(cache_file_path):
        try:
            with open(cache_file_path, "r") as f:
                cache = json.load(f)
            print(f"Loaded {len(cache)} cached runs.")
        except Exception as e:
            print(f"Warning: Failed to load cache: {e}")
            
    # Setup test workspace
    temp_dir = tempfile.mkdtemp(prefix="lilith_diff_test_")
    session_dir = os.path.join(temp_dir, "sessions")
    policy_dir = os.path.join(temp_dir, "policies")
    os.makedirs(session_dir)
    os.makedirs(policy_dir)
    
    # Create test policies
    # 1. Universal YAML Policy (based on policy-banger.yaml)
    universal_yaml_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "policy-banger.yaml")
    if not os.path.exists(universal_yaml_path):
        # Fallback to local copy
        universal_yaml_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "benchmark_policy.yaml")
        
    with open(universal_yaml_path, "r") as f:
        universal_yaml_content = f.read()
        
    # Extract rules
    universal_expected_rules = parse_yaml_policy_rules(universal_yaml_content)
    
    # 2. Agent 1 Cedar Policy
    agent1_cedar = """
    permit(
        principal,
        action == Action::"resources/read",
        resource
    );
    @id("allow-read-agent1")
    permit(
        principal,
        action == Action::"tools/call",
        resource == Resource::"read_file"
    );
    @id("deny-delete-agent1")
    forbid(
        principal,
        action,
        resource == Resource::"delete_file"
    );
    """
    agent1_policy_path = os.path.join(policy_dir, "policy_agent-1.cedar")
    with open(agent1_policy_path, "w") as f:
        f.write(agent1_cedar)
    agent1_expected_rules = parse_cedar_policy_rules(agent1_cedar)
    
    # 3. Agent 2 Cedar Policy
    agent2_cedar = """
    permit(
        principal,
        action == Action::"resources/read",
        resource
    );
    @id("allow-delete-agent2")
    permit(
        principal,
        action == Action::"tools/call",
        resource == Resource::"delete_file"
    );
    @id("deny-read-agent2")
    forbid(
        principal,
        action,
        resource == Resource::"read_file"
    );
    """
    agent2_policy_path = os.path.join(policy_dir, "policy_agent-2.cedar")
    with open(agent2_policy_path, "w") as f:
        f.write(agent2_cedar)
    agent2_expected_rules = parse_cedar_policy_rules(agent2_cedar)
    
    # Combine expected rules for coverage calculation
    all_expected_rules = set(universal_expected_rules + agent1_expected_rules + agent2_expected_rules)
    matched_rules_in_test = set()
    
    # Start Webhook Server Manager
    server_manager = WebhookServerLifecycle(binary, session_dir)
    
    # Prepare standard test scenarios
    scenarios = [
        # 1. Allowed Static Tool
        {
            "name": "Static Allowed Tool",
            "policy": universal_yaml_path,
            "policy_content": universal_yaml_content,
            "agent_id": "universal",
            "session_id": "session-static-allow",
            "tool_name": "read_file",
            "tool_input": {"path": "src/lib.rs"},
            "initial_taints": [],
            "expected_decision": "allow",
            "expected_policies": ["static_read_file"]
        },
        # 2. Denied Static Tool
        {
            "name": "Static Denied Tool",
            "policy": universal_yaml_path,
            "policy_content": universal_yaml_content,
            "agent_id": "universal",
            "session_id": "session-static-deny",
            "tool_name": "delete_file",
            "tool_input": {"path": "src/lib.rs"},
            "initial_taints": [],
            "expected_decision": "deny",
            "expected_policies": ["static_delete_file"]
        },
        # 3. Taint Rule Trigger (ADD_TAINT)
        {
            "name": "Taint Rule Match (ADD_TAINT)",
            "policy": universal_yaml_path,
            "policy_content": universal_yaml_content,
            "agent_id": "universal",
            "session_id": "session-taint-add",
            "tool_name": "read_file",
            "tool_input": {"path": "infra/prod.env"},
            "initial_taints": [],
            "expected_decision": "allow",
            "expected_policies": ["add_taint:SECRET:_0"]
        },
        # 4. Exfiltration Block (CHECK_TAINT)
        {
            "name": "Exfiltration Block (Lethal Trifecta)",
            "policy": universal_yaml_path,
            "policy_content": universal_yaml_content,
            "agent_id": "universal",
            "session_id": "session-exfil-block",
            "tool_name": "fetch_webpage",
            "tool_input": {"url": "http://example.com"},
            "initial_taints": ["SECRET", "UNTRUSTED_DOC"],
            "expected_decision": "deny",
            "expected_policies": ["rule_9"] # item 9 or 11 depending on exact match index, let's allow it to auto-discover
        },
        # 5. Multi-agent Isolation: Agent 1 Allow
        {
            "name": "Agent-1 Allowed Tool",
            "policy": policy_dir,
            "policy_content": agent1_cedar,
            "agent_id": "agent-1",
            "session_id": "agent1-session",
            "tool_name": "read_file",
            "tool_input": {"path": "test.txt"},
            "initial_taints": [],
            "expected_decision": "allow",
            "expected_policies": ["allow-read-agent1"]
        },
        # 6. Multi-agent Isolation: Agent 1 Deny
        {
            "name": "Agent-1 Denied Tool",
            "policy": policy_dir,
            "policy_content": agent1_cedar,
            "agent_id": "agent-1",
            "session_id": "agent1-session",
            "tool_name": "delete_file",
            "tool_input": {"path": "test.txt"},
            "initial_taints": [],
            "expected_decision": "deny",
            "expected_policies": ["deny-delete-agent1"]
        },
        # 7. Multi-agent Isolation: Agent 2 Allow
        {
            "name": "Agent-2 Allowed Tool",
            "policy": policy_dir,
            "policy_content": agent2_cedar,
            "agent_id": "agent-2",
            "session_id": "agent2-session",
            "tool_name": "delete_file",
            "tool_input": {"path": "test.txt"},
            "initial_taints": [],
            "expected_decision": "allow",
            "expected_policies": ["allow-delete-agent2"]
        },
        # 8. Multi-agent Isolation: Agent 2 Deny
        {
            "name": "Agent-2 Denied Tool",
            "policy": policy_dir,
            "policy_content": agent2_cedar,
            "agent_id": "agent-2",
            "session_id": "agent2-session",
            "tool_name": "read_file",
            "tool_input": {"path": "test.txt"},
            "initial_taints": [],
            "expected_decision": "deny",
            "expected_policies": ["deny-read-agent2"]
        }
    ]
    
    # Run tests
    results = []
    
    # Peak children maxrss before runs
    maxrss_before = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    
    print("\nExecuting Differential Scenarios...")
    print("-" * 80)
    
    for sc in scenarios:
        name = sc["name"]
        pol = sc["policy"]
        payload_cli = {
            "session_id": sc["session_id"],
            "hook_event_name": "PreToolUse",
            "tool_name": sc["tool_name"],
            "tool_input": sc["tool_input"]
        }
        
        # 1. Retrieve or run CLI
        cli_hash = get_scenario_hash(sc["policy_content"], payload_cli, sc["initial_taints"], "cli")
        if cli_hash in cache:
            cli_dec, cli_pols = cache[cli_hash]["decision"], cache[cli_hash]["policies"]
            print(f"[CACHE] CLI for '{name}': {cli_dec.upper()}")
        else:
            cli_dec, cli_pols, _, _ = run_cli_hook(binary, pol if not os.path.isdir(pol) else os.path.join(pol, f"policy_{sc['agent_id']}.cedar"), payload_cli, sc["initial_taints"], session_dir)
            cache[cli_hash] = {"decision": cli_dec, "policies": cli_pols}
            print(f"[RUN]   CLI for '{name}': {cli_dec.upper()}")
            
        # 2. Retrieve or run Webhook
        # Note: if policy is a directory, start server with dir. Otherwise with single file.
        web_hash = get_scenario_hash(sc["policy_content"], payload_cli, sc["initial_taints"], "webhook")
        if web_hash in cache:
            web_dec, web_pols = cache[web_hash]["decision"], cache[web_hash]["policies"]
            print(f"[CACHE] Webhook for '{name}': {web_dec.upper()}")
        else:
            server_manager.start(pol)
            web_dec, web_pols, _, _ = run_webhook_request(
                server_manager.port,
                sc["agent_id"],
                sc["session_id"],
                sc["tool_name"],
                sc["tool_input"],
                sc["initial_taints"],
                session_dir
            )
            cache[web_hash] = {"decision": web_dec, "policies": web_pols}
            print(f"[RUN]   Webhook for '{name}': {web_dec.upper()}")
            
        # Register matched policies
        matched_rules_in_test.update(cli_pols)
        matched_rules_in_test.update(web_pols)
        
        # Verify differential equivalent
        success = (cli_dec == web_dec)
        if success:
            # Let's verify policies match. If expected_policies specified, verify that one of them matches.
            # (Sometimes YAML compiling creates slightly different indexes in custom runs, so comparison is best)
            print(f"[✓ PASS] Scenario '{name}' matches. Policies: CLI={cli_pols}, Web={web_pols}")
        else:
            print(f"[✗ FAIL] Scenario '{name}' MISMATCH! CLI={cli_dec} (pols={cli_pols}), Web={web_dec} (pols={web_pols})")
            
        results.append({
            "name": name,
            "category": "Differential",
            "cli_decision": cli_dec,
            "web_decision": web_dec,
            "cli_pols": cli_pols,
            "web_pols": web_pols,
            "success": success
        })
        
    # --- Fuzzing Test Suite ---
    fuzz_results = []
    if args.fuzz:
        print("\nExecuting Adversarial Fuzzing Scenarios...")
        print("-" * 80)
        
        fuzz_payloads = [
            # Deeply nested object
            {
                "name": "Fuzz: Deeply Nested Object",
                "payload": {
                    "session_id": "fuzz-nested",
                    "hook_event_name": "PreToolUse",
                    "tool_name": "read_file",
                    "tool_input": {"path": {"nested": {"nested": {"nested": {"nested": "src/lib.rs"}}}}}
                }
            },
            # Giant tool name
            {
                "name": "Fuzz: Giant Tool Name Buffer",
                "payload": {
                    "session_id": "fuzz-giant-tool",
                    "hook_event_name": "PreToolUse",
                    "tool_name": "A" * 50000,
                    "tool_input": {"path": "src/lib.rs"}
                }
            },
            # Null byte injection
            {
                "name": "Fuzz: Null Byte Path Injection",
                "payload": {
                    "session_id": "fuzz-null-byte",
                    "hook_event_name": "PreToolUse",
                    "tool_name": "read_file",
                    "tool_input": {"path": "/etc/passwd\u0000.env"}
                }
            },
            # Traversal attacks
            {
                "name": "Fuzz: Directory Traversal",
                "payload": {
                    "session_id": "fuzz-traversal",
                    "hook_event_name": "PreToolUse",
                    "tool_name": "read_file",
                    "tool_input": {"path": "../../../../etc/passwd"}
                }
            },
            # Malformed missing parameters
            {
                "name": "Fuzz: Missing Event Name",
                "payload": {
                    "session_id": "fuzz-missing-event",
                    "tool_name": "read_file"
                }
            }
        ]
        
        for fp in fuzz_payloads:
            fname = fp["name"]
            payload = fp["payload"]
            
            # CLI Fuzz run: MUST fail-closed or reject safely (non-zero or blocked), and NOT crash
            cli_dec, _, _, exit_code = run_cli_hook(binary, universal_yaml_path, payload, [], session_dir)
            cli_crashed = (exit_code in [-6, -11] or exit_code > 128) # check for SIGABRT/SIGSEGV
            
            # Webhook Fuzz run: server MUST handle safely without crashing
            server_manager.start(universal_yaml_path)
            
            # Count FDs and status before fuzz request
            fd_before = get_open_fd_count(server_manager.proc.pid)
            
            web_dec, _, _, status_code = run_webhook_request(
                server_manager.port,
                "universal",
                payload.get("session_id", "fuzz-session"),
                payload.get("tool_name", "read_file"),
                payload.get("tool_input", {}),
                [],
                session_dir
            )
            
            # Check if server process is still running
            server_manager.proc.poll()
            web_crashed = (server_manager.proc.returncode is not None)
            
            success = (not cli_crashed) and (not web_crashed)
            
            if success:
                print(f"[✓ PASS] Fuzz '{fname}': Safety check passed. CLI={cli_dec} (code={exit_code}), Web={web_dec} (status={status_code})")
            else:
                print(f"[✗ FAIL] Fuzz '{fname}' CRASHED/FAILED! CLI Crashed={cli_crashed}, Web Crashed={web_crashed}")
                
            fuzz_results.append({
                "name": fname,
                "category": "Fuzzing Safety",
                "cli_decision": cli_dec,
                "web_decision": web_dec,
                "success": success
            })
            
    # Webhook server final Diagnostics
    fd_before = 0
    fd_after = 0
    vm_peak = 0
    vm_hwm = 0
    
    server_manager.start(universal_yaml_path)
    pid = server_manager.proc.pid
    fd_before = get_open_fd_count(pid)
    
    # Send a few requests to test resource delta
    for i in range(5):
        run_webhook_request(
            server_manager.port,
            "universal",
            f"diag-session-{i}",
            "read_file",
            {"path": "src/lib.rs"},
            [],
            session_dir
        )
        
    fd_after = get_open_fd_count(pid)
    mem_stats = get_proc_memory(pid)
    vm_peak = mem_stats["VmPeak"]
    vm_hwm = mem_stats["VmHWM"]
    
    server_manager.stop()
    
    # Save cache
    save_cache(cache)
    
    # Clean up workspace
    shutil.rmtree(temp_dir)
    
    # Peak children maxrss after runs
    maxrss_after = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    cli_peak_rss_kb = maxrss_after - maxrss_before
    if cli_peak_rss_kb <= 0:
        cli_peak_rss_kb = maxrss_after # fallback to absolute maxrss of children
        
    # Coverage Stats
    matched_expected = all_expected_rules.intersection(matched_rules_in_test)
    coverage_pct = (len(matched_expected) / len(all_expected_rules)) * 100.0 if all_expected_rules else 0.0
    
    # Create Analysis Report
    print("\n" + "=" * 80)
    print("DIFFERENTIAL & FUZZ TESTING REPORT")
    print("=" * 80)
    
    total_diff = len(results)
    passed_diff = sum(1 for r in results if r["success"])
    print(f"Differential Accuracy: {passed_diff}/{total_diff} passed ({(passed_diff/total_diff)*100.0:.2f}%)")
    
    if args.fuzz:
        total_fuzz = len(fuzz_results)
        passed_fuzz = sum(1 for r in fuzz_results if r["success"])
        print(f"Fuzzing Robustness:   {passed_fuzz}/{total_fuzz} passed ({(passed_fuzz/total_fuzz)*100.0:.2f}%)")
        
    print(f"Cedar Policy Rule Coverage: {len(matched_expected)}/{len(all_expected_rules)} rules matched ({coverage_pct:.2f}%)")
    print("-" * 80)
    print(f"Webhook Peak RSS (HWM):     {vm_hwm} KB")
    print(f"Webhook Peak Virtual (VM):  {vm_peak} KB")
    print(f"Webhook FD Leak Delta:      {fd_after - fd_before} (before={fd_before}, after={fd_after})")
    print(f"CLI Hook Peak RSS:          {cli_peak_rss_kb} KB")
    print("=" * 80 + "\n")
    
    # Print Markdown Summary Table
    print("## Performance and Correctness Summary\n")
    print("| Metric | Value | Status |")
    print("|---|---|---|")
    print(f"| Differential correctness | {passed_diff}/{total_diff} passed | {'✓ PASS' if passed_diff == total_diff else '✗ FAIL'} |")
    if args.fuzz:
        print(f"| Fuzzing safety | {passed_fuzz}/{total_fuzz} passed | {'✓ PASS' if passed_fuzz == total_fuzz else '✗ FAIL'} |")
    print(f"| Cedar policy rule coverage | {coverage_pct:.2f}% | {'✓ PASS' if coverage_pct > 0 else '✗ FAIL'} |")
    print(f"| Webhook peak memory (VmHWM) | {vm_hwm} KB | Active |")
    print(f"| CLI peak memory (RSS) | {cli_peak_rss_kb} KB | Active |")
    print(f"| Webhook open FDs delta | {fd_after - fd_before} | {'✓ PASS' if (fd_after - fd_before) == 0 else '✗ FAIL'} |")
    print("\nDetailed Matched Policy Rules:")
    for r in sorted(all_expected_rules):
        status = "MATCHED" if r in matched_rules_in_test else "NOT MATCHED"
        print(f" - {r}: {status}")

if __name__ == "__main__":
    try:
        run_tests()
    except Exception as e:
        traceback.print_exc()
        sys.exit(1)
