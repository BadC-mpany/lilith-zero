import streamlit as st
import asyncio
import os
import sys
import json
import re
from datetime import datetime

# Path setup to find Lilith Zero SDK and middleware
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
sys.path.insert(0, os.path.join(ROOT_DIR, "sdk"))

try:
    from lilith_zero import Lilith
    from lilith_zero.exceptions import PolicyViolationError
except ImportError:
    st.error("Lilith Zero SDK not found. Please run individual setup first.")
    st.stop()

# Constants
_EXT = ".exe" if os.name == "nt" else ""
LILITH_BINARY = os.path.join(ROOT_DIR, "lilith-zero/target/release/lilith-zero" + _EXT)
POLICY_PATH = os.path.join(os.path.dirname(__file__), "demo_policy.yaml")
SERVER_SCRIPT = os.path.join(os.path.dirname(__file__), "vulnerable_server.py")

# Page Config
st.set_page_config(
    page_title="Lilith Zero | MCP Security Controller",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for a professional look
st.markdown("""
<style>
    .reportview-container {
        background: #0e1117;
    }
    .stAlert {
        border-radius: 5px;
    }
    .log-container {
        font-family: 'Source Code Pro', monospace;
        background-color: #1e1e1e;
        color: #d4d4d4;
        padding: 10px;
        border-radius: 5px;
        font-size: 0.8rem;
    }
    .status-allowed { color: #4CAF50; font-weight: bold; }
    .status-denied { color: #F44336; font-weight: bold; }
</style>
""", unsafe_allow_html=True)

# Sidebar: Policy Management
with st.sidebar:
    st.title("Controller")
    st.subheader("Security Policy")
    
    if os.path.exists(POLICY_PATH):
        with open(POLICY_PATH, "r") as f:
            policy_content = f.read()
        
        new_policy = st.text_area("Live Policy Editor (YAML)", value=policy_content, height=400)
        
        if new_policy != policy_content:
            if st.button("Apply Policy"):
                with open(POLICY_PATH, "w") as f:
                    f.write(new_policy)
                st.success("Policy Updated & Hot-Reloaded")
                st.rerun()
    else:
        st.error("Policy file not found.")

    st.divider()
    st.info("Lilith Zero acts as a secure MCP Middleware, enforcing Least Privilege at the binary level.")

# Main UI
st.title("Lilith Zero: MCP Security Middleware")
st.caption("Runtime Process Isolation & Context-Aware Policy Enforcement")

col1, col2 = st.columns([1, 1])

with col1:
    st.subheader("Agent Operations")
    
    scenario = st.radio(
        "Select Attack/Test Scenario",
        [
            "Baseline: Unauthorized SQL Dump (Bypass)",
            "Protected: SQL Containment (RLS)",
            "Protected: Network Egress Control",
            "Protected: Valid Intelligence Aggregate"
        ]
    )
    
    st.divider()
    
    async def run_lilith_op(tool_name, tool_args, expect_block=True):
        status_placeholder = st.empty()
        
        status_placeholder.info(f"Initiating {tool_name}...")
        
        try:
            # Use sys.executable to ensure we use the same environment's python
            async with Lilith(
                upstream=f"{sys.executable} {SERVER_SCRIPT}",
                policy=POLICY_PATH,
                binary=LILITH_BINARY
            ) as client:
                
                status_placeholder.warning("Handshake established. Lilith Middleware active.")
                
                try:
                    start_time = datetime.now()
                    result = await client.call_tool(tool_name, tool_args)
                    latency = (datetime.now() - start_time).total_seconds() * 1000
                    
                    status_placeholder.success(f"Access Granted ({latency:.1f}ms)")
                    
                    st.write("### Resource Output")
                    raw_text = result['content'][0]['text']
                    clean_text = re.sub(r'<<<LILITH_ZERO_DATA_(START|END):[a-zA-Z0-9]+>>>', '', raw_text).strip()
                    
                    st.json(result)
                    st.info(f"**Cleaned Response:** {clean_text}")
                    
                except PolicyViolationError as e:
                    status_placeholder.error("SECURITY ENFORCED: REQUEST DENIED")
                    st.write("### Violation Report")
                    st.error(f"**Reason:** {str(e)}")
                    st.warning("Intervention: Blocked attempt to bypass database isolation rules.")
                except Exception as e:
                    st.error(f"Execution Error: {repr(e)}")
        except Exception as e:
            st.error(f"Middleware Error: {repr(e)}")
            st.info(f"Binary Path: {LILITH_BINARY}")
            st.info("Ensure the Lilith binary is built: `cargo build --release`")

    if st.button("Execute Request", type="primary"):
        if "Baseline" in scenario:
            st.error("CRITICAL: Exposing direct access (No Middleware)")
            st.write("### Unprotected Result")
            st.code("[{'id': 1, 'username': 'admin', 'api_key': 'sk_live_88374'}, ...]", language="json")
            st.error("Impact: RLS Bypass Successful. Full DB Dump Exfiltrated.")
        else:
            # Helper to run async in Streamlit
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            if scenario == "Protected: SQL Containment (RLS)":
                loop.run_until_complete(run_lilith_op("execute_sql", {"query": "SELECT * FROM users"}))
            elif scenario == "Protected: Network Egress Control":
                loop.run_until_complete(run_lilith_op("fetch_url", {"url": "http://evil-competitor.com/leak"}))
            elif scenario == "Protected: Valid Intelligence Aggregate":
                loop.run_until_complete(run_lilith_op("execute_sql", {"query": "SELECT COUNT(*) FROM users"}, expect_block=False))
            
            loop.close()

with col2:
    st.subheader("Middleware Audit Trail")
    
    # Placeholder for live tracing
    log_content = """[HANDSHAKE] Protocol: MCP 2024-11-05
[SUPERVISOR] Process ID 12842 spawned in sandbox
[ENGINE] Policy loaded: mcp-security-policy
[MONITOR] Memory: 12MB | CPU: 0.2%
"""
    st.markdown(f'<div class="log-container">{log_content.replace("\n", "<br>")}</div>', unsafe_allow_html=True)
    
    st.divider()
    st.subheader("Architectural Insight")
    st.write("""
    Lilith Zero differs from standard proxies by performing deep inspection of the JSON-RPC stream:
    - **Spotlighting**: Injects randomized tokens to prevent LLM data exfiltration.
    - **Process Supervision**: Forces upstream tools into isolated supervision.
    - **Deterministic Logic**: Policy evaluation happens in sub-millisecond Rust core.
    """)
    
    st.image("https://img.shields.io/badge/Performance-Sub--ms_Latency-green")
    st.image("https://img.shields.io/badge/Security-Fail--Closed-red")
