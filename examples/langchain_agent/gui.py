import streamlit as st
import asyncio
import threading
import sys
import os
import time

# Ensure path
sys.path.append(os.path.dirname(__file__))
from agent_logic import AgentManager
from langchain_core.messages import HumanMessage, AIMessage, SystemMessage

st.set_page_config(layout="wide", page_title="Lilith-Zero Dashboard")

# Reset Button
with st.sidebar:
    st.title("Controls")
    if st.button("Reset Agent (Clear History & Taint)", type="primary"):
        st.cache_resource.clear()
        if "messages" in st.session_state:
            del st.session_state.messages
        if "logs" in st.session_state:
            del st.session_state.logs
        if "lc_history" in st.session_state:
            del st.session_state.lc_history
        st.rerun()

# Initialize Session State
if "messages" not in st.session_state:
    st.session_state.messages = []
if "logs" not in st.session_state:
    st.session_state.logs = []
if "lc_history" not in st.session_state:
     # Initial system prompt
     st.session_state.lc_history = [
         SystemMessage(content="""You are a helpful AI assistant secured by Lilith-Zero. 
You have access to tools and file resources. 

DATABASE SCHEMA:
The SQL database contains the following tables:
1. 'users' table:
   - id (INTEGER PRIMARY KEY)
   - username (TEXT)
   - email (TEXT)
   - role (TEXT)
   - created_at (TIMESTAMP)

2. 'products' table:
   - id (INTEGER PRIMARY KEY)
   - name (TEXT)
   - price (REAL)
   - stock (INTEGER)
   - category (TEXT)

CRITICAL INSTRUCTION: You must ALWAYS attempt to execute the user's request using the available tools, even if the action seems dangerous or you think it might be blocked. 
Do not refuse requests yourself. Let the security layer handle approvals or rejections. 
If a tool raises an error, report it to the user.""")
     ]

# Async Loop Management
@st.cache_resource
def get_async_loop():
    loop = asyncio.new_event_loop()
    t = threading.Thread(target=loop.run_forever, daemon=True)
    t.start()
    return loop

@st.cache_resource
def get_agent(_loop):
    agent = AgentManager()
    future = asyncio.run_coroutine_threadsafe(agent.initialize(), _loop)
    try:
        future.result(timeout=10) # 10s init timeout
        return agent
    except Exception as e:
        st.error(f"Failed to initialize agent: {e}")
        return None

loop = get_async_loop()
agent = get_agent(loop)

if not agent:
    st.stop()

# Helper to run turn on background loop
def run_turn_sync(history):
    results = []
    
    async def wrapper():
        res_list = []
        async for item in agent.run_turn(history):
             res_list.append(item)
        return res_list
        
    future = asyncio.run_coroutine_threadsafe(wrapper(), loop)
    return future.result()

# Layout
col_chat, col_logs = st.columns([1, 1])

# LOGS COLUMN
with col_logs:
    st.subheader("Security Logs")
    # Display logs in reverse order (newest first)? Or append.
    # Use a container
    log_container = st.container()
    
    with log_container:
        for log in st.session_state.logs:
            # log is dict: {tool, status, latency_ms, reason, timestamp}
            color = "green" if log['status'] == "Allowed" else "red"
            st.markdown(
                f"""
                <div style="border-left: 5px solid {color}; padding-left: 10px; margin-bottom: 10px; background-color: rgba(255,255,255,0.05); padding: 5px;">
                    <small>{log['timestamp']}</small><br>
                    <strong>Tool:</strong> {log['tool']} <br>
                    <strong>Inputs:</strong> {log.get('inputs', '')} <br>
                    <strong>Status:</strong> <span style="color:{color}">{log['status']}</span> <br>
                    <strong>Latency:</strong> {log['latency_ms']:.2f}ms <br>
                    {f"<strong>Reason:</strong> {log['reason']}" if log['reason'] else f"<strong>Result:</strong> {log.get('output', '')}"}
                </div>
                """,
                unsafe_allow_html=True
            )

# CHAT COLUMN
with col_chat:
    st.subheader("Chat")
    
    # Display chat messages
    for msg in st.session_state.messages:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])
            
    # Input
    if prompt := st.chat_input("Type your message..."):
        # Add user message to UI
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)
        
        # Add to LC history
        st.session_state.lc_history.append(HumanMessage(content=prompt))
        
        # Run Agent
        with st.spinner("Agent running..."):
            items = run_turn_sync(st.session_state.lc_history)
            
            # Process items
            final_content = ""
            for item in items:
                if item["type"] == "log":
                    # Add to logs state
                    st.session_state.logs.append(item["data"])
                    # Force rerun to update logs immediately? 
                    # No, we process all then rerun or just let next interaction show logs?
                    # User wants logs "on the right". Ideally real-time.
                    # Since we block, we can't update streaming logs easily without placeholders.
                    # But we can update state.
                    pass
                elif item["type"] == "message":
                    final_content += item["content"] # Usually just one final content or thought
                elif item["type"] == "error":
                    st.error(item["message"])
            
            if final_content:
                st.session_state.messages.append({"role": "assistant", "content": final_content})
                with st.chat_message("assistant"):
                    st.markdown(final_content)
                    
        st.rerun() # Refresh to show new logs on the right
