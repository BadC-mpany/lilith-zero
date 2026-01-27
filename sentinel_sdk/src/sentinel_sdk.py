import os
import logging
import json
import asyncio
import uuid
import platform
from typing import List, Optional, Any, Dict, Union
from contextlib import asynccontextmanager

# Handle imports whether running as package or directly
try:
    from .constants import (
        MCP_PROTOCOL_VERSION,
        SDK_NAME,
        SESSION_TIMEOUT_ITERATIONS,
        SESSION_POLL_INTERVAL_SEC,
        ENV_BINARY_PATH,
        ENV_POLICY_PATH,
        get_binary_name,
    )
    from .constants import __version__
except ImportError:
    from constants import (
        MCP_PROTOCOL_VERSION,
        SDK_NAME,
        SESSION_TIMEOUT_ITERATIONS,
        SESSION_POLL_INTERVAL_SEC,
        ENV_BINARY_PATH,
        ENV_POLICY_PATH,
        get_binary_name,
    )
    from constants import __version__

logger = logging.getLogger("sentinel_sdk")

class SentinelClient:
    """
    Sentinel Client for secure AI agent sessions (Middleware Mode).
    
    Manages the lifecycle of the Sentinel sidecar process.
    Communication happens via Stdio (JSON-RPC 2.0).
    """
    
    def __init__(self, 
                 upstream_cmd: str, 
                 upstream_args: Optional[List[str]] = None,
                 binary_path: Optional[str] = None,
                 policy_path: Optional[str] = None):
        
        self.upstream_cmd = upstream_cmd
        self.upstream_args = upstream_args if upstream_args is not None else []
        self.binary_path = binary_path or os.getenv(ENV_BINARY_PATH, get_binary_name())
        self.policy_path = policy_path or os.getenv(ENV_POLICY_PATH)
        
        self.process: Optional[asyncio.subprocess.Process] = None
        self.session_id: Optional[str] = None
        self._lock = asyncio.Lock()
        self._pending_requests: Dict[str, asyncio.Future] = {}
        self._reader_task: Optional[asyncio.Task] = None

    async def __aenter__(self):
        await self.start_session()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.stop_session()

    async def start_session(self):
        """Start the Sentinel middleware process."""
        cmd = [self.binary_path]
        if self.policy_path:
            cmd.extend(["--policy", self.policy_path])
        
        cmd.extend(["--upstream-cmd", self.upstream_cmd])
        if self.upstream_args:
            cmd.append("--")
            cmd.extend(self.upstream_args)

        logger.info(f"Spawning Sentinel: {cmd}")
        
        try:
            self.process = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError:
            raise FileNotFoundError(f"Sentinel binary not found at: {self.binary_path}")

        # Start reading stdout loop
        self._reader_task = asyncio.create_task(self._read_stdout_loop())
        # Start reading stderr to capture session ID
        asyncio.create_task(self._process_stderr())
        
        # Wait for Session ID to be established (handshake)
        for _ in range(SESSION_TIMEOUT_ITERATIONS):
            if self.session_id:
                break
            await asyncio.sleep(SESSION_POLL_INTERVAL_SEC)
            
        if not self.session_id:
            # Check if process died
            if self.process.returncode is not None:
                raise RuntimeError(f"Sentinel process died immediately. Return code: {self.process.returncode}")
            raise TimeoutError("Timed out waiting for Sentinel Session ID")
            
        # Perform MCP Handshake
        logger.info("Sending initialize request...")
        init_result = await self._send_request("initialize", {
            "protocolVersion": MCP_PROTOCOL_VERSION, 
            "capabilities": {}, 
            "clientInfo": {"name": SDK_NAME, "version": __version__}
        })
        logger.info(f"Initialized: {init_result}")
        
        # Send initialized notification
        await self._send_notification("notifications/initialized", {})

    async def stop_session(self):
        """Terminate the Sentinel process."""
        if self._reader_task:
            self._reader_task.cancel()
            
        if self.process:
            try:
                self.process.terminate()
                await self.process.wait()
            except ProcessLookupError:
                pass
        self.session_id = None

    async def _process_stderr(self):
        """Read stderr to extract logs and Session ID."""
        if not self.process or not self.process.stderr:
            return
            
        while True:
            line = await self.process.stderr.readline()
            if not line:
                break
            
            line_str = line.decode().strip()
            # Check for Session ID handshake
            if line_str.startswith("SENTINEL_SESSION_ID="):
                self.session_id = line_str.split("=", 1)[1]
                logger.info(f"Captured Session ID: {self.session_id}")
            else:
                # Forward other logs to python logger
                logger.debug(f"[Sentinel Stderr] {line_str}")

    async def _read_stdout_loop(self):
        """Read JSON-RPC responses from stdout."""
        if not self.process or not self.process.stdout:
            return

        while True:
            line = await self.process.stdout.readline()
            if not line:
                break
            
            try:
                msg = json.loads(line.decode())
                
                # Handle Response
                if "id" in msg:
                    req_id = str(msg["id"])
                    if req_id in self._pending_requests:
                        future = self._pending_requests.pop(req_id)
                        if not future.done():
                            if "error" in msg and msg["error"] is not None:
                                future.set_exception(RuntimeError(f"Sentinel Error: {msg['error']}"))
                            else:
                                future.set_result(msg.get("result", {}))
            except json.JSONDecodeError:
                logger.error(f"Failed to decode JSON from Sentinel: {line}")
            except Exception as e:
                logger.error(f"Error in read loop: {e}")

    async def _send_notification(self, method: str, params: Dict[str, Any]):
        if not self.process or not self.process.stdin:
            raise RuntimeError("Sentinel process not running")
            
        request = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params
        }
        
        data = json.dumps(request) + "\n"
        async with self._lock:
            self.process.stdin.write(data.encode())
            await self.process.stdin.drain()

    async def _send_request(self, method: str, params: Dict[str, Any]) -> Any:
        if not self.process or not self.process.stdin:
            raise RuntimeError("Sentinel process not running")

        req_id = str(uuid.uuid4())
        
        # Inject Session ID for strict validation
        if self.session_id:
            if params is None: 
                params = {}
            params["_sentinel_session_id"] = self.session_id

        request = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": req_id
        }
        
        future = asyncio.Future()
        self._pending_requests[req_id] = future
        
        data = json.dumps(request) + "\n"
        async with self._lock:
            self.process.stdin.write(data.encode())
            await self.process.stdin.drain()
            
        return await future

    async def get_tools_config(self) -> List[Dict[str, Any]]:
        """Fetch raw tool configurations."""
        response = await self._send_request("tools/list", {})
        return response.get("tools", [])

    async def execute_tool(self, tool_name: str, args: Dict[str, Any]) -> Any:
        """Execute a tool via the Sentinel Middleware."""
        payload = {
            "name": tool_name,
            "arguments": args
        }
        result = await self._send_request("tools/call", payload)
        
        # Unpack result content if standard MCP
        # "content": [{"type":"text", "text":"..."}]
        if "content" in result:
             # Just return the raw structure for now, let Agent handle parsing
             # Or helper to extract text?
             pass
        return result

    # --- Integrations ---

    async def get_langchain_tools(self):
        """Convert Sentinel tools to LangChain compatible tools."""
        try:
            from langchain_core.tools import StructuredTool
        except ImportError:
            raise ImportError("langchain-core is required for get_langchain_tools")

        configs = await self.get_tools_config()
        tools = []
        
        for config in configs:
            name = config["name"]
            description = config["description"]
            
            # Create a closure to capture the tool name
            async def _tool_func(tool_name=name, **kwargs):
                return await self.execute_tool(tool_name, kwargs)
            
            args_schema = self._create_pydantic_model(name, config.get("inputSchema", {}))
            
            tool = StructuredTool.from_function(
                coroutine=_tool_func,
                name=name,
                description=description,
                args_schema=args_schema,
            )
            tools.append(tool)
            
        return tools

    def _create_pydantic_model(self, name: str, json_schema: Dict[str, Any]):
        try:
            # Prefer Pydantic V1 for LangChain compatibility if available
            try:
                from pydantic.v1 import create_model, Field
            except ImportError:
                from pydantic import create_model, Field
        except ImportError:
             raise ImportError("pydantic is required for tool schema generation")

        fields = {}
        properties = json_schema.get("properties", {})
        required = set(json_schema.get("required", []))
        
        for field_name, field_info in properties.items():
            field_type = str
            if field_info.get("type") == "integer":
                field_type = int
            elif field_info.get("type") == "boolean":
                field_type = bool
            elif field_info.get("type") == "number":
                field_type = float
            elif field_info.get("type") == "array":
                field_type = list
            elif field_info.get("type") == "object":
                field_type = dict

            is_required = field_name in required
            default = ... if is_required else None
            
            fields[field_name] = (field_type, Field(default=default, description=field_info.get("description", "")))
        
        return create_model(f"{name}Schema", **fields)
