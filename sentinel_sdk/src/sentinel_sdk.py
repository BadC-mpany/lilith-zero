import os
import logging
import json
import asyncio
import uuid
from typing import List, Optional, Any, Dict

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

class Sentinel:
    """
    Sentinel - Deterministic Security Middleware for AI Agents.
    
    Wraps an upstream MCP tool server (subprocess) with policy enforcement,
    session security, and taint tracking.
    """
    
    def __init__(self, 
                 upstream_cmd: str, 
                 upstream_args: Optional[List[str]] = None,
                 binary_path: Optional[str] = None,
                 policy_path: Optional[str] = None,
                 mcp_version: Optional[str] = None,
                 audience_token: Optional[str] = None,
                 # Sandbox flags
                 language_profile: Optional[str] = None,
                 allow_read: Optional[List[str]] = None,
                 allow_write: Optional[List[str]] = None,
                 allow_net: bool = False,
                 allow_env: Optional[List[str]] = None,
                 dry_run: bool = False,
                 skip_handshake: bool = False):
        
        self.upstream_cmd = upstream_cmd
        self.upstream_args = upstream_args if upstream_args is not None else []
        
        # Sandbox config
        self.language_profile = language_profile
        self.allow_read = allow_read or []
        self.allow_write = allow_write or []
        self.allow_net = allow_net
        self.allow_env = allow_env or []
        self.dry_run = dry_run
        self.skip_handshake = skip_handshake
        
        # Resolve Binary Path
        _bin_path = binary_path or os.getenv(ENV_BINARY_PATH, get_binary_name())
        self.binary_path = os.path.abspath(_bin_path)
        
        # Resolve Policy Path
        _pol_path = policy_path or os.getenv(ENV_POLICY_PATH)
        self.policy_path = os.path.abspath(_pol_path) if _pol_path else None
        
        self.mcp_version_preference = mcp_version or MCP_PROTOCOL_VERSION
        self.audience_token = audience_token
        
        self.process: Optional[asyncio.subprocess.Process] = None
        self.session_id: Optional[str] = None
        self._lock = asyncio.Lock()
        self._pending_requests: Dict[str, asyncio.Future] = {}
        self._reader_task: Optional[asyncio.Task] = None
        self._stderr_task: Optional[asyncio.Task] = None
        
        # Captured output
        self.stdout_lines: List[str] = []
        self.stderr_lines: List[str] = []
    
    @staticmethod
    def start(
        upstream: str, 
        binary_path: Optional[str] = None,
        policy_path: Optional[str] = None,
        mcp_version: Optional[str] = None,
        **kwargs
    ):
        """
        Legacy/Sugar factory method to start Sentinel with a single command string.
        """
        parts = upstream.split()
        if not parts:
            raise ValueError("upstream command cannot be empty")
        
        return Sentinel(
            upstream_cmd=parts[0],
            upstream_args=parts[1:],
            binary_path=binary_path,
            policy_path=policy_path,
            mcp_version=mcp_version,
            **kwargs
        )

    async def __aenter__(self):
        await self.start_session()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if not self.dry_run:
            await self.stop_session()

    async def start_session(self):
        """Start the Sentinel middleware process."""
        cmd = [self.binary_path]
        if self.policy_path:
            cmd.extend(["--policy", self.policy_path])
        
        # Sandbox Args
        if self.language_profile:
            cmd.extend(["--language-profile", self.language_profile])
        
        for p in self.allow_read:
            cmd.extend(["--allow-read", p])
            
        for p in self.allow_write:
            cmd.extend(["--allow-write", p])
            
        if self.allow_net:
            cmd.append("--allow-net")
            
        for e in self.allow_env:
            cmd.extend(["--allow-env", e])
            
        if self.dry_run:
            cmd.append("--dry-run") # Hyphen fixed

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
            
        if self.dry_run:
            return

        # Start reading stdout loop (optional if skip_handshake)
        if not self.skip_handshake:
            self._reader_task = asyncio.create_task(self._read_stdout_loop())
        
        # Start reading stderr to capture session ID
        self._stderr_task = asyncio.create_task(self._process_stderr())
        
        if self.skip_handshake:
            # We still wait for session_id if possible
             for _ in range(SESSION_TIMEOUT_ITERATIONS):
                if self.session_id: break
                await asyncio.sleep(SESSION_POLL_INTERVAL_SEC)
             return

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
            "protocolVersion": self.mcp_version_preference, 
            "capabilities": {}, 
            "clientInfo": {"name": SDK_NAME, "version": __version__},
            "_audience_token": self.audience_token
        })
        logger.info(f"Initialized: {init_result}")
        
        # Send initialized notification
        await self._send_notification("notifications/initialized", {})

    async def stop_session(self):
        """
        Terminate the Sentinel process and cleanup resources.
        
        This method cancels the reader tasks and terminates the subprocess.
        """
        if self._reader_task:
            self._reader_task.cancel()
        if self._stderr_task:
            self._stderr_task.cancel()
            
        if self.process:
            try:
                self.process.terminate()
                await self.process.wait()
            except ProcessLookupError:
                pass
        self.session_id = None

    async def _process_stderr(self):
        """
        Internal task to read stderr for logs and session handshake.
        
        Extracts 'SENTINEL_SESSION_ID' printed by the middleware on startup.
        """
        if not self.process or not self.process.stderr:
            return
            
        try:
            while True:
                line = await self.process.stderr.readline()
                if not line:
                    break
                
                line_str = line.decode().strip()
                self.stderr_lines.append(line_str)
                # Check for Session ID handshake
                if line_str.startswith("SENTINEL_SESSION_ID="):
                    self.session_id = line_str.split("=", 1)[1]
                    logger.info(f"Captured Session ID: {self.session_id}")
                else:
                    # Forward other logs to python logger
                    logger.debug(f"[Sentinel Stderr] {line_str}")
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"Error reading stderr: {e}")

    async def _read_stdout_loop(self):
        """
        Internal loop to read JSON-RPC responses from the middleware's stdout.
        
        Dispatches responses to pending request futures.
        """
        if not self.process or not self.process.stdout:
            return

        try:
            while True:
                line = await self.process.stdout.readline()
                if not line:
                    break
                
                line_str = line.decode().strip()
                self.stdout_lines.append(line_str)
                
                try:
                    msg = json.loads(line_str)
                    
                    # Handle Response
                    if "id" in msg:
                        req_id = str(msg["id"])
                        if req_id in self._pending_requests:
                            future = self._pending_requests.pop(req_id)
                            if not future.done():
                                if "error" in msg and msg["error"] is not None:
                                    future.set_exception(RuntimeError(f"Sentinel RPC Error: {msg['error']}"))
                                else:
                                    future.set_result(msg.get("result", {}))
                except json.JSONDecodeError:
                    # Not a JSON line, maybe a log from upstream tool
                    logger.debug(f"[Sentinel Stdout] {line_str}")
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"Error in read loop: {e}")
        finally:
            # Mark all pending requests as failed if the loop ends
            # This prevents _send_request from hanging indefinitely
            for req_id, future in list(self._pending_requests.items()):
                if not future.done():
                    future.set_exception(RuntimeError("Sentinel process terminated unexpectedly"))
            self._pending_requests.clear()

    async def _send_notification(self, method: str, params: Dict[str, Any]):
        """Sent a JSON-RPC notification (no ID) to the middleware."""
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

    async def _send_request(self, method: str, params: Optional[Dict[str, Any]]) -> Any:
        """
        Send a JSON-RPC request and wait for the response.
        
        Automatically injects the session ID into the parameters.
        """
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
            "params": params or {},
            "id": req_id
        }
        
        future = asyncio.Future()
        self._pending_requests[req_id] = future
        
        data = json.dumps(request) + "\n"
        async with self._lock:
            self.process.stdin.write(data.encode())
            await self.process.stdin.drain()
            
        try:
            return await asyncio.wait_for(future, timeout=30.0)
        except asyncio.TimeoutError:
            # Clean up pending request on timeout
            if req_id in self._pending_requests:
                del self._pending_requests[req_id]
            raise RuntimeError(f"Sentinel request '{method}' timed out after 30 seconds")

    async def get_tools_config(self) -> List[Dict[str, Any]]:
        """
        Fetch the list of available tools from the upstream server through Sentinel.
        
        Returns:
            List of tool configuration dictionaries.
        """
        response = await self._send_request("tools/list", {})
        return response.get("tools", [])

    async def execute_tool(self, tool_name: str, args: Dict[str, Any]) -> Any:
        """
        Execute a tool call through the Sentinel Middleware.
        
        Args:
            tool_name: The name of the tool to call.
            args: Dictionary of arguments for the tool.
            
        Returns:
            The MCP result object (often containing a 'content' key).
        """
        payload = {
            "name": tool_name,
            "arguments": args
        }
        return await self._send_request("tools/call", payload)
