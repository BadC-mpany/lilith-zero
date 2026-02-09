# Copyright 2026 BadCompany
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Lilith SDK - Secure MCP Middleware for AI Agents.

This module provides the core Lilith class for wrapping MCP tool servers
with policy enforcement, session security, and process isolation.

Example:
    async with Lilith("python mcp_server.py", policy="policy.yaml") as s:
        tools = await s.list_tools()
        result = await s.call_tool("my_tool", {"arg": "value"})

Copyright 2026 BadCompany. All Rights Reserved.
"""

import asyncio
import json
import logging
import os
import shutil
import uuid
from typing import Any, Dict, List, Optional, Type, cast, TypedDict
from asyncio import Future, Task

from .exceptions import (
    LilithError,
    LilithConfigError,
    LilithConnectionError,
    PolicyViolationError,
    LilithProcessError,
)
from .installer import get_default_install_dir, install_Lilith

__all__ = ["Lilith", "LilithError", "PolicyViolationError"]

# -------------------------------------------------------------------------
# Type Definitions
# -------------------------------------------------------------------------

class ToolRef(TypedDict):
    name: str
    description: Optional[str]
    inputSchema: Dict[str, Any]

class ToolCall(TypedDict):
    name: str
    arguments: Dict[str, Any]

class ToolResult(TypedDict):
    content: List[Dict[str, Any]]
    isError: Optional[bool]


# Module-level constants
_MCP_PROTOCOL_VERSION = "2024-11-05"
_SDK_NAME = "lilith-zero"
_SDK_VERSION = "0.1.0"
_SESSION_TIMEOUT_SEC = 5.0
_SESSION_POLL_INTERVAL_SEC = 0.1
_ENV_BINARY_PATH = "LILITH_ZERO_BINARY_PATH"

# Safety limits for transport
_MAX_HEADER_LINE_LENGTH = 1024       # 1KB per header line max
_MAX_PAYLOAD_SIZE = 128 * 1024 * 1024 # 128MB payload limit (rigorous protection)

# Auto-detect binary name based on OS
_BINARY_NAME = "lilith-zero.exe" if os.name == "nt" else "lilith-zero"

_logger = logging.getLogger("lilith_zero")


def _find_binary() -> str:
    """
    Discover Lilith binary via environment, PATH, or standard locations.
    
    Returns:
        Absolute path to the binary.
        
    Raises:
        LilithConfigError: If binary cannot be found.
    """
    # 1. Environment variable (Highest priority)
    env_path = os.getenv(_ENV_BINARY_PATH)
    if env_path:
        if os.path.exists(env_path):
            return os.path.abspath(env_path)
        else:
             _logger.warning(f"{_ENV_BINARY_PATH} set to '{env_path}' but file not found.")

    # 2. System PATH
    path_binary = shutil.which(_BINARY_NAME)
    if path_binary:
        return os.path.abspath(path_binary)

    # 3. Standard User Install Location (~/.lilith_zero/bin)
    user_bin = os.path.join(get_default_install_dir(), _BINARY_NAME)
    if os.path.exists(user_bin):
        return os.path.abspath(user_bin)

    # 4. Standard Dev/Cargo Location (Fallback for ease of dev)
    # Assumes we are in sdk_root/src/lilith_zero, binary in repo_root/lilith-zero/target/release
    # This is a heuristic for local development convenience.
    try:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        # Go up to repo root: 
        # sdk/src/lilith_zero/client.py -> sdk/src/lilith_zero -> sdk/src -> sdk -> repo
        repo_root = os.path.dirname(os.path.dirname(os.path.dirname(current_dir))) 
        dev_binary = os.path.join(repo_root, "lilith-zero", "target", "release", _BINARY_NAME)
        if os.path.exists(dev_binary):
             _logger.debug(f"Found dev binary at {dev_binary}")
             return dev_binary
    except Exception:
        pass

    # If we get here, we can't find it. Ask installer to guide user.
    return install_Lilith(interactive=False)


class Lilith:
    """Lilith Security Middleware for AI Agents.

    Wraps an upstream MCP tool server with policy enforcement, session integrity,
    and optional process sandboxing.

    Attributes:
        session_id: The HMAC-signed session identifier (set after connect).
    """

    def __init__(
        self,
        upstream: Optional[str] = None,
        *,
        policy: Optional[str] = None,
        binary: Optional[str] = None,
    ) -> None:
        """Initialize Lilith middleware configuration.

        Args:
            upstream: Command to run the upstream MCP server (e.g., "python server.py").
                      If None, Lilith starts in a mode waiting for connection (future).
                      Currently required.
            policy: Path to policy YAML file for rule-based enforcement.
            binary: Path to Lilith binary (auto-discovered if not provided).

        Raises:
            LilithConfigError: If upstream is empty or binary not found.
        """
        if not upstream or not upstream.strip():
            raise LilithConfigError("Upstream command is required in this version.", config_key="upstream")

        import shlex
        # Parse upstream command robustly (handles quotes/spaces correctly)
        try:
            parts = shlex.split(upstream.strip())
        except ValueError as e:
            raise LilithConfigError(f"Malformed upstream command: {e}", config_key="upstream")
            
        if not parts:
            raise LilithConfigError("Upstream command is empty after parsing.", config_key="upstream")
            
        self._upstream_cmd = parts[0]
        self._upstream_args = parts[1:] if len(parts) > 1 else []

        # Resolve binary path
        try:
            self._binary_path = binary or _find_binary()
        except LilithConfigError:
             # Re-raise with clean message
             raise

        if not os.path.exists(self._binary_path):
             raise LilithConfigError(f"Lilith binary not found at {self._binary_path}", config_key="binary")

        self._binary_path = os.path.abspath(self._binary_path)

        # Policy configuration
        self._policy_path = os.path.abspath(policy) if policy else None

        # Runtime state
        self._process: Optional[asyncio.subprocess.Process] = None
        self._session_id: Optional[str] = None
        self._lock = asyncio.Lock()
        self._pending_requests: Dict[str, Future[Any]] = {}
        self._reader_task: Optional[Task[None]] = None
        self._stderr_task: Optional[Task[None]] = None

    @property
    def session_id(self) -> Optional[str]:
        """The HMAC-signed session identifier."""
        return self._session_id
        
    @staticmethod
    def install_binary() -> None:
        """Helper to invoke the installer interactively."""
        install_Lilith(interactive=True)

    # -------------------------------------------------------------------------
    # Async Context Manager Protocol
    # -------------------------------------------------------------------------

    async def __aenter__(self) -> "Lilith":
        await self._connect()
        return self

    async def __aexit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Any,
    ) -> None:
        await self._disconnect()

    # -------------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------------

    async def list_tools(self) -> List[ToolRef]:
        """Fetch available tools from the upstream MCP server."""
        response = await self._send_request("tools/list", {})
        tools = response.get("tools", [])
        return cast(List[ToolRef], tools)

    async def call_tool(self, name: str, arguments: Dict[str, Any]) -> ToolResult:
        """Execute a tool call through Lilith policy enforcement.

        Raises:
            PolicyViolationError: If blocked by policy.
            ToolExecutionError: If the tool itself fails.
            LilithProcessError: If communication fails.
        """
        payload = {"name": name, "arguments": arguments}
        result = await self._send_request("tools/call", payload)
        return cast(ToolResult, result)

    # -------------------------------------------------------------------------
    # Connection Management (Private)
    # -------------------------------------------------------------------------

    async def _connect(self) -> None:
        cmd = self._build_command()
        _logger.info("Spawning Lilith: %s", " ".join(cmd))

        try:
            self._process = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except OSError as e:
            raise LilithConnectionError(f"Failed to spawn Lilith: {e}", phase="spawn", underlying_error=e)

        # Start background readers
        self._reader_task = asyncio.create_task(self._read_stdout_loop())
        self._stderr_task = asyncio.create_task(self._read_stderr_loop())

        try:
            # Wait for session ID
            await self._wait_for_session()

            # MCP handshake
            _logger.info("Performing MCP handshake...")
            await self._send_request(
                "initialize",
                {
                    "protocolVersion": _MCP_PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": _SDK_NAME, "version": _SDK_VERSION},
                },
            )
            await self._send_notification("notifications/initialized", {})
            _logger.info("Handshake complete. Session: %s", self._session_id)
        except Exception:
            # If handshake fails, ensure we clean up processes
            await self._disconnect()
            raise

    async def _disconnect(self) -> None:
        if self._reader_task:
            self._reader_task.cancel()
        if self._stderr_task:
            self._stderr_task.cancel()

        if self._process:
            try:
                self._process.terminate()
                await asyncio.wait_for(self._process.wait(), timeout=5.0)
            except (ProcessLookupError, asyncio.TimeoutError):
                try:
                    self._process.kill()
                except ProcessLookupError:
                    pass

        self._session_id = None

    def _build_command(self) -> List[str]:
        if not self._binary_path or not self._upstream_cmd:
            raise LilithConfigError("Invalid configuration for build_command")
            
        cmd: List[str] = [self._binary_path]

        if self._policy_path:
            cmd.extend(["--policy", self._policy_path])

        cmd.extend(["--upstream-cmd", self._upstream_cmd])
        if self._upstream_args:
            cmd.append("--")
            cmd.extend(self._upstream_args)

        return cmd

    async def _wait_for_session(self) -> None:
        """Poll for session ID from stderr or stdout."""
        iterations = int(_SESSION_TIMEOUT_SEC / _SESSION_POLL_INTERVAL_SEC)
        for _ in range(iterations):
            if self._session_id:
                return
            
            # Rigour: if reader loop died, we can stop waiting
            if self._reader_task and self._reader_task.done():
                try:
                    # Capture if it died with an exception
                    self._reader_task.result()
                except (asyncio.CancelledError, Exception) as e:
                    # If it was cancelled by _disconnect_with_error, it probably failed requests
                    # But here we are still in _connect, so pending_requests might be empty 
                    # except for 'initialize' which hasn't been sent yet.
                    raise LilithConnectionError(f"Connection failed during handshake: {e}", phase="handshake", underlying_error=e)
                
                raise LilithConnectionError("Lilith process terminated during handshake", phase="handshake")

            await asyncio.sleep(_SESSION_POLL_INTERVAL_SEC)

        if self._process and self._process.returncode is not None:
            # Read remaining stderr to give a clue
            err_msg = ""
            if self._process.stderr:
                err_bytes = await self._process.stderr.read()
                err_msg = err_bytes.decode(errors="ignore")
            
            raise LilithProcessError(
                f"Lilith process exited early with code {self._process.returncode}",
                exit_code=self._process.returncode,
                stderr=err_msg
            )
        raise LilithConnectionError("Timed out waiting for Lilith session ID", phase="handshake")

    # -------------------------------------------------------------------------
    # I/O Handling (Private)
    # -------------------------------------------------------------------------

    async def _read_stderr_loop(self) -> None:
        if not self._process or not self._process.stderr:
            return

        try:
            while True:
                line = await self._process.stderr.readline()
                if not line:
                    break

                text = line.decode().strip()
                if text.startswith("LILITH_ZERO_SESSION_ID="):
                    self._session_id = text.split("=", 1)[1]
                    _logger.info("Session ID: %s", self._session_id)
                else:
                    _logger.debug("[stderr] %s", text)
        except asyncio.CancelledError:
            pass

    async def _read_stdout_loop(self) -> None:
        if not self._process or not self._process.stdout:
            return

        try:
            while True:
                # 1. Read Headers
                headers = {}
                while True:
                    # Rigour: readline with a limit to avoid memory bloat on malformed input
                    line_bytes = await self._process.stdout.readline()
                    if not line_bytes:
                        return # EOF

                    if len(line_bytes) > _MAX_HEADER_LINE_LENGTH:
                        _logger.error("Header line too long (%d bytes)", len(line_bytes))
                        await self._disconnect_with_error("Protocol violation: header too long")
                        return

                    line = line_bytes.decode().strip()
                    if not line:
                        # End of headers (empty line)
                        break
                    
                    if ":" in line:
                        key, value = line.split(":", 1)
                        headers[key.lower().strip()] = value.strip()
                    elif line.startswith("LILITH_ZERO_SESSION_ID="):
                        self._session_id = line.split("=", 1)[1]
                        _logger.info("Session ID: %s", self._session_id)
                    else:
                        _logger.debug("[stdout noise] %s", line)

                # 2. Check Content-Length
                if "content-length" in headers:
                    try:
                        length = int(headers["content-length"])
                        
                        # Rigour: sanity check length
                        if length > _MAX_PAYLOAD_SIZE:
                            _logger.error("Payload too large (%d bytes)", length)
                            await self._disconnect_with_error(f"Payload exceeds limit ({_MAX_PAYLOAD_SIZE})")
                            return

                        if length > 0:
                            body = await self._process.stdout.readexactly(length)
                            msg = json.loads(body)
                            _logger.debug("Received: %s", body.decode(errors="replace")[:1000])
                            if "id" in msg:
                                self._dispatch_response(msg)
                    except (ValueError, asyncio.IncompleteReadError, json.JSONDecodeError) as e:
                        _logger.error("Failed to parse message: %s", e)
                        await self._disconnect_with_error(f"Message corruption: {e}")
                        return
                else:
                    # Rigour: If we got noise but no content-length, we might be out of sync.
                    # We continue for now, but in a production env, we might want to be stricter.
                    pass

        except asyncio.CancelledError:
            pass
        except Exception as e:
            _logger.exception("Uncaught error in reader loop: %s", e)
            await self._disconnect_with_error(str(e))
        finally:
            self._cleanup_pending_requests("Lilith process terminated unexpectedly")

    async def _disconnect_with_error(self, message: str) -> None:
        """Helper to terminate connection on protocol error and notify pending callers."""
        _logger.error("Disconnecting due to error: %s", message)
        
        # If we are in the reader task, don't let _disconnect cancel us yet
        current_task = asyncio.current_task()
        reader_task = self._reader_task
        if reader_task == current_task:
            self._reader_task = None
            
        await self._disconnect()
        self._cleanup_pending_requests(message)
        
        # If we were the reader task, we are done
        if reader_task == current_task:
             raise asyncio.CancelledError()

    def _cleanup_pending_requests(self, message: str) -> None:
        """Fail all pending requests with a descriptive error."""
        # Fail all futures that are still active
        for req_id in list(self._pending_requests.keys()):
            future = self._pending_requests.pop(req_id)
            if not future.done():
                future.set_exception(LilithProcessError(message))

    def _dispatch_response(self, msg: Dict[str, Any]) -> None:
        req_id = str(msg["id"])
        future = self._pending_requests.pop(req_id, None)
        if future and not future.done():
            if "error" in msg and msg["error"]:
                # Map standard JSON-RPC errors or specific Lilith codes
                error_data = msg["error"]
                code = error_data.get("code")
                message = error_data.get("message", "Unknown error")
                
                # Check for Policy Violation (Lilith specific code -32000 for now, or match string)
                if "Policy Violation" in message or code == -32000:
                    future.set_exception(PolicyViolationError(message, error_data.get("data")))
                else:
                    future.set_exception(LilithError(
                        f"Lilith RPC Error: {message}", 
                        context={"code": code, "data": error_data.get("data")}
                    ))
            else:
                future.set_result(msg.get("result", {}))

    # -------------------------------------------------------------------------
    # JSON-RPC Transport (Private)
    # -------------------------------------------------------------------------

    async def _send_notification(self, method: str, params: Dict[str, Any]) -> None:
        if not self._process or not self._process.stdin:
            raise LilithConnectionError("Lilith process not running", phase="runtime")

        request = {"jsonrpc": "2.0", "method": method, "params": params}
        body = json.dumps(request).encode("utf-8")
        header = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")

        async with self._lock:
            try:
                self._process.stdin.write(header + body)
                await self._process.stdin.drain()
            except (BrokenPipeError, ConnectionResetError) as e:
                 raise LilithConnectionError("Broken pipe to Lilith process", phase="runtime", underlying_error=e)

    async def _send_request(
        self, method: str, params: Optional[Dict[str, Any]] = None
    ) -> Any:
        # Check process status before even trying
        if not self._process or self._process.returncode is not None:
             raise LilithConnectionError("Lilith process is not running", phase="runtime")
        
        if not self._process.stdin:
            raise LilithConnectionError("Lilith stdin is closed", phase="runtime")

        req_id = str(uuid.uuid4())
        if params is None:
            params = {}
        if self._session_id:
            params["_lilith_zero_session_id"] = self._session_id

        request = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": req_id,
        }

        future: Future[Any] = asyncio.Future()
        self._pending_requests[req_id] = future

        body = json.dumps(request).encode("utf-8")
        header = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
        
        async with self._lock:
            try:
                self._process.stdin.write(header + body)
                await self._process.stdin.drain()
            except (BrokenPipeError, ConnectionResetError) as e:
                 self._pending_requests.pop(req_id, None)
                 raise LilithConnectionError("Broken pipe to Lilith process", phase="runtime", underlying_error=e)

        try:
            return await asyncio.wait_for(future, timeout=30.0)
        except asyncio.TimeoutError:
            self._pending_requests.pop(req_id, None)
            raise LilithError(f"Request '{method}' timed out after 30s")

