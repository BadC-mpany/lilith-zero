"""
Sentinel SDK - Secure MCP Middleware for AI Agents.

This module provides the core Sentinel class for wrapping MCP tool servers
with policy enforcement, session security, and process isolation.

Example:
    async with Sentinel("python mcp_server.py", policy="policy.yaml") as s:
        tools = await s.list_tools()
        result = await s.call_tool("my_tool", {"arg": "value"})

Copyright 2024 Google DeepMind. All Rights Reserved.
"""

import asyncio
import json
import logging
import os
import shutil
import uuid
from typing import Any, Dict, List, Optional

__all__ = ["Sentinel"]

# Module-level constants
_MCP_PROTOCOL_VERSION = "2024-11-05"
_SDK_NAME = "sentinel-sdk"
_SDK_VERSION = "0.2.0"
_SESSION_TIMEOUT_SEC = 5.0
_SESSION_POLL_INTERVAL_SEC = 0.1
_ENV_BINARY_PATH = "SENTINEL_BINARY_PATH"
_BINARY_NAME = "sentinel.exe" if os.name == "nt" else "sentinel"
_BINARY_SEARCH_PATHS = [
    "sentinel/target/release/",
    "sentinel/target/debug/",
    "target/release/",
    "./",
]

_logger = logging.getLogger("sentinel_sdk")


def _find_binary() -> Optional[str]:
    """Discover Sentinel binary via environment, PATH, or relative paths."""
    # 1. Environment variable
    env_path = os.getenv(_ENV_BINARY_PATH)
    if env_path and os.path.exists(env_path):
        return os.path.abspath(env_path)

    # 2. System PATH
    path_binary = shutil.which(_BINARY_NAME)
    if path_binary:
        return path_binary

    # 3. Relative search paths (development)
    for search_path in _BINARY_SEARCH_PATHS:
        candidate = os.path.join(search_path, _BINARY_NAME)
        if os.path.exists(candidate):
            return os.path.abspath(candidate)

    return None


class Sentinel:
    """Sentinel Security Middleware for AI Agents.

    Wraps an upstream MCP tool server with policy enforcement, session integrity,
    and optional process sandboxing.

    Attributes:
        session_id: The HMAC-signed session identifier (set after connect).

    Example:
        async with Sentinel("python server.py", policy="policy.yaml") as s:
            tools = await s.list_tools()
            result = await s.call_tool("read_file", {"path": "/data/file.txt"})
    """

    # -------------------------------------------------------------------------
    # Construction
    # -------------------------------------------------------------------------

    def __init__(
        self,
        upstream: str,
        *,
        policy: Optional[str] = None,
        binary: Optional[str] = None,
        allow_read: Optional[List[str]] = None,
        allow_write: Optional[List[str]] = None,
        allow_net: bool = False,
        allow_env: Optional[List[str]] = None,
        language_profile: Optional[str] = None,
    ) -> None:
        """Initialize Sentinel middleware configuration.

        Args:
            upstream: Command to run the upstream MCP server (e.g., "python server.py").
            policy: Path to policy YAML file for rule-based enforcement.
            binary: Path to Sentinel binary (auto-discovered if not provided).
            allow_read: Paths the sandboxed process may read.
            allow_write: Paths the sandboxed process may write.
            allow_net: Whether to allow network access from sandbox.
            allow_env: Environment variables to expose to sandbox.
            language_profile: Runtime profile (e.g., "python:/path/to/venv").

        Raises:
            ValueError: If upstream command is empty.
            FileNotFoundError: If Sentinel binary cannot be found.
        """
        if not upstream or not upstream.strip():
            raise ValueError("upstream command cannot be empty")

        # Parse upstream command
        parts = upstream.strip().split()
        self._upstream_cmd = parts[0]
        self._upstream_args = parts[1:] if len(parts) > 1 else []

        # Resolve binary path
        self._binary_path = binary or _find_binary()
        if self._binary_path is None:
            raise FileNotFoundError(
                f"Sentinel binary not found. Set {_ENV_BINARY_PATH} or provide binary=."
            )
        self._binary_path = os.path.abspath(self._binary_path)

        # Policy configuration
        self._policy_path = os.path.abspath(policy) if policy else None

        # Sandbox permissions (Deno-style)
        self._allow_read = allow_read or []
        self._allow_write = allow_write or []
        self._allow_net = allow_net
        self._allow_env = allow_env or []
        self._language_profile = language_profile

        # Runtime state
        self._process: Optional[asyncio.subprocess.Process] = None
        self._session_id: Optional[str] = None
        self._lock = asyncio.Lock()
        self._pending_requests: Dict[str, asyncio.Future] = {}
        self._reader_task: Optional[asyncio.Task] = None
        self._stderr_task: Optional[asyncio.Task] = None

    @property
    def session_id(self) -> Optional[str]:
        """The HMAC-signed session identifier."""
        return self._session_id

    # -------------------------------------------------------------------------
    # Async Context Manager Protocol
    # -------------------------------------------------------------------------

    async def __aenter__(self) -> "Sentinel":
        """Start the Sentinel middleware and perform MCP handshake."""
        await self._connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Terminate the Sentinel process and cleanup resources."""
        await self._disconnect()

    # -------------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------------

    async def list_tools(self) -> List[Dict[str, Any]]:
        """Fetch available tools from the upstream MCP server.

        Returns:
            List of tool configuration dictionaries with 'name', 'description',
            and 'inputSchema' keys.
        """
        response = await self._send_request("tools/list", {})
        return response.get("tools", [])

    async def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a tool call through Sentinel policy enforcement.

        Args:
            name: The name of the tool to invoke.
            arguments: Dictionary of tool arguments.

        Returns:
            MCP result object (typically containing 'content' key).

        Raises:
            RuntimeError: If the tool call is blocked by policy or fails.
        """
        payload = {"name": name, "arguments": arguments}
        return await self._send_request("tools/call", payload)

    # -------------------------------------------------------------------------
    # Connection Management (Private)
    # -------------------------------------------------------------------------

    async def _connect(self) -> None:
        """Spawn Sentinel process and perform MCP handshake."""
        cmd = self._build_command()
        _logger.info("Spawning Sentinel: %s", " ".join(cmd))

        try:
            self._process = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError:
            raise FileNotFoundError(f"Sentinel binary not found: {self._binary_path}")

        # Start background readers
        self._reader_task = asyncio.create_task(self._read_stdout_loop())
        self._stderr_task = asyncio.create_task(self._read_stderr_loop())

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

    async def _disconnect(self) -> None:
        """Terminate subprocess and cancel background tasks."""
        if self._reader_task:
            self._reader_task.cancel()
        if self._stderr_task:
            self._stderr_task.cancel()

        if self._process:
            try:
                self._process.terminate()
                await asyncio.wait_for(self._process.wait(), timeout=5.0)
            except (ProcessLookupError, asyncio.TimeoutError):
                self._process.kill()

        self._session_id = None

    def _build_command(self) -> List[str]:
        """Construct the Sentinel CLI command."""
        cmd = [self._binary_path]

        if self._policy_path:
            cmd.extend(["--policy", self._policy_path])

        if self._language_profile:
            cmd.extend(["--language-profile", self._language_profile])

        for path in self._allow_read:
            cmd.extend(["--allow-read", path])

        for path in self._allow_write:
            cmd.extend(["--allow-write", path])

        if self._allow_net:
            cmd.append("--allow-net")

        for env_var in self._allow_env:
            cmd.extend(["--allow-env", env_var])

        cmd.extend(["--upstream-cmd", self._upstream_cmd])
        if self._upstream_args:
            cmd.append("--")
            cmd.extend(self._upstream_args)

        return cmd

    async def _wait_for_session(self) -> None:
        """Poll for session ID from stderr."""
        iterations = int(_SESSION_TIMEOUT_SEC / _SESSION_POLL_INTERVAL_SEC)
        for _ in range(iterations):
            if self._session_id:
                return
            await asyncio.sleep(_SESSION_POLL_INTERVAL_SEC)

        if self._process and self._process.returncode is not None:
            raise RuntimeError(
                f"Sentinel process exited with code {self._process.returncode}"
            )
        raise TimeoutError("Timed out waiting for Sentinel session ID")

    # -------------------------------------------------------------------------
    # I/O Handling (Private)
    # -------------------------------------------------------------------------

    async def _read_stderr_loop(self) -> None:
        """Read stderr for logs and session handshake."""
        if not self._process or not self._process.stderr:
            return

        try:
            while True:
                line = await self._process.stderr.readline()
                if not line:
                    break

                text = line.decode().strip()
                if text.startswith("SENTINEL_SESSION_ID="):
                    self._session_id = text.split("=", 1)[1]
                    _logger.info("Session ID: %s", self._session_id)
                else:
                    _logger.debug("[stderr] %s", text)
        except asyncio.CancelledError:
            pass

    async def _read_stdout_loop(self) -> None:
        """Read JSON-RPC responses from stdout."""
        if not self._process or not self._process.stdout:
            return

        try:
            while True:
                line = await self._process.stdout.readline()
                if not line:
                    break

                text = line.decode().strip()
                try:
                    msg = json.loads(text)
                    if "id" in msg:
                        self._dispatch_response(msg)
                except json.JSONDecodeError:
                    _logger.debug("[stdout] %s", text)
        except asyncio.CancelledError:
            pass
        finally:
            # Fail pending requests if loop ends
            for future in self._pending_requests.values():
                if not future.done():
                    future.set_exception(
                        RuntimeError("Sentinel process terminated unexpectedly")
                    )
            self._pending_requests.clear()

    def _dispatch_response(self, msg: Dict[str, Any]) -> None:
        """Route JSON-RPC response to waiting future."""
        req_id = str(msg["id"])
        future = self._pending_requests.pop(req_id, None)
        if future and not future.done():
            if "error" in msg and msg["error"]:
                future.set_exception(
                    RuntimeError(f"Sentinel error: {msg['error']}")
                )
            else:
                future.set_result(msg.get("result", {}))

    # -------------------------------------------------------------------------
    # JSON-RPC Transport (Private)
    # -------------------------------------------------------------------------

    async def _send_notification(self, method: str, params: Dict[str, Any]) -> None:
        """Send JSON-RPC notification (no response expected)."""
        if not self._process or not self._process.stdin:
            raise RuntimeError("Sentinel process not running")

        request = {"jsonrpc": "2.0", "method": method, "params": params}
        data = json.dumps(request) + "\n"

        async with self._lock:
            self._process.stdin.write(data.encode())
            await self._process.stdin.drain()

    async def _send_request(
        self, method: str, params: Optional[Dict[str, Any]] = None
    ) -> Any:
        """Send JSON-RPC request and await response."""
        if not self._process or not self._process.stdin:
            raise RuntimeError("Sentinel process not running")

        req_id = str(uuid.uuid4())

        # Inject session ID for validation
        if params is None:
            params = {}
        if self._session_id:
            params["_sentinel_session_id"] = self._session_id

        request = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": req_id,
        }

        future: asyncio.Future = asyncio.Future()
        self._pending_requests[req_id] = future

        data = json.dumps(request) + "\n"
        async with self._lock:
            self._process.stdin.write(data.encode())
            await self._process.stdin.drain()

        try:
            return await asyncio.wait_for(future, timeout=30.0)
        except asyncio.TimeoutError:
            self._pending_requests.pop(req_id, None)
            raise RuntimeError(f"Request '{method}' timed out after 30s")
