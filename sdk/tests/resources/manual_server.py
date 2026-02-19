import sys
import json
import logging
import inspect
from typing import Callable, Any, Dict, List

# Configure minimal logging to stderr
logging.basicConfig(level=logging.INFO, stream=sys.stderr, format='[MCP-Manual] %(message)s')
logger = logging.getLogger(__name__)

class ManualMCPServer:
    """Minimalistic MCP Server implementation with LSP-style framing."""
    
    def __init__(self) -> None:
        self._tools: Dict[str, Callable[..., Any]] = {}

    def tool(self, func: Callable[..., Any]) -> Callable[..., Any]:
        """Decorator to register a function as an MCP tool."""
        self._tools[func.__name__] = func
        return func

    def _get_tool_list(self) -> List[Dict[str, Any]]:
        """Auto-generate tool definitions from registered functions."""
        return [
            {
                "name": name,
                "description": func.__doc__ or "",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        k: {"type": "string"} 
                        for k in inspect.signature(func).parameters
                    }
                }
            }
            for name, func in self._tools.items()
        ]

    def run(self) -> None:
        """Main JSON-RPC loop."""
        logger.info("Server started (Stdio Transport)")
        while True:
            try:
                # Read Headers
                line = sys.stdin.readline()
                if not line: break
                
                text = line.strip()
                if text.lower().startswith("content-length:"):
                    length = int(text.split(":")[1].strip())
                    # Consume lines until we hit the empty line
                    while True:
                        l = sys.stdin.readline()
                        if not l.strip(): break
                    
                    # Read Body
                    body = sys.stdin.read(length)
                    if not body: break
                    
                    req = json.loads(body)
                    self._handle_request(req)
                elif text:
                    # Ignore non-header lines or try to parse if it looks like JSON (resilience)
                     try:
                        req = json.loads(text)
                        # If we successfully parsed JSON from a line without headers, 
                        # we might want to handle it, but for this strict test we ignore or log.
                        # Lilith sends headers, so we expect headers.
                        pass
                     except:
                        pass
            except (json.JSONDecodeError, ValueError) as e:
                logger.error(f"JSON Error: {e}")
                continue

    def _handle_request(self, req: Dict[str, Any]):
        method = req.get("method")
        msg_id = req.get("id")
        params = req.get("params", {})
        
        response = {"jsonrpc": "2.0", "id": msg_id}

        try:
            if method == "initialize":
                response["result"] = {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "serverInfo": {"name": "ManualServer", "version": "1.0"}
                }
            
            elif method == "tools/list":
                response["result"] = {"tools": self._get_tool_list()}
            
            elif method == "tools/call":
                name = params.get("name")
                args = params.get("arguments", {})
                if name in self._tools:
                    result = self._tools[name](**args)
                    # Wrap result in MCP content format
                    response["result"] = {
                        "content": [{"type": "text", "text": str(result)}],
                        "isError": False
                    }
                elif name == "read_secret":
                    response["result"] = {
                        "content": [{"type": "text", "text": "super_secret_value"}],
                        "isError": False
                    }
                elif name == "network_send":
                    response["result"] = {
                        "content": [{"type": "text", "text": "sent"}],
                        "isError": False
                    }
                elif name == "redact_data":
                    response["result"] = {
                        "content": [{"type": "text", "text": "redacted"}],
                        "isError": False
                    }
                elif name == "conditional_access":
                    response["result"] = {
                        "content": [{"type": "text", "text": "access_granted"}],
                        "isError": False
                    }
                elif name == "wildcard_access":
                    response["result"] = {
                        "content": [{"type": "text", "text": "access_granted"}],
                        "isError": False
                    }
                else:
                    raise ValueError(f"Tool not found: {name}")
                    
            elif method == "notifications/initialized":
                return # No response needed

            else:
                # Method not found
                raise ValueError(f"Method not found: {method}")

        except Exception as e:
            logger.error(f"Error handling {method}: {e}")
            response["error"] = {"code": -32603, "message": str(e)}

        if msg_id is not None:
            body = json.dumps(response).encode("utf-8")
            # Write with Content-Length header
            header = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
            sys.stdout.buffer.write(header + body)
            sys.stdout.buffer.flush()

# --- Tool Definitions matching tests/resources/vulnerable_tools.py ---

server = ManualMCPServer()

@server.tool
def read_db(query: str) -> str:
    """Mock database read for basic flow tests."""
    return f"Result for {query}"

@server.tool
def send_slack(msg: str) -> str:
    """Mock slack send."""
    return f"Sent: {msg}"

@server.tool
def read_user_db(user_id: str) -> str:
    """Reads sensitive user data (PII)."""
    return f"User data for {user_id}: Sensitive PII Data. [CONFIDENTIAL]"

@server.tool
def export_to_cloud(data: str, destination: str = "default-sink") -> str:
    """Exports data to an external cloud sink."""
    return f"Successfully exported data to {destination}: {data}"

@server.tool
def sleep_tool(seconds: str) -> str:
    """Simulates a long-running process."""
    import time
    sec = float(seconds)
    time.sleep(sec)
    return f"Slept for {sec} seconds"

@server.tool
def ping() -> str:
    """Simple health check."""
    return "pong"

if __name__ == "__main__":
    server.run()
