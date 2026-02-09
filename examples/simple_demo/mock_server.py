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

import sys
import json
import logging
import inspect
from typing import Callable, Any, Dict, List

logging.basicConfig(level=logging.INFO, stream=sys.stderr, format='[MCP] %(message)s')
logger = logging.getLogger(__name__)

class MCPServer:
    def __init__(self):
        self._tools: Dict[str, Callable] = {}

    def tool(self, func: Callable):
        self._tools[func.__name__] = func
        return func

    def _get_tool_list(self) -> List[Dict[str, Any]]:
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

    def run(self):
        while True:
            try:
                # Read Header
                line = sys.stdin.readline()
                if not line: break
                
                content_length = None
                if line.lower().startswith("content-length:"):
                    content_length = int(line.split(":", 1)[1].strip())
                    # Read until empty line
                    while True:
                        l = sys.stdin.readline()
                        if not l or l.strip() == "": break
                
                msg = None
                if content_length:
                    msg = sys.stdin.read(content_length)
                elif line.strip().startswith("{"):
                     # Fallback for plain JSON lines
                    msg = line

                if msg:
                    req = json.loads(msg)
                    self._handle_request(req)
            except Exception as e:
                # logger.error(f"Error: {e}")
                continue

    def _handle_request(self, req: Dict[str, Any]):
        method = req.get("method")
        msg_id = req.get("id")
        params = req.get("params", {})
        response = {"jsonrpc": "2.0", "id": msg_id}

        try:
            if method == "initialize":
                response["result"] = {"protocolVersion": "2024-11-05", "capabilities": {}, "serverInfo": {"name": "SimpleDemoServer", "version": "1.0"}}
            elif method == "tools/list":
                response["result"] = {"tools": self._get_tool_list()}
            elif method == "tools/call":
                name = params.get("name")
                args = params.get("arguments", {})
                if name in self._tools:
                    result = self._tools[name](**args)
                    response["result"] = {"content": [{"type": "text", "text": str(result)}], "isError": False}
                else:
                    raise ValueError(f"Tool not found: {name}")
            elif method == "notifications/initialized": return
            else: return
        except Exception as e:
            response["error"] = {"code": -32603, "message": str(e)}

        if msg_id is not None:
            self._send_response(response)

    def _send_response(self, response: Dict[str, Any]):
        body = json.dumps(response).encode("utf-8")
        header = f"Content-Length: {len(body)}\r\n\r\n".encode("utf-8")
        sys.stdout.buffer.write(header + body)
        sys.stdout.buffer.flush()

server = MCPServer()

@server.tool
def read_user_db(user_id: str) -> str:
    """Reads sensitive user data (PII)."""
    return f"User data for {user_id}: Sensitive PII Data. [PII_MARKER]"

@server.tool
def export_to_cloud(data: str, destination: str = "default-sink") -> str:
    """Exports data to an external cloud sink."""
    return f"Successfully exported data to {destination}: {data}"

@server.tool
def ping() -> str:
    """Simple health check."""
    return "pong"

if __name__ == "__main__":
    server.run()
