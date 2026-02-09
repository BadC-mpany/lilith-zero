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
import inspect
from typing import Callable, Any, Dict, List

class MCPServer:
    """A compact, reusable MCP Server base for Lilith examples."""
    def __init__(self, name: str = "LilithMockServer"):
        self.name = name
        self._tools: Dict[str, Callable] = {}
        self._resources: Dict[str, Callable] = {}

    def tool(self, func: Callable):
        """Decorator to register a function as an MCP tool."""
        self._tools[func.__name__] = func
        return func

    def resource(self, uri_pattern: str):
        """Decorator to register a function as a dynamic resource provider."""
        def decorator(func):
            self._resources[uri_pattern] = func
            return func
        return decorator

    def _get_tool_list(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": name,
                "description": func.__doc__ or "No description",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        k: {"type": "string"}
                        for k in inspect.signature(func).parameters
                    },
                    "required": list(inspect.signature(func).parameters.keys())
                }
            }
            for name, func in self._tools.items()
        ]

    def _get_resource_list(self) -> List[Dict[str, Any]]:
        return [
            {"uri": uri, "name": uri.split("/")[-1], "mimeType": "text/plain"}
            for uri in self._resources.keys()
        ]

    def run(self):
        """Main loop for JSON-RPC over stdio, supporting both framed and line-based."""
        while True:
            line = sys.stdin.readline()
            if not line: break
            
            line = line.strip()
            if not line: continue

            try:
                if line.lower().startswith("content-length:"):
                    # Header-based framing
                    length = int(line.split(":")[1].strip())
                    # Skip until empty line
                    while True:
                        l = sys.stdin.readline().strip()
                        if not l: break
                    # Read body
                    body = sys.stdin.read(length)
                    req = json.loads(body)
                else:
                    # Line-based JSON
                    req = json.loads(line)
                
                self._handle_request(req)
            except Exception:
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
                    "capabilities": {"resources": {}}, 
                    "serverInfo": {"name": self.name, "version": "1.0"}
                }
            elif method == "tools/list":
                response["result"] = {"tools": self._get_tool_list()}
            elif method == "resources/list":
                response["result"] = {"resources": self._get_resource_list()}
            elif method == "tools/call":
                name = params.get("name")
                args = params.get("arguments", {})
                if name in self._tools:
                    clean_args = {k: v for k, v in args.items() if not k.startswith("_lilith")}
                    result = self._tools[name](**clean_args)
                    response["result"] = {"content": [{"type": "text", "text": str(result)}], "isError": False}
                else:
                    response["error"] = {"code": -32601, "message": f"Tool not found: {name}"}
            elif method == "resources/read":
                uri = params.get("uri")
                if uri in self._resources:
                    content = self._resources[uri]()
                    response["result"] = {"contents": [{"uri": uri, "mimeType": "text/plain", "text": str(content)}]}
                else:
                    response["error"] = {"code": -32601, "message": f"Resource not found: {uri}"}
            elif method.startswith("notifications/"):
                return
            else:
                return
        except Exception as e:
            response["error"] = {"code": -32603, "message": str(e)}

        if msg_id is not None:
            body = json.dumps(response).encode("utf-8")
            sys.stdout.buffer.write(f"Content-Length: {len(body)}\r\n\r\n".encode("ascii"))
            sys.stdout.buffer.write(body)
            sys.stdout.buffer.flush()
