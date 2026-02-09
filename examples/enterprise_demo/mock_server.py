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
import datetime
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
                line = sys.stdin.readline()
                if not line: break
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
                response["result"] = {"protocolVersion": "2024-11-05", "capabilities": {}, "serverInfo": {"name": "EnterpriseDemoServer", "version": "1.0"}}
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
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()

server = MCPServer()

@server.tool
def get_current_time() -> str:
    """Returns the current system time."""
    return f"Current time is: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"

@server.tool
def calculate(expression: str) -> str:
    """Performs a mathematical calculation."""
    try:
        res = eval(expression, {"__builtins__": {}}, {})
        return f"Result: {res}"
    except Exception as e:
        return f"Error: {e}"

@server.tool
def get_user_profile(user_id: str) -> str:
    """Returns sensitive user profile data (PII)."""
    profiles = {
        "12345": {"name": "Alice Smith", "email": "alice@example.com", "ssn": "XXX-XX-1234"},
        "67890": {"name": "Bob Jones", "email": "bob@example.com", "ssn": "XXX-XX-5678"}
    }
    return f"Profile Data: {profiles.get(user_id, 'User not found')}"

@server.tool
def send_email(to: str, subject: str, body: str) -> str:
    """Sends an email to an external recipient."""
    return f"Email sent to {to} with subject: {subject}"

@server.tool
def post_to_slack(channel: str, message: str) -> str:
    """Posts a message to a Slack channel."""
    return f"Posted to Slack channel #{channel}: {message}"

@server.tool
def execute_shell(command: str) -> str:
    """Executes a shell command (Dangerous)."""
    return "Shell command executed (Mock)"

@server.tool
def delete_records(table: str, condition: str) -> str:
    """Deletes records from a database table."""
    return f"Records deleted from {table}"

if __name__ == "__main__":
    server.run()
