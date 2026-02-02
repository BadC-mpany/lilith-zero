import sys
import json
import logging
import inspect
from typing import Callable, Any, Dict, List

# Configure minimal logging to stderr
logging.basicConfig(level=logging.INFO, stream=sys.stderr, format='[MCP] %(message)s')
logger = logging.getLogger(__name__)

class MCPServer:
    """Minimalistic MCP Server implementation."""
    
    def __init__(self):
        self._tools: Dict[str, Callable] = {}

    def tool(self, func: Callable):
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
                        k: {"type": "string"} # Simplified schema inference
                        for k in inspect.signature(func).parameters
                    }
                }
            }
            for name, func in self._tools.items()
        ]

    def run(self):
        """Main JSON-RPC loop."""
        logger.info("Server started (Stio Transport)")
        while True:
            try:
                line = sys.stdin.readline()
                if not line: break
                
                req = json.loads(line)
                self._handle_request(req)
            except json.JSONDecodeError:
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
                    "serverInfo": {"name": "DemoServer", "version": "1.0"}
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
                else:
                    raise ValueError(f"Tool not found: {name}")
                    
            elif method == "notifications/initialized":
                return # No response needed

            else:
                return # Ignore unsupported methods

        except Exception as e:
            logger.error(f"Error: {e}")
            response["error"] = {"code": -32603, "message": str(e)}

        if msg_id is not None:
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()

# --- Tool Implementation ---

server = MCPServer()

@server.tool
def get_financial_report() -> str:
    """Retrieves the confidential financial report."""
    return "CONFIDENTIAL REPORT: Revenue $50M. Project Code: PHOENIX."

@server.tool
def analyze_data(data: str) -> str:
    """Analyzes provided text data."""
    return f"Analysis: {len(data)} chars. Sentiment: Positive."

@server.tool
def upload_to_cloud(url: str, content: str) -> str:
    """Uploads data to external cloud storage."""
    logger.info(f"Uploading to {url}...")
    return f"Uploaded successfully to {url}"

if __name__ == "__main__":
    server.run()
