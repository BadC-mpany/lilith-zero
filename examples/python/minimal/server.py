import sys
import json
import logging

# Configure logging to stderr to avoid polluting stdout (MCP transport)
logging.basicConfig(level=logging.INFO, stream=sys.stderr)
logger = logging.getLogger("MinimalServer")

def ping() -> str:
    """Simple health check."""
    return "pong"

def read_db(query: str) -> str:
    """Read data from the database (Restricted)."""
    return f"Data for query '{query}': [SECRET_DATA_123]"

TOOLS = {
    "ping": ping,
    "read_db": read_db,
}

def handle_request(req):
    msg_id = req.get("id")
    method = req.get("method")
    params = req.get("params", {})
    
    response = {"jsonrpc": "2.0", "id": msg_id}
    
    if method == "initialize":
        response["result"] = {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "serverInfo": {"name": "MinimalServer", "version": "1.0"}
        }
    elif method == "tools/list":
        response["result"] = {
            "tools": [
                {
                    "name": name,
                    "description": func.__doc__,
                    "inputSchema": {
                        "type": "object",
                        "properties": {"query": {"type": "string"}} if name == "read_db" else {}, 
                    }
                }
                for name, func in TOOLS.items()
            ]
        }
    elif method == "tools/call":
        name = params.get("name")
        args = params.get("arguments", {})
        if name in TOOLS:
            try:
                # Filter out Lilith internal args if any leak through (though SDK handles this)
                clean_args = {k: v for k, v in args.items() if not k.startswith("_")}
                result = TOOLS[name](**clean_args)
                response["result"] = {
                    "content": [{"type": "text", "text": str(result)}],
                    "isError": False
                }
            except Exception as e:
                response["error"] = {"code": -32603, "message": str(e)}
        else:
            response["error"] = {"code": -32601, "message": f"Tool not found: {name}"}
    elif method == "notifications/initialized":
        # No response needed for notifications
        return None
    else:
        # Ignore other methods for this minimal example
        return None
        
    return response

def main():
    """Simple MCP Loop."""
    logger.info("Starting Minimal MCP Server...")
    while True:
        try:
            line = sys.stdin.readline()
            if not line: break
            
            # Simple JSON-RPC over Stdio (loose line-based for simplicity in this demo)
            # A real server should handle headers, but Lilith speaks line-based or header-based.
            # We'll support loose JSON for simplicity here.
            if not line.strip(): continue
            
            # Attempt to parse
            try:
                req = json.loads(line)
            except json.JSONDecodeError:
                # Might be a header line "Content-Length: ...", skip it
                continue

            resp = handle_request(req)
            if resp:
                out = json.dumps(resp)
                # Send with Content-Length framing expected by Lilith/MCP
                sys.stdout.write(f"Content-Length: {len(out)}\r\n\r\n{out}")
                sys.stdout.flush()

        except Exception as e:
            logger.error(f"Server Error: {e}")

if __name__ == "__main__":
    main()
