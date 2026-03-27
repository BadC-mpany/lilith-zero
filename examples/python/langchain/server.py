import sys
import json
import logging

# Configure logging to stderr
logging.basicConfig(level=logging.INFO, stream=sys.stderr)
logger = logging.getLogger("LangChainServer")

# Tool Implementations
def calculator(expression: str) -> str:
    """Evaluate a math expression."""
    # Unsafe eval for demo purposes (Lilith protects this!)
    try:
        return str(eval(expression))
    except Exception as e:
        return f"Error: {e}"

def read_customer_data(customer_id: str) -> str:
    """Read sensitive customer PII."""
    return f"{{ 'id': '{customer_id}', 'name': 'John Doe', 'ssn': '123-45-6789' }}"

def export_analytics(data: str) -> str:
    """Export data to external analytics service."""
    return "Export accepted: 200 OK"

def system_maintenance(region: str) -> str:
    """Perform system maintenance operations."""
    return f"Maintenance scheduled for region: {region}"

def database(query: str) -> str:
    """Access the internal knowledge database."""
    return f"Database results for '{query}': Found 3 sensitive records."

def web_search(query: str) -> str:
    """Search the public internet."""
    return f"Search results for '{query}': No public information found."

def delete_record(record_id: str) -> str:
    """Delete a record from the database."""
    return f"Record {record_id} deleted successfully."

def list_files(path: str) -> str:
    """List files in a directory."""
    return f"Files in {path}: README.md, src/, tests/, target/"

TOOLS = {
    "calculator": calculator,
    "read_customer_data": read_customer_data,
    "export_analytics": export_analytics,
    "system_maintenance": system_maintenance,
    "database": database,
    "web_search": web_search,
    "delete_record": delete_record,
    "list_files": list_files,
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
            "serverInfo": {"name": "LangChainServer", "version": "1.0"}
        }
    elif method == "tools/list":
        response["result"] = {
            "tools": [
                {
                    "name": name,
                    "description": func.__doc__,
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "expression": {"type": "string"},
                            "customer_id": {"type": "string"},
                            "data": {"type": "string"},
                            "region": {"type": "string"}
                        }
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
                # Naive argument mapping for demo
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
        return None
    else:
        return None
        
    return response

def main():
    logger.info("Starting LangChain MCP Server...")
    
    # We use a robust reader that handles LSP-style Content-Length headers
    stdin = sys.stdin.buffer

    while True:
        try:
            # 1. Read Headers
            headers = {}
            while True:
                line = stdin.readline()
                if not line:
                    return # EOF
                line = line.decode().strip()
                if not line:
                    break # End of headers
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.lower().strip()] = v.strip()

            # 2. Read Body
            if "content-length" in headers:
                length = int(headers["content-length"])
                body = stdin.read(length)
                if not body:
                    break
                req = json.loads(body.decode())
                
                resp = handle_request(req)
                if resp:
                    out = json.dumps(resp)
                    # We also respond with Content-Length for the Lilith interceptor
                    sys.stdout.write(f"Content-Length: {len(out)}\r\n\r\n{out}")
                    sys.stdout.flush()
            else:
                # Fallback for plain newline-delimited JSON (if headers missing)
                # Note: this is a bit tricky with mixed binary read, 
                # but for the demo we assume Lilith is always sending headers now.
                logger.warning("Received message without Content-Length header")
                continue

        except Exception as e:
            logger.error(f"Server Error: {e}")
            break

if __name__ == "__main__":
    main()
