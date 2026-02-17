import sys
import json
import logging

# Configure logging to stderr
logging.basicConfig(level=logging.INFO, stream=sys.stderr)
logger = logging.getLogger("AdvancedServer")

# Tool Implementations
def get_user_profile(user_id: str) -> str:
    """Get user profile (Source of Taint)."""
    return f"User {user_id} Profile [TAINTED]"

def export_to_untrusted_cloud(data: str) -> str:
    """Export data to cloud (Sink)."""
    return f"Exported: {data}"

def sanitize_data(data: str) -> str:
    """Sanitize data (Removes Taint)."""
    return f"[SANITIZED] {data}"

def execute_system_command(command: str, force: str) -> str:
    """Execute system command (Logic Rules)."""
    return f"Executed: {command} (Force: {force})"

TOOLS = {
    "get_user_profile": get_user_profile,
    "export_to_untrusted_cloud": export_to_untrusted_cloud,
    "sanitize_data": sanitize_data,
    "execute_system_command": execute_system_command,
}

# Resource Implementations
RESOURCES = {
    "s3://public/release_notes.txt": "v1.0 Release Notes: All systems go.",
    "s3://internal/audit_logs.txt": "AUDIT LOG: [SECRET] User login at 12:00."
}

def handle_request(req):
    msg_id = req.get("id")
    method = req.get("method")
    params = req.get("params", {})
    
    response = {"jsonrpc": "2.0", "id": msg_id}
    
    if method == "initialize":
        response["result"] = {
            "protocolVersion": "2024-11-05",
            "capabilities": {"resources": {}},
            "serverInfo": {"name": "AdvancedServer", "version": "1.0"}
        }
    elif method == "tools/list":
        response["result"] = {
            "tools": [
                {
                    "name": name,
                    "description": func.__doc__,
                    "inputSchema": {
                        "type": "object",
                        "properties": {k: {"type": "string"} for k in func.__code__.co_varnames[:func.__code__.co_argcount]},
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
                # Naive argument filtering
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
    elif method == "resources/list":
        response["result"] = {
            "resources": [
                {"uri": uri, "name": uri.split("/")[-1], "mimeType": "text/plain"}
                for uri in RESOURCES.keys()
            ]
        }
    elif method == "resources/read":
        uri = params.get("uri")
        if uri in RESOURCES:
            response["result"] = {
                "contents": [{"uri": uri, "mimeType": "text/plain", "text": RESOURCES[uri]}]
            }
        else:
            response["error"] = {"code": -32602, "message": "Resource not found"}
    elif method == "notifications/initialized":
        return None
    else:
        return None
        
    return response

def main():
    logger.info("Starting Advanced MCP Server...")
    while True:
        try:
            line = sys.stdin.readline()
            if not line: break
            if not line.strip(): continue
            try:
                req = json.loads(line)
            except json.JSONDecodeError:
                continue

            resp = handle_request(req)
            if resp:
                out = json.dumps(resp)
                sys.stdout.write(f"Content-Length: {len(out)}\r\n\r\n{out}")
                sys.stdout.flush()
        except Exception as e:
            logger.error(f"Server Error: {e}")

if __name__ == "__main__":
    main()
