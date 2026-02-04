import sys
import json
import logging
from tools import calculator, read_customer_data, export_analytics, system_maintenance, nuke_database

logging.basicConfig(filename="upstream.log", level=logging.INFO, format='%(asctime)s %(message)s')
logger = logging.getLogger("upstream")

def handle_request(req):
    try:
        msg_id = req.get("id")
        method = req.get("method")
        params = req.get("params", {})
        response = {"jsonrpc": "2.0", "id": msg_id}

        if method == "initialize":
            response["result"] = {"serverInfo": {"name": "demo_upstream", "version": "0.1.0"}, "capabilities": {}}
        elif method == "tools/list":
            response["result"] = {
                "tools": [
                    {"name": "calculator", "description": "Calculate math", "inputSchema": {"type": "object", "properties": {"expression": {"type": "string"}}}},
                    {"name": "read_customer_data", "description": "Read sensitive data", "inputSchema": {"type": "object", "properties": {"customer_id": {"type": "string"}}}},
                    {"name": "export_analytics", "description": "Export data", "inputSchema": {"type": "object", "properties": {"data": {"type": "string"}}}},
                    {"name": "system_maintenance", "description": "System maintenance", "inputSchema": {"type": "object", "properties": {"region": {"type": "string"}}}},
                    {"name": "nuke_database", "description": "Destroy DB", "inputSchema": {"type": "object", "properties": {}}}
                ]
            }
        elif method == "tools/call":
            name = params.get("name")
            args = params.get("arguments", {})
            func_map = {
                "calculator": lambda: calculator.func(args.get("expression", "0")),
                "read_customer_data": lambda: read_customer_data.func(args.get("customer_id", "0")),
                "export_analytics": lambda: export_analytics.func(args.get("data", "")),
                "system_maintenance": lambda: system_maintenance.func(args.get("region", "unknown")),
                "nuke_database": lambda: nuke_database.func(),
            }
            if name in func_map:
                res = func_map[name]()
                response["result"] = {"content": [{"type": "text", "text": str(res)}], "isError": False}
            else:
                response["error"] = {"code": -32601, "message": f"Tool not found: {name}"}
        return response
    except Exception as e:
        logger.error(f"Error in handler: {e}")
        return {"jsonrpc": "2.0", "id": req.get("id"), "error": {"code": -32603, "message": str(e)}}

def read_message():
    # Read headers until \r\n\r\n or \n\n
    headers_raw = b""
    while True:
        chunk = sys.stdin.buffer.read(1)
        if not chunk: return None
        headers_raw += chunk
        if headers_raw.endswith(b"\r\n\r\n") or headers_raw.endswith(b"\n\n"):
            break
            
    headers_str = headers_raw.decode("ascii").lower()
    content_length = 0
    for line in headers_str.splitlines():
        if line.startswith("content-length:"):
            content_length = int(line.split(":")[1].strip())
            
    if content_length > 0:
        body = sys.stdin.buffer.read(content_length)
        return json.loads(body.decode("utf-8"))
    return None

def write_message(msg):
    body = json.dumps(msg).encode("utf-8")
    header = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
    sys.stdout.buffer.write(header + body)
    sys.stdout.buffer.flush()

def main():
    logger.info("Upstream binary-safe server starting...")
    while True:
        try:
            req = read_message()
            if req is None: break
            logger.info(f"Received: {req.get('method')}")
            resp = handle_request(req)
            if resp:
                write_message(resp)
        except Exception as e:
            logger.error(f"Loop error: {e}")
            break

if __name__ == "__main__":
    main()
