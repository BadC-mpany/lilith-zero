

import sys
import time
import json

sys.stderr.write("[NoisyTool] Starting...\n")
sys.stderr.flush()

# Print garbage to stdout
# Use buffer write to avoid CRLF issues but print text garbage
sys.stdout.buffer.write(b"Downloading model 10%...\n")
sys.stdout.buffer.write(b"Downloading model 50%...\n")
sys.stdout.buffer.write(b"DEBUG: Init complete\n")
sys.stdout.buffer.write(b"{ 'bad': json }\n")
sys.stdout.buffer.flush()

# Actual JSON-RPC response simulation loop
while True:
    line = sys.stdin.readline()
    if not line: break
    
    # Simple header parsing
    text = line.strip()
    if text.lower().startswith("content-length:"):
        length = int(text.split(":")[1].strip())
        # Consume empty line
        while True:
            l = sys.stdin.readline()
            if not l.strip(): break
        
        body = sys.stdin.read(length)
        sys.stderr.write(f"[NoisyTool] Received Body: {body}\n")
        
        try:
            req = json.loads(body)
            msg_id = req.get("id")
            method = req.get("method")
            
            response = {"jsonrpc": "2.0", "id": msg_id}
            
            if method == "initialize":
                response["result"] = {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "serverInfo": {"name": "NoisyTool", "version": "1.0"}
                }
            else:
                 response["result"] = {"content": [{"type":"text", "text":"ok"}]}

            resp_body = json.dumps(response).encode("utf-8")
            header = f"Content-Length: {len(resp_body)}\r\n\r\n".encode("ascii")
            sys.stdout.buffer.write(header + resp_body)
            sys.stdout.buffer.flush()
            
        except Exception as e:
            sys.stderr.write(f"[NoisyTool] Error: {e}\n")

