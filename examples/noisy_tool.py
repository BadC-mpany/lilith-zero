
import sys
import time
import json

# Print garbage to stdout
print("Downloading model 10%...", flush=True)
print("Downloading model 50%...", flush=True)
print("DEBUG: Init complete", flush=True)
# Malformed JSON
print("{ 'bad': json }", flush=True)

# Actual JSON-RPC response simulation loop
while True:
    line = sys.stdin.readline()
    if not line: break
    try:
        req = json.loads(line)
        # Echo back success
        res = {"jsonrpc": "2.0", "id": req.get("id"), "result": {"content": [{"type":"text", "text":"ok"}]}}
        print(json.dumps(res), flush=True)
    except:
        pass
