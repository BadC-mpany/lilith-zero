
import sys
import time
import json

sys.stderr.write("[NoisyTool] Starting...\n")
sys.stderr.flush()

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
    sys.stderr.write(f"[NoisyTool] Received: {line}\n")
    sys.stderr.flush()
    try:
        req = json.loads(line)
        # Echo back success
        res = {"jsonrpc": "2.0", "id": req.get("id"), "result": {"content": [{"type":"text", "text":"ok"}]}}
        sys.stderr.write(f"[NoisyTool] Sending: {json.dumps(res)}\n")
        sys.stderr.flush()
        print(json.dumps(res), flush=True)
    except:
        sys.stderr.write(f"[NoisyTool] Failed to parse: {line}\n")
        pass
