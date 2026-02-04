import subprocess
import sys
import os
import json
import time

SENTINEL_BIN = r"c:\Users\Peter\Documents\proj\active\bad\sentinel\sentinel\target\release\sentinel.exe"
MANUAL_SERVER = r"c:\Users\Peter\Documents\proj\active\bad\sentinel\tests\resources\manual_server.py"

def run_test():
    print(f"Launching {SENTINEL_BIN}...")
    
    # Start Sentinel
    proc = subprocess.Popen(
        [SENTINEL_BIN, "--upstream-cmd", "python", "--", MANUAL_SERVER],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=sys.stderr, # Pass stderr through to console
        text=False, # Binary mode for exact byte control
        bufsize=0   # Unbuffered
    )
    
    # Prepare Request
    req = {
        "jsonrpc": "2.0",
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "manual-driver", "version": "1.0"}
        },
        "id": 1
    }
    
    body = json.dumps(req).encode("utf-8")
    header = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
    payload = header + body
    
    print(f"Sending {len(payload)} bytes...")
    proc.stdin.write(payload)
    proc.stdin.flush()
    
    print("Waiting for response...")
    
    # Read Header
    # Simple state machine to read header
    header_buffer = b""
    content_length = 0
    
    while True:
        chunk = proc.stdout.read(1)
        if not chunk:
            print("EOF reading header")
            break
        header_buffer += chunk
        if b"\r\n\r\n" in header_buffer:
            # Parse length
            header_str = header_buffer.decode("ascii")
            for line in header_str.split("\r\n"):
                if line.lower().startswith("content-length:"):
                    content_length = int(line.split(":")[1].strip())
            break
            
    if content_length > 0:
        print(f"Reading body ({content_length} bytes)...")
        body_bytes = proc.stdout.read(content_length)
        print("Response Body:", body_bytes.decode("utf-8"))
    
    print("Closing...")
    proc.terminate()

if __name__ == "__main__":
    run_test()
