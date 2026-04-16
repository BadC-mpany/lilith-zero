"""
Calculator MCP server — pure stdlib, no external dependencies.

Demonstrates how any MCP server (including one built with FastMCP or another
framework) can be wrapped by Lilith without modification to the server itself.
The server exposes simple math tools and a constants resource.

Tools: add, multiply, divide, sqrt
Resources: constants://{name}  (pi, e, golden_ratio)
"""

import json
import logging
import math
import sys

logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="%(name)s: %(message)s")
log = logging.getLogger("calculator-server")


TOOLS: dict = {
    "add": {
        "description": "Add two numbers together.",
        "inputSchema": {
            "type": "object",
            "properties": {"a": {"type": "number"}, "b": {"type": "number"}},
            "required": ["a", "b"],
        },
        "fn": lambda a, b: a + b,
    },
    "multiply": {
        "description": "Multiply two numbers.",
        "inputSchema": {
            "type": "object",
            "properties": {"a": {"type": "number"}, "b": {"type": "number"}},
            "required": ["a", "b"],
        },
        "fn": lambda a, b: a * b,
    },
    "divide": {
        "description": "Divide a by b. Blocked by policy — use multiply with reciprocal.",
        "inputSchema": {
            "type": "object",
            "properties": {"a": {"type": "number"}, "b": {"type": "number"}},
            "required": ["a", "b"],
        },
        "fn": lambda a, b: a / b,
    },
    "sqrt": {
        "description": "Compute the square root of a non-negative number.",
        "inputSchema": {
            "type": "object",
            "properties": {"x": {"type": "number"}},
            "required": ["x"],
        },
        "fn": lambda x: math.sqrt(x),
    },
}

CONSTANTS: dict[str, str] = {
    "constants://pi": f"pi = {math.pi}",
    "constants://e": f"e = {math.e}",
    "constants://golden_ratio": f"golden_ratio = {(1 + math.sqrt(5)) / 2}",
}


def read_message() -> dict | None:
    while True:
        header_line = sys.stdin.readline()
        if not header_line:
            return None
        header_line = header_line.strip()
        if not header_line:
            continue
        if header_line.lower().startswith("content-length:"):
            length = int(header_line.split(":", 1)[1].strip())
            sys.stdin.readline()  # blank separator
            body = sys.stdin.read(length)
            return json.loads(body)


def send_message(msg: dict) -> None:
    body = json.dumps(msg)
    sys.stdout.write(f"Content-Length: {len(body)}\r\n\r\n{body}")
    sys.stdout.flush()


def handle(req: dict) -> dict | None:
    req_id = req.get("id")
    method = req.get("method", "")
    params = req.get("params") or {}
    base = {"jsonrpc": "2.0", "id": req_id}

    if method == "notifications/initialized":
        return None

    if method == "initialize":
        return {**base, "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {"resources": {}},
            "serverInfo": {"name": "calculator-server", "version": "1.0.0"},
        }}

    if method == "tools/list":
        return {**base, "result": {"tools": [
            {"name": name, "description": spec["description"], "inputSchema": spec["inputSchema"]}
            for name, spec in TOOLS.items()
        ]}}

    if method == "tools/call":
        name = params.get("name", "")
        args = {k: v for k, v in (params.get("arguments") or {}).items()
                if not k.startswith("_")}
        spec = TOOLS.get(name)
        if spec is None:
            return {**base, "error": {"code": -32601, "message": f"Unknown tool: {name}"}}
        try:
            result = spec["fn"](**args)
            return {**base, "result": {
                "content": [{"type": "text", "text": str(result)}],
                "isError": False,
            }}
        except Exception as exc:
            return {**base, "error": {"code": -32603, "message": str(exc)}}

    if method == "resources/list":
        return {**base, "result": {"resources": [
            {"uri": uri, "name": uri.split("://", 1)[1], "mimeType": "text/plain"}
            for uri in CONSTANTS
        ]}}

    if method == "resources/read":
        uri = params.get("uri", "")
        content = CONSTANTS.get(uri)
        if content is None:
            return {**base, "error": {"code": -32602, "message": f"Resource not found: {uri}"}}
        return {**base, "result": {"contents": [
            {"uri": uri, "mimeType": "text/plain", "text": content}
        ]}}

    return {**base, "error": {"code": -32601, "message": f"Method not found: {method}"}}


def main() -> None:
    log.info("calculator-server ready")
    while True:
        try:
            req = read_message()
            if req is None:
                break
            resp = handle(req)
            if resp is not None:
                send_message(resp)
        except (KeyboardInterrupt, BrokenPipeError):
            break
        except Exception as exc:
            log.error("unhandled error: %s", exc)


if __name__ == "__main__":
    main()
