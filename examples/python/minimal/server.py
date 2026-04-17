"""
Minimal MCP server — no external dependencies, pure stdlib.

This server implements only what MCP requires:
  - initialize / notifications/initialized handshake
  - tools/list
  - tools/call

It intentionally exposes one allowed tool and one denied tool so that the
Lilith policy (policy.yaml) can demonstrate static allow/deny enforcement.
"""

import json
import logging
import sys

logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="%(name)s: %(message)s")
log = logging.getLogger("minimal-server")


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

def search_web(query: str) -> str:
    """Search the web for information on a topic."""
    return f"[mock] Top results for '{query}': Wikipedia, arXiv, Stack Overflow"


def get_time() -> str:
    """Return the current UTC time."""
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def query_database(sql: str) -> str:
    """Execute a raw SQL query against the production database."""
    # In reality this would hit a real DB; here it is intentionally blocked
    # by the Lilith policy before it even reaches this function.
    return f"[DB] Result for: {sql!r}"


TOOLS: dict = {
    "search_web": {
        "fn": search_web,
        "description": search_web.__doc__,
        "inputSchema": {
            "type": "object",
            "properties": {"query": {"type": "string", "description": "Search query"}},
            "required": ["query"],
        },
    },
    "get_time": {
        "fn": get_time,
        "description": get_time.__doc__,
        "inputSchema": {"type": "object", "properties": {}},
    },
    "query_database": {
        "fn": query_database,
        "description": query_database.__doc__,
        "inputSchema": {
            "type": "object",
            "properties": {"sql": {"type": "string", "description": "SQL query"}},
            "required": ["sql"],
        },
    },
}


# ---------------------------------------------------------------------------
# MCP wire protocol (Content-Length framing)
# ---------------------------------------------------------------------------

def read_message() -> dict | None:
    """Read one Content-Length framed JSON-RPC message from stdin."""
    while True:
        header_line = sys.stdin.readline()
        if not header_line:
            return None  # EOF
        header_line = header_line.strip()
        if not header_line:
            continue
        if header_line.lower().startswith("content-length:"):
            length = int(header_line.split(":", 1)[1].strip())
            sys.stdin.readline()  # consume the blank separator line
            body = sys.stdin.read(length)
            return json.loads(body)
        # Ignore unrecognised header lines (forward compat)


def send_message(msg: dict) -> None:
    """Write one Content-Length framed JSON-RPC message to stdout."""
    body = json.dumps(msg)
    sys.stdout.write(f"Content-Length: {len(body)}\r\n\r\n{body}")
    sys.stdout.flush()


# ---------------------------------------------------------------------------
# Request dispatcher
# ---------------------------------------------------------------------------

def handle(req: dict) -> dict | None:
    req_id = req.get("id")
    method = req.get("method", "")
    params = req.get("params") or {}

    if method == "notifications/initialized":
        return None  # notification — no response

    base = {"jsonrpc": "2.0", "id": req_id}

    if method == "initialize":
        return {**base, "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "serverInfo": {"name": "minimal-server", "version": "1.0.0"},
        }}

    if method == "tools/list":
        return {**base, "result": {"tools": [
            {"name": name, "description": spec["description"], "inputSchema": spec["inputSchema"]}
            for name, spec in TOOLS.items()
        ]}}

    if method == "tools/call":
        name = params.get("name", "")
        args = {k: v for k, v in (params.get("arguments") or {}).items()
                if not k.startswith("_")}  # strip Lilith internal keys
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

    # Unknown method — return method-not-found
    return {**base, "error": {"code": -32601, "message": f"Method not found: {method}"}}


def main() -> None:
    log.info("minimal-server ready")
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
