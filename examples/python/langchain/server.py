"""
Agentic-loop MCP server — pure stdlib, no external dependencies.

Scenario: An AI agent assistant with access to:
  - calculator   — safe, always allowed
  - database     — internal data (adds SENSITIVE_CONTEXT taint)
  - web_search   — blocked after database access (taint sink)
  - delete_record — permanently destructive (static DENY)
"""

import json
import logging
import sys

logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="%(name)s: %(message)s")
log = logging.getLogger("agentic-server")


def calculator(expression: str) -> str:
    """Evaluate a simple arithmetic expression (e.g. '2 + 2')."""
    allowed = set("0123456789 +-*/().")
    if not all(c in allowed for c in expression):
        return "Error: invalid characters in expression"
    return str(eval(expression))  # noqa: S307 — demo only, Lilith guards externally


def database(query: str) -> str:
    """Query the internal knowledge database."""
    return (
        f"DB results for '{query}': "
        "3 records found — customer IDs 1001, 1002, 1003 with PII attached."
    )


def web_search(query: str) -> str:
    """Search the public internet for information."""
    return f"Web results for '{query}': Found 5 public articles."


def delete_record(record_id: str) -> str:
    """Permanently delete a record from the database."""
    return f"Record {record_id} deleted."


TOOLS: dict = {
    "calculator": {
        "fn": calculator,
        "description": calculator.__doc__,
        "inputSchema": {
            "type": "object",
            "properties": {"expression": {"type": "string"}},
            "required": ["expression"],
        },
    },
    "database": {
        "fn": database,
        "description": database.__doc__,
        "inputSchema": {
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
        },
    },
    "web_search": {
        "fn": web_search,
        "description": web_search.__doc__,
        "inputSchema": {
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
        },
    },
    "delete_record": {
        "fn": delete_record,
        "description": delete_record.__doc__,
        "inputSchema": {
            "type": "object",
            "properties": {"record_id": {"type": "string"}},
            "required": ["record_id"],
        },
    },
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
            sys.stdin.readline()
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
            "capabilities": {},
            "serverInfo": {"name": "agentic-server", "version": "1.0.0"},
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

    return {**base, "error": {"code": -32601, "message": f"Method not found: {method}"}}


def main() -> None:
    log.info("agentic-server ready")
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
