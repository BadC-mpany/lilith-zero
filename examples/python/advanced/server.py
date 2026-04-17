"""
Advanced MCP server — no external dependencies, pure stdlib.

Scenario: Document intelligence agent.  Tools:
  - read_report(path)     source of taint
  - summarize(text)       neutral transform
  - post_to_slack(text)   exfiltration sink (blocked when taint present)
  - redact(text)          taint cleaner
  - archive(path, confirmed)  conditional — blocked unless confirmed=true

Resources:
  - reports://public/*         → allowed, no taint
  - reports://confidential/*   → allowed, adds CONFIDENTIAL taint (via policy rule)
"""

import json
import logging
import sys

logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="%(name)s: %(message)s")
log = logging.getLogger("advanced-server")


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

def read_report(path: str) -> str:
    """Read a document report from the document store."""
    return f"[Report] path={path!r} content: Quarterly revenue is $42M. Internal only."


def summarize(text: str) -> str:
    """Summarize a block of text into bullet points."""
    words = text.split()[:10]
    return "Summary: " + " ".join(words) + "..."


def post_to_slack(text: str) -> str:
    """Post a message to the public Slack channel #general."""
    return f"[Slack] Posted: {text[:80]}"


def redact(text: str) -> str:
    """Redact personally identifiable and confidential information from text."""
    return "[REDACTED] " + " ".join(
        "***" if any(w in text.upper() for w in ("INTERNAL", "REVENUE", "SALARY"))
        else w
        for w in text.split()
    )


def archive(path: str, confirmed: bool = False) -> str:
    """Permanently archive (delete) a document. Requires confirmed=true."""
    return f"[Archive] Archived: {path!r}"


TOOLS: dict = {
    "read_report": {
        "fn": read_report,
        "description": read_report.__doc__,
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },
    "summarize": {
        "fn": summarize,
        "description": summarize.__doc__,
        "inputSchema": {
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": ["text"],
        },
    },
    "post_to_slack": {
        "fn": post_to_slack,
        "description": post_to_slack.__doc__,
        "inputSchema": {
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": ["text"],
        },
    },
    "redact": {
        "fn": redact,
        "description": redact.__doc__,
        "inputSchema": {
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": ["text"],
        },
    },
    "archive": {
        "fn": archive,
        "description": archive.__doc__,
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "confirmed": {"type": "boolean"},
            },
            "required": ["path"],
        },
    },
}


# ---------------------------------------------------------------------------
# Resource store
# ---------------------------------------------------------------------------

RESOURCES: dict[str, str] = {
    "reports://public/q3_press_release.txt": "Q3 press release: record growth across all segments.",
    "reports://confidential/q3_full_financials.txt": "CONFIDENTIAL: Q3 revenue $42M, EBITDA $8M.",
}


# ---------------------------------------------------------------------------
# MCP wire protocol
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Request dispatcher
# ---------------------------------------------------------------------------

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
            "serverInfo": {"name": "advanced-server", "version": "1.0.0"},
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
            {"uri": uri, "name": uri.rsplit("/", 1)[-1], "mimeType": "text/plain"}
            for uri in RESOURCES
        ]}}

    if method == "resources/read":
        uri = params.get("uri", "")
        content = RESOURCES.get(uri)
        if content is None:
            return {**base, "error": {"code": -32602, "message": f"Resource not found: {uri}"}}
        return {**base, "result": {"contents": [
            {"uri": uri, "mimeType": "text/plain", "text": content}
        ]}}

    return {**base, "error": {"code": -32601, "message": f"Method not found: {method}"}}


def main() -> None:
    log.info("advanced-server ready")
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
