"""
Streamable HTTP MCP server (MCP 2025-11-25).

Implements POST /mcp with:
  - initialize / notifications/initialized handshake
  - tools/list
  - tools/call

The same tool surface as the minimal example: search_web (allowed),
get_time (allowed), query_database (denied by Lilith policy).

Run standalone:
    python server.py          # listens on http://127.0.0.1:8090/mcp
"""

import asyncio
import datetime
import json
import logging
import sys
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread

HOST = "127.0.0.1"
PORT = 8090

logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="%(name)s: %(message)s")
log = logging.getLogger("http-server")

# Active sessions: {mcp_session_id -> {"initialized": bool}}
_sessions: dict[str, dict] = {}


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

def search_web(query: str) -> str:
    return f"[mock] Results for '{query}': Wikipedia, arXiv, GitHub"


def get_time() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def query_database(sql: str) -> str:
    # This is intentionally blocked by the Lilith policy before reaching here.
    return f"[DB] {sql!r}"


# ---------------------------------------------------------------------------
# JSON-RPC dispatch
# ---------------------------------------------------------------------------

def handle_rpc(msg: dict, session_id: str | None) -> dict | None:
    method = msg.get("method", "")
    req_id = msg.get("id")
    params = msg.get("params", {})

    def ok(result: object) -> dict:
        return {"jsonrpc": "2.0", "id": req_id, "result": result}

    def err(code: int, message: str) -> dict:
        return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}

    if method == "initialize":
        return ok({
            "protocolVersion": "2025-11-25",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "http-example-server", "version": "0.1.0"},
        })

    if method == "notifications/initialized":
        return None  # no response for notifications

    if method == "tools/list":
        return ok({"tools": [
            {"name": "search_web",     "description": "Search the web", "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]}},
            {"name": "get_time",       "description": "Current UTC time", "inputSchema": {"type": "object", "properties": {}}},
            {"name": "query_database", "description": "Raw SQL query",   "inputSchema": {"type": "object", "properties": {"sql": {"type": "string"}},   "required": ["sql"]}},
        ]})

    if method == "tools/call":
        name = params.get("name", "")
        args = params.get("arguments", {})
        if name == "search_web":
            text = search_web(args.get("query", ""))
        elif name == "get_time":
            text = get_time()
        elif name == "query_database":
            text = query_database(args.get("sql", ""))
        else:
            return err(-32601, f"Unknown tool: {name}")
        return ok({"content": [{"type": "text", "text": text}]})

    if req_id is not None:
        return err(-32601, f"Method not found: {method}")
    return None


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

class McpHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: object) -> None:  # suppress default output
        log.debug(fmt, *args)

    def do_POST(self) -> None:
        if self.path != "/mcp":
            self._send(404, b"Not found")
            return

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)

        try:
            msg = json.loads(body)
        except json.JSONDecodeError:
            self._send(400, b"Bad JSON")
            return

        # Session handling
        sid = self.headers.get("Mcp-Session-Id")
        new_session = False

        if msg.get("method") == "initialize":
            sid = str(uuid.uuid4())
            _sessions[sid] = {"initialized": False}
            new_session = True
            log.info("New session: %s", sid)
        elif sid and sid not in _sessions:
            self._send(404, b"Session not found")
            return

        resp = handle_rpc(msg, sid)

        if resp is None:
            # Notification — no body response
            self.send_response(204)
            if sid:
                self.send_header("Mcp-Session-Id", sid)
            self.end_headers()
            return

        resp_bytes = json.dumps(resp).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(resp_bytes)))
        if new_session and sid:
            self.send_header("Mcp-Session-Id", sid)
        elif sid:
            self.send_header("Mcp-Session-Id", sid)
        self.end_headers()
        self.wfile.write(resp_bytes)

    def do_DELETE(self) -> None:
        if self.path != "/mcp":
            self._send(404, b"Not found")
            return
        sid = self.headers.get("Mcp-Session-Id")
        if sid and sid in _sessions:
            del _sessions[sid]
            log.info("Session closed: %s", sid)
        self.send_response(204)
        self.end_headers()

    def _send(self, code: int, body: bytes) -> None:
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def serve(host: str = HOST, port: int = PORT, daemon: bool = False) -> HTTPServer:
    server = HTTPServer((host, port), McpHandler)
    t = Thread(target=server.serve_forever, daemon=daemon)
    t.start()
    log.info("Listening on http://%s:%d/mcp", host, port)
    return server


if __name__ == "__main__":
    serve(daemon=False)
