#!/usr/bin/env node
/**
 * Streamable HTTP MCP server — Node.js stdlib, MCP 2025-11-25.
 *
 * Implements the minimal wire format Lilith expects when running with
 * --transport http:
 *   POST /mcp  → JSON-RPC dispatch (application/json response)
 *   DELETE /mcp → session teardown
 *
 * Session IDs are tracked in a plain Map so each Mcp-Session-Id gets its own
 * initialized flag.  The server is intentionally minimal — no SSE streaming,
 * no OAuth, no persistence — to keep the reference implementation readable.
 *
 * Tools (same as the stdio example so policy.yaml is identical):
 *   search_web    → ALLOW
 *   get_time      → ALLOW
 *   query_database → DENY  (blocked by Lilith before reaching here)
 */

import { createServer } from "http";

export const HOST = "127.0.0.1";
export const PORT = 18080;

const log = (...a) => process.stderr.write("[ts-http-server] " + a.join(" ") + "\n");

// sessionId → { initialized: bool }
const sessions = new Map();

function jsonReply(res, body) {
  const payload = JSON.stringify(body);
  res.writeHead(200, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(payload),
  });
  res.end(payload);
}

function errorReply(res, code, message, id = null) {
  jsonReply(res, { jsonrpc: "2.0", id, error: { code, message } });
}

function handleRpc(req, res, msg) {
  const { method, id, params = {} } = msg;
  const sessionId = req.headers["mcp-session-id"];

  if (method === "initialize") {
    const sid = sessionId ?? crypto.randomUUID();
    sessions.set(sid, { initialized: false });
    const reply = {
      jsonrpc: "2.0",
      id,
      result: {
        protocolVersion: "2025-11-25",
        capabilities: { tools: {} },
        serverInfo: { name: "ts-http-server", version: "0.1.0" },
      },
    };
    const payload = JSON.stringify(reply);
    res.writeHead(200, {
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(payload),
      "Mcp-Session-Id": sid,
    });
    res.end(payload);
    return;
  }

  if (method === "notifications/initialized") {
    if (sessionId && sessions.has(sessionId)) {
      sessions.get(sessionId).initialized = true;
    }
    res.writeHead(204);
    res.end();
    return;
  }

  if (method === "tools/list") {
    return jsonReply(res, {
      jsonrpc: "2.0",
      id,
      result: {
        tools: [
          { name: "search_web",     description: "Search the web",          inputSchema: { type: "object", properties: { query: { type: "string" } }, required: ["query"] } },
          { name: "get_time",       description: "Current UTC time",         inputSchema: { type: "object", properties: {} } },
          { name: "query_database", description: "Raw SQL (always denied)",  inputSchema: { type: "object", properties: { sql: { type: "string" } }, required: ["sql"] } },
        ],
      },
    });
  }

  if (method === "tools/call") {
    const { name, arguments: args = {} } = params;
    let text;
    if (name === "search_web")      text = `[mock] Results for '${args.query}': Wikipedia, arXiv`;
    else if (name === "get_time")   text = new Date().toISOString();
    else if (name === "query_database") text = `[DB] ${args.sql}`;
    else return errorReply(res, -32601, `Unknown tool: ${name}`, id);
    return jsonReply(res, { jsonrpc: "2.0", id, result: { content: [{ type: "text", text }] } });
  }

  if (id != null) errorReply(res, -32601, `Unknown method: ${method}`, id);
  else { res.writeHead(204); res.end(); }
}

function handleRequest(req, res) {
  const url = new URL(req.url, `http://${req.headers.host}`);

  if (url.pathname !== "/mcp") {
    res.writeHead(404);
    res.end("Not found");
    return;
  }

  if (req.method === "DELETE") {
    const sid = req.headers["mcp-session-id"];
    if (sid) sessions.delete(sid);
    res.writeHead(204);
    res.end();
    return;
  }

  if (req.method !== "POST") {
    res.writeHead(405);
    res.end("Method not allowed");
    return;
  }

  let body = "";
  req.on("data", (chunk) => { body += chunk; });
  req.on("end", () => {
    let msg;
    try {
      msg = JSON.parse(body);
    } catch {
      errorReply(res, -32700, "Parse error");
      return;
    }
    handleRpc(req, res, msg);
  });
}

// Start the server.  When imported by agent.ts, call serve() instead.
function serve(daemon = false) {
  const server = createServer(handleRequest);
  server.listen(PORT, HOST, () => {
    log(`listening on http://${HOST}:${PORT}/mcp`);
  });
  return server;
}

// Run directly: node server.mjs
if (process.argv[1] === new URL(import.meta.url).pathname) {
  serve();
}

export { serve };
