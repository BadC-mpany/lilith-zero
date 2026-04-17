#!/usr/bin/env node
/**
 * Minimal MCP server — stdio transport, pure Node.js stdlib.
 *
 * Tools:
 *   search_web    → ALLOW (static policy)
 *   get_time      → ALLOW
 *   query_database → DENY  (blocked by Lilith before reaching here)
 */

import { createInterface } from "readline";

const log = (...a) => process.stderr.write("[server] " + a.join(" ") + "\n");

function send(msg) {
  const body = JSON.stringify(msg);
  process.stdout.write(`Content-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`);
}

function reply(id, result) {
  send({ jsonrpc: "2.0", id, result });
}

// Read Content-Length framed messages from stdin
let buf = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  buf += chunk;
  while (true) {
    const m = buf.match(/Content-Length:\s*(\d+)\r?\n\r?\n/i);
    if (!m) break;
    const hdrEnd = m.index + m[0].length;
    const len = parseInt(m[1], 10);
    if (buf.length < hdrEnd + len) break;
    const body = buf.slice(hdrEnd, hdrEnd + len);
    buf = buf.slice(hdrEnd + len);
    handle(JSON.parse(body));
  }
});

function handle(msg) {
  const { method, id, params = {} } = msg;

  if (method === "initialize") {
    return reply(id, {
      protocolVersion: "2024-11-05",
      capabilities: { tools: {} },
      serverInfo: { name: "ts-minimal-server", version: "0.1.0" },
    });
  }
  if (method === "notifications/initialized") return;

  if (method === "tools/list") {
    return reply(id, {
      tools: [
        { name: "search_web",     description: "Search the web",       inputSchema: { type: "object", properties: { query: { type: "string" } }, required: ["query"] } },
        { name: "get_time",       description: "Current UTC time",     inputSchema: { type: "object", properties: {} } },
        { name: "query_database", description: "Raw SQL (always denied)", inputSchema: { type: "object", properties: { sql: { type: "string" } }, required: ["sql"] } },
      ],
    });
  }

  if (method === "tools/call") {
    const { name, arguments: args = {} } = params;
    let text;
    if (name === "search_web")     text = `[mock] Results for '${args.query}': Wikipedia, arXiv`;
    else if (name === "get_time")  text = new Date().toISOString();
    else if (name === "query_database") text = `[DB] ${args.sql}`;
    else return send({ jsonrpc: "2.0", id, error: { code: -32601, message: `Unknown tool: ${name}` } });
    return reply(id, { content: [{ type: "text", text }] });
  }

  if (id != null) send({ jsonrpc: "2.0", id, error: { code: -32601, message: `Unknown method: ${method}` } });
}

log("ready");
