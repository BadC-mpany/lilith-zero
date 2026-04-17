/**
 * TypeScript HTTP transport Lilith example — Streamable HTTP MCP 2025-11-25.
 *
 * Mirrors examples/python/http/agent.py exactly:
 *   1. Start the local MCP server (server.mjs) in-process
 *   2. Connect Lilith with upstreamUrl → --transport http
 *   3. Tool discovery, allowed call, denied call → PolicyViolationError
 *   4. Session ID + full audit log
 *
 * Run:
 *   export LILITH_ZERO_BINARY_PATH=/path/to/lilith-zero
 *   bun agent.ts
 */

import { join } from "path";
import { Lilith, PolicyViolationError } from "../../../sdk-ts/src/index.ts";
// @ts-ignore — .mjs module, no types needed
import { serve, HOST, PORT } from "./server.mjs";

const POLICY = join(import.meta.dir, "policy.yaml");
const SERVER_URL = `http://${HOST}:${PORT}/mcp`;

// Start the HTTP MCP server in-process.
const httpServer = serve();
// Give the socket a moment to bind.
await new Promise<void>((r) => setTimeout(r, 50));

const lilith = new Lilith({ upstreamUrl: SERVER_URL, policy: POLICY });
await using _ = lilith;
await lilith.connect();

console.log(`transport : HTTP → ${SERVER_URL}`);
console.log(`session   : ${lilith.sessionId}`);

const tools = await lilith.listTools();
console.log(`tools     : [${tools.map((t) => t.name).join(", ")}]`);

const search = await lilith.callTool("search_web", { query: "MCP security" });
console.log(`search    : ${(search.content[0] as { text: string }).text}`);

const time = await lilith.callTool("get_time", {});
console.log(`time      : ${(time.content[0] as { text: string }).text}`);

try {
  await lilith.callTool("query_database", { sql: "SELECT * FROM users" });
  console.log("ERROR: should have been blocked");
} catch (e) {
  if (e instanceof PolicyViolationError) {
    console.log(`blocked   : ${e.message}`);
  } else throw e;
}

const audit = await lilith.drainAuditLogs();
console.log(`\naudit     : ${audit.length} entries, ${audit.filter((e) => e.signature).length} signed`);
for (const entry of audit) {
  const dec = (entry.details["decision"] as string | undefined) ?? entry.event_type;
  const tool = (entry.details["tool_name"] as string | undefined) ?? "";
  console.log(`  [${dec.padEnd(12)}] ${tool}`);
}

httpServer.close();
