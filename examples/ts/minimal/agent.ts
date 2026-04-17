/**
 * TypeScript minimal Lilith example — stdio transport.
 *
 * Mirrors examples/python/minimal/agent.py exactly:
 *   1. SDK init (binary auto-discovery)
 *   2. Tool discovery
 *   3. Allowed call
 *   4. Denied call → PolicyViolationError
 *   5. Session ID + audit log
 *
 * Run:
 *   export LILITH_ZERO_BINARY_PATH=/path/to/lilith-zero
 *   bun agent.ts
 */

import { join } from "path";
import { Lilith, PolicyViolationError } from "../../../sdk-ts/src/index.ts";

const POLICY = join(import.meta.dir, "policy.yaml");
const SERVER = join(import.meta.dir, "server.mjs");

const lilith = new Lilith({
  upstream: `node ${SERVER}`,
  policy: POLICY,
});

await using _ = lilith;
await lilith.connect();

console.log(`session  : ${lilith.sessionId}`);

const tools = await lilith.listTools();
console.log(`tools    : [${tools.map((t) => t.name).join(", ")}]`);

const search = await lilith.callTool("search_web", { query: "Lilith Zero MCP security" });
console.log(`search   : ${search.content[0].text}`);

const time = await lilith.callTool("get_time", {});
console.log(`time     : ${time.content[0].text}`);

try {
  await lilith.callTool("query_database", { sql: "SELECT * FROM users" });
  console.log("ERROR: should have been blocked");
} catch (e) {
  if (e instanceof PolicyViolationError) {
    console.log(`blocked  : ${e.message}`);
  } else throw e;
}

const audit = await lilith.drainAuditLogs();
console.log(`\naudit    : ${audit.length} entries`);
for (const entry of audit) {
  const dec = entry.details?.decision ?? entry.event_type;
  const tool = entry.details?.tool_name ?? "";
  console.log(`  [${dec?.padEnd(6)}] ${tool}`);
}
