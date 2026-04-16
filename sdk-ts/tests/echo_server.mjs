#!/usr/bin/env node
/**
 * Minimal MCP server for Lilith SDK integration tests.
 *
 * Implements the Content-Length framing protocol and responds to:
 *   - initialize
 *   - tools/list
 *   - tools/call  (echoes arguments.text or returns "ok")
 *   - resources/list
 *   - resources/read
 *   - notifications/initialized  (no response — notification)
 */

// ─── Framing codec ───────────────────────────────────────────────────────────

let buf = Buffer.alloc(0);
let expectedLength = -1;

process.stdin.on("data", (chunk) => {
  buf = Buffer.concat([buf, chunk]);
  processBuffer();
});

process.stdin.on("end", () => process.exit(0));

function processBuffer() {
  for (;;) {
    if (expectedLength === -1) {
      const sep = buf.indexOf("\r\n\r\n");
      if (sep === -1) return;
      const headerBlock = buf.subarray(0, sep).toString("utf-8");
      const match = headerBlock.match(/content-length:\s*(\d+)/i);
      if (!match) return;
      expectedLength = parseInt(match[1], 10);
      buf = buf.subarray(sep + 4);
    }
    if (buf.length < expectedLength) return;
    const body = buf.subarray(0, expectedLength);
    buf = buf.subarray(expectedLength);
    expectedLength = -1;
    let msg;
    try { msg = JSON.parse(body.toString("utf-8")); } catch { return; }
    handleMessage(msg);
  }
}

function send(id, result) {
  const body = JSON.stringify({ jsonrpc: "2.0", id, result });
  const frame = `Content-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`;
  process.stdout.write(frame);
}

function sendError(id, code, message) {
  const body = JSON.stringify({ jsonrpc: "2.0", id, error: { code, message } });
  const frame = `Content-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`;
  process.stdout.write(frame);
}

// ─── MCP method handlers ─────────────────────────────────────────────────────

function handleMessage(msg) {
  // Notifications have no `id` — do not respond.
  if (msg.id === undefined || msg.id === null) return;

  switch (msg.method) {
    case "initialize":
      send(msg.id, {
        protocolVersion: "2024-11-05",
        capabilities: {},
        serverInfo: { name: "echo-server", version: "0.1.0" },
      });
      break;

    case "tools/list":
      send(msg.id, {
        tools: [
          {
            name: "echo",
            description: "Echoes the input text",
            inputSchema: {
              type: "object",
              properties: { text: { type: "string" } },
            },
          },
          {
            name: "add",
            description: "Adds two numbers",
            inputSchema: {
              type: "object",
              properties: {
                a: { type: "number" },
                b: { type: "number" },
              },
            },
          },
        ],
      });
      break;

    case "tools/call": {
      const { name, arguments: args = {} } = msg.params ?? {};
      if (name === "echo") {
        send(msg.id, {
          content: [{ type: "text", text: String(args.text ?? "hello") }],
          isError: false,
        });
      } else if (name === "add") {
        const result = (args.a ?? 0) + (args.b ?? 0);
        send(msg.id, {
          content: [{ type: "text", text: String(result) }],
          isError: false,
        });
      } else {
        sendError(msg.id, -32601, `Unknown tool: ${name}`);
      }
      break;
    }

    case "resources/list":
      send(msg.id, {
        resources: [
          { uri: "test://hello", name: "Hello resource", mimeType: "text/plain" },
        ],
      });
      break;

    case "resources/read":
      send(msg.id, {
        contents: [{ uri: msg.params?.uri, text: "hello world" }],
      });
      break;

    default:
      sendError(msg.id, -32601, `Method not found: ${msg.method}`);
  }
}
