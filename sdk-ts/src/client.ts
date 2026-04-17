// Copyright 2026 BadCompany
// Licensed under the Apache License, Version 2.0

/**
 * Lilith SDK — secure MCP middleware client.
 *
 * @example
 * ```ts
 * await using lilith = new Lilith("python server.py", { policy: "policy.yaml" });
 * await lilith.connect();
 * const tools = await lilith.listTools();
 * const result = await lilith.callTool("echo", { text: "hello" });
 * ```
 */

import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { existsSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { randomUUID } from "node:crypto";
import type { Readable } from "node:stream";
import {
  LilithConfigError,
  LilithConnectionError,
  LilithError,
  LilithProcessError,
  PolicyViolationError,
} from "./errors.js";
import { findBinary } from "./binary.js";

// ─── Public types ────────────────────────────────────────────────────────────

export interface ToolRef {
  name: string;
  description?: string;
  inputSchema: Record<string, unknown>;
}

export interface ToolResult {
  content: Array<Record<string, unknown>>;
  isError?: boolean;
}

export interface AuditEntry {
  session_id: string;
  timestamp: number;
  event_type: string;
  details: Record<string, unknown>;
  signature: string;
}

export interface LilithOptions {
  /** Upstream MCP server command string (stdio transport). Mutually exclusive with upstreamUrl. */
  upstream?: string;
  /** Upstream MCP server URL (HTTP transport). Mutually exclusive with upstream. */
  upstreamUrl?: string;
  /** Path to the policy YAML file. */
  policy?: string;
  /** Absolute path to the Lilith binary (auto-discovered if omitted). */
  binary?: string;
  /** Telemetry flock connection link. */
  telemetryLink?: string;
}

// ─── Internal constants ──────────────────────────────────────────────────────

const MCP_PROTOCOL_VERSION = "2024-11-05";
const SDK_NAME = "lilith-zero-ts";
const SDK_VERSION = "0.1.3";
const SESSION_TIMEOUT_MS = 5_000;
const SESSION_ID_MARKER = "LILITH_ZERO_SESSION_ID=";
const MAX_PAYLOAD_BYTES = 10 * 1024 * 1024; // 10 MB
const MAX_HEADER_LINE_BYTES = 1024; // 1 KB
const REQUEST_TIMEOUT_MS = 30_000;

// ─── BufferedReader ──────────────────────────────────────────────────────────

/**
 * Wraps a Node.js `Readable` stream and provides promise-based `readLine()`
 * and `readBytes()` — necessary for parsing the LSP-style `Content-Length`
 * framing used by the Lilith stdio transport.
 */
class BufferedReader {
  private buf: Buffer = Buffer.alloc(0);
  private ended = false;
  private waiters: Array<() => void> = [];

  constructor(stream: Readable) {
    stream.on("data", (chunk: Buffer) => {
      this.buf = Buffer.concat([this.buf, chunk]);
      this.flush();
    });
    const end = () => {
      this.ended = true;
      this.flush();
    };
    stream.on("end", end);
    stream.on("close", end);
    stream.on("error", end);
  }

  private flush(): void {
    const ws = this.waiters.splice(0);
    for (const w of ws) w();
  }

  private waitForData(): Promise<void> {
    if (this.buf.length > 0 || this.ended) return Promise.resolve();
    return new Promise<void>((resolve) => {
      this.waiters.push(resolve);
    });
  }

  /** Read one line (stripped of trailing CR/LF). Returns `null` on EOF. */
  async readLine(): Promise<string | null> {
    for (;;) {
      const idx = this.buf.indexOf(0x0a); // '\n'
      if (idx !== -1) {
        const line = this.buf
          .subarray(0, idx)
          .toString("utf-8")
          .replace(/\r$/, "");
        this.buf = this.buf.subarray(idx + 1);
        return line;
      }
      if (this.ended) {
        if (this.buf.length > 0) {
          const line = this.buf.toString("utf-8");
          this.buf = Buffer.alloc(0);
          return line;
        }
        return null;
      }
      await this.waitForData();
    }
  }

  /** Read exactly `n` bytes. Returns `null` on EOF before enough data. */
  async readBytes(n: number): Promise<Buffer | null> {
    for (;;) {
      if (this.buf.length >= n) {
        const chunk = Buffer.from(this.buf.subarray(0, n));
        this.buf = this.buf.subarray(n);
        return chunk;
      }
      if (this.ended) return null;
      await this.waitForData();
    }
  }
}

// ─── Pending request tracker ─────────────────────────────────────────────────

interface PendingRequest {
  resolve: (value: unknown) => void;
  reject: (err: Error) => void;
  timer: ReturnType<typeof setTimeout>;
}

// ─── Lilith client ───────────────────────────────────────────────────────────

/**
 * Lilith Security Middleware client.
 *
 * Spawns the Lilith binary, performs the MCP handshake, and forwards
 * tool/resource calls through the security policy engine.
 */
export class Lilith {
  private readonly _upstreamCmd: string | null;
  private readonly _upstreamArgs: string[];
  private readonly _upstreamUrl: string | null;
  private readonly _binaryPath: string;
  private readonly _policyPath: string | undefined;
  private readonly _telemetryLink: string | undefined;

  private _proc: ChildProcessWithoutNullStreams | null = null;
  private _reader: BufferedReader | null = null;
  private _readerLoop: Promise<void> | null = null;
  private _sessionId: string | null = null;
  private _sessionResolve: (() => void) | null = null;
  private _sessionReject: ((err: Error) => void) | null = null;
  private _sessionPromise: Promise<void> | null = null;
  private _pending = new Map<string, PendingRequest>();
  private _auditLogs: AuditEntry[] = [];
  private _auditFilePath: string | null = null;
  private _auditPoller: ReturnType<typeof setInterval> | null = null;
  private _auditFileOffset = 0;
  private _stopped = false;

  constructor(upstreamOrOptions: string | LilithOptions, legacyOptions: LilithOptions = {}) {
    // Support both forms:
    //   new Lilith("node server.mjs", { policy: "..." })   ← positional (old)
    //   new Lilith({ upstream: "node server.mjs", ... })   ← options object
    //   new Lilith({ upstreamUrl: "http://...", ... })      ← HTTP transport
    const opts: LilithOptions =
      typeof upstreamOrOptions === "string"
        ? { ...legacyOptions, upstream: upstreamOrOptions }
        : upstreamOrOptions;

    const { upstream, upstreamUrl, policy, binary, telemetryLink } = opts;

    if (upstream && upstreamUrl) {
      throw new LilithConfigError(
        "upstream and upstreamUrl are mutually exclusive",
        "upstream",
      );
    }

    if (upstreamUrl) {
      this._upstreamCmd = null;
      this._upstreamArgs = [];
      this._upstreamUrl = upstreamUrl;
    } else {
      const cmd = upstream?.trim() ?? "";
      if (!cmd) {
        throw new LilithConfigError(
          "upstream command is required (or use upstreamUrl for HTTP transport)",
          "upstream",
        );
      }
      const parts = splitCommand(cmd);
      if (parts.length === 0) {
        throw new LilithConfigError(
          "upstream command is empty after parsing",
          "upstream",
        );
      }
      this._upstreamCmd = parts[0]!;
      this._upstreamArgs = parts.slice(1);
      this._upstreamUrl = null;
    }

    // Resolve binary.
    try {
      this._binaryPath = binary ? resolve(binary) : findBinary();
    } catch (e) {
      throw e instanceof LilithConfigError
        ? e
        : new LilithConfigError(String(e), "binary");
    }

    if (!existsSync(this._binaryPath)) {
      throw new LilithConfigError(
        `Lilith binary not found at ${this._binaryPath}`,
        "binary",
      );
    }

    this._policyPath = policy ? resolve(policy) : undefined;
    this._telemetryLink = telemetryLink;
  }

  // ─── Public properties ──────────────────────────────────────────────────

  /** HMAC-signed session identifier (set after {@link connect}). */
  get sessionId(): string | null {
    return this._sessionId;
  }

  /** Structured audit log entries captured from the Lilith audit file. */
  get auditLogs(): AuditEntry[] {
    return [...this._auditLogs];
  }

  // ─── Lifecycle ──────────────────────────────────────────────────────────

  /**
   * Connect to the Lilith middleware and perform the MCP handshake.
   *
   * Must be called before any tool or resource operations.
   * Use `await using` (TypeScript 5.2+) or a try/finally with
   * {@link disconnect} to ensure cleanup.
   */
  async connect(): Promise<void> {
    this._stopped = false;
    this._auditFilePath = join(
      tmpdir(),
      `lilith_audit_${randomUUID()}.jsonl`,
    );

    const cmd = this._buildCommand();
    try {
      this._proc = spawn(cmd[0]!, cmd.slice(1), {
        stdio: ["pipe", "pipe", "pipe"],
      }) as ChildProcessWithoutNullStreams;
    } catch (e) {
      throw new LilithConnectionError("Failed to spawn Lilith process", {
        phase: "spawn",
        underlyingError: e instanceof Error ? e : new Error(String(e)),
      });
    }

    this._reader = new BufferedReader(this._proc.stdout);

    // Start stderr listener (captures session ID).
    this._listenStderr();

    // Start the reader loop (processes framed JSON-RPC responses).
    this._readerLoop = this._runReaderLoop().catch((err: unknown) => {
      this._failAllPending(
        err instanceof Error ? err.message : "Reader loop crashed",
      );
    });

    // Start audit poller.
    this._startAuditPoller();

    try {
      await this._waitForSession();
      await this._sendRequest("initialize", {
        protocolVersion: MCP_PROTOCOL_VERSION,
        capabilities: {},
        clientInfo: { name: SDK_NAME, version: SDK_VERSION },
      });
      await this._sendNotification("notifications/initialized", {});
    } catch (e) {
      await this.disconnect();
      throw e;
    }
  }

  /** Cleanly shut down the Lilith subprocess and release all resources. */
  async disconnect(): Promise<void> {
    this._stopped = true;

    if (this._auditPoller) {
      clearInterval(this._auditPoller);
      this._auditPoller = null;
    }

    this._failAllPending("Lilith disconnected");

    if (this._proc) {
      try {
        this._proc.kill("SIGTERM");
        // Give process up to 5 s to exit cleanly.
        await Promise.race([
          new Promise<void>((res) => this._proc!.once("close", res)),
          new Promise<void>((res) => setTimeout(res, 5_000)),
        ]);
        if (this._proc.exitCode === null) this._proc.kill("SIGKILL");
      } catch {
        // Ignore kill errors — process may have already exited.
      }
      this._proc = null;
    }

    // Wait for the reader loop to drain.
    if (this._readerLoop) {
      await this._readerLoop.catch(() => {});
      this._readerLoop = null;
    }

    // Final synchronous drain of the audit file.
    this._drainAuditFile();

    // Remove the audit temp file.
    if (this._auditFilePath && existsSync(this._auditFilePath)) {
      try {
        unlinkSync(this._auditFilePath);
      } catch {
        // Best-effort cleanup.
      }
    }
    this._auditFilePath = null;
    this._sessionId = null;
    this._reader = null;
  }

  /**
   * `using` / `await using` support (TypeScript 5.2+).
   *
   * @example
   * ```ts
   * await using lilith = new Lilith("python server.py");
   * await lilith.connect();
   * ```
   */
  async [Symbol.asyncDispose](): Promise<void> {
    await this.disconnect();
  }

  /**
   * Flush the audit file and return all captured entries.
   *
   * Waits one poll cycle so recent entries are included.
   */
  async drainAuditLogs(): Promise<AuditEntry[]> {
    await new Promise<void>((r) => setTimeout(r, 150));
    this._drainAuditFile();
    return [...this._auditLogs];
  }

  // ─── Public MCP API ─────────────────────────────────────────────────────

  /** Fetch the list of tools from the upstream MCP server. */
  async listTools(): Promise<ToolRef[]> {
    const result = await this._sendRequest("tools/list", {});
    return ((result as Record<string, unknown>)["tools"] ?? []) as ToolRef[];
  }

  /**
   * Execute a tool call through Lilith policy enforcement.
   *
   * @throws {@link PolicyViolationError} if blocked by policy.
   * @throws {@link LilithProcessError} on communication failure.
   */
  async callTool(
    name: string,
    args: Record<string, unknown>,
  ): Promise<ToolResult> {
    const result = await this._sendRequest("tools/call", {
      name,
      arguments: args,
    });
    return result as ToolResult;
  }

  /** Fetch the list of resources from the upstream MCP server. */
  async listResources(): Promise<Array<Record<string, unknown>>> {
    const result = await this._sendRequest("resources/list", {});
    return ((result as Record<string, unknown>)["resources"] ??
      []) as Array<Record<string, unknown>>;
  }

  /** Read a resource through Lilith policy enforcement. */
  async readResource(uri: string): Promise<Record<string, unknown>> {
    return (await this._sendRequest("resources/read", {
      uri,
    })) as Record<string, unknown>;
  }

  // ─── Internal: connection ────────────────────────────────────────────────

  private _buildCommand(): string[] {
    const cmd: string[] = [this._binaryPath];

    if (this._policyPath) cmd.push("--policy", this._policyPath);
    if (this._auditFilePath) cmd.push("--audit-logs", this._auditFilePath);
    if (this._telemetryLink) cmd.push("--telemetry-link", this._telemetryLink);

    if (this._upstreamUrl) {
      cmd.push("--transport", "http", "--upstream-url", this._upstreamUrl);
    } else {
      cmd.push("--upstream-cmd", this._upstreamCmd!);
      if (this._upstreamArgs.length > 0) {
        cmd.push("--", ...this._upstreamArgs);
      }
    }
    return cmd;
  }

  private _waitForSession(): Promise<void> {
    this._sessionPromise = new Promise<void>((resolve, reject) => {
      this._sessionResolve = resolve;
      this._sessionReject = reject;
    });

    const timer = setTimeout(() => {
      const exitCode = this._proc?.exitCode;
      if (exitCode !== null && exitCode !== undefined) {
        this._sessionReject?.(
          new LilithProcessError(
            `Lilith process exited early with code ${exitCode}`,
            { exitCode },
          ),
        );
      } else {
        this._sessionReject?.(
          new LilithConnectionError(
            `Handshake timeout after ${SESSION_TIMEOUT_MS / 1000}s`,
            { phase: "handshake" },
          ),
        );
      }
    }, SESSION_TIMEOUT_MS);

    return this._sessionPromise.finally(() => clearTimeout(timer));
  }

  private _listenStderr(): void {
    if (!this._proc?.stderr) return;
    let stderrBuf = "";
    this._proc.stderr.on("data", (chunk: Buffer) => {
      stderrBuf += chunk.toString("utf-8");
      const lines = stderrBuf.split("\n");
      stderrBuf = lines.pop() ?? "";
      for (const line of lines) {
        if (line.includes(SESSION_ID_MARKER)) {
          const parts = line.split(SESSION_ID_MARKER);
          if (parts.length > 1) {
            this._sessionId = parts[1]!.trim();
            this._sessionResolve?.();
          }
        }
      }
    });
  }

  // ─── Internal: reader loop ───────────────────────────────────────────────

  private async _runReaderLoop(): Promise<void> {
    const reader = this._reader;
    if (!reader) return;

    for (;;) {
      // Read headers until blank line.
      const headers: Record<string, string> = {};
      for (;;) {
        const line = await reader.readLine();
        if (line === null) return; // EOF
        if (line.length > MAX_HEADER_LINE_BYTES) {
          this._failAllPending("Protocol violation: header line too long");
          return;
        }
        if (line === "") break; // End of headers.
        const colon = line.indexOf(":");
        if (colon !== -1) {
          const key = line.slice(0, colon).toLowerCase().trim();
          const val = line.slice(colon + 1).trim();
          headers[key] = val;
        }
      }

      const lengthStr = headers["content-length"];
      if (!lengthStr) continue;
      const length = parseInt(lengthStr, 10);
      if (isNaN(length) || length < 0) continue;
      if (length > MAX_PAYLOAD_BYTES) {
        this._failAllPending(
          `Payload size (${length}) exceeds limit (${MAX_PAYLOAD_BYTES})`,
        );
        return;
      }
      if (length === 0) continue;

      const body = await reader.readBytes(length);
      if (body === null) return; // EOF before full body.

      let msg: Record<string, unknown>;
      try {
        msg = JSON.parse(body.toString("utf-8")) as Record<string, unknown>;
      } catch {
        this._failAllPending("Protocol error: malformed JSON body");
        return;
      }

      if ("id" in msg) {
        this._dispatchResponse(msg);
      }
      // Notifications (no `id`) are silently dropped.
    }
  }

  private _dispatchResponse(msg: Record<string, unknown>): void {
    const id = String(msg["id"]);
    const pending = this._pending.get(id);
    if (!pending) return;
    this._pending.delete(id);
    clearTimeout(pending.timer);

    if (msg["error"]) {
      const err = msg["error"] as Record<string, unknown>;
      const code = err["code"] as number | undefined;
      const message = String(err["message"] ?? "Unknown error");

      if (code === -32000 || message.includes("Policy Violation")) {
        pending.reject(
          new PolicyViolationError(message, (err["data"] as Record<string, unknown>) ?? {}),
        );
      } else {
        pending.reject(
          new LilithError(`Lilith RPC Error: ${message}`, {
            code,
            data: err["data"],
          }),
        );
      }
    } else {
      pending.resolve(msg["result"] ?? {});
    }
  }

  private _failAllPending(reason: string): void {
    const err = new LilithProcessError(reason);
    for (const [id, pending] of this._pending) {
      clearTimeout(pending.timer);
      pending.reject(err);
      this._pending.delete(id);
    }
  }

  // ─── Internal: JSON-RPC transport ────────────────────────────────────────

  private async _sendNotification(
    method: string,
    params: Record<string, unknown>,
  ): Promise<void> {
    if (!this._proc?.stdin) {
      throw new LilithConnectionError("Lilith process not running", {
        phase: "runtime",
      });
    }
    const body = JSON.stringify({ jsonrpc: "2.0", method, params });
    const frame = `Content-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`;
    this._proc.stdin.write(frame);
  }

  private _sendRequest(
    method: string,
    params: Record<string, unknown>,
  ): Promise<unknown> {
    if (!this._proc || this._proc.exitCode !== null) {
      return Promise.reject(
        new LilithConnectionError("Lilith process is not running", {
          phase: "runtime",
        }),
      );
    }
    if (!this._proc.stdin) {
      return Promise.reject(
        new LilithConnectionError("Lilith stdin is closed", {
          phase: "runtime",
        }),
      );
    }

    const id = randomUUID();
    const sessionParam = this._sessionId
      ? { _lilith_zero_session_id: this._sessionId }
      : {};

    const request = {
      jsonrpc: "2.0",
      method,
      params: { ...params, ...sessionParam },
      id,
    };

    const body = JSON.stringify(request);
    if (Buffer.byteLength(body) > MAX_PAYLOAD_BYTES) {
      return Promise.reject(
        new LilithError(
          `Payload size (${Buffer.byteLength(body)}) exceeds limit (${MAX_PAYLOAD_BYTES})`,
        ),
      );
    }

    return new Promise<unknown>((resolve, reject) => {
      const timer = setTimeout(() => {
        this._pending.delete(id);
        const exitCode = this._proc?.exitCode;
        if (exitCode !== null && exitCode !== undefined) {
          reject(
            new LilithProcessError(
              `Request '${method}' failed — Lilith process exited with code ${exitCode}`,
              { exitCode },
            ),
          );
        } else {
          reject(
            new LilithError(
              `Request '${method}' timed out after ${REQUEST_TIMEOUT_MS / 1000}s`,
            ),
          );
        }
      }, REQUEST_TIMEOUT_MS);

      this._pending.set(id, { resolve, reject, timer });

      const frame = `Content-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`;
      try {
        this._proc!.stdin.write(frame);
      } catch (e) {
        this._pending.delete(id);
        clearTimeout(timer);
        reject(
          new LilithConnectionError("Write to Lilith stdin failed", {
            phase: "runtime",
            ...(e instanceof Error ? { underlyingError: e } : {}),
          }),
        );
      }
    });
  }

  // ─── Internal: audit log ─────────────────────────────────────────────────

  private _startAuditPoller(): void {
    // Give Lilith a moment to create the file, then poll every 100 ms.
    this._auditPoller = setInterval(() => {
      if (!this._auditFilePath) return;
      this._drainAuditFile();
    }, 100);
  }

  private _drainAuditFile(): void {
    if (!this._auditFilePath || !existsSync(this._auditFilePath)) return;
    try {
      const { readFileSync } = require("node:fs") as typeof import("node:fs");
      const raw = readFileSync(this._auditFilePath, "utf-8");
      const lines = raw.split("\n");
      let offset = 0;
      for (const line of lines) {
        if (offset++ < this._auditFileOffset) continue;
        if (line.trim()) {
          this._parseAuditLine(line);
          this._auditFileOffset++;
        }
      }
    } catch {
      // File may not exist yet or be partially written — ignore.
    }
  }

  private _parseAuditLine(line: string): void {
    try {
      const data = JSON.parse(line) as Record<string, unknown>;
      const signature = data["signature"] as string | undefined;
      const payloadRaw = data["payload"];
      if (!signature || !payloadRaw) return;

      const payload =
        typeof payloadRaw === "string"
          ? (JSON.parse(payloadRaw) as Record<string, unknown>)
          : (payloadRaw as Record<string, unknown>);

      this._auditLogs.push({
        session_id: String(payload["session_id"] ?? ""),
        timestamp: Number(payload["timestamp"] ?? 0),
        event_type: String(payload["event_type"] ?? "UNKNOWN"),
        details: (payload["details"] as Record<string, unknown>) ?? {},
        signature,
      });
    } catch {
      // Ignore malformed lines.
    }
  }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Minimal shell-style command splitter.
 *
 * Handles quoted strings and unquoted tokens. Does not support: escapes
 * inside single-quoted strings, substitutions, or pipes. Covers the common
 * case of `"python -u server.py"` or `"node --experimental-strip-types srv.ts"`.
 */
export function splitCommand(cmd: string): string[] {
  const tokens: string[] = [];
  let current = "";
  let inSingle = false;
  let inDouble = false;

  for (let i = 0; i < cmd.length; i++) {
    const ch = cmd[i]!;
    if (ch === "'" && !inDouble) {
      inSingle = !inSingle;
    } else if (ch === '"' && !inSingle) {
      inDouble = !inDouble;
    } else if (ch === " " && !inSingle && !inDouble) {
      if (current) {
        tokens.push(current);
        current = "";
      }
    } else {
      current += ch;
    }
  }
  if (current) tokens.push(current);
  return tokens;
}
