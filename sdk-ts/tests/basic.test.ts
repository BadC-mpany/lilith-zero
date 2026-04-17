/**
 * Lilith TypeScript SDK — test suite.
 *
 * Unit tests run always; integration tests are skipped when the Lilith
 * binary is unavailable (set LILITH_ZERO_BINARY_PATH or build the Rust crate).
 */

import { describe, it, expect, beforeAll, afterAll } from "bun:test";
import { existsSync } from "node:fs";
import { join } from "node:path";
import {
  LilithError,
  LilithConfigError,
  LilithConnectionError,
  LilithProcessError,
  PolicyViolationError,
} from "../src/errors.ts";
import { splitCommand } from "../src/client.ts";
import { findBinary, ENV_BINARY_PATH, BINARY_NAME } from "../src/binary.ts";
import { Lilith } from "../src/client.ts";

// ─── Helpers ────────────────────────────────────────────────────────────────

function lilithBinary(): string | null {
  try {
    return findBinary();
  } catch {
    return null;
  }
}

const BINARY = lilithBinary();
const SKIP_INTEGRATION = BINARY === null;

/** Skip wrapper — runs `fn` only when the binary is available. */
function integration(name: string, fn: () => Promise<void>): void {
  if (SKIP_INTEGRATION) {
    it.skip(`[integration] ${name} (no binary)`, () => {});
  } else {
    it(`[integration] ${name}`, fn);
  }
}

/** Path to the echo server script (sibling of this test file). */
const ECHO_SERVER = join(import.meta.dir, "echo_server.mjs");
const ECHO_UPSTREAM = `node ${ECHO_SERVER}`;

/** Path to the allow-all policy for integration tests. */
const ALLOW_ALL_POLICY = join(import.meta.dir, "allow_all.yaml");

// ─── Error class unit tests ──────────────────────────────────────────────────

describe("Error hierarchy", () => {
  it("LilithError has correct name and message", () => {
    const e = new LilithError("base error");
    expect(e.name).toBe("LilithError");
    expect(e.message).toBe("base error");
    expect(e).toBeInstanceOf(Error);
    expect(e).toBeInstanceOf(LilithError);
  });

  it("LilithError includes context in toString()", () => {
    const e = new LilithError("msg", { key: "val" });
    expect(e.toString()).toContain("msg");
    expect(e.toString()).toContain("val");
  });

  it("LilithConfigError is instanceof LilithError", () => {
    const e = new LilithConfigError("bad config", "upstream");
    expect(e).toBeInstanceOf(LilithError);
    expect(e).toBeInstanceOf(LilithConfigError);
    expect(e.configKey).toBe("upstream");
    expect(e.context["config_key"]).toBe("upstream");
  });

  it("LilithConnectionError stores phase and underlyingError", () => {
    const cause = new Error("ECONNREFUSED");
    const e = new LilithConnectionError("conn failed", {
      phase: "spawn",
      underlyingError: cause,
    });
    expect(e).toBeInstanceOf(LilithError);
    expect(e.phase).toBe("spawn");
    expect(e.underlyingError).toBe(cause);
    expect(e.context["connection_phase"]).toBe("spawn");
    expect(e.context["underlying_error"]).toBe("ECONNREFUSED");
  });

  it("LilithProcessError stores exitCode and truncated stderr", () => {
    const longStderr = "x".repeat(1000);
    const e = new LilithProcessError("crash", {
      exitCode: 2,
      stderr: longStderr,
    });
    expect(e).toBeInstanceOf(LilithError);
    expect(e.exitCode).toBe(2);
    expect(e.context["exit_code"]).toBe(2);
    const stored = e.context["stderr"] as string;
    expect(stored.length).toBeLessThanOrEqual(500);
  });

  it("PolicyViolationError stores policyDetails", () => {
    const e = new PolicyViolationError("blocked", { rule: "deny-write" });
    expect(e).toBeInstanceOf(LilithError);
    expect(e.policyDetails).toEqual({ rule: "deny-write" });
    expect(e.context["policy_details"]).toEqual({ rule: "deny-write" });
  });

  it("instanceof works across different catch paths", () => {
    function throwConfig() {
      throw new LilithConfigError("oops");
    }
    expect(() => throwConfig()).toThrow(LilithError);
    expect(() => throwConfig()).toThrow(LilithConfigError);
  });
});

// ─── splitCommand unit tests ─────────────────────────────────────────────────

describe("splitCommand", () => {
  it("splits a simple command", () => {
    expect(splitCommand("python server.py")).toEqual(["python", "server.py"]);
  });

  it("respects double-quoted strings", () => {
    expect(splitCommand('node "my server.js" --flag')).toEqual([
      "node",
      "my server.js",
      "--flag",
    ]);
  });

  it("respects single-quoted strings", () => {
    expect(splitCommand("node 'my server.js'")).toEqual([
      "node",
      "my server.js",
    ]);
  });

  it("handles extra whitespace", () => {
    expect(splitCommand("  bun   run   server.ts  ")).toEqual([
      "bun",
      "run",
      "server.ts",
    ]);
  });

  it("returns empty array for blank string", () => {
    expect(splitCommand("")).toEqual([]);
    expect(splitCommand("   ")).toEqual([]);
  });
});

// ─── Binary discovery unit tests ─────────────────────────────────────────────

describe("findBinary", () => {
  it("respects LILITH_ZERO_BINARY_PATH env var when file exists", () => {
    if (!BINARY) return; // Need at least one binary to test with.
    const original = process.env[ENV_BINARY_PATH];
    process.env[ENV_BINARY_PATH] = BINARY;
    try {
      const found = findBinary();
      expect(found).toBe(BINARY);
    } finally {
      if (original === undefined) delete process.env[ENV_BINARY_PATH];
      else process.env[ENV_BINARY_PATH] = original;
    }
  });

  it("throws LilithConfigError when binary explicitly set to nonexistent path", () => {
    // The constructor validates the explicit `binary` option — use that to
    // test the error path cleanly without relying on clearing PATH (Bun caches
    // the real env and ignores process.env mutations for child processes).
    expect(
      () => new Lilith("echo test", { binary: "/nonexistent/lilith-zero" }),
    ).toThrow(LilithConfigError);
  });
});

// ─── Client constructor validation ───────────────────────────────────────────

describe("Lilith constructor validation", () => {
  it("throws LilithConfigError for empty upstream", () => {
    expect(() => new Lilith("")).toThrow(LilithConfigError);
    expect(() => new Lilith("   ")).toThrow(LilithConfigError);
  });

  it("throws LilithConfigError when binary path does not exist", () => {
    expect(
      () => new Lilith("echo test", { binary: "/nonexistent/lilith-zero" }),
    ).toThrow(LilithConfigError);
  });

  it("accepts a valid binary path", () => {
    if (!BINARY) return;
    const l = new Lilith("echo hello", { binary: BINARY });
    expect(l.sessionId).toBeNull();
    expect(l.auditLogs).toEqual([]);
  });
});

// ─── Integration tests ───────────────────────────────────────────────────────

describe("Integration (requires Lilith binary)", () => {
  if (SKIP_INTEGRATION) {
    it("SKIPPED — set LILITH_ZERO_BINARY_PATH to enable", () => {});
    return;
  }

  let lilith: Lilith;

  beforeAll(async () => {
    lilith = new Lilith(ECHO_UPSTREAM, { binary: BINARY!, policy: ALLOW_ALL_POLICY });
    await lilith.connect();
  });

  afterAll(async () => {
    await lilith.disconnect();
  });

  it("session ID is set after connect", () => {
    expect(lilith.sessionId).toBeTruthy();
    expect(typeof lilith.sessionId).toBe("string");
  });

  it("listTools returns echo and add", async () => {
    const tools = await lilith.listTools();
    expect(tools.length).toBeGreaterThanOrEqual(2);
    const names = tools.map((t) => t.name);
    expect(names).toContain("echo");
    expect(names).toContain("add");
  });

  it("callTool(echo) returns echoed text", async () => {
    const result = await lilith.callTool("echo", { text: "lilith-ts" });
    expect(result.content).toHaveLength(1);
    expect((result.content[0] as { text: string }).text).toBe("lilith-ts");
    expect(result.isError).toBeFalsy();
  });

  it("callTool(add) sums two numbers", async () => {
    const result = await lilith.callTool("add", { a: 21, b: 21 });
    expect((result.content[0] as { text: string }).text).toBe("42");
  });

  it("listResources returns at least one resource", async () => {
    const resources = await lilith.listResources();
    expect(resources.length).toBeGreaterThanOrEqual(1);
  });

  it("readResource returns content", async () => {
    const result = await lilith.readResource("test://hello");
    expect(result).toBeDefined();
  });

  it("concurrent requests all resolve", async () => {
    const calls = Array.from({ length: 5 }, (_, i) =>
      lilith.callTool("echo", { text: `concurrent-${i}` }),
    );
    const results = await Promise.all(calls);
    expect(results).toHaveLength(5);
    for (const r of results) {
      expect(r.isError).toBeFalsy();
    }
  });
});

// ─── Large payload test ──────────────────────────────────────────────────────

describe("Payload size enforcement", () => {
  it("rejects payloads over 10 MB before sending", async () => {
    if (!BINARY) return;
    const l = new Lilith(ECHO_UPSTREAM, { binary: BINARY!, policy: ALLOW_ALL_POLICY });
    await l.connect();
    try {
      const big = "x".repeat(11 * 1024 * 1024);
      await expect(l.callTool("echo", { text: big })).rejects.toThrow(
        LilithError,
      );
    } finally {
      await l.disconnect();
    }
  });
});

// ─── Lifecycle tests ─────────────────────────────────────────────────────────

describe("Lifecycle", () => {
  it("disconnect before connect is a no-op", async () => {
    if (!BINARY) return;
    const l = new Lilith(ECHO_UPSTREAM, { binary: BINARY!, policy: ALLOW_ALL_POLICY });
    await expect(l.disconnect()).resolves.toBeUndefined();
  });

  it("can reconnect after disconnect", async () => {
    if (!BINARY) return;
    const l = new Lilith(ECHO_UPSTREAM, { binary: BINARY!, policy: ALLOW_ALL_POLICY });
    await l.connect();
    const sid1 = l.sessionId;
    await l.disconnect();

    await l.connect();
    const sid2 = l.sessionId;
    expect(sid2).toBeTruthy();
    expect(sid1).not.toBe(sid2); // New session each time.
    await l.disconnect();
  });
});
