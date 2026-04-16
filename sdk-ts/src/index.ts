// Copyright 2026 BadCompany
// Licensed under the Apache License, Version 2.0

/**
 * Lilith Zero TypeScript SDK.
 *
 * @module @bad-company/lilith-zero
 */

export { Lilith, splitCommand } from "./client.js";
export type { ToolRef, ToolResult, AuditEntry, LilithOptions } from "./client.js";
export {
  LilithError,
  LilithConfigError,
  LilithConnectionError,
  LilithProcessError,
  PolicyViolationError,
} from "./errors.js";
export { findBinary, getDefaultInstallDir, ENV_BINARY_PATH, BINARY_NAME } from "./binary.js";

export const VERSION = "0.1.3";
