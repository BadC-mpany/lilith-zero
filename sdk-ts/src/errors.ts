// Copyright 2026 BadCompany
// Licensed under the Apache License, Version 2.0

/**
 * Lilith SDK error hierarchy.
 *
 * All errors extend {@link LilithError} so callers can catch the base class
 * and inspect the `context` map for structured debugging metadata.
 */

export class LilithError extends Error {
  readonly context: Record<string, unknown>;

  constructor(message: string, context: Record<string, unknown> = {}) {
    super(message);
    this.name = "LilithError";
    this.context = context;
    // Restore prototype chain for `instanceof` checks across transpilation boundaries.
    Object.setPrototypeOf(this, new.target.prototype);
  }

  override toString(): string {
    const keys = Object.keys(this.context);
    return keys.length
      ? `${this.message} (context: ${JSON.stringify(this.context)})`
      : this.message;
  }
}

/** Raised when configuration is invalid or missing. */
export class LilithConfigError extends LilithError {
  readonly configKey: string | undefined;

  constructor(
    message: string,
    configKey?: string,
    context: Record<string, unknown> = {},
  ) {
    const ctx = configKey ? { ...context, config_key: configKey } : context;
    super(message, ctx);
    this.name = "LilithConfigError";
    this.configKey = configKey;
  }
}

/** Raised when the SDK fails to connect to, or loses connection with, Lilith. */
export class LilithConnectionError extends LilithError {
  readonly phase: string | undefined;
  readonly underlyingError: Error | undefined;

  constructor(
    message: string,
    options: {
      phase?: string;
      underlyingError?: Error;
      context?: Record<string, unknown>;
    } = {},
  ) {
    const ctx: Record<string, unknown> = { ...options.context };
    if (options.phase) ctx["connection_phase"] = options.phase;
    if (options.underlyingError)
      ctx["underlying_error"] = options.underlyingError.message;
    super(message, ctx);
    this.name = "LilithConnectionError";
    this.phase = options.phase;
    this.underlyingError = options.underlyingError;
  }
}

/** Raised when the Lilith process behaves unexpectedly (crash, early exit). */
export class LilithProcessError extends LilithError {
  readonly exitCode: number | undefined;
  readonly stderr: string | undefined;

  constructor(
    message: string,
    options: {
      exitCode?: number;
      stderr?: string;
      context?: Record<string, unknown>;
    } = {},
  ) {
    const ctx: Record<string, unknown> = { ...options.context };
    if (options.exitCode !== undefined) ctx["exit_code"] = options.exitCode;
    if (options.stderr) ctx["stderr"] = options.stderr.trim().slice(-500);
    super(message, ctx);
    this.name = "LilithProcessError";
    this.exitCode = options.exitCode;
    this.stderr = options.stderr;
  }
}

/** Raised when a tool call is blocked by the security policy. */
export class PolicyViolationError extends LilithError {
  readonly policyDetails: Record<string, unknown>;

  constructor(
    message: string,
    policyDetails: Record<string, unknown> = {},
  ) {
    super(message, { policy_details: policyDetails });
    this.name = "PolicyViolationError";
    this.policyDetails = policyDetails;
  }
}
