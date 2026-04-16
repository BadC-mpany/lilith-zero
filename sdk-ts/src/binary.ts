// Copyright 2026 BadCompany
// Licensed under the Apache License, Version 2.0

/**
 * Binary discovery for the Lilith Zero native executable.
 *
 * Search order (same as Python SDK):
 * 1. `LILITH_ZERO_BINARY_PATH` environment variable
 * 2. System PATH (`which lilith-zero`)
 * 3. `~/.lilith_zero/bin/lilith-zero` (standard user install)
 * 4. Repo-relative Cargo build output (`target/release` then `target/debug`)
 */

import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { execSync } from "node:child_process";
import { LilithConfigError } from "./errors.js";

export const ENV_BINARY_PATH = "LILITH_ZERO_BINARY_PATH";
export const BINARY_NAME =
  process.platform === "win32" ? "lilith-zero.exe" : "lilith-zero";

/** Returns `~/.lilith_zero/bin` — the standard user install location. */
export function getDefaultInstallDir(): string {
  return join(homedir(), ".lilith_zero", "bin");
}

function whichBinary(): string | null {
  try {
    const cmd =
      process.platform === "win32"
        ? `where ${BINARY_NAME}`
        : `which ${BINARY_NAME}`;
    const out = execSync(cmd, { stdio: ["ignore", "pipe", "ignore"] })
      .toString()
      .trim()
      .split("\n")[0]
      ?.trim();
    return out && existsSync(out) ? resolve(out) : null;
  } catch {
    return null;
  }
}

/**
 * Locate the Lilith binary.
 *
 * @throws {@link LilithConfigError} if the binary cannot be found.
 */
export function findBinary(): string {
  // 1. Environment variable — highest priority.
  const envPath = process.env[ENV_BINARY_PATH];
  if (envPath) {
    if (existsSync(envPath)) return resolve(envPath);
    console.warn(
      `[lilith-zero] ${ENV_BINARY_PATH} set to '${envPath}' but file not found.`,
    );
  }

  // 2. System PATH.
  const onPath = whichBinary();
  if (onPath) return onPath;

  // 3. Standard user install location.
  const userBin = join(getDefaultInstallDir(), BINARY_NAME);
  if (existsSync(userBin)) return resolve(userBin);

  // 4. Developer Cargo output — search up for a repo root containing
  //    `lilith-zero/Cargo.toml`.
  try {
    const __filename = fileURLToPath(import.meta.url);
    let searchDir = dirname(__filename);
    for (let i = 0; i < 6; i++) {
      if (existsSync(join(searchDir, "lilith-zero", "Cargo.toml"))) {
        const releaseBin = join(
          searchDir,
          "lilith-zero",
          "target",
          "release",
          BINARY_NAME,
        );
        if (existsSync(releaseBin)) return resolve(releaseBin);

        const debugBin = join(
          searchDir,
          "lilith-zero",
          "target",
          "debug",
          BINARY_NAME,
        );
        if (existsSync(debugBin)) return resolve(debugBin);
        break;
      }
      searchDir = dirname(searchDir);
    }
  } catch {
    // Ignore — heuristic only.
  }

  throw new LilithConfigError(
    `Lilith binary '${BINARY_NAME}' not found. ` +
      `Set ${ENV_BINARY_PATH} or install via: curl -sSfL https://lilith.sh/install | sh`,
    "binary",
  );
}
