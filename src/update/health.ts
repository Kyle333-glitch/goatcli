import path from "node:path";
import os from "node:os";
import { randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";
import { chmod, lstat, realpath, rm } from "node:fs/promises";
import { UpdateError } from "./errors.js";
import type { UpdatePlatform } from "./schema.js";
import { ensurePrivateDirectory } from "./durable.js";

export interface HealthCommandResult {
  readonly status: number | null;
  readonly signal?: NodeJS.Signals | null;
  readonly stdout: string;
  readonly stderr: string;
  readonly error?: Error;
}

export type HealthCommandRunner = (
  executablePath: string,
  args: readonly string[],
  options: {
    readonly cwd: string;
    readonly environment: NodeJS.ProcessEnv;
    readonly timeoutMs: number;
    readonly maxBufferBytes: number;
    readonly shell: false;
  },
) => HealthCommandResult;

export interface EngineHealthCheckOptions {
  readonly executablePath: string;
  readonly expectedVersion: string;
  readonly platform: UpdatePlatform;
  readonly runCommand?: HealthCommandRunner;
}

const HEALTH_TIMEOUT_MS = 10_000;
const MAX_HEALTH_OUTPUT_BYTES = 8 * 1024;

export async function runEngineHealthCheck(
  options: EngineHealthCheckOptions,
): Promise<void> {
  await assertRegularExecutable(options.executablePath);
  // Use a private, launcher-owned directory instead of a publicly writable
  // temp path. ensurePrivateDirectory rejects links and enforces 0700/strict
  // canonical placement under the package temp root.
  const tempRoot = path.join(os.tmpdir(), "goat-health");
  const emptyWorkingDirectory = await ensurePrivateDirectory(
    path.join(tempRoot, `goat-health-${randomUUID()}`),
    "GOAT_UPDATE_HEALTH_CHECK_FAILED",
  );
  try {
    const runner = options.runCommand ?? defaultRunner;
    const result = runner(options.executablePath, ["--version"], {
      cwd: emptyWorkingDirectory,
      environment: minimalHealthEnvironment(
        options.platform,
        emptyWorkingDirectory,
      ),
      timeoutMs: HEALTH_TIMEOUT_MS,
      maxBufferBytes: MAX_HEALTH_OUTPUT_BYTES,
      shell: false,
    });
    if (
      result.status !== 0 ||
      result.signal ||
      result.error ||
      result.stderr.length !== 0 ||
      Buffer.byteLength(result.stdout, "utf8") > MAX_HEALTH_OUTPUT_BYTES ||
      !isExactVersionOutput(result.stdout, options.expectedVersion)
    ) {
      throw new UpdateError("GOAT_UPDATE_HEALTH_CHECK_FAILED");
    }
  } finally {
    await rm(emptyWorkingDirectory, { recursive: true, force: true }).catch(
      () => undefined,
    );
  }
}

function defaultRunner(
  executablePath: string,
  args: readonly string[],
  options: {
    readonly cwd: string;
    readonly environment: NodeJS.ProcessEnv;
    readonly timeoutMs: number;
    readonly maxBufferBytes: number;
    readonly shell: false;
  },
): HealthCommandResult {
  const result = spawnSync(executablePath, [...args], {
    cwd: options.cwd,
    env: options.environment,
    shell: false,
    windowsHide: true,
    encoding: "utf8",
    timeout: options.timeoutMs,
    maxBuffer: options.maxBufferBytes,
    stdio: ["ignore", "pipe", "pipe"],
    // Use SIGKILL so a candidate that traps SIGTERM cannot block the
    // bounded health check indefinitely.
    killSignal: "SIGKILL",
  });
  return {
    status: result.status,
    signal: result.signal,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
    error: result.error,
  };
}

function minimalHealthEnvironment(
  platform: UpdatePlatform,
  workingDirectory: string,
): NodeJS.ProcessEnv {
  if (platform === "win32") {
    // Route any Windows temp usage into the launcher-owned working directory.
    // Do not inherit the process's TEMP/TMP, which may point to a publicly
    // writable directory.
    return {
      SystemRoot: process.env.SystemRoot ?? "C:\\Windows",
      TEMP: workingDirectory,
      TMP: workingDirectory,
    };
  }
  return {
    HOME: "/var/empty",
    LANG: "C",
    LC_ALL: "C",
    PATH: "/usr/bin:/bin",
    TMPDIR: workingDirectory,
  };
}

function isExactVersionOutput(
  output: string,
  expectedVersion: string,
): boolean {
  if (
    expectedVersion.length === 0 ||
    expectedVersion.length > 64 ||
    /[\r\n\0]/.test(expectedVersion)
  ) {
    return false;
  }
  const normalized = output.endsWith("\r\n")
    ? output.slice(0, -2)
    : output.endsWith("\n")
      ? output.slice(0, -1)
      : output;
  return normalized === expectedVersion && !/[\r\n\0]/.test(normalized);
}

async function assertRegularExecutable(executablePath: string): Promise<void> {
  if (!path.isAbsolute(executablePath)) {
    throw new UpdateError("GOAT_UPDATE_HEALTH_CHECK_FAILED");
  }
  try {
    const stats = await lstat(executablePath);
    const canonical = await realpath(executablePath);
    if (
      !stats.isFile() ||
      stats.isSymbolicLink() ||
      stats.nlink !== 1 ||
      path.resolve(canonical) !== path.resolve(executablePath)
    ) {
      throw new UpdateError("GOAT_UPDATE_HEALTH_CHECK_FAILED");
    }
  } catch (error) {
    if (error instanceof UpdateError) throw error;
    throw new UpdateError("GOAT_UPDATE_HEALTH_CHECK_FAILED", { cause: error });
  }
}
