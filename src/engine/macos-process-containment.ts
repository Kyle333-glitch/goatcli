import {
  spawn,
  type ChildProcess,
  type ChildProcessWithoutNullStreams,
} from "node:child_process";
import { createInterface } from "node:readline";

const WATCHDOG_START_TIMEOUT_MS = 5_000;
const WATCHDOG_STOP_TIMEOUT_MS = 5_000;

const MACOS_PROCESS_WATCHDOG_SCRIPT = String.raw`
"use strict";

let buffer = "";
let processGroupId;
let settled = false;

process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  buffer += chunk;
  if (buffer.length > 256) failClosed();
  while (true) {
    const newline = buffer.indexOf("\n");
    if (newline < 0) break;
    const line = buffer.slice(0, newline);
    buffer = buffer.slice(newline + 1);
    if (processGroupId === undefined) {
      const match = /^BIND ([1-9][0-9]{0,14})$/.exec(line);
      const parsed = match ? Number(match[1]) : Number.NaN;
      if (!Number.isSafeInteger(parsed) || parsed <= 0) failClosed();
      processGroupId = parsed;
      continue;
    }
    if (line === "RELEASE") {
      settled = true;
      process.exit(0);
    }
    if (line === "KILL") failClosed();
    failClosed();
  }
});
process.stdin.on("end", failClosed);
process.stdin.on("error", failClosed);
process.stdout.write("READY\n");

function failClosed() {
  if (settled) return;
  settled = true;
  if (processGroupId !== undefined) {
    try {
      process.kill(-processGroupId, "SIGHUP");
    } catch {}
    setTimeout(() => {
      try {
        process.kill(-processGroupId, "SIGKILL");
      } catch {}
      process.exit(0);
    }, 750);
    return;
  }
  process.exit(0);
}
`;

export interface MacOsProcessContainment {
  bind(processGroupId: number): void;
  release(): Promise<void>;
  terminate(): void;
}

export async function createMacOsProcessContainment(options: {
  readonly runtimeExecutable: string;
  readonly startTimeoutMs?: number;
  readonly stopTimeoutMs?: number;
}): Promise<MacOsProcessContainment> {
  const watchdog = spawn(
    options.runtimeExecutable,
    ["-e", MACOS_PROCESS_WATCHDOG_SCRIPT],
    {
      detached: true,
      env: {},
      shell: false,
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
    },
  );
  watchdog.stderr.resume();
  watchdog.stdout.setEncoding("utf8");
  const lines = createInterface({
    input: watchdog.stdout,
    crlfDelay: Number.POSITIVE_INFINITY,
  });
  const iterator = lines[Symbol.asyncIterator]();

  try {
    await expectWatchdogLine(
      watchdog,
      iterator,
      "READY",
      options.startTimeoutMs ?? WATCHDOG_START_TIMEOUT_MS,
    );
  } catch {
    lines.close();
    watchdog.stdin.destroy();
    terminateWatchdog(watchdog);
    throw new Error("macOS process containment is unavailable.");
  }

  let bound = false;
  let releasePromise: Promise<void> | undefined;
  let terminating = false;
  return {
    bind(processGroupId) {
      if (
        bound ||
        !Number.isSafeInteger(processGroupId) ||
        processGroupId <= 0 ||
        watchdog.exitCode !== null ||
        watchdog.signalCode !== null
      ) {
        throw new Error("macOS process containment is unavailable.");
      }
      bound = true;
      watchdog.stdin.write("BIND " + String(processGroupId) + "\n");
    },
    release() {
      if (releasePromise) return releasePromise;
      releasePromise = (async () => {
        lines.close();
        if (!bound) {
          watchdog.stdin.end();
        } else {
          watchdog.stdin.end("RELEASE\n");
        }
        try {
          await waitForWatchdogExit(
            watchdog,
            options.stopTimeoutMs ?? WATCHDOG_STOP_TIMEOUT_MS,
          );
        } catch {
          terminateWatchdog(watchdog);
          throw new Error("macOS process containment did not stop safely.");
        }
        if (watchdog.exitCode !== 0) {
          throw new Error("macOS process containment ended unexpectedly.");
        }
      })();
      return releasePromise;
    },
    terminate() {
      if (terminating || releasePromise) return;
      terminating = true;
      lines.close();
      if (bound) {
        watchdog.stdin.end("KILL\n");
      } else {
        watchdog.stdin.end();
      }
    },
  };
}

async function expectWatchdogLine(
  watchdog: ChildProcess,
  iterator: AsyncIterator<string>,
  expected: string,
  timeoutMs: number,
): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    let settled = false;
    const finish = (error?: Error): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      watchdog.removeListener("error", onFailure);
      watchdog.removeListener("exit", onFailure);
      if (error) reject(error);
      else resolve();
    };
    const onFailure = (): void =>
      finish(new Error("Process-containment watchdog failed."));
    const timer = setTimeout(
      () => finish(new Error("Process-containment watchdog timed out.")),
      timeoutMs,
    );
    watchdog.once("error", onFailure);
    watchdog.once("exit", onFailure);
    void iterator.next().then(
      (result) => {
        if (result.done || result.value !== expected) {
          finish(new Error("Process-containment watchdog protocol failed."));
          return;
        }
        finish();
      },
      () => finish(new Error("Process-containment watchdog protocol failed.")),
    );
  });
}

async function waitForWatchdogExit(
  watchdog: ChildProcessWithoutNullStreams,
  timeoutMs: number,
): Promise<void> {
  if (watchdog.exitCode !== null || watchdog.signalCode !== null) return;
  await new Promise<void>((resolve, reject) => {
    let settled = false;
    const finish = (error?: Error): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      watchdog.removeListener("error", onError);
      watchdog.removeListener("exit", onExit);
      if (error) reject(error);
      else resolve();
    };
    const onError = (): void =>
      finish(new Error("Process-containment watchdog failed."));
    const onExit = (): void => finish();
    const timer = setTimeout(
      () => finish(new Error("Process-containment watchdog timed out.")),
      timeoutMs,
    );
    watchdog.once("error", onError);
    watchdog.once("exit", onExit);
  });
}

function terminateWatchdog(watchdog: ChildProcess): void {
  try {
    watchdog.kill();
  } catch {
    // The watchdog may already be gone.
  }
}
