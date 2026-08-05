import assert from "node:assert/strict";
import {
  spawn,
  spawnSync,
  type ChildProcessWithoutNullStreams,
} from "node:child_process";
import { randomUUID } from "node:crypto";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { createInterface } from "node:readline";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

type FixtureMode =
  "normal" | "termination-command-failure" | "spawn-failure" | "ipc-failure";
type FixtureRole = "launcher" | "engine" | "child" | "grandchild" | "sentinel";

interface FixtureMessage {
  readonly goatProcessFixture: 1;
  readonly event: string;
  readonly role?: FixtureRole;
  readonly pid?: number;
  readonly code?: string;
  readonly command?: string;
  readonly args?: readonly string[];
}

interface ReportedProcess {
  readonly child: ChildProcessWithoutNullStreams;
  readonly messages: FixtureMessage[];
  readonly stdout: () => string;
  readonly stderr: () => string;
}

interface TreeRun {
  readonly launcher: ReportedProcess;
  readonly sentinel: ReportedProcess;
  readonly consoleSignalTrigger?: string;
}

const fixtureDirectory = path.dirname(fileURLToPath(import.meta.url));
const fixturePath = path.join(fixtureDirectory, "process-tree-fixture.ts");
const launcherPath = path.join(fixtureDirectory, "process-tree-launcher.ts");
const windowsConsoleHostSourcePath = path.join(
  fixtureDirectory,
  "windows-console-host.cs",
);
let windowsConsoleHostBuildDirectory: string | undefined;
let windowsConsoleHostExecutable: string | undefined;

test.after(() => {
  if (windowsConsoleHostBuildDirectory) {
    rmSync(windowsConsoleHostBuildDirectory, { recursive: true, force: true });
  }
});

const nativeTerminationSignals: NodeJS.Signals[] =
  process.platform === "win32"
    ? ["SIGINT", "SIGTERM", "SIGBREAK"]
    : ["SIGINT", "SIGTERM", "SIGHUP"];

for (const signal of nativeTerminationSignals) {
  test(
    `native containment removes descendants for real ${signal}`,
    { timeout: 60_000 },
    async (context) => {
      if (!supportedPlatform()) {
        context.skip("native containment runs only on Windows and macOS");
        return;
      }
      const consoleSignal: "CTRL_C" | "CTRL_BREAK" | undefined =
        process.platform === "win32" &&
        (signal === "SIGINT" || signal === "SIGBREAK")
          ? signal === "SIGINT"
            ? "CTRL_C"
            : "CTRL_BREAK"
          : undefined;
      const run = await startTree("normal", true, consoleSignal);
      try {
        await sendNativeSignal(run, signal, consoleSignal !== undefined);
        await assertTreeStopped(run);
        assertSentinelAlive(run);
      } finally {
        await cleanupRun(run);
      }
    },
  );
}

test(
  "native containment closes descendants after launcher exit and engine crash",
  { timeout: 90_000 },
  async (context) => {
    if (!supportedPlatform()) {
      context.skip("native containment runs only on Windows and macOS");
      return;
    }

    const launcherExit = await startTree("normal");
    try {
      forceKill(rolePid(launcherExit, "launcher"));
      await assertTreeStopped(launcherExit);
      assertSentinelAlive(launcherExit);
    } finally {
      await cleanupRun(launcherExit);
    }

    const engineCrash = await startTree("normal");
    try {
      forceKill(rolePid(engineCrash, "engine"));
      await assertTreeStopped(engineCrash);
      assertSentinelAlive(engineCrash);
    } finally {
      await cleanupRun(engineCrash);
    }
  },
);

test(
  "Windows Job Object cleanup survives termination-command failure",
  { timeout: 60_000 },
  async (context) => {
    if (process.platform !== "win32") {
      context.skip("taskkill command failure is Windows-specific");
      return;
    }
    const run = await startTree("termination-command-failure");
    try {
      run.launcher.child.stdin.write("TRIGGER\n");
      await waitForMessage(
        run.launcher,
        (message) => message.event === "termination-command",
      );
      await assertTreeStopped(run);
      assertSentinelAlive(run);
      const attempts = run.launcher.messages.filter(
        (message) => message.event === "termination-command",
      );
      assert.deepEqual(
        attempts.map((message) => message.args),
        [
          ["/pid", String(rolePid(run, "engine")), "/T"],
          ["/pid", String(rolePid(run, "engine")), "/T", "/F"],
        ],
      );
    } finally {
      await cleanupRun(run);
    }
  },
);

test(
  "native spawn and IPC failures fail closed without touching the sentinel",
  { timeout: 90_000 },
  async (context) => {
    if (!supportedPlatform()) {
      context.skip("native containment runs only on Windows and macOS");
      return;
    }

    const spawnFailure = await startTree("spawn-failure", false);
    try {
      const error = await waitForMessage(
        spawnFailure.launcher,
        (message) => message.event === "error",
      );
      assert.equal(error.code, "GOAT_ENGINE_SPAWN_FAILED");
      assert.equal(
        spawnFailure.launcher.messages.some(
          (message) => message.role === "engine",
        ),
        false,
      );
      await waitForGone([rolePid(spawnFailure, "launcher")], 15_000);
      assertSentinelAlive(spawnFailure);
    } finally {
      await cleanupRun(spawnFailure);
    }

    const ipcFailure = await startTree("ipc-failure");
    try {
      const error = await waitForMessage(
        ipcFailure.launcher,
        (message) => message.event === "error",
        20_000,
      );
      assert.equal(error.code, "GOAT_PRIVACY_IPC_FAILED");
      await assertTreeStopped(ipcFailure);
      assertSentinelAlive(ipcFailure);
    } finally {
      await cleanupRun(ipcFailure);
    }
  },
);

async function startTree(
  mode: FixtureMode,
  expectTree = true,
  consoleSignal?: "CTRL_C" | "CTRL_BREAK",
): Promise<TreeRun> {
  const sentinel = spawnReported(fixturePath, ["sentinel"], false);
  await waitForMessage(
    sentinel,
    (message) => message.event === "ready" && message.role === "sentinel",
  );

  let launcher: ReportedProcess;
  let consoleSignalTrigger: string | undefined;
  try {
    if (consoleSignal) {
      const hosted = spawnConsoleHostedLauncher(mode, consoleSignal);
      launcher = hosted.launcher;
      consoleSignalTrigger = hosted.signalTrigger;
    } else {
      launcher = spawnReported(
        launcherPath,
        [mode],
        process.platform === "win32",
      );
    }
  } catch (error) {
    cleanupProcess(sentinel.child.pid);
    if (sentinel.child.pid) {
      await waitForGone([sentinel.child.pid], 5_000).catch(() => undefined);
    }
    throw error;
  }
  const run: TreeRun = { launcher, sentinel, consoleSignalTrigger };
  try {
    await waitForMessage(
      launcher,
      (message) => message.event === "ready" && message.role === "launcher",
    );
    if (expectTree) {
      for (const role of ["engine", "child", "grandchild"] as const) {
        await waitForMessage(
          launcher,
          (message) => message.event === "ready" && message.role === role,
          20_000,
        );
      }
    }
    return run;
  } catch (error) {
    await cleanupRun(run);
    throw error;
  }
}

function spawnConsoleHostedLauncher(
  mode: FixtureMode,
  signal: "CTRL_C" | "CTRL_BREAK",
): {
  launcher: ReportedProcess;
  signalTrigger: string;
} {
  assert.equal(process.platform, "win32");
  const executable = buildWindowsConsoleHost();
  assert.ok(windowsConsoleHostBuildDirectory);
  const signalTrigger = path.join(
    windowsConsoleHostBuildDirectory,
    `signal-${randomUUID()}.trigger`,
  );
  const environment = fixtureEnvironment();
  environment.GOAT_FIXTURE_NODE = process.execPath;
  environment.GOAT_FIXTURE_LAUNCHER = launcherPath;
  environment.GOAT_FIXTURE_MODE = mode;
  environment.GOAT_FIXTURE_SIGNAL = signal;
  environment.GOAT_FIXTURE_SIGNAL_TRIGGER = signalTrigger;
  environment.GOAT_FIXTURE_CWD = path.resolve(fixtureDirectory, "../..");
  const child = spawn(executable, [], {
    cwd: environment.GOAT_FIXTURE_CWD,
    detached: false,
    env: environment,
    shell: false,
    stdio: ["pipe", "pipe", "pipe"],
    windowsHide: true,
  });
  return { launcher: observeChild(child), signalTrigger };
}

function buildWindowsConsoleHost(): string {
  if (
    windowsConsoleHostExecutable &&
    existsSync(windowsConsoleHostExecutable)
  ) {
    return windowsConsoleHostExecutable;
  }

  const systemRoot =
    process.env.SystemRoot ?? process.env.SYSTEMROOT ?? process.env.WINDIR;
  assert.ok(systemRoot && path.win32.isAbsolute(systemRoot));
  const compilerCandidates = [
    path.win32.join(
      systemRoot,
      "Microsoft.NET",
      "Framework64",
      "v4.0.30319",
      "csc.exe",
    ),
    path.win32.join(
      systemRoot,
      "Microsoft.NET",
      "Framework",
      "v4.0.30319",
      "csc.exe",
    ),
  ];
  const compiler = compilerCandidates.find(existsSync);
  assert.ok(compiler, "Windows .NET Framework C# compiler is required");

  const buildDirectory = mkdtempSync(path.join(tmpdir(), "goat-console-host-"));
  const executablePath = path.join(buildDirectory, "goat-console-host.exe");
  const compilation = spawnSync(
    compiler,
    [
      "/nologo",
      "/target:exe",
      "/platform:anycpu",
      `/out:${executablePath}`,
      windowsConsoleHostSourcePath,
    ],
    {
      cwd: fixtureDirectory,
      env: fixtureEnvironment(),
      encoding: "utf8",
      shell: false,
      windowsHide: true,
    },
  );
  const compilerOutput =
    String(compilation.stderr ?? "") + String(compilation.stdout ?? "");
  assert.equal(
    compilation.status,
    0,
    "failed to compile Windows console host: " + compilerOutput.slice(0, 4_096),
  );
  assert.equal(
    existsSync(executablePath),
    true,
    "native Windows console host was not created",
  );
  windowsConsoleHostBuildDirectory = buildDirectory;
  windowsConsoleHostExecutable = executablePath;
  return executablePath;
}

function spawnReported(
  scriptPath: string,
  args: readonly string[],
  detached: boolean,
): ReportedProcess {
  const child = spawn(
    process.execPath,
    ["--import", "tsx", scriptPath, ...args],
    {
      cwd: path.resolve(fixtureDirectory, "../.."),
      detached,
      env: fixtureEnvironment(),
      shell: false,
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
    },
  );
  return observeChild(child);
}

function observeChild(child: ChildProcessWithoutNullStreams): ReportedProcess {
  const messages: FixtureMessage[] = [];
  let rawStdout = "";
  let stderr = "";
  const stdout = createInterface({
    input: child.stdout,
    crlfDelay: Number.POSITIVE_INFINITY,
  });
  stdout.on("line", (line) => {
    if (rawStdout.length < 8_192) {
      rawStdout += line.slice(0, 8_192 - rawStdout.length) + "\n";
    }
    if (line.length > 2_048) return;
    try {
      const parsed = JSON.parse(line) as Partial<FixtureMessage>;
      if (parsed.goatProcessFixture !== 1) return;
      messages.push(parsed as FixtureMessage);
    } catch {
      // Only the structured fixture channel is accepted as evidence.
    }
  });
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk: string) => {
    if (stderr.length < 8_192) stderr += chunk.slice(0, 8_192 - stderr.length);
  });
  return {
    child,
    messages,
    stdout: () => rawStdout,
    stderr: () => stderr,
  };
}

async function waitForMessage(
  reported: ReportedProcess,
  predicate: (message: FixtureMessage) => boolean,
  timeoutMs = 15_000,
): Promise<FixtureMessage> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const found = reported.messages.find(predicate);
    if (found) return found;
    if (
      reported.child.exitCode !== null ||
      reported.child.signalCode !== null
    ) {
      throw new Error(
        "fixture exited before reporting expected evidence" +
          ` (exit=${String(reported.child.exitCode)}, signal=${String(reported.child.signalCode)}): ` +
          reported.stdout() +
          reported.stderr(),
      );
    }
    await delay(20);
  }
  throw new Error(
    "fixture timed out before reporting expected evidence: " +
      reported.stderr(),
  );
}

function rolePid(run: TreeRun, role: FixtureRole): number {
  const message = run.launcher.messages.find(
    (candidate) =>
      candidate.event === "ready" &&
      candidate.role === role &&
      Number.isSafeInteger(candidate.pid),
  );
  assert.ok(message?.pid && message.pid > 0, "missing fixture PID for " + role);
  return message.pid;
}

function treePids(run: TreeRun): number[] {
  return ["launcher", "engine", "child", "grandchild"].map((role) =>
    rolePid(run, role as FixtureRole),
  );
}

async function assertTreeStopped(run: TreeRun): Promise<void> {
  const roles = ["launcher", "engine", "child", "grandchild"] as const;
  const processes = roles.map((role) => ({ role, pid: rolePid(run, role) }));
  const deadline = Date.now() + 20_000;
  let remaining = processes.filter(({ pid }) => isProcessAlive(pid));
  while (remaining.length > 0 && Date.now() < deadline) {
    await delay(25);
    remaining = remaining.filter(({ pid }) => isProcessAlive(pid));
  }
  assert.deepEqual(
    remaining,
    [],
    "fixture processes remained alive: " +
      remaining.map(({ role, pid }) => `${role}=${pid}`).join(", ") +
      "; evidence=" +
      run.launcher.stdout().slice(0, 4_096),
  );
}

function assertSentinelAlive(run: TreeRun): void {
  const sentinelPid = run.sentinel.child.pid;
  assert.ok(sentinelPid && sentinelPid > 0);
  assert.equal(isProcessAlive(sentinelPid), true);
  assert.equal(run.sentinel.child.exitCode, null);
  assert.equal(run.sentinel.child.signalCode, null);
}

async function waitForGone(
  processIds: readonly number[],
  timeoutMs: number,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  let remaining = processIds.filter(isProcessAlive);
  while (remaining.length > 0 && Date.now() < deadline) {
    await delay(25);
    remaining = remaining.filter(isProcessAlive);
  }
  assert.deepEqual(remaining, [], "fixture processes remained alive");
}

function isProcessAlive(processId: number): boolean {
  try {
    process.kill(processId, 0);
    return true;
  } catch (error) {
    return !hasErrorCode(error, "ESRCH");
  }
}

function forceKill(processId: number): void {
  assert.ok(Number.isSafeInteger(processId) && processId > 0);
  try {
    process.kill(processId, "SIGKILL");
  } catch (error) {
    if (!hasErrorCode(error, "ESRCH")) throw error;
  }
}

async function cleanupRun(run: TreeRun): Promise<void> {
  const known = new Set<number>();
  for (const message of run.launcher.messages) {
    if (Number.isSafeInteger(message.pid) && (message.pid ?? 0) > 0) {
      known.add(message.pid!);
    }
  }
  if (run.launcher.child.pid) known.add(run.launcher.child.pid);

  for (const processId of [...known].reverse()) {
    cleanupProcess(processId);
  }
  cleanupProcess(run.sentinel.child.pid);
  await waitForGone(
    [...known, run.sentinel.child.pid].filter(
      (value): value is number => value !== undefined,
    ),
    5_000,
  ).catch(() => undefined);
}

function cleanupProcess(processId: number | undefined): void {
  if (!processId || !isProcessAlive(processId)) return;
  if (process.platform === "win32") {
    spawnSync("taskkill", ["/pid", String(processId), "/T", "/F"], {
      shell: false,
      stdio: "ignore",
      timeout: 5_000,
      windowsHide: true,
    });
    return;
  }
  try {
    process.kill(processId, "SIGKILL");
  } catch {
    // The fixture may have completed between the liveness check and cleanup.
  }
}

async function sendNativeSignal(
  run: TreeRun,
  signal: NodeJS.Signals,
  consoleHosted: boolean,
): Promise<void> {
  if (consoleHosted) {
    assert.equal(process.platform, "win32");
    assert.ok(signal === "SIGINT" || signal === "SIGBREAK");
    assert.ok(run.consoleSignalTrigger);
    writeFileSync(run.consoleSignalTrigger, signal, {
      encoding: "utf8",
      flag: "wx",
      mode: 0o600,
    });
    return;
  }
  process.kill(rolePid(run, "launcher"), signal);
}

function fixtureEnvironment(): NodeJS.ProcessEnv {
  const allowed = new Set([
    "PATH",
    "SYSTEMROOT",
    "WINDIR",
    "TEMP",
    "TMP",
    "HOME",
    "USERPROFILE",
    "APPDATA",
    "LOCALAPPDATA",
    "LANG",
    "LC_ALL",
  ]);
  const result: NodeJS.ProcessEnv = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (value !== undefined && allowed.has(key.toUpperCase())) {
      result[key] = value;
    }
  }
  return result;
}

function supportedPlatform(): boolean {
  return process.platform === "win32" || process.platform === "darwin";
}

function hasErrorCode(error: unknown, code: string): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    (error as { code?: unknown }).code === code
  );
}

function delay(timeoutMs: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, timeoutMs));
}
