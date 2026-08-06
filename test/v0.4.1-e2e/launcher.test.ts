import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { spawn, type ChildProcess } from "node:child_process";
import {
  mkdir,
  mkdtemp,
  readFile,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  launchEngine,
  type ProcessLike,
  type SpawnEngine,
} from "../../src/engine/launch.js";
import {
  getEngineExecutableName,
  getPlatformAdapter,
} from "../../src/platform.js";
import { getEngineInstallRoot } from "../../src/utils/paths.js";
import {
  resolveControlPlaneUrl,
  createAuthApiClient,
} from "../../src/auth/client.js";
import { refreshStoredCredentials } from "../../src/auth/credentials.js";
import { runLogin } from "../../src/commands/login.js";
import type { CredentialStore, GoatCredentials } from "../../src/auth/types.js";
import {
  MockControlPlaneServer,
  mockCredentialSet,
} from "./mock-control-plane.js";

test("launches the development engine with spaces, Unicode, and exact argv/cwd", async (context) => {
  const platform = supportedPlatform(context);
  if (!platform) return;
  const root = await mkdtemp(path.join(os.tmpdir(), "goat v0.4.1 e2e "));
  context.after(() => rm(root, { recursive: true, force: true }));
  const workingDirectory = path.join(root, "工作 space");
  const outputPath = path.join(root, "argv output.json");
  const forwarded = [
    "run",
    "value with spaces",
    "Unicode-雪",
    "--",
    "fixture-prompt-7qx9",
  ];
  const script = [
    'const fs=require("node:fs");',
    "fs.writeFileSync(process.argv[1],JSON.stringify({argv:process.argv.slice(2),cwd:process.cwd()}));",
  ].join("");
  await mkdir(workingDirectory, { recursive: true });

  const result = await launchDevelopmentEngine(
    ["-e", script, outputPath, ...forwarded],
    {
      cwd: workingDirectory,
    },
  );
  assert.deepEqual(result, { exitCode: 0, signal: null });
  const observed = JSON.parse(await readFile(outputPath, "utf8")) as {
    argv: string[];
    cwd: string;
  };
  assert.deepEqual(observed.argv, forwarded);
  const expectedCwd = path.resolve(workingDirectory);
  assert.equal(
    process.platform === "win32" ? observed.cwd.toLowerCase() : observed.cwd,
    process.platform === "win32" ? expectedCwd.toLowerCase() : expectedCwd,
  );
});

test("uses platform executable names and installation layouts without shell interpolation", () => {
  assert.equal(getEngineExecutableName("win32"), "goat-engine.exe");
  assert.equal(getEngineExecutableName("darwin"), "goat-engine");
  assert.equal(
    getEngineInstallRoot({
      platform: "win32",
      architecture: "x64",
      appDataDir: "C:\\Users\\Test User\\AppData\\Local\\goat",
    }),
    "C:\\Users\\Test User\\AppData\\Local\\goat\\engines\\stable\\win32-x64",
  );
  assert.equal(
    getEngineInstallRoot({
      platform: "darwin",
      architecture: "arm64",
      appDataDir: "/Users/Test User/Library/Application Support/goat/雪",
    }),
    "/Users/Test User/Library/Application Support/goat/雪/engines/stable/darwin-arm64",
  );
});

test("macOS executable permission repair is deterministic and Windows treats permissions as native", async (context) => {
  const platform = supportedPlatform(context);
  if (!platform) return;
  const root = await mkdtemp(path.join(os.tmpdir(), "goat-permission-e2e-"));
  context.after(() => rm(root, { recursive: true, force: true }));
  const executable = path.join(root, getEngineExecutableName(platform));
  await writeFile(executable, "#!/bin/sh\nexit 0\n", { mode: 0o644 });
  const adapter = getPlatformAdapter(platform);
  adapter.ensureExecutablePermission(executable);
  if (currentPlatform() === "darwin") {
    const stats = await stat(executable);
    assert.equal((stats.mode & 0o111) !== 0, true);
    assert.equal(await runExecutable(executable), 0);
  } else {
    assert.equal(adapter.hasExecutablePermission(executable), true);
  }
});

test("Ctrl+C terminates the real child and removes launcher listeners", async (context) => {
  const platform = supportedPlatform(context);
  if (!platform) return;
  const root = await mkdtemp(path.join(os.tmpdir(), "goat-signal-e2e-"));
  context.after(() => rm(root, { recursive: true, force: true }));
  const readyPath = path.join(root, "ready");
  const emitter = new EventEmitter();
  const child = await launchWithSignal(emitter, [
    "-e",
    'require("node:fs").writeFileSync(process.argv[1],"ready");setInterval(()=>{},1000)',
    readyPath,
  ]);
  assert.notEqual(child.result.exitCode, 0);
  if (platform === "darwin") assert.equal(child.result.signal, "SIGINT");
  assert.ok(typeof child.process.pid === "number" && child.process.pid > 0);
  await assertProcessGone(child.process, child.close);
  assert.equal(emitter.listenerCount("SIGINT"), 0);
  assert.equal(emitter.listenerCount("SIGTERM"), 0);
  assert.equal(emitter.listenerCount("exit"), 0);
});

test("runs mocked login, refresh, quota rejection, and bounded offline behavior", async (context) => {
  const platform = supportedPlatform(context);
  if (!platform) return;
  const server = new MockControlPlaneServer();
  const origin = await server.listen();
  context.after(() => server.close());
  const client = createAuthApiClient(
    resolveControlPlaneUrl({}, { developmentOrigin: origin }),
  );
  const current = mockCredentialSet();
  const store = memoryStore(null);
  let loginOutput = "";
  let loginError = "";
  const loginResult = await runLogin({
    client,
    store,
    opener: { open: async () => true },
    stdout: { write: (value) => ((loginOutput += value), true) },
    stderr: { write: (value) => ((loginError += value), true) },
    clock: { sleep: async () => {} },
  });
  assert.equal(loginResult, 0);
  assert.equal(loginError, "");
  assert.equal(loginOutput.includes(current.accessToken), false);
  assert.ok((await store.get())?.accessToken === current.accessToken);

  const refreshed = await refreshStoredCredentials(client, store);
  assert.equal(refreshed?.accessToken === current.accessToken, true);
  assert.equal(refreshed?.refreshToken === "N".repeat(43), true);
  assert.deepEqual(server.requests, [
    { method: "POST", path: "/v1/auth/device/sessions" },
    { method: "POST", path: "/v1/auth/device/token" },
    { method: "POST", path: "/v1/auth/tokens/refresh" },
  ]);
  assert.equal(server.validDeviceTokenRequests, 1);
  assert.equal(server.validRefreshRequests, 1);

  const quotaResponse = await fetch(`${origin}/v1/inference/stream`, {
    method: "POST",
    headers: { Authorization: `Bearer ${current.accessToken}` },
    body: "{}",
  });
  assert.equal(quotaResponse.status, 403);
  assert.equal((await quotaResponse.json()).error.code, "quota_exceeded");
  assert.equal(server.validInferenceRequests, 1);
  assert.equal(server.validInferenceBodies, 1);

  await server.close();
  const offline = await client.getUsageSummary(current.accessToken);
  assert.equal(offline.status, "network_error");
  assert.equal(JSON.stringify(offline).includes(current.accessToken), false);
});

async function launchDevelopmentEngine(
  args: readonly string[],
  options: { readonly cwd?: string } = {},
) {
  return launchEngine({
    launcherVersion: "0.0.6",
    args,
    cwd: options.cwd,
    resolvedEngine: {
      executablePath: process.execPath,
      manifestPath: null,
      source: "development",
      releaseChannel: "dev",
      platform: currentPlatform(),
      architecture: currentArchitecture(),
      developmentOverride: true,
    },
    nodeVersion: "24.16.0",
  });
}

async function launchWithSignal(
  emitter: EventEmitter,
  args: readonly string[],
): Promise<{
  result: Awaited<ReturnType<typeof launchEngine>>;
  process: ChildProcess;
  close: Promise<void>;
}> {
  const readyPath = args[args.length - 1]!;
  const deadline = Date.now() + 8_000;
  let childProcess: ChildProcess | undefined;
  let childClose: Promise<void> | undefined;
  let resolveSpawnStarted!: () => void;
  const spawnStarted = new Promise<void>((resolve) => {
    resolveSpawnStarted = resolve;
  });
  let cleanupRequested = false;
  let resolveLateCleanup!: () => void;
  const lateCleanup = new Promise<void>((resolve) => {
    resolveLateCleanup = resolve;
  });
  const processTerminator = () => ({ status: 1 });
  const terminate = (child: ChildProcess, signal: "SIGTERM" | "SIGKILL") =>
    getPlatformAdapter(currentPlatform()).terminateProcess(child, signal, {
      runCommand: processTerminator,
    });
  const spawnEngine: SpawnEngine = (command, childArgs, options) => {
    const child = spawn(command, [...childArgs], options);
    childProcess = child;
    resolveSpawnStarted();
    childClose = new Promise<void>((resolve) => {
      child.once("close", () => resolve());
    });
    if (cleanupRequested) {
      terminate(child, "SIGTERM");
      childClose.then(resolveLateCleanup, resolveLateCleanup);
    }
    return child;
  };
  const processLike: ProcessLike = {
    platform: currentPlatform(),
    arch: currentArchitecture(),
    pid: process.pid,
    env: process.env,
    cwd: () => process.cwd(),
    on: emitter.on.bind(emitter) as ProcessLike["on"],
    removeListener: emitter.removeListener.bind(
      emitter,
    ) as ProcessLike["removeListener"],
  };
  const resultPromise = launchEngine({
    launcherVersion: "0.0.6",
    args,
    resolvedEngine: {
      executablePath: process.execPath,
      manifestPath: null,
      source: "development",
      releaseChannel: "dev",
      platform: currentPlatform(),
      architecture: currentArchitecture(),
      developmentOverride: true,
    },
    spawnEngine,
    processLike,
    processTerminator,
    nodeVersion: "24.16.0",
  });
  const outcomePromise = resultPromise.then(
    (result) => ({ result }) as const,
    (error: unknown) => ({ error }) as const,
  );
  try {
    while (true) {
      const outcome = await Promise.race([
        outcomePromise,
        new Promise<undefined>((resolve) =>
          setTimeout(() => resolve(undefined), 20),
        ),
      ]);
      if (outcome && "error" in outcome) throw outcome.error;
      if (outcome && "result" in outcome) {
        try {
          await readFile(readyPath, "utf8");
          break;
        } catch {
          throw new Error("launcher child exited before becoming ready");
        }
      }
      try {
        await readFile(readyPath, "utf8");
        break;
      } catch {
        if (
          childProcess &&
          (childProcess.exitCode !== null || childProcess.signalCode !== null)
        )
          throw new Error("launcher child exited before becoming ready");
        if (Date.now() >= deadline)
          throw new Error("launcher child did not become ready");
        await new Promise((resolve) => setTimeout(resolve, 20));
      }
    }
  } catch (error) {
    cleanupRequested = true;
    if (childProcess && childClose) {
      terminate(childProcess, "SIGTERM");
      await awaitBounded(childClose, 2_000);
    } else {
      await awaitBounded(
        Promise.race([
          spawnStarted,
          lateCleanup,
          outcomePromise.then(
            () => undefined,
            () => undefined,
          ),
        ]),
        2_000,
      );
      if (childProcess && childClose) {
        terminate(childProcess, "SIGTERM");
        await awaitBounded(childClose, 2_000);
      }
    }
    await awaitBounded(
      outcomePromise.then(
        () => undefined,
        () => undefined,
      ),
      2_000,
    );
    throw error;
  }
  const child = childProcess;
  const close = childClose;
  assert.ok(child);
  assert.ok(close);
  emitter.emit("SIGINT");
  const outcome = await outcomePromise;
  if ("error" in outcome) throw outcome.error;
  return { result: outcome.result, process: child, close };
}

async function assertProcessGone(
  child: ChildProcess,
  close: Promise<void>,
): Promise<void> {
  await waitForChildExit(child, 2_000);
  assert.ok(child.exitCode !== null || child.signalCode !== null);
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([
      close,
      new Promise<never>((_, reject) => {
        timer = setTimeout(
          () =>
            reject(new Error("launcher child did not close after termination")),
          2_000,
        );
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

function supportedPlatform(context: {
  skip(message?: string): void;
}): "win32" | "darwin" | undefined {
  if (process.platform !== "win32" && process.platform !== "darwin") {
    context.skip("GOAT v0.4.1 platform E2E runs on Windows and macOS only");
    return undefined;
  }
  if (process.arch !== "x64" && process.arch !== "arm64") {
    context.skip("GOAT v0.4.1 platform E2E supports x64 and arm64 only");
    return undefined;
  }
  return process.platform;
}

function currentPlatform(): "win32" | "darwin" {
  assert.ok(process.platform === "win32" || process.platform === "darwin");
  return process.platform;
}

function currentArchitecture(): "x64" | "arm64" {
  assert.ok(process.arch === "x64" || process.arch === "arm64");
  return process.arch;
}

async function runExecutable(executablePath: string): Promise<number> {
  const child = spawn(executablePath, [], { stdio: "ignore" });
  return new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (code) => resolve(code ?? 1));
  });
}

async function awaitBounded(
  promise: Promise<void>,
  timeoutMs: number,
): Promise<void> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([
      promise,
      new Promise<never>((_, reject) => {
        timer = setTimeout(
          () => reject(new Error("launcher cleanup timed out")),
          timeoutMs,
        );
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

function delay(timeoutMs: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, timeoutMs));
}

async function waitForChildExit(
  child: ChildProcess,
  timeoutMs: number,
): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return;
  await new Promise<void>((resolve) => {
    let settled = false;
    const finish = (): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      child.removeListener("exit", finish);
      resolve();
    };
    const timer = setTimeout(finish, timeoutMs);
    child.once("exit", finish);
  });
}

function memoryStore(initial: GoatCredentials | null): CredentialStore {
  let value: GoatCredentials | null = initial;
  return {
    async get() {
      return value;
    },
    async set(next) {
      value = next;
    },
    async delete() {
      value = null;
    },
  };
}
