import { EventEmitter } from "node:events";
import { test } from "node:test";
import assert from "node:assert/strict";
import type { ChildProcess } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import { finishWithLaunchResult, runCli } from "./cli.js";
import type { AuthApiClient, CredentialStore } from "./auth/types.js";
import type { EngineManifest, ResolvedEngine } from "./engine/contract.js";
import type { ProcessLike, SpawnEngine } from "./engine/launch.js";
import type { EngineFileSystem } from "./engine/validate.js";
import { engineManifestTrustPolicy } from "./privacy/release-policy.js";

test("runCli handles exact launcher-owned version command", async () => {
  let output = "";

  await runCli({
    argv: ["version"],
    stdout: {
      write(chunk: string | Uint8Array) {
        output += chunk.toString();
        return true;
      },
    },
    spawnEngine: () => {
      throw new Error("version should not spawn the engine");
    },
  });

  assert.equal(output, "0.3.2\n");
});

test("runCli handles version command with trailing arguments", async () => {
  let output = "";

  await runCli({
    argv: ["-v", "some-argument"],
    stdout: {
      write(chunk: string | Uint8Array) {
        output += chunk.toString();
        return true;
      },
    },
    spawnEngine: () => {
      throw new Error("version should not spawn the engine");
    },
  });

  assert.equal(output, "0.3.2\n");
});

test("runCli forwards non-launcher-owned arguments to the engine unchanged", async () => {
  const executablePath =
    "C:\\GOAT\\engines\\stable\\win32-x64\\bin\\goat-engine.exe";
  const manifestPath = "C:\\GOAT\\engines\\stable\\win32-x64\\goat-engine.json";
  const engineBytes = Buffer.from("engine");
  const fakeFs = makeFakeFs({
    [executablePath]: { content: engineBytes, isFile: true },
    [manifestPath]: {
      content: JSON.stringify(makeManifest(sha256(engineBytes))),
      isFile: true,
    },
  });
  const child = new FakeChild();
  let forwardedArgs: readonly string[] | null = null;
  const spawnEngine: SpawnEngine = (_command, args) => {
    forwardedArgs = args;
    queueMicrotask(() => child.emit("exit", 0, null));
    return child as unknown as ChildProcess;
  };
  let exitCode: number | undefined;

  await assert.rejects(
    () =>
      runCli({
        argv: ["--help"],
        resolvedEngine: makeResolvedEngine({ executablePath, manifestPath }),
        fs: fakeFs,
        spawnEngine,
        processLike: new FakeProcess("win32", "x64", "D:\\repo"),
        exit(code?: number): never {
          exitCode = code;
          throw new Error("exit");
        },
      }),
    /exit/,
  );

  assert.deepEqual(forwardedArgs, ["--help"]);
  assert.equal(exitCode, 0);
});

test("engine-local privacy and absent update/download contexts never use launcher networking", async () => {
  const executablePath =
    "C:\\GOAT\\engines\\stable\\win32-x64\\bin\\goat-engine.exe";
  const manifestPath = "C:\\GOAT\\engines\\stable\\win32-x64\\goat-engine.json";
  const engineBytes = Buffer.from("engine");
  const fakeFs = makeFakeFs({
    [executablePath]: { content: engineBytes, isFile: true },
    [manifestPath]: {
      content: JSON.stringify(makeManifest(sha256(engineBytes))),
      isFile: true,
    },
  });
  let sensitiveAccesses = 0;
  const authClient = new Proxy({} as AuthApiClient, {
    get() {
      sensitiveAccesses += 1;
      throw new Error("TOKEN_SECRET_8MVP");
    },
  });
  const credentialStore = new Proxy({} as CredentialStore, {
    get() {
      sensitiveAccesses += 1;
      throw new Error("PATH_SECRET_3HT6");
    },
  });
  const syntheticEnvironment = {
    ENV_SECRET_9DK1: "ENV_SECRET_9DK1",
    GOAT_UPDATE_FAILURE: "SOURCE_CODE_SECRET_4JK2",
    GOAT_DOWNLOAD_FAILURE: "TOKEN_SECRET_8MVP",
    GOAT_DOWNLOAD_PATH: "C:\\PATH_SECRET_3HT6\\PROMPT_SECRET_7QX9.bin",
  };

  for (const argv of [
    ["privacy"],
    ["privacy", "status"],
    ["privacy", "telemetry", "on"],
    ["privacy", "telemetry", "off"],
    ["privacy", "telemetry", "reset"],
    ["update", "SOURCE_CODE_SECRET_4JK2"],
    ["download", "C:\\PATH_SECRET_3HT6\\PROMPT_SECRET_7QX9.bin"],
  ]) {
    const child = new FakeChild();
    let stdio: Parameters<SpawnEngine>[2]["stdio"] | undefined;
    let forwarded: readonly string[] | undefined;
    let exitCode: number | undefined;
    const spawnEngine: SpawnEngine = (_command, args, options) => {
      stdio = options.stdio;
      forwarded = args;
      queueMicrotask(() => child.emit("exit", 0, null));
      return child as unknown as ChildProcess;
    };

    const processLike = new FakeProcess("win32", "x64", "D:\\repo");
    Object.assign(processLike.env, syntheticEnvironment);

    await assert.rejects(
      () =>
        runCli({
          argv,
          authClient,
          credentialStore,
          resolvedEngine: makeResolvedEngine({
            executablePath,
            manifestPath,
          }),
          fs: fakeFs,
          spawnEngine,
          processLike,
          exit(code?: number): never {
            exitCode = code;
            throw new Error("exit");
          },
        }),
      /exit/,
    );
    assert.equal(exitCode, 0);
    assert.deepEqual(forwarded, argv);
    assert.deepEqual(stdio, ["inherit", "inherit", "inherit", "pipe", "pipe"]);
  }

  let failureExit: number | undefined;
  let failureOutput = "";
  const failedChild = new FakeChild();
  await assert.rejects(
    () =>
      runCli({
        argv: ["privacy", "telemetry", "off"],
        authClient,
        credentialStore,
        resolvedEngine: makeResolvedEngine({
          executablePath,
          manifestPath,
        }),
        fs: fakeFs,
        spawnEngine() {
          queueMicrotask(() =>
            failedChild.emit("error", new Error("SOURCE_CODE_SECRET_4JK2")),
          );
          return failedChild as unknown as ChildProcess;
        },
        processLike: new FakeProcess("win32", "x64", "D:\\repo"),
        stderr: {
          write(value: string | Uint8Array) {
            failureOutput += value.toString();
            return true;
          },
        },
        exit(code?: number): never {
          failureExit = code;
          throw new Error("exit");
        },
      }),
    /exit/,
  );
  assert.equal(failureExit, 1);
  assert.equal(failureOutput.includes("SOURCE_CODE_SECRET_4JK2"), false);

  const cancelledChild = new FakeChild();
  let forwardedSignal: NodeJS.Signals | undefined;
  await runCli({
    argv: ["privacy", "telemetry", "off"],
    authClient,
    credentialStore,
    resolvedEngine: makeResolvedEngine({ executablePath, manifestPath }),
    fs: fakeFs,
    spawnEngine() {
      queueMicrotask(() => cancelledChild.emit("exit", null, "SIGTERM"));
      return cancelledChild as unknown as ChildProcess;
    },
    processLike: new FakeProcess("win32", "x64", "D:\\repo"),
    killSelf(signal) {
      forwardedSignal = signal;
    },
  });
  assert.equal(forwardedSignal, "SIGTERM");
  assert.equal(sensitiveAccesses, 0);
});

test("runCli forwards upgrade command to the engine unchanged", async () => {
  const executablePath =
    "C:\\GOAT\\engines\\stable\\win32-x64\\bin\\goat-engine.exe";
  const manifestPath = "C:\\GOAT\\engines\\stable\\win32-x64\\goat-engine.json";
  const engineBytes = Buffer.from("engine");
  const fakeFs = makeFakeFs({
    [executablePath]: { content: engineBytes, isFile: true },
    [manifestPath]: {
      content: JSON.stringify(makeManifest(sha256(engineBytes))),
      isFile: true,
    },
  });
  const child = new FakeChild();
  let forwardedArgs: readonly string[] | null = null;
  const spawnEngine: SpawnEngine = (_command, args) => {
    forwardedArgs = args;
    queueMicrotask(() => child.emit("exit", 0, null));
    return child as unknown as ChildProcess;
  };
  let exitCode: number | undefined;

  await assert.rejects(
    () =>
      runCli({
        argv: ["upgrade"],
        resolvedEngine: makeResolvedEngine({ executablePath, manifestPath }),
        fs: fakeFs,
        spawnEngine,
        processLike: new FakeProcess("win32", "x64", "D:\\repo"),
        exit(code?: number): never {
          exitCode = code;
          throw new Error("exit");
        },
      }),
    /exit/,
  );

  assert.deepEqual(forwardedArgs, ["upgrade"]);
  assert.equal(exitCode, 0);
});

test("finishWithLaunchResult exits by code or re-signals the launcher", () => {
  const exitCodes: Array<number | undefined> = [];
  const signals: NodeJS.Signals[] = [];

  assert.throws(
    () =>
      finishWithLaunchResult(
        { exitCode: 5, signal: null },
        {
          exit(code?: number): never {
            exitCodes.push(code);
            throw new Error("exit");
          },
          killSelf(signal) {
            signals.push(signal);
          },
        },
      ),
    /exit/,
  );
  finishWithLaunchResult(
    { exitCode: 0, signal: "SIGTERM" },
    {
      exit(code?: number): never {
        exitCodes.push(code);
        throw new Error("exit");
      },
      killSelf(signal) {
        signals.push(signal);
      },
    },
  );

  assert.deepEqual(exitCodes, [5]);
  assert.deepEqual(signals, ["SIGTERM"]);
});

class FakeChild extends EventEmitter {
  kill(): boolean {
    return true;
  }
}

class FakeProcess extends EventEmitter implements ProcessLike {
  readonly env: NodeJS.ProcessEnv = {};
  readonly pid = 4_001;

  constructor(
    readonly platform: NodeJS.Platform,
    readonly arch: string,
    private readonly cwdValue: string,
  ) {
    super();
  }

  cwd(): string {
    return this.cwdValue;
  }
}

function makeManifest(checksum: string): EngineManifest {
  return {
    manifestVersion: 1,
    releasePolicyDigest: engineManifestTrustPolicy().releasePolicyDigest,
    engineVersion: "1.17.11",
    platform: "win32",
    architecture: "x64",
    executablePath: "bin/goat-engine.exe",
    releaseChannel: "dev",
    checksum: {
      algorithm: "sha256",
      value: checksum,
    },
    compatibility: {
      minimumLauncherVersion: "0.0.6",
      maximumLauncherVersion: "0.0.6",
    },
    signature: { status: "unsigned-development" },
  };
}

function makeResolvedEngine(
  overrides: Partial<ResolvedEngine>,
): ResolvedEngine {
  return {
    executablePath:
      "C:\\GOAT\\engines\\stable\\win32-x64\\bin\\goat-engine.exe",
    manifestPath: "C:\\GOAT\\engines\\stable\\win32-x64\\goat-engine.json",
    source: "local-install",
    releaseChannel: "dev",
    platform: "win32",
    architecture: "x64",
    developmentOverride: false,
    ...overrides,
  };
}

interface FakeFile {
  content: Buffer | string;
  isFile: boolean;
}

function makeFakeFs(files: Record<string, FakeFile>): EngineFileSystem {
  return {
    constants: {
      X_OK: fs.constants.X_OK,
    },
    existsSync(filePath: string) {
      return files[filePath] !== undefined;
    },
    statSync(filePath: string) {
      const file = files[filePath];
      if (!file) throw new Error(`missing ${filePath}`);
      return {
        isFile: () => file.isFile,
      };
    },
    accessSync(filePath: string) {
      if (!files[filePath]) throw new Error(`missing ${filePath}`);
    },
    readFileSync(filePath: string) {
      const file = files[filePath];
      if (!file) throw new Error(`missing ${filePath}`);
      return file.content;
    },
  };
}

function sha256(input: Buffer | string): string {
  return createHash("sha256").update(input).digest("hex");
}
