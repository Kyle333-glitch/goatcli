import assert from "node:assert/strict";
import type { ChildProcess } from "node:child_process";
import { EventEmitter } from "node:events";
import { test } from "node:test";
import { EngineContractError, formatEngineContractError } from "./contract.js";
import {
  launchEngine,
  launchValidatedEngine,
  selectEngineSpawner,
  type ProcessLike,
  type SpawnEngine,
} from "./launch.js";
import {
  createWindowsPrivacySpawner,
  WINDOWS_PRIVACY_SPAWN_ABI_VERSION,
} from "./windows-privacy-spawn.js";

const nativeSpawner: SpawnEngine = () => ({}) as ChildProcess;
const plainSpawner: SpawnEngine = () => ({}) as ChildProcess;
const overrideSpawner: SpawnEngine = () => ({}) as ChildProcess;

test("all supported Windows privacy launches select the native spawner", async () => {
  let loads = 0;
  const selected = await selectEngineSpawner({
    platform: "win32",
    privacyIpc: true,
    async loadWindowsPrivacySpawner() {
      loads += 1;
      return nativeSpawner;
    },
    defaultSpawner: plainSpawner,
  });

  assert.equal(selected, nativeSpawner);
  assert.equal(loads, 1);
});

test("the retained Node 22 compatibility option no longer gates Windows privacy", async () => {
  await assert.rejects(
    () =>
      launchEngine({
        launcherVersion: "0.4.0",
        args: ["privacy", "diagnostics", "preview"],
        nodeVersion: "22.18.0",
        processLike: new FakeProcess(),
        resolvedEngine: {
          executablePath: "C:\\GOAT\\goat-engine.exe",
          manifestPath: "C:\\GOAT\\goat-engine.json",
          source: "local-install",
          releaseChannel: "stable",
          platform: "win32",
          architecture: "x64",
          developmentOverride: false,
        },
        fs: {
          constants: { X_OK: 0 },
          existsSync: () => false,
          statSync: () => ({ isFile: () => false }),
          accessSync: () => undefined,
          readFileSync: () => "",
        },
      }),
    (error) =>
      error instanceof EngineContractError &&
      error.code === "GOAT_ENGINE_MISSING",
  );
});

test("an injected SpawnEngine wins over Windows native loading", async () => {
  let loads = 0;
  const selected = await selectEngineSpawner({
    platform: "win32",
    privacyIpc: true,
    spawnEngine: overrideSpawner,
    async loadWindowsPrivacySpawner() {
      loads += 1;
      return nativeSpawner;
    },
    defaultSpawner: plainSpawner,
  });

  assert.equal(selected, overrideSpawner);
  assert.equal(loads, 0);
});

test("macOS privacy and Windows non-privacy launches retain plain spawn", async () => {
  for (const fixture of [
    { platform: "darwin" as const, privacyIpc: true },
    { platform: "win32" as const, privacyIpc: false },
  ]) {
    let loads = 0;
    const selected = await selectEngineSpawner({
      ...fixture,
      async loadWindowsPrivacySpawner() {
        loads += 1;
        return nativeSpawner;
      },
      defaultSpawner: plainSpawner,
    });

    assert.equal(selected, plainSpawner);
    assert.equal(loads, 0);
  }
});

test("missing native support fails closed without exposing loader details", async () => {
  await assert.rejects(
    () =>
      selectEngineSpawner({
        platform: "win32",
        privacyIpc: true,
        async loadWindowsPrivacySpawner() {
          throw new Error("C:\\PATH_SECRET_3HT6\\binding.node TOKEN_8MVP");
        },
        defaultSpawner: plainSpawner,
      }),
    (error) => {
      assert.ok(error instanceof EngineContractError);
      assert.equal(error.code, "GOAT_WINDOWS_PRIVACY_SPAWN_UNAVAILABLE");
      const rendered = `${error.message}\n${error.suggestion}\n${formatEngineContractError(error)}`;
      assert.equal(rendered.includes("PATH_SECRET_3HT6"), false);
      assert.equal(rendered.includes("TOKEN_8MVP"), false);
      return true;
    },
  );
});

test("a malformed loader result uses the same fixed unavailable error", async () => {
  await assert.rejects(
    () =>
      selectEngineSpawner({
        platform: "win32",
        privacyIpc: true,
        loadWindowsPrivacySpawner: async () => null as unknown as SpawnEngine,
        defaultSpawner: plainSpawner,
      }),
    (error) =>
      error instanceof EngineContractError &&
      error.code === "GOAT_WINDOWS_PRIVACY_SPAWN_UNAVAILABLE",
  );
});

test("stable native pipe errors map to privacy IPC failure", async () => {
  await assertNativeSpawnFailure(
    "GOAT_NATIVE_PRIVACY_PIPE_FAILED",
    "GOAT_PRIVACY_IPC_FAILED",
  );
});

test("process-creation and unknown native errors map to spawn failure", async () => {
  await assertNativeSpawnFailure(
    "GOAT_NATIVE_PROCESS_CREATE_FAILED",
    "GOAT_ENGINE_SPAWN_FAILED",
  );
  await assertNativeSpawnFailure(undefined, "GOAT_ENGINE_SPAWN_FAILED");
});

test("throwing native error properties never escape the stable mapping", async () => {
  const binding = {
    WINDOWS_PRIVACY_SPAWN_ABI_VERSION,
    spawnWindowsPrivacyProcess() {
      throw Object.defineProperty({}, "code", {
        get() {
          throw new Error("C:\\PATH_SECRET_3HT6\\binding.node");
        },
      });
    },
  } as Parameters<typeof createWindowsPrivacySpawner>[0];

  await assert.rejects(
    () =>
      launchValidatedEngine(
        { executablePath: "C:\\GOAT\\goat-engine.exe", platform: "win32" },
        ["privacy", "diagnostics", "preview"],
        {
          cwd: "C:\\work",
          processLike: new FakeProcess(),
          loadWindowsPrivacySpawner: async () =>
            createWindowsPrivacySpawner(binding),
          privacyIpc: {
            mode: "eager",
            engineIntegrity: "verified",
            credentialStore: "not_checked",
            launcherPid: 4_100,
          },
        },
      ),
    (error) =>
      error instanceof EngineContractError &&
      error.code === "GOAT_ENGINE_SPAWN_FAILED" &&
      !error.message.includes("PATH_SECRET_3HT6"),
  );
});

async function assertNativeSpawnFailure(
  nativeCode:
    | "GOAT_NATIVE_PROCESS_CREATE_FAILED"
    | "GOAT_NATIVE_PRIVACY_PIPE_FAILED"
    | undefined,
  expectedCode: "GOAT_ENGINE_SPAWN_FAILED" | "GOAT_PRIVACY_IPC_FAILED",
): Promise<void> {
  const binding = {
    WINDOWS_PRIVACY_SPAWN_ABI_VERSION,
    spawnWindowsPrivacyProcess() {
      throw nativeCode
        ? { code: nativeCode, message: "PATH_SECRET_3HT6 TOKEN_8MVP" }
        : new Error("PATH_SECRET_3HT6 TOKEN_8MVP");
    },
  } as Parameters<typeof createWindowsPrivacySpawner>[0];
  const nativeSpawn = createWindowsPrivacySpawner(binding);

  await assert.rejects(
    () =>
      launchValidatedEngine(
        { executablePath: "C:\\GOAT\\goat-engine.exe", platform: "win32" },
        ["privacy", "diagnostics", "preview"],
        {
          cwd: "C:\\work",
          processLike: new FakeProcess(),
          loadWindowsPrivacySpawner: async () => nativeSpawn,
          privacyIpc: {
            mode: "eager",
            engineIntegrity: "verified",
            credentialStore: "not_checked",
            launcherPid: 4_100,
          },
        },
      ),
    (error) => {
      assert.ok(error instanceof EngineContractError);
      assert.equal(error.code, expectedCode);
      const rendered = `${error.message}\n${error.suggestion}`;
      assert.equal(rendered.includes("PATH_SECRET_3HT6"), false);
      assert.equal(rendered.includes("TOKEN_8MVP"), false);
      return true;
    },
  );
}

class FakeProcess extends EventEmitter implements ProcessLike {
  readonly platform = "win32";
  readonly arch = "x64";
  readonly pid = 4_100;
  readonly env: NodeJS.ProcessEnv = {};

  cwd(): string {
    return "C:\\work";
  }
}
