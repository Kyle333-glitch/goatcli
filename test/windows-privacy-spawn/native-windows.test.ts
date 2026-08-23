import assert from "node:assert/strict";
import type { ChildProcess } from "node:child_process";
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import type { Readable, Writable } from "node:stream";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
  createWindowsPrivacySpawner,
  loadWindowsPrivacySpawner,
  WINDOWS_PRIVACY_SPAWN_ABI_VERSION,
} from "../../src/engine/windows-privacy-spawn.js";
import type { SpawnEngine } from "../../src/engine/launch.js";

type WindowsTestHooksBinding = Parameters<
  typeof createWindowsPrivacySpawner
>[0] & {
  createInheritableEventForTest(): number;
  isHandleInheritableForTest(handle: number): boolean;
  isHandleValidForTest(handle: number): boolean;
  isFdInheritableForTest(fd: number): boolean;
  closeHandleForTest(handle: number): boolean;
};

type TestSpawnedProcess = ReturnType<
  WindowsTestHooksBinding["spawnWindowsPrivacyProcess"]
> & {
  readonly childReadHandleForTest: number;
  readonly childWriteHandleForTest: number;
};

interface ProbeResponse {
  readonly payload: string;
  readonly canaryInvalid: boolean;
  readonly canaryError: number;
  readonly stdioValid: readonly [boolean, boolean, boolean];
  readonly argvAndEnvironmentClean: boolean;
}

const testDirectory = path.dirname(fileURLToPath(import.meta.url));
const workspaceRoot = path.resolve(testDirectory, "../..");
const fixtureSource = path.join(testDirectory, "bun-fd-responder.mjs");
const fixtureExecutable = path.join(
  workspaceRoot,
  "dist",
  "native-fixtures",
  "bun-fd-responder.exe",
);
const defaultTestBinding = path.join(
  workspaceRoot,
  "native",
  "windows-spawn",
  "target",
  "test-hooks",
  "goatcli-windows-spawn-test.node",
);
const testBindingPath =
  process.env.GOAT_WINDOWS_PRIVACY_SPAWN_TEST_BINDING ?? defaultTestBinding;

test(
  "release Windows privacy spawner allowlists stdio and fd 3/4 only",
  { timeout: 60_000 },
  async (context) => {
    if (process.platform !== "win32") {
      context.skip("native Windows privacy spawn runs only on Windows");
      return;
    }

    buildBunFixture();
    const require = createRequire(import.meta.url);
    const productionBinding = require("goatcli-windows-spawn") as Record<
      string,
      unknown
    >;
    for (const testOnlyExport of [
      "createInheritableEventForTest",
      "isHandleInheritableForTest",
      "isHandleValidForTest",
      "isFdInheritableForTest",
      "closeHandleForTest",
    ]) {
      assert.equal(
        testOnlyExport in productionBinding,
        false,
        `production binding exported ${testOnlyExport}`,
      );
    }

    assert.equal(
      existsSync(testBindingPath),
      true,
      "the test-hooks native binding was not built",
    );
    const testBinding = require(testBindingPath) as WindowsTestHooksBinding;
    assert.equal(
      testBinding.WINDOWS_PRIVACY_SPAWN_ABI_VERSION,
      WINDOWS_PRIVACY_SPAWN_ABI_VERSION,
    );
    for (const method of [
      "createInheritableEventForTest",
      "isHandleInheritableForTest",
      "isHandleValidForTest",
      "isFdInheritableForTest",
      "closeHandleForTest",
    ] as const) {
      assert.equal(typeof testBinding[method], "function");
    }

    const spawner = await loadWindowsPrivacySpawner();
    await assertRestrictedSpawn(spawner, testBinding);

    let testProcess: TestSpawnedProcess | undefined;
    const testSpawner = createWindowsPrivacySpawner({
      WINDOWS_PRIVACY_SPAWN_ABI_VERSION,
      spawnWindowsPrivacyProcess(request, onExit) {
        const spawned = testBinding.spawnWindowsPrivacyProcess(
          request,
          onExit,
        ) as TestSpawnedProcess;
        testProcess = spawned;
        return spawned;
      },
    });
    await assertRestrictedSpawn(testSpawner, testBinding, () => {
      assert.ok(testProcess);
      assert.ok(testProcess.childReadHandleForTest > 0);
      assert.ok(testProcess.childWriteHandleForTest > 0);
      assert.notEqual(
        testProcess.childReadHandleForTest,
        testProcess.childWriteHandleForTest,
      );
      assert.equal(
        testBinding.isHandleValidForTest(testProcess.childReadHandleForTest),
        false,
      );
      assert.equal(
        testBinding.isHandleValidForTest(testProcess.childWriteHandleForTest),
        false,
      );
    });
  },
);

function buildBunFixture(): void {
  const result = spawnSync(
    "bun.exe",
    [
      path.join(workspaceRoot, "scripts", "build-windows-privacy-fixture.mjs"),
      fixtureSource,
      fixtureExecutable,
    ],
    {
      cwd: workspaceRoot,
      encoding: "utf8",
      env: process.env,
      shell: false,
      windowsHide: true,
    },
  );
  assert.equal(
    result.status,
    0,
    `Bun fixture compilation failed: ${String(result.stderr).slice(0, 4_096)}`,
  );
  assert.equal(existsSync(fixtureExecutable), true);
}

async function assertRestrictedSpawn(
  spawner: SpawnEngine,
  hooks: WindowsTestHooksBinding,
  afterSpawn?: () => void,
): Promise<void> {
  const canaryHandle = hooks.createInheritableEventForTest();
  assert.ok(Number.isSafeInteger(canaryHandle) && canaryHandle > 0);
  assert.equal(hooks.isHandleInheritableForTest(canaryHandle), true);

  let child: ChildProcess | undefined;
  try {
    child = spawner(fixtureExecutable, [], {
      cwd: workspaceRoot,
      env: safeFixtureEnvironment(),
      stdio: ["inherit", "inherit", "inherit", "pipe", "pipe"],
      shell: false,
      windowsHide: true,
      detached: true,
    });
    afterSpawn?.();
    const toChild = child.stdio[3] as Writable & { fd?: number };
    const fromChild = child.stdio[4] as Readable & { fd?: number };
    assert.ok(toChild && fromChild);
    assert.ok(Number.isSafeInteger(toChild.fd) && (toChild.fd ?? -1) >= 0);
    assert.ok(Number.isSafeInteger(fromChild.fd) && (fromChild.fd ?? -1) >= 0);
    assert.equal(hooks.isFdInheritableForTest(toChild.fd!), false);
    assert.equal(hooks.isFdInheritableForTest(fromChild.fd!), false);

    const payload = "fd3-fd4-roundtrip-6f1a9d08";
    const privacyToken = "T".repeat(43);
    const transportPath = "PIPE_PATH_MUST_NOT_APPEAR_932e1d";
    const responsePromise = readAll(fromChild);
    const exitPromise = new Promise<readonly [number | null, string | null]>(
      (resolve, reject) => {
        child!.once("error", reject);
        child!.once("exit", (code, signal) => resolve([code, signal]));
      },
    );
    toChild.end(
      JSON.stringify({
        payload,
        canaryHandle,
        privacyToken,
        transportPath,
      }),
    );

    const response = JSON.parse(await responsePromise) as ProbeResponse;
    assert.deepEqual(await exitPromise, [0, null]);
    assert.deepEqual(response, {
      payload,
      canaryInvalid: true,
      canaryError: 6,
      stdioValid: [true, true, true],
      argvAndEnvironmentClean: true,
    });
  } finally {
    child?.kill("SIGKILL");
    assert.equal(hooks.closeHandleForTest(canaryHandle), true);
  }
}

async function readAll(stream: Readable): Promise<string> {
  stream.setEncoding("utf8");
  let value = "";
  for await (const chunk of stream) {
    value += chunk;
    assert.ok(value.length <= 16_384, "native fixture response was too large");
  }
  return value;
}

function safeFixtureEnvironment(): NodeJS.ProcessEnv {
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
  ]);
  const environment: NodeJS.ProcessEnv = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (value !== undefined && allowed.has(key.toUpperCase())) {
      environment[key] = value;
    }
  }
  return environment;
}
