import assert from "node:assert/strict";
import type { ChildProcess } from "node:child_process";
import { once } from "node:events";
import { PassThrough } from "node:stream";
import { test } from "node:test";
import { EngineContractError } from "./contract.js";
import type { SpawnEngine } from "./launch.js";
import {
  createWindowsPrivacySpawner,
  isWindowsPrivacyPipeSetupError,
  WINDOWS_PRIVACY_SPAWN_ABI_VERSION,
} from "./windows-privacy-spawn.js";

type Binding = Parameters<typeof createWindowsPrivacySpawner>[0];
type StreamFactory = NonNullable<
  Parameters<typeof createWindowsPrivacySpawner>[1]
>;

const spawnOptions: Parameters<SpawnEngine>[2] = {
  cwd: "C:\\work",
  env: { PATH: "C:\\bin", OMITTED: undefined },
  stdio: ["inherit", "inherit", "inherit", "pipe", "pipe"],
  shell: false,
  windowsHide: true,
  detached: true,
};

test("native adapter forwards only process launch data and exposes fd 3/4 streams", async () => {
  const launcherWrite = new PassThrough();
  const launcherRead = new PassThrough();
  let request: Parameters<Binding["spawnWindowsPrivacyProcess"]>[0] | undefined;
  let onExit: Parameters<Binding["spawnWindowsPrivacyProcess"]>[1] | undefined;
  let closeCalls = 0;
  let writeTakes = 0;
  let readTakes = 0;
  const binding: Binding = {
    WINDOWS_PRIVACY_SPAWN_ABI_VERSION,
    spawnWindowsPrivacyProcess(received, callback) {
      request = received;
      onExit = callback;
      return {
        pid: 4_242,
        takeLauncherWriteFd() {
          writeTakes += 1;
          return 30;
        },
        takeLauncherReadFd() {
          readTakes += 1;
          return 31;
        },
        terminate: () => true,
        close() {
          closeCalls += 1;
        },
      };
    },
  };
  const streams: StreamFactory = {
    createWrite(fd) {
      assert.equal(fd, 30);
      return launcherWrite;
    },
    createRead(fd) {
      assert.equal(fd, 31);
      return launcherRead;
    },
    close() {
      assert.fail("valid transferred descriptors must be stream-owned");
    },
  };

  const child = createWindowsPrivacySpawner(binding, streams)(
    "C:\\GOAT\\goat-engine.exe",
    ["privacy", "diagnostics", "preview"],
    spawnOptions,
  );

  assert.equal(child.pid, 4_242);
  assert.equal(writeTakes, 1);
  assert.equal(readTakes, 1);
  assert.equal(child.stdio[3], launcherWrite);
  assert.equal(child.stdio[4], launcherRead);
  assert.deepEqual(request, {
    command: "C:\\GOAT\\goat-engine.exe",
    args: ["privacy", "diagnostics", "preview"],
    cwd: "C:\\work",
    env: [{ name: "PATH", value: "C:\\bin" }],
    windowsHide: true,
    detached: true,
  });

  const exited = once(child, "exit");
  onExit!(17, null);
  assert.deepEqual(await exited, [17, null]);
  assert.equal(closeCalls, 1);

  onExit!(18, null);
  assert.equal(closeCalls, 1, "duplicate native completion must be ignored");
});

test("native adapter buffers an exit delivered before spawn returns", async () => {
  const streams = passThroughStreams();
  const binding: Binding = {
    WINDOWS_PRIVACY_SPAWN_ABI_VERSION,
    spawnWindowsPrivacyProcess(_request, onExit) {
      onExit(0, null);
      return nativeProcess();
    },
  };

  const child = createWindowsPrivacySpawner(binding, streams)(
    "C:\\GOAT\\goat-engine.exe",
    [],
    spawnOptions,
  );

  assert.deepEqual(await once(child, "exit"), [0, null]);
});

test("native adapter reports the requested kill signal on completion", async () => {
  const streams = passThroughStreams();
  let onExit: Parameters<Binding["spawnWindowsPrivacyProcess"]>[1] | undefined;
  let terminateCalls = 0;
  const binding: Binding = {
    WINDOWS_PRIVACY_SPAWN_ABI_VERSION,
    spawnWindowsPrivacyProcess(_request, callback) {
      onExit = callback;
      return nativeProcess({
        terminate() {
          terminateCalls += 1;
          return true;
        },
      });
    },
  };
  const child = createWindowsPrivacySpawner(binding, streams)(
    "C:\\GOAT\\goat-engine.exe",
    [],
    spawnOptions,
  );
  const exited = once(child, "exit");

  assert.equal(child.kill("SIGBREAK"), true);
  assert.equal(terminateCalls, 1);
  onExit!(1, null);

  assert.deepEqual(await exited, [null, "SIGBREAK"]);
  assert.equal(child.kill("SIGTERM"), false);
  assert.equal(terminateCalls, 1);
});

test("stream setup failure closes unclaimed fds and terminates the child", () => {
  const launcherWrite = new PassThrough();
  const closedFds: number[] = [];
  let terminateCalls = 0;
  let closeCalls = 0;
  const binding: Binding = {
    WINDOWS_PRIVACY_SPAWN_ABI_VERSION,
    spawnWindowsPrivacyProcess() {
      return nativeProcess({
        terminate() {
          terminateCalls += 1;
          return true;
        },
        close() {
          closeCalls += 1;
        },
      });
    },
  };
  const streams: StreamFactory = {
    createWrite: () => launcherWrite,
    createRead: () => {
      throw new Error("PATH_SECRET_3HT6");
    },
    close(fd) {
      closedFds.push(fd);
    },
  };
  const spawn = createWindowsPrivacySpawner(binding, streams);

  assert.throws(
    () => spawn("C:\\GOAT\\goat-engine.exe", [], spawnOptions),
    isWindowsPrivacyPipeSetupError,
  );
  assert.equal(launcherWrite.destroyed, true);
  assert.deepEqual(closedFds, [31]);
  assert.equal(terminateCalls, 1);
  assert.equal(closeCalls, 1);
});

test("descriptor transfer failure reclaims the transferred fd and child", () => {
  const closedFds: number[] = [];
  let terminateCalls = 0;
  let closeCalls = 0;
  const binding: Binding = {
    WINDOWS_PRIVACY_SPAWN_ABI_VERSION,
    spawnWindowsPrivacyProcess() {
      return nativeProcess({
        takeLauncherReadFd() {
          throw Object.assign(new Error("PATH_SECRET_3HT6"), {
            code: "GOAT_NATIVE_PRIVACY_PIPE_FAILED",
          });
        },
        terminate() {
          terminateCalls += 1;
          return true;
        },
        close() {
          closeCalls += 1;
        },
      });
    },
  };
  const streams: StreamFactory = {
    createWrite: () => assert.fail("failed transfer must not create streams"),
    createRead: () => assert.fail("failed transfer must not create streams"),
    close(fd) {
      closedFds.push(fd);
    },
  };

  assert.throws(
    () =>
      createWindowsPrivacySpawner(binding, streams)(
        "C:\\GOAT\\goat-engine.exe",
        [],
        spawnOptions,
      ),
    isWindowsPrivacyPipeSetupError,
  );
  assert.deepEqual(closedFds, [30]);
  assert.equal(terminateCalls, 1);
  assert.equal(closeCalls, 1);
});

test("invalid transferred descriptors identify a malformed native package", () => {
  let terminateCalls = 0;
  let closeCalls = 0;
  const binding: Binding = {
    WINDOWS_PRIVACY_SPAWN_ABI_VERSION,
    spawnWindowsPrivacyProcess() {
      return nativeProcess({
        takeLauncherWriteFd: () => -1,
        terminate() {
          terminateCalls += 1;
          return true;
        },
        close() {
          closeCalls += 1;
        },
      });
    },
  };

  assert.throws(
    () =>
      createWindowsPrivacySpawner(binding, passThroughStreams())(
        "C:\\GOAT\\goat-engine.exe",
        [],
        spawnOptions,
      ),
    (error) =>
      error instanceof EngineContractError &&
      error.code === "GOAT_WINDOWS_PRIVACY_SPAWN_UNAVAILABLE" &&
      !error.message.includes("PATH_SECRET_3HT6"),
  );
  assert.equal(terminateCalls, 1);
  assert.equal(closeCalls, 1);
});

test("malformed native process results fail closed with a stable error", () => {
  const closedFds: number[] = [];
  let terminateCalls = 0;
  let closeCalls = 0;
  const binding = {
    WINDOWS_PRIVACY_SPAWN_ABI_VERSION,
    spawnWindowsPrivacyProcess() {
      return {
        pid: 0,
        takeLauncherWriteFd: () => 30,
        takeLauncherReadFd: () => 31,
        terminate() {
          terminateCalls += 1;
          return true;
        },
        close() {
          closeCalls += 1;
        },
      };
    },
  } as Binding;
  const streams: StreamFactory = {
    createWrite: () => assert.fail("malformed results must not create streams"),
    createRead: () => assert.fail("malformed results must not create streams"),
    close(fd) {
      closedFds.push(fd);
    },
  };
  const spawn = createWindowsPrivacySpawner(binding, streams);

  assert.throws(
    () => spawn("C:\\GOAT\\goat-engine.exe", [], spawnOptions),
    (error) =>
      error instanceof EngineContractError &&
      error.code === "GOAT_WINDOWS_PRIVACY_SPAWN_UNAVAILABLE" &&
      !error.message.includes("PATH_SECRET_3HT6"),
  );
  assert.deepEqual(closedFds, []);
  assert.equal(terminateCalls, 1);
  assert.equal(closeCalls, 1);
});

test("wrong ABI versions fail before a native process can be created", () => {
  let spawned = false;
  const binding = {
    WINDOWS_PRIVACY_SPAWN_ABI_VERSION: 2,
    spawnWindowsPrivacyProcess() {
      spawned = true;
      return nativeProcess();
    },
  } as Binding;

  assert.throws(
    () => createWindowsPrivacySpawner(binding, passThroughStreams()),
    (error) =>
      error instanceof EngineContractError &&
      error.code === "GOAT_WINDOWS_PRIVACY_SPAWN_UNAVAILABLE",
  );
  assert.equal(spawned, false);
});

function nativeProcess(
  overrides: Partial<{
    takeLauncherWriteFd(): number;
    takeLauncherReadFd(): number;
    terminate(): boolean;
    close(): void;
  }> = {},
): ReturnType<Binding["spawnWindowsPrivacyProcess"]> {
  return {
    pid: 4_242,
    takeLauncherWriteFd: () => 30,
    takeLauncherReadFd: () => 31,
    terminate: () => true,
    close: () => undefined,
    ...overrides,
  };
}

function passThroughStreams(): StreamFactory {
  return {
    createWrite: () => new PassThrough(),
    createRead: () => new PassThrough(),
    close: () => undefined,
  };
}
