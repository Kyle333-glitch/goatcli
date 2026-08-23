"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const nativeRoot = path.resolve(__dirname, "..");
const binding = require(
  path.join(
    nativeRoot,
    "target",
    "test-hooks",
    "goatcli-windows-spawn-test.node",
  ),
);
const fixture = path.join(
  nativeRoot,
  "target",
  "test-hooks",
  "bun-fd-responder.exe",
);

assert.equal(binding.WINDOWS_PRIVACY_SPAWN_ABI_VERSION, 1);
(async () => {
  const canaryHandle = binding.createInheritableEventForTest();
  assert.equal(binding.isHandleInheritableForTest(canaryHandle), true);

  let child;
  let writeFd;
  let readFd;
  try {
    let resolveExit;
    const exit = new Promise((resolve) => {
      resolveExit = resolve;
    });
    child = binding.spawnWindowsPrivacyProcess(
      {
        command: fixture,
        args: [],
        cwd: path.resolve(nativeRoot, "../.."),
        env: safeEnvironment(),
        windowsHide: true,
        detached: true,
      },
      (code, signal) => resolveExit([code, signal]),
    );

    assert.equal(
      binding.isHandleValidForTest(child.childReadHandleForTest),
      false,
    );
    assert.equal(
      binding.isHandleValidForTest(child.childWriteHandleForTest),
      false,
    );
    writeFd = child.takeLauncherWriteFd();
    readFd = child.takeLauncherReadFd();
    assert.equal(binding.isFdInheritableForTest(writeFd), false);
    assert.equal(binding.isFdInheritableForTest(readFd), false);
    assert.throws(() => child.takeLauncherWriteFd(), {
      code: "GOAT_NATIVE_PRIVACY_PIPE_FAILED",
    });
    assert.throws(() => child.takeLauncherReadFd(), {
      code: "GOAT_NATIVE_PRIVACY_PIPE_FAILED",
    });

    const request = JSON.stringify({
      payload: "native-roundtrip",
      canaryHandle,
      privacyToken: "T".repeat(43),
      transportPath: "NO_TRANSPORT_PATH_2852",
    });
    fs.writeSync(writeFd, request);
    fs.closeSync(writeFd);
    writeFd = undefined;

    const chunks = [];
    const buffer = Buffer.alloc(4_096);
    for (;;) {
      const count = fs.readSync(readFd, buffer, 0, buffer.length, null);
      if (count === 0) break;
      chunks.push(Buffer.from(buffer.subarray(0, count)));
    }
    fs.closeSync(readFd);
    readFd = undefined;

    const response = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    assert.deepEqual(response, {
      payload: "native-roundtrip",
      canaryInvalid: true,
      canaryError: 6,
      stdioValid: [true, true, true],
      argvAndEnvironmentClean: true,
    });
    assert.deepEqual(await exit, [0, null]);
  } finally {
    closeFdIfOpen(writeFd);
    closeFdIfOpen(readFd);
    try {
      child?.terminate();
    } finally {
      child?.close();
      assert.equal(binding.closeHandleForTest(canaryHandle), true);
    }
  }
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

function safeEnvironment() {
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
  return Object.entries(process.env)
    .filter(
      ([name, value]) => value !== undefined && allowed.has(name.toUpperCase()),
    )
    .map(([name, value]) => ({ name, value }));
}

function closeFdIfOpen(fd) {
  if (fd === undefined) return;
  try {
    fs.closeSync(fd);
  } catch (error) {
    if (error?.code !== "EBADF") throw error;
  }
}
