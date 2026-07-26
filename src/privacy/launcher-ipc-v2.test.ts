import assert from "node:assert/strict";
import { test } from "node:test";
import type { LauncherIpcTransport } from "./launcher-ipc.js";
import {
  LAUNCHER_IPC_LAZY_ACTIVATION_V2,
  waitForLauncherIpcV2Activation,
} from "./launcher-ipc-v2.js";

test("lazy IPC v2 accepts only the exact bounded activation preamble", async () => {
  const chunks = [
    LAUNCHER_IPC_LAZY_ACTIVATION_V2.slice(0, 3),
    LAUNCHER_IPC_LAZY_ACTIVATION_V2.slice(3),
  ];
  let writes = 0;
  const transport: LauncherIpcTransport = {
    async read() {
      return chunks.shift() ?? null;
    },
    async write() {
      writes += 1;
    },
  };

  await waitForLauncherIpcV2Activation({
    transport,
    signal: new AbortController().signal,
  });
  assert.equal(writes, 0);
});

test("lazy IPC v2 rejects bytes appended to the activation preamble", async () => {
  const transport: LauncherIpcTransport = {
    async read() {
      const value = new Uint8Array(
        LAUNCHER_IPC_LAZY_ACTIVATION_V2.byteLength + 1,
      );
      value.set(LAUNCHER_IPC_LAZY_ACTIVATION_V2);
      return value;
    },
    async write() {},
  };

  await assert.rejects(
    waitForLauncherIpcV2Activation({
      transport,
      signal: new AbortController().signal,
    }),
    { code: "LAUNCHER_IPC_MESSAGE_INVALID" },
  );
});
