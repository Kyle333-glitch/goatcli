import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { PassThrough, Readable, type Writable } from "node:stream";
import { test } from "node:test";
import { LauncherIpcError } from "./launcher-ipc.js";
import { createNodeLauncherIpcTransport } from "./node-transport.js";

test("read rechecks after listener registration and cannot miss buffered data", async () => {
  class RaceReadable extends Readable {
    calls = 0;

    override _read(): void {}

    override read(_size?: number): Buffer | null {
      this.calls += 1;
      return this.calls === 2 ? Buffer.from([1, 2, 3]) : null;
    }
  }

  const readable = new RaceReadable();
  const writable = new PassThrough();
  const transport = createNodeLauncherIpcTransport(readable, writable);
  const result = await transport.read(new AbortController().signal);

  assert.deepEqual(result, Uint8Array.from([1, 2, 3]));
  assert.equal(readable.listenerCount("readable"), 0);
  transport.close?.();
});

test("malformed readable chunks reject with a fixed IPC error", async () => {
  class MalformedReadable extends Readable {
    override _read(): void {}

    override read(_size?: number): Buffer {
      return "" as unknown as Buffer;
    }
  }

  const transport = createNodeLauncherIpcTransport(
    new MalformedReadable(),
    new PassThrough(),
  );
  await assert.rejects(
    Promise.resolve().then(() => transport.read(new AbortController().signal)),
    hasIpcCode("LAUNCHER_IPC_MESSAGE_INVALID"),
  );
  transport.close?.();
});

test("pending reads abort with a fixed error and remove listeners", async () => {
  const readable = new PassThrough();
  const transport = createNodeLauncherIpcTransport(readable, new PassThrough());
  const controller = new AbortController();
  const pending = transport.read(controller.signal);
  controller.abort();

  await assert.rejects(pending, hasIpcCode("LAUNCHER_IPC_CANCELLED"));
  assert.equal(readable.listenerCount("readable"), 0);
  transport.close?.();
});

test("synchronous write failures zero the owned pipe buffer", async () => {
  const events = new EventEmitter();
  let captured: Uint8Array | undefined;
  let destroyed = false;
  const writable = {
    get destroyed() {
      return destroyed;
    },
    once(event: string, listener: (...args: unknown[]) => void) {
      events.once(event, listener);
      return this;
    },
    removeListener(event: string, listener: (...args: unknown[]) => void) {
      events.removeListener(event, listener);
      return this;
    },
    destroy() {
      destroyed = true;
      return this;
    },
    write(bytes: Uint8Array) {
      captured = bytes;
      throw new Error("SOURCE_CODE_SECRET_4JK2");
    },
  } as unknown as Writable;
  const transport = createNodeLauncherIpcTransport(new PassThrough(), writable);

  await assert.rejects(
    transport.write(Uint8Array.from([9, 8, 7]), new AbortController().signal),
    hasIpcCode("LAUNCHER_IPC_WRITE_FAILED"),
  );
  assert.ok(captured);
  assert.ok(captured.every((byte) => byte === 0));
  transport.close?.();
});

function hasIpcCode(
  code: LauncherIpcError["code"],
): (error: unknown) => boolean {
  return (error) =>
    error instanceof LauncherIpcError &&
    error.code === code &&
    !error.message.includes("SOURCE_CODE_SECRET_4JK2");
}
