import type { Readable, Writable } from "node:stream";
import { LauncherIpcError, type LauncherIpcTransport } from "./launcher-ipc.js";

export function createNodeLauncherIpcTransport(
  readable: Readable,
  writable: Writable,
): LauncherIpcTransport {
  let closed = false;

  const close = (): void => {
    if (closed) return;
    closed = true;
    readable.destroy();
    writable.destroy();
  };

  return {
    read(signal) {
      if (signal.aborted) {
        return Promise.reject(new LauncherIpcError("LAUNCHER_IPC_CANCELLED"));
      }
      if (closed || readable.readableEnded || readable.destroyed) {
        return Promise.resolve(null);
      }

      let available: Uint8Array | null;
      try {
        available = readChunk(readable);
      } catch (error) {
        return Promise.reject(normalizeReadError(error));
      }
      if (available) return Promise.resolve(available);

      return new Promise<Uint8Array | null>((resolve, reject) => {
        let settled = false;
        const cleanup = (): void => {
          readable.removeListener("readable", onReadable);
          readable.removeListener("end", onEnd);
          readable.removeListener("close", onEnd);
          readable.removeListener("error", onError);
          signal.removeEventListener("abort", onAbort);
        };
        const finish = (operation: () => void): void => {
          if (settled) return;
          settled = true;
          cleanup();
          operation();
        };
        const onReadable = (): void => {
          try {
            const chunk = readChunk(readable);
            if (chunk) finish(() => resolve(chunk));
          } catch (error) {
            finish(() => reject(normalizeReadError(error)));
          }
        };
        const onEnd = (): void => finish(() => resolve(null));
        const onError = (): void =>
          finish(() =>
            reject(new LauncherIpcError("LAUNCHER_IPC_PEER_CLOSED")),
          );
        const onAbort = (): void =>
          finish(() => reject(new LauncherIpcError("LAUNCHER_IPC_CANCELLED")));

        readable.on("readable", onReadable);
        readable.once("end", onEnd);
        readable.once("close", onEnd);
        readable.once("error", onError);
        signal.addEventListener("abort", onAbort, { once: true });
        // Recheck after listeners are installed so data cannot arrive in the
        // gap between the initial read and listener registration.
        onReadable();
        if (!settled && signal.aborted) onAbort();
        if (
          !settled &&
          (closed || readable.readableEnded || readable.destroyed)
        )
          onEnd();
      });
    },

    write(bytes, signal) {
      if (signal.aborted) {
        return Promise.reject(new LauncherIpcError("LAUNCHER_IPC_CANCELLED"));
      }
      if (closed || writable.destroyed) {
        return Promise.reject(
          new LauncherIpcError("LAUNCHER_IPC_WRITE_FAILED"),
        );
      }

      const owned = Buffer.from(bytes);
      return new Promise<void>((resolve, reject) => {
        let settled = false;
        const cleanup = (): void => {
          writable.removeListener("error", onError);
          signal.removeEventListener("abort", onAbort);
        };
        const finish = (operation: () => void): void => {
          if (settled) return;
          settled = true;
          cleanup();
          owned.fill(0);
          operation();
        };
        const onError = (): void =>
          finish(() =>
            reject(new LauncherIpcError("LAUNCHER_IPC_WRITE_FAILED")),
          );
        const onAbort = (): void => {
          writable.destroy();
          finish(() => reject(new LauncherIpcError("LAUNCHER_IPC_CANCELLED")));
        };

        writable.once("error", onError);
        signal.addEventListener("abort", onAbort, { once: true });
        if (signal.aborted) {
          onAbort();
          return;
        }
        try {
          writable.write(owned, (error?: Error | null) => {
            if (error) {
              finish(() =>
                reject(new LauncherIpcError("LAUNCHER_IPC_WRITE_FAILED")),
              );
            } else {
              finish(resolve);
            }
          });
        } catch {
          finish(() =>
            reject(new LauncherIpcError("LAUNCHER_IPC_WRITE_FAILED")),
          );
        }
      });
    },

    close,
  };
}

function readChunk(readable: Readable): Uint8Array | null {
  let chunk: unknown;
  try {
    chunk = readable.read();
  } catch {
    throw new LauncherIpcError("LAUNCHER_IPC_PEER_CLOSED");
  }
  if (chunk === null) return null;
  if (!(chunk instanceof Uint8Array) || chunk.byteLength === 0) {
    throw new LauncherIpcError("LAUNCHER_IPC_MESSAGE_INVALID");
  }
  return Uint8Array.from(chunk);
}

function normalizeReadError(error: unknown): LauncherIpcError {
  return error instanceof LauncherIpcError
    ? error
    : new LauncherIpcError("LAUNCHER_IPC_PEER_CLOSED");
}
