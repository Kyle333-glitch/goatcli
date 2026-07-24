import type { LauncherIpcTransport } from "./launcher-ipc.js";
import { LauncherIpcError } from "./launcher-ipc.js";

/**
 * Protocol v2 is a fixed, one-shot activation preamble. The authenticated
 * session that follows deliberately reuses the audited v1 framing.
 *
 * Waiting for this value must not read credentials, sample entropy, inspect
 * the clock, or start a network client. Those operations begin only after a
 * validated engine requests activation over its inherited private pipe.
 */
export const LAUNCHER_IPC_LAZY_ACTIVATION_V2 = new TextEncoder().encode(
  "GOATIPC2",
);

export async function waitForLauncherIpcV2Activation(input: {
  readonly transport: LauncherIpcTransport;
  readonly signal: AbortSignal;
}): Promise<void> {
  let buffered = new Uint8Array();
  try {
    while (buffered.byteLength < LAUNCHER_IPC_LAZY_ACTIVATION_V2.byteLength) {
      let chunk: Uint8Array | null;
      try {
        chunk = await input.transport.read(input.signal);
      } catch {
        throw new LauncherIpcError(
          input.signal.aborted
            ? "LAUNCHER_IPC_CANCELLED"
            : "LAUNCHER_IPC_PEER_CLOSED",
        );
      }
      if (chunk === null) {
        throw new LauncherIpcError("LAUNCHER_IPC_PEER_CLOSED");
      }
      if (
        !(chunk instanceof Uint8Array) ||
        chunk.byteLength === 0 ||
        buffered.byteLength + chunk.byteLength >
          LAUNCHER_IPC_LAZY_ACTIVATION_V2.byteLength
      ) {
        chunk.fill(0);
        throw new LauncherIpcError("LAUNCHER_IPC_MESSAGE_INVALID");
      }
      const next = new Uint8Array(buffered.byteLength + chunk.byteLength);
      next.set(buffered);
      next.set(chunk, buffered.byteLength);
      buffered.fill(0);
      chunk.fill(0);
      buffered = next;
    }

    for (let index = 0; index < buffered.byteLength; index += 1) {
      if (buffered[index] !== LAUNCHER_IPC_LAZY_ACTIVATION_V2[index]) {
        throw new LauncherIpcError("LAUNCHER_IPC_MESSAGE_INVALID");
      }
    }
  } finally {
    buffered.fill(0);
  }
}
