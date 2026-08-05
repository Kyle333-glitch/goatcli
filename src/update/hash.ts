import { createHash } from "node:crypto";
import type { FileHandle } from "node:fs/promises";
import { UpdateError } from "./errors.js";

/**
 * Incrementally hash the contents of an already-open file handle.
 * The handle is read from offset 0 for exactly `length` bytes.
 * Throws GOAT_UPDATE_ARCHIVE_CONTENT_MISMATCH (archive callers) when the
 * declared length cannot be read.
 *
 * @param handle An open FileHandle positioned at the start of the data.
 * @param length Number of bytes to hash.
 * @param errorCode Error code to throw on read/hash failure.
 */
export async function hashFileHandle(
  handle: FileHandle,
  length: number,
  errorCode:
    | "GOAT_UPDATE_ARCHIVE_CONTENT_MISMATCH"
    | "GOAT_UPDATE_ACTIVATION_FAILED"
    | "GOAT_UPDATE_ARTIFACT_HASH_MISMATCH" = "GOAT_UPDATE_ARCHIVE_CONTENT_MISMATCH",
): Promise<string> {
  const digest = createHash("sha256");
  const buffer = Buffer.allocUnsafe(Math.min(1024 * 1024, Math.max(length, 1)));
  let position = 0;
  while (position < length) {
    let bytesRead: number;
    try {
      ({ bytesRead } = await handle.read(
        buffer,
        0,
        Math.min(buffer.byteLength, length - position),
        position,
      ));
    } catch (error) {
      throw new UpdateError(errorCode, {
        cause: error instanceof Error ? error : new Error(String(error)),
      });
    }
    if (bytesRead <= 0) {
      throw new UpdateError(errorCode, {
        cause: new Error(`unexpected EOF while hashing ${length} bytes`),
      });
    }
    digest.update(buffer.subarray(0, bytesRead));
    position += bytesRead;
  }
  return digest.digest("hex");
}
