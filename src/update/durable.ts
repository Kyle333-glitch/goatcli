import { randomBytes } from "node:crypto";
import path from "node:path";
import {
  chmod,
  link,
  lstat,
  mkdir,
  open,
  readFile,
  realpath,
  rename,
  rm,
  unlink,
  type FileHandle,
} from "node:fs/promises";
import { UpdateError, type UpdateErrorCode } from "./errors.js";

export async function ensurePrivateDirectory(
  directory: string,
  errorCode: UpdateErrorCode = "GOAT_UPDATE_STATE_INVALID",
): Promise<string> {
  const resolved = path.resolve(directory);
  try {
    await mkdir(resolved, { recursive: true, mode: 0o700 });
    await assertPrivateDirectory(resolved, errorCode);
    if (process.platform !== "win32") await chmod(resolved, 0o700);
    return resolved;
  } catch (error) {
    if (error instanceof UpdateError) throw error;
    throw new UpdateError(errorCode, { cause: error });
  }
}

export async function assertPrivateDirectory(
  directory: string,
  errorCode: UpdateErrorCode = "GOAT_UPDATE_STATE_INVALID",
): Promise<void> {
  try {
    const stats = await lstat(directory);
    if (!stats.isDirectory() || stats.isSymbolicLink()) {
      throw new UpdateError(errorCode);
    }
    const canonical = await realpath(directory);
    // Compare by device/inode so Windows short-name/long-name aliases and
    // case variations do not cause a false mismatch. A symlink/junction would
    // either have been rejected by lstat above or would resolve to a different
    // physical directory and therefore fail this identity check.
    const canonicalStats = await lstat(canonical);
    if (stats.dev !== canonicalStats.dev || stats.ino !== canonicalStats.ino) {
      throw new UpdateError(errorCode);
    }
  } catch (error) {
    if (error instanceof UpdateError) throw error;
    throw new UpdateError(errorCode, { cause: error });
  }
}

export async function writeImmutableFile(
  directory: string,
  fileName: string,
  bytes: Uint8Array,
  errorCode: UpdateErrorCode,
): Promise<string> {
  if (
    fileName.length === 0 ||
    fileName !== path.basename(fileName) ||
    fileName.includes("\\") ||
    !/^[A-Za-z0-9._-]+$/.test(fileName)
  ) {
    throw new UpdateError(errorCode);
  }
  const root = await ensurePrivateDirectory(directory, errorCode);
  const destination = path.join(root, fileName);
  const temporaryName = `.tmp-${randomBytes(16).toString("hex")}`;
  const temporary = path.join(root, temporaryName);
  let handle: FileHandle | undefined;
  let renamed = false;
  try {
    handle = await open(temporary, "wx", 0o600);
    await writeAll(handle, Buffer.from(bytes));
    await handle.sync();
    const beforeClose = await handle.stat();
    if (
      !beforeClose.isFile() ||
      beforeClose.nlink !== 1 ||
      beforeClose.size !== bytes.byteLength
    ) {
      throw new UpdateError(errorCode);
    }
    await handle.close();
    handle = undefined;
    if (process.platform !== "win32") await chmod(temporary, 0o600);
    try {
      await link(temporary, destination);
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === "EEXIST") {
        throw new UpdateError(errorCode);
      }
      if (
        process.platform === "win32" &&
        (code === "ENOTSUP" || code === "EPERM")
      ) {
        // Windows may not support hard links for this filesystem, so fall
        // back to a rename after confirming the destination does not already
        // exist. This is weaker than link+unlink, but it is the best available
        // no-clobber primitive on Windows.
        const exists = await lstat(destination).catch((err) => {
          if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
          throw new UpdateError(errorCode, { cause: err });
        });
        if (exists) throw new UpdateError(errorCode);
        await rename(temporary, destination);
      } else if (code === "EACCES" || code === "EPERM") {
        throw new UpdateError(errorCode);
      } else {
        throw new UpdateError(errorCode, { cause: error });
      }
    }
    renamed = true;
    try {
      await unlink(temporary);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
        throw new UpdateError(errorCode, { cause: error });
      }
    }
    await syncDirectory(root, errorCode);
    const stored = await readImmutableFile(
      destination,
      bytes.byteLength,
      errorCode,
    );
    if (!stored.equals(Buffer.from(bytes))) throw new UpdateError(errorCode);
    return destination;
  } catch (error) {
    await handle?.close().catch(() => undefined);
    if (!renamed) await rm(temporary, { force: true }).catch(() => undefined);
    if (error instanceof UpdateError) throw error;
    throw new UpdateError(errorCode, { cause: error });
  }
}

export async function readImmutableFile(
  filePath: string,
  maxBytes: number,
  errorCode: UpdateErrorCode,
): Promise<Buffer> {
  if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0) {
    throw new UpdateError(errorCode);
  }
  let handle: FileHandle | undefined;
  try {
    const before = await lstat(filePath);
    if (
      !before.isFile() ||
      before.isSymbolicLink() ||
      before.nlink !== 1 ||
      before.size <= 0 ||
      before.size > maxBytes
    ) {
      throw new UpdateError(errorCode);
    }
    const canonical = await realpath(filePath);
    // Identity check by device/inode handles Windows short/long-name aliases and
    // case variations. Symlinks are already rejected by lstat above.
    const canonicalStats = await lstat(canonical);
    if (
      before.dev !== canonicalStats.dev ||
      before.ino !== canonicalStats.ino
    ) {
      throw new UpdateError(errorCode);
    }
    handle = await open(filePath, "r");
    const opened = await handle.stat();
    if (
      !opened.isFile() ||
      opened.nlink !== 1 ||
      opened.size !== before.size ||
      opened.dev !== before.dev ||
      opened.ino !== before.ino
    ) {
      throw new UpdateError(errorCode);
    }
    const bytes = await readFile(handle);
    const after = await handle.stat();
    if (
      bytes.byteLength !== before.size ||
      after.size !== before.size ||
      after.dev !== before.dev ||
      after.ino !== before.ino
    ) {
      throw new UpdateError(errorCode);
    }
    return bytes;
  } catch (error) {
    if (error instanceof UpdateError) throw error;
    throw new UpdateError(errorCode, { cause: error });
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

export async function syncDirectory(
  directory: string,
  errorCode: UpdateErrorCode,
): Promise<void> {
  let handle: FileHandle | undefined;
  try {
    handle = await open(directory, "r");
    await handle.sync();
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (
      process.platform === "win32" &&
      (code === "EISDIR" || code === "EPERM" || code === "EACCES")
    ) {
      return;
    }
    throw new UpdateError(errorCode, { cause: error });
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

async function writeAll(handle: FileHandle, bytes: Buffer): Promise<void> {
  let offset = 0;
  while (offset < bytes.byteLength) {
    const { bytesWritten } = await handle.write(
      bytes,
      offset,
      bytes.byteLength - offset,
      offset,
    );
    if (bytesWritten <= 0) {
      throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
    }
    offset += bytesWritten;
  }
}
