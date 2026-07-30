import { createHash, randomInt } from "node:crypto";
import path from "node:path";
import { rm, type FileHandle } from "node:fs/promises";
import { UpdateError } from "./errors.js";
import {
  ARTIFACT_NETWORK_LIMITS,
  isRetryableNetworkError,
  normalizeNetworkError,
  type FixedOriginTransport,
} from "./network.js";
import type { AuthenticatedTarget } from "./schema.js";
import {
  closeAndRemoveTemporaryFile,
  createExclusiveTemporaryFile,
  type UpdateTransactionPaths,
} from "./temporary.js";

export interface HeldVerifiedArtifact {
  readonly path: string;
  readonly handle: FileHandle;
  readonly length: number;
  readonly sha256: string;
  readonly device: number;
  readonly inode: number;
}

export interface DownloadArtifactOptions {
  readonly waitBeforeRetry?: () => Promise<void>;
}

const MAX_DOWNLOAD_ATTEMPTS = 2;

export async function downloadVerifiedArtifact(
  transport: FixedOriginTransport,
  target: AuthenticatedTarget,
  transaction: UpdateTransactionPaths,
  options: DownloadArtifactOptions = {},
): Promise<HeldVerifiedArtifact> {
  const resourcePath = consistentSnapshotArtifactPath(target);
  let lastError: UpdateError | undefined;
  for (let attempt = 1; attempt <= MAX_DOWNLOAD_ATTEMPTS; attempt += 1) {
    const temporary = await createExclusiveTemporaryFile(transaction);
    try {
      const response = await transport.openResource(
        resourcePath,
        ARTIFACT_NETWORK_LIMITS,
      );
      if (
        response.contentLength !== undefined &&
        response.contentLength !== target.length
      ) {
        response.body.destroy();
        throw new UpdateError("GOAT_UPDATE_ARTIFACT_SIZE_MISMATCH");
      }

      const digest = createHash("sha256");
      let bytesWritten = 0;
      try {
        for await (const chunk of response.body) {
          const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
          if (bytesWritten + bytes.byteLength > target.length) {
            response.body.destroy();
            throw new UpdateError("GOAT_UPDATE_ARTIFACT_SIZE_MISMATCH");
          }
          await writeAll(temporary.handle, bytes, bytesWritten);
          digest.update(bytes);
          bytesWritten += bytes.byteLength;
        }
      } catch (error) {
        throw normalizeNetworkError(error);
      }

      if (bytesWritten !== target.length) {
        throw new UpdateError("GOAT_UPDATE_ARTIFACT_SIZE_MISMATCH");
      }
      const observedDigest = digest.digest("hex");
      if (observedDigest !== target.sha256) {
        throw new UpdateError("GOAT_UPDATE_ARTIFACT_HASH_MISMATCH");
      }
      await temporary.handle.sync();
      const stats = await temporary.handle.stat();
      if (
        !stats.isFile() ||
        stats.nlink !== 1 ||
        stats.size !== target.length
      ) {
        throw new UpdateError("GOAT_UPDATE_TEMPORARY_FILE_UNSAFE");
      }
      const rereadDigest = await hashHeldFile(temporary.handle, target.length);
      if (rereadDigest !== target.sha256) {
        throw new UpdateError("GOAT_UPDATE_ARTIFACT_HASH_MISMATCH");
      }
      return {
        path: temporary.path,
        handle: temporary.handle,
        length: target.length,
        sha256: target.sha256,
        device: stats.dev,
        inode: stats.ino,
      };
    } catch (error) {
      const normalized = normalizeNetworkError(error);
      lastError = normalized;
      await closeAndRemoveTemporaryFile(transaction, temporary).catch(
        () => undefined,
      );
      if (
        attempt < MAX_DOWNLOAD_ATTEMPTS &&
        isRetryableNetworkError(normalized)
      ) {
        await (options.waitBeforeRetry ?? randomizedBackoff)();
        continue;
      }
      throw normalized;
    }
  }
  throw lastError ?? new UpdateError("GOAT_UPDATE_NETWORK_FAILED");
}

export async function assertHeldArtifactUnchanged(
  artifact: HeldVerifiedArtifact,
): Promise<void> {
  let stats;
  try {
    stats = await artifact.handle.stat();
  } catch (error) {
    throw new UpdateError("GOAT_UPDATE_ARTIFACT_HASH_MISMATCH", {
      cause: error,
    });
  }
  if (
    !stats.isFile() ||
    stats.nlink !== 1 ||
    stats.size !== artifact.length ||
    stats.dev !== artifact.device ||
    stats.ino !== artifact.inode ||
    (await hashHeldFile(artifact.handle, artifact.length)) !== artifact.sha256
  ) {
    throw new UpdateError("GOAT_UPDATE_ARTIFACT_HASH_MISMATCH");
  }
}

export async function disposeHeldArtifact(
  artifact: HeldVerifiedArtifact,
): Promise<void> {
  await artifact.handle.close().catch(() => undefined);
  await rm(artifact.path, { force: true }).catch(() => undefined);
}

export function consistentSnapshotArtifactPath(
  target: AuthenticatedTarget,
): string {
  const normalized = target.targetPath.replaceAll("\\", "/");
  const directory = path.posix.dirname(normalized);
  const filename = path.posix.basename(normalized);
  return `/targets/${directory}/${target.sha256}.${filename}`;
}

async function writeAll(
  handle: FileHandle,
  bytes: Buffer,
  position: number,
): Promise<void> {
  let offset = 0;
  while (offset < bytes.byteLength) {
    const result = await handle.write(
      bytes,
      offset,
      bytes.byteLength - offset,
      position + offset,
    );
    if (result.bytesWritten <= 0) {
      throw new UpdateError("GOAT_UPDATE_NETWORK_FAILED");
    }
    offset += result.bytesWritten;
  }
}

async function hashHeldFile(
  handle: FileHandle,
  length: number,
): Promise<string> {
  const digest = createHash("sha256");
  const buffer = Buffer.allocUnsafe(Math.min(1024 * 1024, Math.max(length, 1)));
  let position = 0;
  while (position < length) {
    const { bytesRead } = await handle.read(
      buffer,
      0,
      Math.min(buffer.byteLength, length - position),
      position,
    );
    if (bytesRead <= 0) {
      throw new UpdateError("GOAT_UPDATE_ARTIFACT_SIZE_MISMATCH");
    }
    digest.update(buffer.subarray(0, bytesRead));
    position += bytesRead;
  }
  return digest.digest("hex");
}

async function randomizedBackoff(): Promise<void> {
  await new Promise<void>((resolve) =>
    setTimeout(resolve, randomInt(250, 1_001)),
  );
}
