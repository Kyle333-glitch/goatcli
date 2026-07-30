import { createHash } from "node:crypto";
import { constants, type BigIntStats } from "node:fs";
import path from "node:path";
import {
  lstat,
  open,
  readdir,
  realpath,
  type FileHandle,
} from "node:fs/promises";
import {
  canonicalJsonBytes,
  type JsonObject,
  type JsonValue,
} from "./canonical-json.js";
import { UpdateError } from "./errors.js";
import type { AuthenticatedTarget, SignedContentEntry } from "./schema.js";
import { assertNoLinkOrReparsePath } from "./temporary.js";

interface FileSystemObjectIdentity {
  readonly device: string;
  readonly inode: string;
}

interface HeldDirectory {
  readonly relativePath: "." | "bin";
  readonly handle: FileHandle;
  readonly identity: FileSystemObjectIdentity;
  readonly mode: number;
  readonly modifiedAtNs: string;
  readonly changedAtNs: string;
}

interface HeldSlotEntry {
  readonly relativePath: string;
  readonly handle: FileHandle;
  readonly identity: FileSystemObjectIdentity;
  readonly length: number;
  readonly mode: number;
  readonly modifiedAtNs: string;
  readonly changedAtNs: string;
  readonly sha256: string;
}

export interface HeldVerifiedSlot {
  readonly originalRoot: string;
  readonly target: AuthenticatedTarget;
  readonly directories: readonly HeldDirectory[];
  readonly entries: readonly HeldSlotEntry[];
  readonly treeSha256: string;
  readonly manifestBytes: Buffer;
  readonly manifestSha256: string;
  readonly executableSha256: string;
  readonly slotSealSha256: string;
}

const MAX_ENGINE_MANIFEST_BYTES = 64 * 1024;
const OPEN_READ_NOFOLLOW =
  constants.O_RDONLY |
  (typeof constants.O_NOFOLLOW === "number" ? constants.O_NOFOLLOW : 0);

export async function openHeldVerifiedSlot(
  root: string,
  target: AuthenticatedTarget,
): Promise<HeldVerifiedSlot> {
  const resolvedRoot = path.resolve(root);
  const directories: HeldDirectory[] = [];
  const entries: HeldSlotEntry[] = [];
  try {
    await assertExactMembership(resolvedRoot, target);
    directories.push(
      await openHeldDirectory(resolvedRoot, resolvedRoot, "."),
      await openHeldDirectory(
        resolvedRoot,
        path.join(resolvedRoot, "bin"),
        "bin",
      ),
    );

    const treeDigest = createHash("sha256");
    for (const content of [...target.custom.contents].sort((left, right) =>
      asciiCompare(left.path, right.path),
    )) {
      const held = await openHeldEntry(resolvedRoot, content);
      entries.push(held);
      treeDigest.update(held.relativePath, "utf8");
      treeDigest.update("\0");
      treeDigest.update(String(held.length));
      treeDigest.update("\0");
      treeDigest.update(held.sha256, "ascii");
      treeDigest.update("\0");
    }
    const treeSha256 = treeDigest.digest("hex");
    const manifest = requireEntry(entries, "goat-engine.json");
    const executable = requireEntry(
      entries,
      target.custom.platform === "win32"
        ? "bin/goat-engine.exe"
        : "bin/goat-engine",
    );
    if (manifest.length > MAX_ENGINE_MANIFEST_BYTES) {
      throw contentMismatch();
    }
    const manifestBytes = await readHeldFile(manifest);
    const slotSealSha256 = sealDigest({
      schema: 1,
      artifactSha256: target.sha256,
      directories: directories.map((directory) => ({
        path: directory.relativePath,
        device: directory.identity.device,
        inode: directory.identity.inode,
        mode: directory.mode,
        modifiedAtNs: directory.modifiedAtNs,
        changedAtNs: directory.changedAtNs,
      })),
      entries: entries.map((entry) => ({
        path: entry.relativePath,
        device: entry.identity.device,
        inode: entry.identity.inode,
        length: entry.length,
        mode: entry.mode,
        modifiedAtNs: entry.modifiedAtNs,
        changedAtNs: entry.changedAtNs,
        sha256: entry.sha256,
      })),
      treeSha256,
      manifestSha256: manifest.sha256,
      executableSha256: executable.sha256,
    });
    const held: HeldVerifiedSlot = {
      originalRoot: resolvedRoot,
      target,
      directories,
      entries,
      treeSha256,
      manifestBytes,
      manifestSha256: manifest.sha256,
      executableSha256: executable.sha256,
      slotSealSha256,
    };
    await assertHeldVerifiedSlotBound(held, resolvedRoot);
    return held;
  } catch (error) {
    await closeHandles(directories, entries).catch(() => undefined);
    if (error instanceof UpdateError) throw error;
    throw new UpdateError("GOAT_UPDATE_ACTIVATION_FAILED", { cause: error });
  }
}

export async function assertHeldVerifiedSlotBound(
  held: HeldVerifiedSlot,
  root: string,
): Promise<void> {
  const resolvedRoot = path.resolve(root);
  try {
    await assertExactMembership(resolvedRoot, held.target);
    for (const directory of held.directories) {
      const directoryPath =
        directory.relativePath === "."
          ? resolvedRoot
          : path.join(resolvedRoot, directory.relativePath);
      await assertDirectoryBound(resolvedRoot, directoryPath, directory);
    }
    for (const entry of held.entries) {
      await assertEntryBound(resolvedRoot, entry);
    }
  } catch (error) {
    if (error instanceof UpdateError) throw error;
    throw new UpdateError("GOAT_UPDATE_ACTIVATION_FAILED", { cause: error });
  }
}

export async function disposeHeldVerifiedSlot(
  held: HeldVerifiedSlot,
): Promise<void> {
  await closeHandles(held.directories, held.entries);
}

async function openHeldDirectory(
  boundary: string,
  directoryPath: string,
  relativePath: HeldDirectory["relativePath"],
): Promise<HeldDirectory> {
  await assertSlotPath(boundary, directoryPath);
  const before = await lstat(directoryPath, { bigint: true });
  if (!before.isDirectory() || before.isSymbolicLink()) {
    throw contentMismatch();
  }
  const handle = await open(directoryPath, OPEN_READ_NOFOLLOW);
  try {
    const opened = await handle.stat({ bigint: true });
    if (
      !opened.isDirectory() ||
      !sameIdentity(identity(before), identity(opened))
    ) {
      throw contentMismatch();
    }
    const canonical = await realpath(directoryPath);
    if (path.resolve(canonical) !== path.resolve(directoryPath)) {
      throw contentMismatch();
    }
    return {
      relativePath,
      handle,
      identity: identity(opened),
      mode: finalizedMode(opened.mode),
      modifiedAtNs: opened.mtimeNs.toString(10),
      changedAtNs: opened.ctimeNs.toString(10),
    };
  } catch (error) {
    await handle.close().catch(() => undefined);
    throw error;
  }
}

async function openHeldEntry(
  root: string,
  content: SignedContentEntry,
): Promise<HeldSlotEntry> {
  const filePath = contentPath(root, content.path);
  await assertSlotPath(root, filePath);
  const before = await lstat(filePath, { bigint: true });
  assertExpectedFile(before, content);
  const handle = await open(filePath, OPEN_READ_NOFOLLOW);
  try {
    const opened = await handle.stat({ bigint: true });
    assertExpectedFile(opened, content);
    if (!sameIdentity(identity(before), identity(opened))) {
      throw contentMismatch();
    }
    const digest = await hashFileHandle(handle, content.length);
    if (digest !== content.sha256) throw contentMismatch();
    const after = await lstat(filePath, { bigint: true });
    assertExpectedFile(after, content);
    if (
      !sameIdentity(identity(opened), identity(after)) ||
      opened.mtimeNs !== after.mtimeNs ||
      opened.ctimeNs !== after.ctimeNs
    ) {
      throw contentMismatch();
    }
    return {
      relativePath: content.path,
      handle,
      identity: identity(opened),
      length: content.length,
      mode: finalizedMode(opened.mode),
      modifiedAtNs: opened.mtimeNs.toString(10),
      changedAtNs: opened.ctimeNs.toString(10),
      sha256: digest,
    };
  } catch (error) {
    await handle.close().catch(() => undefined);
    throw error;
  }
}

async function assertDirectoryBound(
  boundary: string,
  directoryPath: string,
  held: HeldDirectory,
): Promise<void> {
  await assertSlotPath(boundary, directoryPath);
  const opened = await held.handle.stat({ bigint: true });
  const current = await lstat(directoryPath, { bigint: true });
  if (
    !opened.isDirectory() ||
    !current.isDirectory() ||
    current.isSymbolicLink() ||
    !sameIdentity(held.identity, identity(opened)) ||
    !sameIdentity(held.identity, identity(current)) ||
    finalizedMode(opened.mode) !== held.mode ||
    finalizedMode(current.mode) !== held.mode ||
    opened.mtimeNs.toString(10) !== held.modifiedAtNs ||
    current.mtimeNs.toString(10) !== held.modifiedAtNs ||
    opened.ctimeNs.toString(10) !== held.changedAtNs ||
    current.ctimeNs.toString(10) !== held.changedAtNs
  ) {
    throw contentMismatch();
  }
}

async function assertEntryBound(
  root: string,
  held: HeldSlotEntry,
): Promise<void> {
  const filePath = contentPath(root, held.relativePath);
  await assertSlotPath(root, filePath);
  const opened = await held.handle.stat({ bigint: true });
  const current = await lstat(filePath, { bigint: true });
  if (
    !opened.isFile() ||
    !current.isFile() ||
    current.isSymbolicLink() ||
    opened.nlink !== 1n ||
    current.nlink !== 1n ||
    !sameIdentity(held.identity, identity(opened)) ||
    !sameIdentity(held.identity, identity(current)) ||
    opened.size !== BigInt(held.length) ||
    current.size !== BigInt(held.length) ||
    finalizedMode(opened.mode) !== held.mode ||
    finalizedMode(current.mode) !== held.mode ||
    opened.mtimeNs.toString(10) !== held.modifiedAtNs ||
    current.mtimeNs.toString(10) !== held.modifiedAtNs ||
    opened.ctimeNs.toString(10) !== held.changedAtNs ||
    current.ctimeNs.toString(10) !== held.changedAtNs ||
    (await hashFileHandle(held.handle, held.length)) !== held.sha256
  ) {
    throw contentMismatch();
  }
}

async function assertExactMembership(
  root: string,
  target: AuthenticatedTarget,
): Promise<void> {
  await assertSlotPath(root, root);
  const expectedRootEntries = new Set([
    "bin",
    ...target.custom.contents
      .filter((entry) => !entry.path.includes("/"))
      .map((entry) => entry.path),
  ]);
  const rootEntries = await readdir(root);
  if (
    rootEntries.length !== expectedRootEntries.size ||
    rootEntries.some((entry) => !expectedRootEntries.has(entry))
  ) {
    throw contentMismatch();
  }
  const expectedBinEntries = new Set(
    target.custom.contents
      .filter((entry) => entry.path.startsWith("bin/"))
      .map((entry) => path.posix.basename(entry.path)),
  );
  const binEntries = await readdir(path.join(root, "bin"));
  if (
    binEntries.length !== expectedBinEntries.size ||
    binEntries.some((entry) => !expectedBinEntries.has(entry))
  ) {
    throw contentMismatch();
  }
}

async function assertSlotPath(boundary: string, target: string): Promise<void> {
  const resolvedBoundary = path.resolve(boundary);
  const resolvedTarget = path.resolve(target);
  if (resolvedBoundary === resolvedTarget) {
    await assertNoLinkOrReparsePath(
      path.dirname(resolvedBoundary),
      resolvedTarget,
    );
    return;
  }
  await assertNoLinkOrReparsePath(resolvedBoundary, resolvedTarget);
}

function assertExpectedFile(
  stats: BigIntStats,
  content: SignedContentEntry,
): void {
  if (
    !stats.isFile() ||
    stats.isSymbolicLink() ||
    stats.nlink !== 1n ||
    stats.size !== BigInt(content.length) ||
    (process.platform !== "win32" &&
      finalizedMode(stats.mode) !== (content.mode & 0o777))
  ) {
    throw contentMismatch();
  }
}

async function readHeldFile(entry: HeldSlotEntry): Promise<Buffer> {
  const bytes = Buffer.alloc(entry.length);
  let offset = 0;
  while (offset < bytes.byteLength) {
    const { bytesRead } = await entry.handle.read(
      bytes,
      offset,
      bytes.byteLength - offset,
      offset,
    );
    if (bytesRead <= 0) throw contentMismatch();
    offset += bytesRead;
  }
  return bytes;
}

async function hashFileHandle(
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
    if (bytesRead <= 0) throw contentMismatch();
    digest.update(buffer.subarray(0, bytesRead));
    position += bytesRead;
  }
  return digest.digest("hex");
}

async function closeHandles(
  directories: readonly HeldDirectory[],
  entries: readonly HeldSlotEntry[],
): Promise<void> {
  const results = await Promise.allSettled([
    ...entries.map((entry) => entry.handle.close()),
    ...directories.map((directory) => directory.handle.close()),
  ]);
  const failures = results
    .filter(
      (result): result is PromiseRejectedResult => result.status === "rejected",
    )
    .map((result) => result.reason);
  if (failures.length > 0) {
    throw new UpdateError("GOAT_UPDATE_ACTIVATION_FAILED", {
      cause: new AggregateError(
        failures,
        "Failed to close verified slot handles",
      ),
    });
  }
}

function identity(stats: { readonly dev: bigint; readonly ino: bigint }) {
  if (stats.dev <= 0n || stats.ino <= 0n) throw contentMismatch();
  return {
    device: stats.dev.toString(10),
    inode: stats.ino.toString(10),
  };
}

function sameIdentity(
  left: FileSystemObjectIdentity,
  right: FileSystemObjectIdentity,
): boolean {
  return left.device === right.device && left.inode === right.inode;
}

function finalizedMode(mode: bigint): number {
  return process.platform === "win32" ? 0 : Number(mode & 0o777n);
}

function contentPath(root: string, relativePath: string): string {
  const candidate = path.resolve(root, ...relativePath.split("/"));
  const boundary = `${path.resolve(root)}${path.sep}`;
  if (!candidate.startsWith(boundary)) throw contentMismatch();
  return candidate;
}

function requireEntry(
  entries: readonly HeldSlotEntry[],
  relativePath: string,
): HeldSlotEntry {
  const entry = entries.find(
    (candidate) => candidate.relativePath === relativePath,
  );
  if (!entry) throw contentMismatch();
  return entry;
}

function sealDigest(value: JsonObject): string {
  return createHash("sha256")
    .update(canonicalJsonBytes(value as JsonValue))
    .digest("hex");
}

function contentMismatch(): UpdateError {
  return new UpdateError("GOAT_UPDATE_ARCHIVE_CONTENT_MISMATCH");
}

function asciiCompare(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
