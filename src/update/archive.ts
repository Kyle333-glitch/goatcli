import { createHash } from "node:crypto";
import path from "node:path";
import {
  chmod,
  lstat,
  mkdir,
  open,
  readdir,
  type FileHandle,
} from "node:fs/promises";
import yauzl, { type Entry, type LocalFileHeader, type ZipFile } from "yauzl";
import {
  assertHeldArtifactUnchanged,
  type HeldVerifiedArtifact,
} from "./download.js";
import { UpdateError } from "./errors.js";
import type {
  AuthenticatedTarget,
  SignedContentEntry,
  UpdatePlatform,
} from "./schema.js";
import {
  assertEmptyStagingDirectory,
  assertNoLinkOrReparsePath,
  resetStagingDirectory,
  type UpdateTransactionPaths,
} from "./temporary.js";

export interface ArchiveResourceLimits {
  readonly maxEntries: number;
  readonly maxSingleExpandedBytes: number;
  readonly maxTotalExpandedBytes: number;
  readonly maxCompressionRatio: number;
}

export interface StagedArchive {
  readonly root: string;
  readonly target: AuthenticatedTarget;
  readonly treeSha256: string;
}

interface PlannedEntry {
  readonly entry: Entry;
  readonly signed: SignedContentEntry;
  readonly dataStart: number;
  readonly dataEnd: number;
  readonly localStart: number;
}

interface ArchivePlan {
  readonly zip: ZipFile;
  readonly entries: readonly PlannedEntry[];
}

export const DEFAULT_ARCHIVE_LIMITS: ArchiveResourceLimits = {
  maxEntries: 32,
  maxSingleExpandedBytes: 512 * 1024 * 1024,
  maxTotalExpandedBytes: 1024 * 1024 * 1024,
  maxCompressionRatio: 100,
};

const EOCD_LENGTH = 22;
const EOCD_SIGNATURE = 0x06054b50;
const LOCAL_FILE_SIGNATURE = 0x04034b50;
const UTF8_FILENAME_FLAG = 0x0800;
const UNIX_FILE_TYPE_MASK = 0o170000;
const UNIX_REGULAR_FILE = 0o100000;
const WINDOWS_DEVICE_NAME =
  /^(?:con|prn|aux|nul|clock\$|conin\$|conout\$|com[0-9]{1,2}|lpt[0-9]{1,2})(?:\..*)?$/i;

export async function extractVerifiedArchive(
  artifact: HeldVerifiedArtifact,
  target: AuthenticatedTarget,
  transaction: UpdateTransactionPaths,
  limits: ArchiveResourceLimits = DEFAULT_ARCHIVE_LIMITS,
): Promise<StagedArchive> {
  await assertHeldArtifactUnchanged(artifact);
  await assertEmptyStagingDirectory(transaction);
  let plan: ArchivePlan | undefined;
  try {
    plan = await preflightArchive(artifact, target, limits);
    const binDirectory = path.join(transaction.stagingRoot, "bin");
    await mkdir(binDirectory, { mode: 0o700 });
    if (process.platform !== "win32") await chmod(binDirectory, 0o700);
    await assertNoLinkOrReparsePath(transaction.stagingRoot, binDirectory);

    for (const planned of plan.entries) {
      await extractEntry(plan.zip, planned, transaction);
    }
    await assertHeldArtifactUnchanged(artifact);
    const treeSha256 = await verifyStagedArchive(
      transaction.stagingRoot,
      target,
      false,
    );
    return { root: transaction.stagingRoot, target, treeSha256 };
  } catch (error) {
    await resetStagingDirectory(transaction).catch(() => undefined);
    if (error instanceof UpdateError) throw error;
    throw new UpdateError("GOAT_UPDATE_ARCHIVE_INVALID", { cause: error });
  } finally {
    plan?.zip.close();
  }
}

export async function finalizeStagedPermissions(
  staged: StagedArchive,
): Promise<StagedArchive> {
  await verifyStagedArchive(staged.root, staged.target, false);
  if (staged.target.custom.platform !== "win32") {
    for (const content of staged.target.custom.contents) {
      await chmod(destinationPath(staged.root, content.path), content.mode);
    }
  }
  const treeSha256 = await verifyStagedArchive(
    staged.root,
    staged.target,
    true,
  );
  return { ...staged, treeSha256 };
}

export async function verifyStagedArchive(
  root: string,
  target: AuthenticatedTarget,
  permissionsFinalized: boolean,
): Promise<string> {
  const expectedRootEntries = new Set([
    "bin",
    ...target.custom.contents
      .filter((entry) => !entry.path.includes("/"))
      .map((entry) => entry.path),
  ]);
  const actualRootEntries = await readdir(root);
  if (
    actualRootEntries.length !== expectedRootEntries.size ||
    actualRootEntries.some((entry) => !expectedRootEntries.has(entry))
  ) {
    throw new UpdateError("GOAT_UPDATE_ARCHIVE_CONTENT_MISMATCH");
  }
  const binEntries = await readdir(path.join(root, "bin"));
  const expectedBinEntries = target.custom.contents
    .filter((entry) => entry.path.startsWith("bin/"))
    .map((entry) => path.posix.basename(entry.path));
  if (
    binEntries.length !== expectedBinEntries.length ||
    binEntries.some((entry) => !expectedBinEntries.includes(entry))
  ) {
    throw new UpdateError("GOAT_UPDATE_ARCHIVE_CONTENT_MISMATCH");
  }

  const treeDigest = createHash("sha256");
  for (const content of target.custom.contents) {
    const filePath = destinationPath(root, content.path);
    await assertNoLinkOrReparsePath(root, filePath);
    const stats = await lstat(filePath);
    if (
      !stats.isFile() ||
      stats.isSymbolicLink() ||
      stats.nlink !== 1 ||
      stats.size !== content.length
    ) {
      throw new UpdateError("GOAT_UPDATE_ARCHIVE_CONTENT_MISMATCH");
    }
    const executableBits = stats.mode & 0o111;
    if (
      process.platform !== "win32" &&
      ((!permissionsFinalized && executableBits !== 0) ||
        (permissionsFinalized && executableBits !== (content.mode & 0o111)))
    ) {
      throw new UpdateError("GOAT_UPDATE_ARCHIVE_ENTRY_UNSAFE");
    }
    const handle = await open(filePath, "r");
    let digest: string;
    try {
      digest = await hashFileHandle(handle, content.length);
    } finally {
      await handle.close();
    }
    if (digest !== content.sha256) {
      throw new UpdateError("GOAT_UPDATE_ARCHIVE_CONTENT_MISMATCH");
    }
    treeDigest.update(content.path, "utf8");
    treeDigest.update("\0");
    treeDigest.update(String(content.length));
    treeDigest.update("\0");
    treeDigest.update(digest, "ascii");
    treeDigest.update("\0");
  }
  return treeDigest.digest("hex");
}

async function preflightArchive(
  artifact: HeldVerifiedArtifact,
  target: AuthenticatedTarget,
  limits: ArchiveResourceLimits,
): Promise<ArchivePlan> {
  validateLimits(limits);
  const eocd = await readEndOfCentralDirectory(artifact);
  if (
    eocd.entryCount !== target.custom.contents.length ||
    eocd.entryCount > limits.maxEntries
  ) {
    throw new UpdateError("GOAT_UPDATE_ARCHIVE_LIMIT");
  }

  let zip: ZipFile;
  try {
    zip = await yauzl.fromFdPromise(artifact.handle.fd, {
      autoClose: false,
      lazyEntries: true,
      // Decode and validate names ourselves. yauzl's decoded-string path
      // rejects some hostile names before our policy layer can classify them,
      // and its non-strict mode normalizes backslashes.
      decodeStrings: false,
      validateEntrySizes: true,
      strictFileNames: true,
    });
  } catch (error) {
    throw new UpdateError("GOAT_UPDATE_ARCHIVE_INVALID", { cause: error });
  }
  try {
    if (
      zip.entryCount !== eocd.entryCount ||
      Buffer.byteLength(zip.comment) !== 0 ||
      zip.fileSize !== artifact.length
    ) {
      throw new UpdateError("GOAT_UPDATE_ARCHIVE_INVALID");
    }
    const signedByPath = new Map(
      target.custom.contents.map((entry) => [entry.path, entry]),
    );
    const normalizedPaths = new Set<string>();
    const planned: PlannedEntry[] = [];
    let totalExpanded = 0;
    let totalCompressed = 0;

    for await (const entry of zip.eachEntry()) {
      entry.fileName = decodeArchivePath(entry.fileNameRaw);
      const signed = signedByPath.get(entry.fileName);
      validateCentralEntry(entry, signed, normalizedPaths, limits);
      const local = await zip.readLocalFileHeaderPromise(entry);
      validateLocalHeader(entry, local);
      const dataEnd = local.fileDataStart + entry.compressedSize;
      if (
        entry.relativeOffsetOfLocalHeader < 0 ||
        local.fileDataStart <= entry.relativeOffsetOfLocalHeader ||
        dataEnd > eocd.centralDirectoryOffset
      ) {
        throw new UpdateError("GOAT_UPDATE_ARCHIVE_INVALID");
      }
      totalExpanded += entry.uncompressedSize;
      totalCompressed += entry.compressedSize;
      if (totalExpanded > limits.maxTotalExpandedBytes) {
        throw new UpdateError("GOAT_UPDATE_ARCHIVE_LIMIT");
      }
      planned.push({
        entry,
        signed: signed!,
        dataStart: local.fileDataStart,
        dataEnd,
        localStart: entry.relativeOffsetOfLocalHeader,
      });
    }
    if (
      planned.length !== target.custom.contents.length ||
      normalizedPaths.size !== target.custom.contents.length ||
      compressionRatio(totalExpanded, totalCompressed) >
        limits.maxCompressionRatio
    ) {
      throw new UpdateError("GOAT_UPDATE_ARCHIVE_LIMIT");
    }
    const ranges = [...planned].sort(
      (left, right) => left.localStart - right.localStart,
    );
    let expectedStart = 0;
    for (const range of ranges) {
      if (range.localStart !== expectedStart) {
        throw new UpdateError("GOAT_UPDATE_ARCHIVE_INVALID");
      }
      expectedStart = range.dataEnd;
    }
    if (expectedStart !== eocd.centralDirectoryOffset) {
      throw new UpdateError("GOAT_UPDATE_ARCHIVE_INVALID");
    }
    planned.sort((left, right) =>
      asciiCompare(left.entry.fileName, right.entry.fileName),
    );
    return { zip, entries: planned };
  } catch (error) {
    zip.close();
    throw error;
  }
}

function validateCentralEntry(
  entry: Entry,
  signed: SignedContentEntry | undefined,
  normalizedPaths: Set<string>,
  limits: ArchiveResourceLimits,
): void {
  validateArchivePath(entry.fileName);
  const normalized = entry.fileName.toLowerCase();
  if (normalizedPaths.has(normalized)) {
    throw new UpdateError("GOAT_UPDATE_ARCHIVE_PATH_UNSAFE");
  }
  normalizedPaths.add(normalized);
  if (!signed) {
    throw new UpdateError("GOAT_UPDATE_ARCHIVE_CONTENT_MISMATCH");
  }
  if (
    entry.generalPurposeBitFlag !== UTF8_FILENAME_FLAG ||
    entry.isEncrypted() ||
    (entry.compressionMethod !== 0 && entry.compressionMethod !== 8) ||
    entry.versionNeededToExtract > 20 ||
    entry.extraFieldLength !== 0 ||
    entry.extraFieldRaw.length !== 0 ||
    entry.extraFields.length !== 0 ||
    entry.fileCommentLength !== 0 ||
    entry.fileCommentRaw.length !== 0 ||
    entry.internalFileAttributes !== 0 ||
    !entry.fileNameRaw.equals(Buffer.from(entry.fileName, "ascii")) ||
    entry.uncompressedSize !== signed.length ||
    entry.uncompressedSize > limits.maxSingleExpandedBytes ||
    compressionRatio(entry.uncompressedSize, entry.compressedSize) >
      limits.maxCompressionRatio ||
    (entry.compressionMethod === 0 &&
      entry.compressedSize !== entry.uncompressedSize)
  ) {
    throw new UpdateError("GOAT_UPDATE_ARCHIVE_ENTRY_UNSAFE");
  }
  validateExternalAttributes(entry);
}

function validateExternalAttributes(entry: Entry): void {
  const host = entry.versionMadeBy >>> 8;
  const attributes = entry.externalFileAttributes >>> 0;
  if (host === 3) {
    const unixMode = attributes >>> 16;
    if (
      (unixMode & UNIX_FILE_TYPE_MASK) !== UNIX_REGULAR_FILE ||
      (unixMode & 0o7000) !== 0
    ) {
      throw new UpdateError("GOAT_UPDATE_ARCHIVE_ENTRY_UNSAFE");
    }
    return;
  }
  if (host === 0) {
    if ((attributes & 0x10) !== 0 || (attributes & ~0x20) !== 0) {
      throw new UpdateError("GOAT_UPDATE_ARCHIVE_ENTRY_UNSAFE");
    }
    return;
  }
  throw new UpdateError("GOAT_UPDATE_ARCHIVE_ENTRY_UNSAFE");
}

function validateLocalHeader(entry: Entry, local: LocalFileHeader): void {
  if (
    local.versionNeededToExtract !== entry.versionNeededToExtract ||
    local.generalPurposeBitFlag !== entry.generalPurposeBitFlag ||
    local.compressionMethod !== entry.compressionMethod ||
    local.crc32 !== entry.crc32 ||
    local.compressedSize !== entry.compressedSize ||
    local.uncompressedSize !== entry.uncompressedSize ||
    local.extraFieldLength !== 0 ||
    local.extraField.length !== 0 ||
    !local.fileName.equals(entry.fileNameRaw)
  ) {
    throw new UpdateError("GOAT_UPDATE_ARCHIVE_INVALID");
  }
}

async function extractEntry(
  zip: ZipFile,
  planned: PlannedEntry,
  transaction: UpdateTransactionPaths,
): Promise<void> {
  const destination = destinationPath(
    transaction.stagingRoot,
    planned.signed.path,
  );
  const parent = path.dirname(destination);
  if (path.resolve(parent) !== path.resolve(transaction.stagingRoot)) {
    await assertNoLinkOrReparsePath(transaction.stagingRoot, parent);
  }
  const output = await open(destination, "wx", 0o600).catch((error) => {
    throw new UpdateError("GOAT_UPDATE_ARCHIVE_ENTRY_UNSAFE", { cause: error });
  });
  let completed = false;
  try {
    const stream = await zip.openReadStreamPromise(planned.entry);
    const digest = createHash("sha256");
    let length = 0;
    for await (const chunk of stream) {
      const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      if (length + bytes.byteLength > planned.signed.length) {
        stream.destroy();
        throw new UpdateError("GOAT_UPDATE_ARCHIVE_CONTENT_MISMATCH");
      }
      await writeAll(output, bytes, length);
      digest.update(bytes);
      length += bytes.byteLength;
    }
    if (
      length !== planned.signed.length ||
      digest.digest("hex") !== planned.signed.sha256
    ) {
      throw new UpdateError("GOAT_UPDATE_ARCHIVE_CONTENT_MISMATCH");
    }
    await output.sync();
    completed = true;
  } finally {
    await output.close();
  }
  if (!completed) return;
  await assertNoLinkOrReparsePath(transaction.stagingRoot, destination);
  const stats = await lstat(destination);
  if (
    !stats.isFile() ||
    stats.isSymbolicLink() ||
    stats.nlink !== 1 ||
    stats.size !== planned.signed.length ||
    (process.platform !== "win32" && (stats.mode & 0o111) !== 0)
  ) {
    throw new UpdateError("GOAT_UPDATE_ARCHIVE_ENTRY_UNSAFE");
  }
}

async function readEndOfCentralDirectory(
  artifact: HeldVerifiedArtifact,
): Promise<{
  readonly entryCount: number;
  readonly centralDirectoryOffset: number;
}> {
  if (artifact.length < EOCD_LENGTH) {
    throw new UpdateError("GOAT_UPDATE_ARCHIVE_INVALID");
  }
  const first = Buffer.alloc(4);
  await readExactly(artifact.handle, first, 0);
  if (first.readUInt32LE(0) !== LOCAL_FILE_SIGNATURE) {
    throw new UpdateError("GOAT_UPDATE_ARCHIVE_INVALID");
  }
  const eocd = Buffer.alloc(EOCD_LENGTH);
  await readExactly(artifact.handle, eocd, artifact.length - EOCD_LENGTH);
  const disk = eocd.readUInt16LE(4);
  const centralDisk = eocd.readUInt16LE(6);
  const diskEntries = eocd.readUInt16LE(8);
  const entryCount = eocd.readUInt16LE(10);
  const centralDirectorySize = eocd.readUInt32LE(12);
  const centralDirectoryOffset = eocd.readUInt32LE(16);
  const commentLength = eocd.readUInt16LE(20);
  if (
    eocd.readUInt32LE(0) !== EOCD_SIGNATURE ||
    disk !== 0 ||
    centralDisk !== 0 ||
    diskEntries !== entryCount ||
    entryCount === 0 ||
    entryCount === 0xffff ||
    centralDirectorySize === 0xffffffff ||
    centralDirectoryOffset === 0xffffffff ||
    commentLength !== 0 ||
    centralDirectoryOffset + centralDirectorySize !==
      artifact.length - EOCD_LENGTH
  ) {
    throw new UpdateError("GOAT_UPDATE_ARCHIVE_INVALID");
  }
  return { entryCount, centralDirectoryOffset };
}

function validateArchivePath(fileName: string): void {
  if (
    fileName.length === 0 ||
    fileName.length > 240 ||
    fileName.startsWith("/") ||
    fileName.endsWith("/") ||
    fileName.includes("\\") ||
    fileName.includes(":") ||
    fileName.includes("\0") ||
    !/^[\x20-\x7e]+$/.test(fileName)
  ) {
    throw new UpdateError("GOAT_UPDATE_ARCHIVE_PATH_UNSAFE");
  }
  const components = fileName.split("/");
  for (const component of components) {
    if (
      component.length === 0 ||
      component.length > 64 ||
      component === "." ||
      component === ".." ||
      component.endsWith(".") ||
      component.endsWith(" ") ||
      !/^[A-Za-z0-9._-]+$/.test(component) ||
      WINDOWS_DEVICE_NAME.test(component)
    ) {
      throw new UpdateError("GOAT_UPDATE_ARCHIVE_PATH_UNSAFE");
    }
  }
}

function decodeArchivePath(raw: Buffer): string {
  if (raw.length === 0 || raw.some((byte) => byte < 0x20 || byte > 0x7e)) {
    throw new UpdateError("GOAT_UPDATE_ARCHIVE_PATH_UNSAFE");
  }
  return raw.toString("ascii");
}

function destinationPath(root: string, archivePath: string): string {
  const destination = path.resolve(root, ...archivePath.split("/"));
  const relative = path.relative(path.resolve(root), destination);
  if (
    relative === "" ||
    relative === ".." ||
    relative.startsWith(`..${path.sep}`) ||
    path.isAbsolute(relative)
  ) {
    throw new UpdateError("GOAT_UPDATE_ARCHIVE_PATH_UNSAFE");
  }
  return destination;
}

function validateLimits(limits: ArchiveResourceLimits): void {
  if (
    !Number.isSafeInteger(limits.maxEntries) ||
    limits.maxEntries <= 0 ||
    limits.maxEntries > 32 ||
    !Number.isSafeInteger(limits.maxSingleExpandedBytes) ||
    limits.maxSingleExpandedBytes <= 0 ||
    !Number.isSafeInteger(limits.maxTotalExpandedBytes) ||
    limits.maxTotalExpandedBytes < limits.maxSingleExpandedBytes ||
    !Number.isFinite(limits.maxCompressionRatio) ||
    limits.maxCompressionRatio <= 0 ||
    limits.maxCompressionRatio > 100
  ) {
    throw new UpdateError("GOAT_UPDATE_ARCHIVE_LIMIT");
  }
}

function compressionRatio(uncompressed: number, compressed: number): number {
  if (uncompressed === 0) return 1;
  if (compressed === 0) return Number.POSITIVE_INFINITY;
  return uncompressed / compressed;
}

async function readExactly(
  handle: FileHandle,
  buffer: Buffer,
  position: number,
): Promise<void> {
  let offset = 0;
  while (offset < buffer.byteLength) {
    const { bytesRead } = await handle.read(
      buffer,
      offset,
      buffer.byteLength - offset,
      position + offset,
    );
    if (bytesRead <= 0) throw new UpdateError("GOAT_UPDATE_ARCHIVE_INVALID");
    offset += bytesRead;
  }
}

async function writeAll(
  handle: FileHandle,
  bytes: Buffer,
  position: number,
): Promise<void> {
  let offset = 0;
  while (offset < bytes.byteLength) {
    const { bytesWritten } = await handle.write(
      bytes,
      offset,
      bytes.byteLength - offset,
      position + offset,
    );
    if (bytesWritten <= 0) {
      throw new UpdateError("GOAT_UPDATE_ARCHIVE_CONTENT_MISMATCH");
    }
    offset += bytesWritten;
  }
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
    if (bytesRead <= 0) {
      throw new UpdateError("GOAT_UPDATE_ARCHIVE_CONTENT_MISMATCH");
    }
    digest.update(buffer.subarray(0, bytesRead));
    position += bytesRead;
  }
  return digest.digest("hex");
}

function asciiCompare(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
