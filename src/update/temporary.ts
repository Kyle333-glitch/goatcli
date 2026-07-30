import { randomBytes } from "node:crypto";
import path from "node:path";
import {
  chmod,
  lstat,
  mkdir,
  open,
  readdir,
  realpath,
  rm,
  type FileHandle,
} from "node:fs/promises";
import { UpdateError } from "./errors.js";

export interface UpdateTransactionPaths {
  readonly transactionId: string;
  readonly updatesRoot: string;
  readonly temporaryRoot: string;
  readonly transactionRoot: string;
  readonly stagingRoot: string;
}

export interface ExclusiveTemporaryFile {
  readonly path: string;
  readonly handle: FileHandle;
}

const TRANSACTION_ID_PATTERN = /^[a-f0-9]{32}$/;

export async function createUpdateTransactionPaths(
  appDataDirectory: string,
): Promise<UpdateTransactionPaths> {
  const appData = path.resolve(appDataDirectory);
  await mkdir(appData, { recursive: true, mode: 0o700 });
  await assertDirectory(appData);
  const updatesRoot = await ensurePrivateChildDirectory(appData, "updates");
  const temporaryRoot = await ensurePrivateChildDirectory(updatesRoot, "tmp");
  const transactionId = randomBytes(16).toString("hex");
  const transactionRoot = path.join(temporaryRoot, transactionId);
  try {
    await mkdir(transactionRoot, { mode: 0o700 });
    await assertDirectory(transactionRoot);
    const stagingRoot = path.join(transactionRoot, "staging");
    await mkdir(stagingRoot, { mode: 0o700 });
    await assertDirectory(stagingRoot);
    return {
      transactionId,
      updatesRoot,
      temporaryRoot,
      transactionRoot,
      stagingRoot,
    };
  } catch (error) {
    await safeRemoveTransaction(temporaryRoot, transactionRoot).catch(
      () => undefined,
    );
    throw new UpdateError("GOAT_UPDATE_TEMPORARY_FILE_UNSAFE", {
      cause: error,
    });
  }
}

export async function createExclusiveTemporaryFile(
  transaction: UpdateTransactionPaths,
): Promise<ExclusiveTemporaryFile> {
  await assertTransactionRoot(transaction);
  const localName = `${randomBytes(16).toString("hex")}.partial`;
  const filePath = path.join(transaction.transactionRoot, localName);
  try {
    const handle = await open(filePath, "wx+", 0o600);
    if (process.platform !== "win32") await chmod(filePath, 0o600);
    const stats = await handle.stat();
    if (!stats.isFile() || stats.nlink !== 1 || stats.size !== 0) {
      await handle.close();
      await rm(filePath, { force: true });
      throw new UpdateError("GOAT_UPDATE_TEMPORARY_FILE_UNSAFE");
    }
    return { path: filePath, handle };
  } catch (error) {
    if (error instanceof UpdateError) throw error;
    throw new UpdateError("GOAT_UPDATE_TEMPORARY_FILE_UNSAFE", {
      cause: error,
    });
  }
}

export async function closeAndRemoveTemporaryFile(
  transaction: UpdateTransactionPaths,
  file: ExclusiveTemporaryFile,
): Promise<void> {
  await file.handle.close().catch(() => undefined);
  const root = path.resolve(transaction.transactionRoot);
  const target = path.resolve(file.path);
  if (
    path.dirname(target) !== root ||
    !/^[a-f0-9]{32}\.partial$/.test(path.basename(target))
  ) {
    throw new UpdateError("GOAT_UPDATE_TEMPORARY_FILE_UNSAFE");
  }
  await rm(target, { force: true });
}

export async function assertEmptyStagingDirectory(
  transaction: UpdateTransactionPaths,
): Promise<void> {
  await assertTransactionRoot(transaction);
  await assertDirectory(transaction.stagingRoot);
  const entries = await readdir(transaction.stagingRoot);
  if (entries.length !== 0) {
    throw new UpdateError("GOAT_UPDATE_TEMPORARY_FILE_UNSAFE");
  }
}

export async function resetStagingDirectory(
  transaction: UpdateTransactionPaths,
): Promise<void> {
  await assertTransactionRoot(transaction);
  const expected = path.join(transaction.transactionRoot, "staging");
  if (path.resolve(transaction.stagingRoot) !== path.resolve(expected)) {
    throw new UpdateError("GOAT_UPDATE_TEMPORARY_FILE_UNSAFE");
  }
  await rm(transaction.stagingRoot, { recursive: true, force: true });
  await mkdir(transaction.stagingRoot, { mode: 0o700 });
  await assertDirectory(transaction.stagingRoot);
  if (process.platform !== "win32") await chmod(transaction.stagingRoot, 0o700);
}

export async function cleanupUpdateTransaction(
  transaction: UpdateTransactionPaths,
): Promise<void> {
  await safeRemoveTransaction(
    transaction.temporaryRoot,
    transaction.transactionRoot,
  );
}

export async function assertNoLinkOrReparsePath(
  boundary: string,
  target: string,
): Promise<void> {
  const resolvedBoundary = path.resolve(boundary);
  const resolvedTarget = path.resolve(target);
  if (!isInside(resolvedBoundary, resolvedTarget)) {
    throw new UpdateError("GOAT_UPDATE_TEMPORARY_FILE_UNSAFE");
  }
  const relative = path.relative(resolvedBoundary, resolvedTarget);
  let current = resolvedBoundary;
  await assertDirectory(current);
  for (const component of relative.split(path.sep).filter(Boolean)) {
    current = path.join(current, component);
    let stats;
    try {
      stats = await lstat(current);
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === "ENOENT") return;
      throw new UpdateError("GOAT_UPDATE_TEMPORARY_FILE_UNSAFE", {
        cause: error,
      });
    }
    if (stats.isSymbolicLink()) {
      throw new UpdateError("GOAT_UPDATE_TEMPORARY_FILE_UNSAFE");
    }
    if (current !== resolvedTarget && !stats.isDirectory()) {
      throw new UpdateError("GOAT_UPDATE_TEMPORARY_FILE_UNSAFE");
    }
  }
}

async function ensurePrivateChildDirectory(
  parent: string,
  name: string,
): Promise<string> {
  if (!/^[a-z]+$/.test(name)) {
    throw new UpdateError("GOAT_UPDATE_TEMPORARY_FILE_UNSAFE");
  }
  await assertDirectory(parent);
  const child = path.join(parent, name);
  try {
    await mkdir(child, { mode: 0o700 });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") {
      throw error;
    }
  }
  await assertDirectory(child);
  if (process.platform !== "win32") await chmod(child, 0o700);
  return child;
}

async function assertTransactionRoot(
  transaction: UpdateTransactionPaths,
): Promise<void> {
  if (!TRANSACTION_ID_PATTERN.test(transaction.transactionId)) {
    throw new UpdateError("GOAT_UPDATE_TEMPORARY_FILE_UNSAFE");
  }
  const expected = path.join(
    path.resolve(transaction.temporaryRoot),
    transaction.transactionId,
  );
  if (path.resolve(transaction.transactionRoot) !== expected) {
    throw new UpdateError("GOAT_UPDATE_TEMPORARY_FILE_UNSAFE");
  }
  await assertNoLinkOrReparsePath(
    transaction.temporaryRoot,
    transaction.transactionRoot,
  );
}

async function assertDirectory(directory: string): Promise<void> {
  try {
    const stats = await lstat(directory);
    if (!stats.isDirectory() || stats.isSymbolicLink()) {
      throw new UpdateError("GOAT_UPDATE_TEMPORARY_FILE_UNSAFE");
    }
    const canonical = await realpath(directory);
    if (path.resolve(canonical) !== path.resolve(directory)) {
      throw new UpdateError("GOAT_UPDATE_TEMPORARY_FILE_UNSAFE");
    }
  } catch (error) {
    if (error instanceof UpdateError) throw error;
    throw new UpdateError("GOAT_UPDATE_TEMPORARY_FILE_UNSAFE", {
      cause: error,
    });
  }
}

async function safeRemoveTransaction(
  temporaryRoot: string,
  transactionRoot: string,
): Promise<void> {
  const root = path.resolve(temporaryRoot);
  const target = path.resolve(transactionRoot);
  if (
    !isInside(root, target) ||
    path.dirname(target) !== root ||
    !TRANSACTION_ID_PATTERN.test(path.basename(target))
  ) {
    throw new UpdateError("GOAT_UPDATE_TEMPORARY_FILE_UNSAFE");
  }
  await rm(target, { recursive: true, force: true, maxRetries: 2 });
}

function isInside(boundary: string, target: string): boolean {
  const relative = path.relative(boundary, target);
  return (
    relative !== "" &&
    relative !== ".." &&
    !relative.startsWith(`..${path.sep}`) &&
    !path.isAbsolute(relative)
  );
}
