import { randomBytes } from "node:crypto";
import { constants, type BigIntStats, type Stats } from "node:fs";
import path from "node:path";
import {
  chmod,
  lstat,
  open,
  realpath,
  type FileHandle,
} from "node:fs/promises";
import { DatabaseSync } from "node:sqlite";
import {
  assertPrivateDirectory,
  ensurePrivateDirectory,
  syncDirectory,
} from "./durable.js";
import { UpdateError } from "./errors.js";

export interface UpdateLockOwner {
  readonly schema: 1;
  readonly token: string;
  readonly pid: number;
  readonly startedAtUnixMs: number;
}

export interface UpdateLock {
  readonly owner: UpdateLockOwner;
  readonly path: string;
  release(): Promise<void>;
}

export interface AcquireUpdateLockOptions {
  readonly pid?: number;
  readonly now?: () => number;
  readonly isProcessAlive?: (pid: number) => boolean | Promise<boolean>;
  /** Runs for every owner, after durable exclusive ownership is established. */
  readonly recoverStaleTransaction: () => Promise<void>;
  /** Test-only scheduling hook; production callers must leave this undefined. */
  readonly beforeOwnershipClaim?: (owner: UpdateLockOwner) => Promise<void>;
}

interface LockAuthority {
  readonly token: string;
  readonly owner: UpdateLockOwner | null;
}

interface OpenLockDatabase {
  readonly database: DatabaseSync;
  readonly fileHandle: FileHandle;
  readonly fileIdentity: FileIdentity;
  readonly lockPath: string;
  readonly updatesRoot: string;
}

interface FileIdentity {
  readonly device: string;
  readonly inode: string;
}

interface LockRow {
  readonly singleton: bigint;
  readonly schema: bigint;
  readonly authority_token: string;
  readonly owner_token: string | null;
  readonly pid: bigint | null;
  readonly started_at_unix_ms: bigint | null;
}

interface SchemaRow {
  readonly type: string;
  readonly name: string;
  readonly tbl_name: string;
  readonly sql: string | null;
}

const LOCK_FILE_NAME = "update.lock";
const TOKEN_PATTERN = /^[a-f0-9]{32}$/;
const MAX_ACQUIRE_ATTEMPTS = 32;
const MAX_LOCK_DATABASE_BYTES = 1024 * 1024;
const SQLITE_APPLICATION_ID = 0x474f4154;
const SQLITE_SCHEMA_VERSION = 1;
const OPEN_READ_WRITE_NOFOLLOW =
  constants.O_RDWR |
  (typeof constants.O_NOFOLLOW === "number" ? constants.O_NOFOLLOW : 0);
const LOCK_SCHEMA_SQL = `CREATE TABLE update_lock (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  schema INTEGER NOT NULL CHECK (schema = 1),
  authority_token TEXT NOT NULL CHECK (
    length(authority_token) = 32 AND
    authority_token NOT GLOB '*[^a-f0-9]*'
  ),
  owner_token TEXT,
  pid INTEGER,
  started_at_unix_ms INTEGER,
  CHECK (
    (owner_token IS NULL AND pid IS NULL AND started_at_unix_ms IS NULL) OR
    (
      owner_token = authority_token AND
      length(owner_token) = 32 AND
      owner_token NOT GLOB '*[^a-f0-9]*' AND
      typeof(pid) = 'integer' AND pid > 0 AND pid <= 2147483647 AND
      typeof(started_at_unix_ms) = 'integer' AND
      started_at_unix_ms >= 0 AND
      started_at_unix_ms <= 9007199254740991
    )
  )
) STRICT`;

export async function acquireUpdateLock(
  appDataDirectory: string,
  options: AcquireUpdateLockOptions,
): Promise<UpdateLock> {
  const pid = options.pid ?? process.pid;
  const now = options.now ?? Date.now;
  if (
    !Number.isSafeInteger(pid) ||
    pid <= 0 ||
    pid > 0x7fffffff ||
    typeof options.recoverStaleTransaction !== "function"
  ) {
    throw lockInvalid();
  }
  const owner: UpdateLockOwner = {
    schema: 1,
    token: randomToken(),
    pid,
    startedAtUnixMs: checkedNow(now()),
  };
  const updatesRoot = await ensurePrivateDirectory(
    path.join(path.resolve(appDataDirectory), "updates"),
    "GOAT_UPDATE_LOCK_INVALID",
  );
  const lockPath = path.join(updatesRoot, LOCK_FILE_NAME);
  await ensureLockDatabaseFile(updatesRoot, lockPath);

  let schedulingHookInvoked = false;
  for (let attempt = 0; attempt < MAX_ACQUIRE_ATTEMPTS; attempt += 1) {
    let opened: OpenLockDatabase | undefined;
    let transactionOpen = false;
    let ownershipTransferred = false;
    try {
      opened = await openLockDatabase(updatesRoot, lockPath, false);
      beginImmediate(opened.database);
      transactionOpen = true;
      initializeOrValidateSchema(opened.database);
      const observed = readAuthority(opened.database);

      if (observed.owner) {
        const isAlive = await checkedIsProcessAlive(
          options.isProcessAlive ?? defaultIsProcessAlive,
          observed.owner.pid,
        );
        if (isAlive) throw new UpdateError("GOAT_UPDATE_BUSY");
        if (options.beforeOwnershipClaim && !schedulingHookInvoked) {
          rollback(opened.database);
          transactionOpen = false;
          await closeLockDatabase(opened);
          opened = undefined;
          schedulingHookInvoked = true;
          await options.beforeOwnershipClaim(observed.owner);
          continue;
        }
      }

      claimAuthority(opened.database, observed, owner);
      commit(opened.database);
      transactionOpen = false;

      // There is deliberately no await between the durable claim and acquiring
      // the long-lived SQLite writer transaction. A contender that wins this
      // narrow scheduling window still cannot cause duplicate recovery because
      // the committed owner is revalidated before the callback.
      beginImmediate(opened.database);
      transactionOpen = true;
      const committed = readAuthority(opened.database);
      if (!committed.owner || !sameOwner(committed.owner, owner)) {
        throw lockInvalid();
      }
      await assertDatabasePathBound(opened, false);
      await opened.fileHandle.sync();
      await syncDirectory(updatesRoot, "GOAT_UPDATE_LOCK_INVALID");

      const held = createHeldLock(opened, owner);
      ownershipTransferred = true;
      transactionOpen = false;
      return await enterOwnedRecovery(held, options.recoverStaleTransaction);
    } catch (error) {
      if (ownershipTransferred) throw error;
      if (transactionOpen && opened) rollbackNoThrow(opened.database);
      if (opened) await closeLockDatabaseIgnoringPrimary(opened, error);
      if (error instanceof UpdateError) throw error;
      if (isSqliteBusy(error)) throw new UpdateError("GOAT_UPDATE_BUSY");
      throw lockInvalid(error);
    }
  }
  throw lockInvalid();
}

export async function inspectUpdateLock(
  appDataDirectory: string,
): Promise<UpdateLockOwner | null> {
  const updatesRoot = path.join(path.resolve(appDataDirectory), "updates");
  try {
    await lstat(updatesRoot);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw lockInvalid(error);
  }
  await assertPrivateDirectory(updatesRoot, "GOAT_UPDATE_LOCK_INVALID");
  const lockPath = path.join(updatesRoot, LOCK_FILE_NAME);
  let stats;
  try {
    stats = await lstat(lockPath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw lockInvalid(error);
  }
  assertSafeDatabaseStats(stats, true);
  if (stats.size === 0) return null;

  let opened: OpenLockDatabase | undefined;
  try {
    opened = await openLockDatabase(updatesRoot, lockPath, true);
    validateInitializedSchema(opened.database);
    return readAuthority(opened.database).owner;
  } catch (error) {
    if (error instanceof UpdateError) throw error;
    throw lockInvalid(error);
  } finally {
    if (opened) await closeLockDatabase(opened);
  }
}

async function enterOwnedRecovery(
  held: UpdateLock,
  recoverStaleTransaction: () => Promise<void>,
): Promise<UpdateLock> {
  try {
    await recoverStaleTransaction();
    return held;
  } catch (recoveryError) {
    try {
      await held.release();
    } catch (releaseError) {
      throw lockInvalid(new AggregateError([recoveryError, releaseError]));
    }
    throw recoveryError;
  }
}

function createHeldLock(
  opened: OpenLockDatabase,
  owner: UpdateLockOwner,
): UpdateLock {
  let released = false;
  return {
    owner,
    path: opened.lockPath,
    async release(): Promise<void> {
      if (released) return;
      let committed = false;
      let primaryFailure: unknown;
      try {
        const authority = readAuthority(opened.database);
        if (!authority.owner || !sameOwner(authority.owner, owner)) {
          throw lockInvalid();
        }
        const nextToken = randomToken();
        const result = opened.database
          .prepare(
            `UPDATE update_lock
             SET authority_token = ?, owner_token = NULL, pid = NULL,
                 started_at_unix_ms = NULL
             WHERE singleton = 1 AND schema = 1
               AND authority_token = ? AND owner_token = ?
               AND pid = ? AND started_at_unix_ms = ?`,
          )
          .run(
            nextToken,
            owner.token,
            owner.token,
            BigInt(owner.pid),
            BigInt(owner.startedAtUnixMs),
          );
        if (Number(result.changes) !== 1) throw lockInvalid();
        commit(opened.database);
        committed = true;
        released = true;
        await opened.fileHandle.sync();
        await syncDirectory(opened.updatesRoot, "GOAT_UPDATE_LOCK_INVALID");
        await assertDatabasePathBound(opened, false);
      } catch (error) {
        primaryFailure = error;
        if (!committed) rollbackNoThrow(opened.database);
      }
      try {
        await closeLockDatabase(opened);
      } catch (closeError) {
        primaryFailure = primaryFailure
          ? new AggregateError([primaryFailure, closeError])
          : closeError;
      }
      if (primaryFailure) {
        if (primaryFailure instanceof UpdateError) throw primaryFailure;
        throw lockInvalid(primaryFailure);
      }
    },
  };
}

async function ensureLockDatabaseFile(
  updatesRoot: string,
  lockPath: string,
): Promise<void> {
  let handle: FileHandle | undefined;
  try {
    handle = await open(lockPath, "wx+", 0o600);
    if (process.platform !== "win32") await chmod(lockPath, 0o600);
    await handle.sync();
    await handle.close();
    handle = undefined;
    await syncDirectory(updatesRoot, "GOAT_UPDATE_LOCK_INVALID");
  } catch (error) {
    await handle?.close().catch(() => undefined);
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") {
      if (error instanceof UpdateError) throw error;
      throw lockInvalid(error);
    }
  }
  const stats = await lstat(lockPath).catch((error) => {
    throw lockInvalid(error);
  });
  assertSafeDatabaseStats(stats, true);
  const canonical = await realpath(lockPath).catch((error) => {
    throw lockInvalid(error);
  });
  if (!samePath(canonical, lockPath)) throw lockInvalid();
}

async function openLockDatabase(
  updatesRoot: string,
  lockPath: string,
  readOnly: boolean,
): Promise<OpenLockDatabase> {
  const before = await lstat(lockPath, { bigint: true }).catch((error) => {
    throw lockInvalid(error);
  });
  assertSafeBigIntDatabaseStats(before, true);
  let fileHandle: FileHandle | undefined;
  let database: DatabaseSync | undefined;
  try {
    fileHandle = await open(lockPath, OPEN_READ_WRITE_NOFOLLOW);
    const openedStats = await fileHandle.stat({ bigint: true });
    assertSafeBigIntDatabaseStats(openedStats, true);
    if (!sameIdentity(identity(before), identity(openedStats)))
      throw lockInvalid();
    database = new DatabaseSync(lockPath, {
      readOnly,
      allowExtension: false,
      enableDoubleQuotedStringLiterals: false,
      enableForeignKeyConstraints: true,
      timeout: 0,
      readBigInts: true,
      allowBareNamedParameters: false,
      allowUnknownNamedParameters: false,
      defensive: true,
    });
    configureConnection(database, readOnly);
    const result: OpenLockDatabase = {
      database,
      fileHandle,
      fileIdentity: identity(openedStats),
      lockPath,
      updatesRoot,
    };
    await assertDatabasePathBound(result, true);
    return result;
  } catch (error) {
    try {
      database?.close();
    } catch {
      // The primary validation error is more useful and remains fail-closed.
    }
    await fileHandle?.close().catch(() => undefined);
    if (error instanceof UpdateError) throw error;
    if (isSqliteBusy(error)) throw new UpdateError("GOAT_UPDATE_BUSY");
    throw lockInvalid(error);
  }
}

function configureConnection(database: DatabaseSync, readOnly: boolean): void {
  database.enableDefensive(true);
  database.exec("PRAGMA trusted_schema = OFF");
  database.exec("PRAGMA foreign_keys = ON");
  database.exec("PRAGMA temp_store = MEMORY");
  if (!readOnly) {
    database.exec("PRAGMA synchronous = FULL");
    database.exec("PRAGMA fullfsync = ON");
  }
  const journal = database.prepare("PRAGMA journal_mode").get() as
    { readonly journal_mode?: unknown } | undefined;
  if (journal?.journal_mode !== "delete") throw lockInvalid();
}

function initializeOrValidateSchema(database: DatabaseSync): void {
  const schema = loadSchema(database);
  if (schema.length === 0) {
    if (
      pragmaInteger(database, "application_id") !== 0 ||
      pragmaInteger(database, "user_version") !== 0
    ) {
      throw lockInvalid();
    }
    database.exec(`${LOCK_SCHEMA_SQL};`);
    database.exec(`PRAGMA application_id = ${SQLITE_APPLICATION_ID}`);
    database.exec(`PRAGMA user_version = ${SQLITE_SCHEMA_VERSION}`);
    database
      .prepare(
        `INSERT INTO update_lock
         (singleton, schema, authority_token, owner_token, pid, started_at_unix_ms)
         VALUES (1, 1, ?, NULL, NULL, NULL)`,
      )
      .run(randomToken());
  }
  validateInitializedSchema(database);
}

function validateInitializedSchema(database: DatabaseSync): void {
  const schema = loadSchema(database);
  if (
    schema.length !== 1 ||
    schema[0]!.type !== "table" ||
    schema[0]!.name !== "update_lock" ||
    schema[0]!.tbl_name !== "update_lock" ||
    schema[0]!.sql !== LOCK_SCHEMA_SQL ||
    pragmaInteger(database, "application_id") !== SQLITE_APPLICATION_ID ||
    pragmaInteger(database, "user_version") !== SQLITE_SCHEMA_VERSION
  ) {
    throw lockInvalid();
  }
  const quickCheck = database.prepare("PRAGMA quick_check(1)").get() as
    { readonly quick_check?: unknown } | undefined;
  if (quickCheck?.quick_check !== "ok") throw lockInvalid();
  readAuthority(database);
}

function loadSchema(database: DatabaseSync): readonly SchemaRow[] {
  return database
    .prepare(
      `SELECT type, name, tbl_name, sql
       FROM sqlite_schema
       WHERE name NOT LIKE 'sqlite_%'
       ORDER BY type, name`,
    )
    .all() as unknown as readonly SchemaRow[];
}

function pragmaInteger(database: DatabaseSync, name: string): number {
  if (name !== "application_id" && name !== "user_version") throw lockInvalid();
  const row = database.prepare(`PRAGMA ${name}`).get() as
    Record<string, unknown> | undefined;
  const value = row?.[name];
  if (typeof value !== "bigint" || value < 0n || value > 0x7fffffffn) {
    throw lockInvalid();
  }
  return Number(value);
}

function readAuthority(database: DatabaseSync): LockAuthority {
  const rows = database
    .prepare(
      `SELECT singleton, schema, authority_token, owner_token, pid,
              started_at_unix_ms
       FROM update_lock`,
    )
    .all() as unknown as readonly LockRow[];
  if (rows.length !== 1) throw lockInvalid();
  const row = rows[0]!;
  if (
    row.singleton !== 1n ||
    row.schema !== 1n ||
    !TOKEN_PATTERN.test(row.authority_token)
  ) {
    throw lockInvalid();
  }
  if (row.owner_token === null) {
    if (row.pid !== null || row.started_at_unix_ms !== null)
      throw lockInvalid();
    return { token: row.authority_token, owner: null };
  }
  if (
    row.owner_token !== row.authority_token ||
    !TOKEN_PATTERN.test(row.owner_token) ||
    row.pid === null ||
    row.pid <= 0n ||
    row.pid > 0x7fffffffn ||
    row.started_at_unix_ms === null ||
    row.started_at_unix_ms < 0n ||
    row.started_at_unix_ms > BigInt(Number.MAX_SAFE_INTEGER)
  ) {
    throw lockInvalid();
  }
  return {
    token: row.authority_token,
    owner: {
      schema: 1,
      token: row.owner_token,
      pid: Number(row.pid),
      startedAtUnixMs: Number(row.started_at_unix_ms),
    },
  };
}

function claimAuthority(
  database: DatabaseSync,
  observed: LockAuthority,
  owner: UpdateLockOwner,
): void {
  const statement = observed.owner
    ? database.prepare(
        `UPDATE update_lock
         SET authority_token = ?, owner_token = ?, pid = ?,
             started_at_unix_ms = ?
         WHERE singleton = 1 AND schema = 1
           AND authority_token = ? AND owner_token = ?
           AND pid = ? AND started_at_unix_ms = ?`,
      )
    : database.prepare(
        `UPDATE update_lock
         SET authority_token = ?, owner_token = ?, pid = ?,
             started_at_unix_ms = ?
         WHERE singleton = 1 AND schema = 1
           AND authority_token = ? AND owner_token IS NULL
           AND pid IS NULL AND started_at_unix_ms IS NULL`,
      );
  const values = [
    owner.token,
    owner.token,
    BigInt(owner.pid),
    BigInt(owner.startedAtUnixMs),
    observed.token,
  ] as const;
  const result = observed.owner
    ? statement.run(
        ...values,
        observed.owner.token,
        BigInt(observed.owner.pid),
        BigInt(observed.owner.startedAtUnixMs),
      )
    : statement.run(...values);
  if (Number(result.changes) !== 1) throw lockInvalid();
  const claimed = readAuthority(database);
  if (!claimed.owner || !sameOwner(claimed.owner, owner)) throw lockInvalid();
}

function beginImmediate(database: DatabaseSync): void {
  database.exec("BEGIN IMMEDIATE");
}

function commit(database: DatabaseSync): void {
  database.exec("COMMIT");
}

function rollback(database: DatabaseSync): void {
  database.exec("ROLLBACK");
}

function rollbackNoThrow(database: DatabaseSync): void {
  try {
    rollback(database);
  } catch {
    // The connection is closed immediately afterward; SQLite rolls back there too.
  }
}

async function assertDatabasePathBound(
  opened: OpenLockDatabase,
  allowEmpty: boolean,
): Promise<void> {
  const [pathStats, handleStats, canonical] = await Promise.all([
    lstat(opened.lockPath, { bigint: true }),
    opened.fileHandle.stat({ bigint: true }),
    realpath(opened.lockPath),
  ]).catch((error) => {
    throw lockInvalid(error);
  });
  assertSafeBigIntDatabaseStats(pathStats, allowEmpty);
  assertSafeBigIntDatabaseStats(handleStats, allowEmpty);
  if (
    !sameIdentity(opened.fileIdentity, identity(pathStats)) ||
    !sameIdentity(opened.fileIdentity, identity(handleStats)) ||
    !samePath(canonical, opened.lockPath)
  ) {
    throw lockInvalid();
  }
}

function assertSafeDatabaseStats(stats: Stats, allowEmpty: boolean): void {
  if (
    !stats.isFile() ||
    stats.isSymbolicLink() ||
    stats.nlink !== 1 ||
    (!allowEmpty && stats.size === 0) ||
    stats.size < 0 ||
    stats.size > MAX_LOCK_DATABASE_BYTES ||
    (process.platform !== "win32" && (stats.mode & 0o077) !== 0)
  ) {
    throw lockInvalid();
  }
}

function assertSafeBigIntDatabaseStats(
  stats: BigIntStats,
  allowEmpty: boolean,
): void {
  if (
    !stats.isFile() ||
    stats.isSymbolicLink() ||
    stats.nlink !== 1n ||
    (!allowEmpty && stats.size === 0n) ||
    stats.size < 0n ||
    stats.size > BigInt(MAX_LOCK_DATABASE_BYTES) ||
    (process.platform !== "win32" && (stats.mode & 0o077n) !== 0n)
  ) {
    throw lockInvalid();
  }
}

async function closeLockDatabase(opened: OpenLockDatabase): Promise<void> {
  const failures: unknown[] = [];
  try {
    opened.database.close();
  } catch (error) {
    failures.push(error);
  }
  try {
    await opened.fileHandle.close();
  } catch (error) {
    failures.push(error);
  }
  if (failures.length > 0) throw lockInvalid(new AggregateError(failures));
}

async function closeLockDatabaseIgnoringPrimary(
  opened: OpenLockDatabase,
  primary: unknown,
): Promise<void> {
  try {
    await closeLockDatabase(opened);
  } catch (closeError) {
    throw lockInvalid(new AggregateError([primary, closeError]));
  }
}

async function checkedIsProcessAlive(
  check: (pid: number) => boolean | Promise<boolean>,
  pid: number,
): Promise<boolean> {
  try {
    const result = await check(pid);
    if (typeof result !== "boolean") throw lockInvalid();
    return result;
  } catch (error) {
    if (error instanceof UpdateError) throw error;
    throw lockInvalid(error);
  }
}

function defaultIsProcessAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ESRCH") return false;
    if (code === "EPERM") return true;
    throw lockInvalid(error);
  }
}

function sameOwner(left: UpdateLockOwner, right: UpdateLockOwner): boolean {
  return (
    left.schema === right.schema &&
    left.token === right.token &&
    left.pid === right.pid &&
    left.startedAtUnixMs === right.startedAtUnixMs
  );
}

function identity(stats: {
  readonly dev: bigint;
  readonly ino: bigint;
}): FileIdentity {
  if (stats.dev <= 0n || stats.ino <= 0n) throw lockInvalid();
  return { device: stats.dev.toString(10), inode: stats.ino.toString(10) };
}

function sameIdentity(left: FileIdentity, right: FileIdentity): boolean {
  return left.device === right.device && left.inode === right.inode;
}

function samePath(left: string, right: string): boolean {
  const normalizedLeft = path.resolve(left);
  const normalizedRight = path.resolve(right);
  return process.platform === "win32"
    ? normalizedLeft.toLowerCase() === normalizedRight.toLowerCase()
    : normalizedLeft === normalizedRight;
}

function checkedNow(value: number): number {
  if (!Number.isSafeInteger(value) || value < 0) throw lockInvalid();
  return value;
}

function randomToken(): string {
  return randomBytes(16).toString("hex");
}

function isSqliteBusy(error: unknown): boolean {
  if (typeof error !== "object" || error === null) return false;
  const candidate = error as {
    readonly errcode?: unknown;
    readonly code?: unknown;
  };
  return (
    candidate.code === "ERR_SQLITE_ERROR" &&
    (candidate.errcode === 5 || candidate.errcode === 6)
  );
}

function lockInvalid(cause?: unknown): UpdateError {
  return new UpdateError("GOAT_UPDATE_LOCK_INVALID", { cause });
}
