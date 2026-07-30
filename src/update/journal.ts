import { createHash } from "node:crypto";
import path from "node:path";
import { readdir } from "node:fs/promises";
import {
  canonicalJsonBytes,
  hasExactJsonKeys,
  isJsonObject,
  parseCanonicalJson,
  type JsonObject,
  type JsonValue,
} from "./canonical-json.js";
import {
  ensurePrivateDirectory,
  readImmutableFile,
  writeImmutableFile,
} from "./durable.js";
import { UpdateError } from "./errors.js";

export const UPDATE_PHASES = [
  "check",
  "fetch-manifest",
  "authenticate-manifest",
  "select-artifact",
  "download-artifact",
  "verify-artifact",
  "stage-archive",
  "check-compatibility",
  "prepare-rollback",
  "prepare-activation",
  "place-provisional-slot",
  "validate-provisional-slot",
  "commit-activation",
  "cleanup",
  "recover",
] as const;

export type UpdatePhase = (typeof UPDATE_PHASES)[number];

export interface JournalData {
  readonly releaseSequence: number | null;
  readonly receiptSha256: string | null;
  readonly slotName: string | null;
  readonly slotSealSha256: string | null;
  readonly activationGeneration: number | null;
}

export interface JournalRecord {
  readonly schema: 1;
  readonly transactionId: string;
  readonly transition: number;
  readonly phase: UpdatePhase;
  readonly recordedAtUnixMs: number;
  readonly previousSha256: string | null;
  readonly data: JournalData;
}

export interface LoadedJournalRecord {
  readonly record: JournalRecord;
  readonly sha256: string;
  readonly path: string;
}

export interface TransactionJournal {
  readonly transactionId: string;
  readonly root: string;
  readonly records: readonly LoadedJournalRecord[];
  readonly orphanTemporaryFiles: readonly string[];
}

const TRANSACTION_ID_PATTERN = /^[a-f0-9]{32}$/;
const RECORD_PATTERN = /^(\d{2})-([a-f0-9]{64})\.json$/;
const TEMPORARY_PATTERN = /^\.tmp-[a-f0-9]{32}$/;
const MAX_RECORD_BYTES = 16 * 1024;

export async function createTransactionJournal(
  appDataDirectory: string,
  transactionId: string,
): Promise<TransactionJournal> {
  assertTransactionId(transactionId);
  const root = journalRoot(appDataDirectory, transactionId);
  await ensurePrivateDirectory(root, "GOAT_UPDATE_RECOVERY_REQUIRED");
  const loaded = await loadTransactionJournal(appDataDirectory, transactionId);
  if (loaded.records.length !== 0) {
    throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
  }
  return loaded;
}

export async function appendJournalTransition(
  journal: TransactionJournal,
  phase: UpdatePhase,
  data: JournalData,
  recordedAtUnixMs = Date.now(),
): Promise<TransactionJournal> {
  const actual = await loadTransactionJournal(
    path.resolve(journal.root, "..", "..", ".."),
    journal.transactionId,
  );
  const expectedDigest = journal.records.at(-1)?.sha256;
  if (actual.records.at(-1)?.sha256 !== expectedDigest) {
    throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
  }
  const transition = actual.records.length + 1;
  if (
    transition > UPDATE_PHASES.length ||
    actual.records.at(-1)?.record.phase === "recover" ||
    (phase === "recover"
      ? actual.records.length === 0
      : UPDATE_PHASES[transition - 1] !== phase)
  ) {
    throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
  }
  const record: JournalRecord = {
    schema: 1,
    transactionId: journal.transactionId,
    transition,
    phase,
    recordedAtUnixMs,
    previousSha256: actual.records.at(-1)?.sha256 ?? null,
    data,
  };
  validateJournalRecord(record, actual.records.at(-1)?.record);
  const bytes = canonicalJsonBytes(record as unknown as JsonValue);
  const digest = sha256(bytes);
  const recordPath = await writeImmutableFile(
    actual.root,
    `${String(transition).padStart(2, "0")}-${digest}.json`,
    bytes,
    "GOAT_UPDATE_RECOVERY_REQUIRED",
  );
  return {
    transactionId: actual.transactionId,
    root: actual.root,
    records: [...actual.records, { record, sha256: digest, path: recordPath }],
    orphanTemporaryFiles: actual.orphanTemporaryFiles,
  };
}

export async function loadTransactionJournal(
  appDataDirectory: string,
  transactionId: string,
): Promise<TransactionJournal> {
  assertTransactionId(transactionId);
  const root = journalRoot(appDataDirectory, transactionId);
  let entries;
  try {
    entries = await readdir(root, { withFileTypes: true });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return {
        transactionId,
        root,
        records: [],
        orphanTemporaryFiles: [],
      };
    }
    throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED", { cause: error });
  }
  const finals: { name: string; transition: number; digest: string }[] = [];
  const temporary: string[] = [];
  for (const entry of entries) {
    if (entry.isFile() && TEMPORARY_PATTERN.test(entry.name)) {
      temporary.push(path.join(root, entry.name));
      continue;
    }
    const match = RECORD_PATTERN.exec(entry.name);
    if (!entry.isFile() || !match) {
      throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
    }
    finals.push({
      name: entry.name,
      transition: Number(match[1]),
      digest: match[2]!,
    });
  }
  finals.sort((left, right) => left.transition - right.transition);
  const records: LoadedJournalRecord[] = [];
  for (let index = 0; index < finals.length; index += 1) {
    const entry = finals[index]!;
    if (entry.transition !== index + 1) {
      throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
    }
    const recordPath = path.join(root, entry.name);
    const bytes = await readImmutableFile(
      recordPath,
      MAX_RECORD_BYTES,
      "GOAT_UPDATE_RECOVERY_REQUIRED",
    );
    const digest = sha256(bytes);
    if (digest !== entry.digest) {
      throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
    }
    const record = parseJournalRecord(bytes);
    const previous = records.at(-1);
    if (
      record.transactionId !== transactionId ||
      record.transition !== entry.transition ||
      record.previousSha256 !== (previous?.sha256 ?? null)
    ) {
      throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
    }
    validateJournalRecord(record, previous?.record);
    records.push({ record, sha256: digest, path: recordPath });
  }
  return {
    transactionId,
    root,
    records,
    orphanTemporaryFiles: temporary.sort(asciiCompare),
  };
}

export async function listTransactionJournals(
  appDataDirectory: string,
): Promise<readonly TransactionJournal[]> {
  const transactionsRoot = path.join(
    path.resolve(appDataDirectory),
    "updates",
    "transactions",
  );
  let entries;
  try {
    entries = await readdir(transactionsRoot, { withFileTypes: true });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED", { cause: error });
  }
  const ids: string[] = [];
  for (const entry of entries) {
    if (
      !entry.isDirectory() ||
      entry.isSymbolicLink() ||
      !TRANSACTION_ID_PATTERN.test(entry.name)
    ) {
      throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
    }
    ids.push(entry.name);
  }
  ids.sort(asciiCompare);
  const journals: TransactionJournal[] = [];
  for (const id of ids) {
    journals.push(await loadTransactionJournal(appDataDirectory, id));
  }
  return journals;
}

export function emptyJournalData(): JournalData {
  return {
    releaseSequence: null,
    receiptSha256: null,
    slotName: null,
    slotSealSha256: null,
    activationGeneration: null,
  };
}

function parseJournalRecord(bytes: Uint8Array): JournalRecord {
  const value = parseCanonicalJson(bytes, {
    maxBytes: MAX_RECORD_BYTES,
    errorCode: "GOAT_UPDATE_RECOVERY_REQUIRED",
  });
  if (
    !isJsonObject(value) ||
    !hasExactJsonKeys(value, [
      "data",
      "phase",
      "previousSha256",
      "recordedAtUnixMs",
      "schema",
      "transactionId",
      "transition",
    ])
  ) {
    throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
  }
  const data = parseJournalData(value.data);
  const phase = value.phase;
  if (
    typeof phase !== "string" ||
    !UPDATE_PHASES.includes(phase as UpdatePhase)
  ) {
    throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
  }
  const record: JournalRecord = {
    schema: expectLiteral(value.schema, 1),
    transactionId: expectTransactionId(value.transactionId),
    transition: expectPositiveInteger(value.transition),
    phase: phase as UpdatePhase,
    recordedAtUnixMs: expectNonnegativeInteger(value.recordedAtUnixMs),
    previousSha256: expectNullableSha256(value.previousSha256),
    data,
  };
  return record;
}

function parseJournalData(value: unknown): JournalData {
  const record = expectExactObject(value, [
    "activationGeneration",
    "receiptSha256",
    "releaseSequence",
    "slotName",
    "slotSealSha256",
  ]);
  return {
    releaseSequence: expectNullablePositiveInteger(record.releaseSequence),
    receiptSha256: expectNullableSha256(record.receiptSha256),
    slotName: expectNullableSlotName(record.slotName),
    slotSealSha256: expectNullableSha256(record.slotSealSha256),
    activationGeneration: expectNullablePositiveInteger(
      record.activationGeneration,
    ),
  };
}

function validateJournalRecord(
  record: JournalRecord,
  previous?: JournalRecord,
): void {
  const phaseNumber = UPDATE_PHASES.indexOf(record.phase) + 1;
  if (
    record.schema !== 1 ||
    !TRANSACTION_ID_PATTERN.test(record.transactionId) ||
    record.transition <= 0 ||
    !Number.isSafeInteger(record.recordedAtUnixMs) ||
    record.recordedAtUnixMs < 0 ||
    record.transition > UPDATE_PHASES.length ||
    (record.phase === "recover"
      ? previous === undefined || !sameJournalData(record.data, previous.data)
      : phaseNumber !== record.transition ||
        !hasExpectedNormalPhaseData(record.data, phaseNumber)) ||
    (record.transition === 1) !== (record.previousSha256 === null)
  ) {
    throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
  }
  if (previous) {
    if (
      record.transition !== previous.transition + 1 ||
      previous.phase === "recover" ||
      record.recordedAtUnixMs < previous.recordedAtUnixMs
    ) {
      throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
    }
    for (const key of Object.keys(previous.data) as (keyof JournalData)[]) {
      const oldValue = previous.data[key];
      const newValue = record.data[key];
      if (oldValue !== null && oldValue !== newValue) {
        throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
      }
    }
  }
}

function hasExpectedNormalPhaseData(
  data: JournalData,
  phaseNumber: number,
): boolean {
  return (
    (data.releaseSequence === null) === phaseNumber < 3 &&
    (data.receiptSha256 === null) === phaseNumber < 6 &&
    (data.slotName === null) === phaseNumber < 10 &&
    (data.slotSealSha256 === null) === phaseNumber < 12 &&
    (data.activationGeneration === null) === phaseNumber < 13
  );
}

function sameJournalData(left: JournalData, right: JournalData): boolean {
  return (
    left.releaseSequence === right.releaseSequence &&
    left.receiptSha256 === right.receiptSha256 &&
    left.slotName === right.slotName &&
    left.slotSealSha256 === right.slotSealSha256 &&
    left.activationGeneration === right.activationGeneration
  );
}

function journalRoot(appDataDirectory: string, transactionId: string): string {
  return path.join(
    path.resolve(appDataDirectory),
    "updates",
    "transactions",
    transactionId,
  );
}

function expectExactObject(
  value: unknown,
  keys: readonly string[],
): JsonObject {
  if (!isJsonObject(value) || !hasExactJsonKeys(value, keys)) {
    throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
  }
  return value;
}

function expectLiteral<T extends JsonValue>(value: unknown, expected: T): T {
  if (value !== expected)
    throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
  return expected;
}

function expectTransactionId(value: unknown): string {
  if (typeof value !== "string")
    throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
  assertTransactionId(value);
  return value;
}

function assertTransactionId(value: string): void {
  if (!TRANSACTION_ID_PATTERN.test(value)) {
    throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
  }
}

function expectPositiveInteger(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) <= 0) {
    throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
  }
  return value as number;
}

function expectNonnegativeInteger(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
  }
  return value as number;
}

function expectNullablePositiveInteger(value: unknown): number | null {
  return value === null ? null : expectPositiveInteger(value);
}

function expectNullableSha256(value: unknown): string | null {
  if (value === null) return null;
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) {
    throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
  }
  return value;
}

function expectNullableSlotName(value: unknown): string | null {
  if (value === null) return null;
  if (
    typeof value !== "string" ||
    value.length > 128 ||
    !/^[A-Za-z0-9.-]+$/.test(value)
  ) {
    throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
  }
  return value;
}

function sha256(value: Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function asciiCompare(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
