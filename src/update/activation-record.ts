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
import { readImmutableFile, writeImmutableFile } from "./durable.js";
import { UpdateError } from "./errors.js";
import type {
  UpdateArchitecture,
  UpdateChannel,
  UpdatePlatform,
} from "./schema.js";

export type ActivationReason = "update" | "automatic-rollback";

export interface ActivationRecord {
  readonly schema: 1;
  readonly generation: number;
  readonly previousRecordSha256: string | null;
  readonly previousActivationGeneration: number | null;
  readonly reason: ActivationReason;
  readonly rollbackSourceGeneration: number | null;
  readonly committedAtUnixMs: number;
  readonly channel: UpdateChannel;
  readonly platform: UpdatePlatform;
  readonly architecture: UpdateArchitecture;
  readonly releaseSequence: number;
  readonly productVersion: string;
  readonly goatEngineVersion: string;
  readonly artifactSha256: string;
  readonly slotName: string;
  readonly slotSealSha256: string;
  readonly treeSha256: string;
  readonly receiptSha256: string;
  readonly manifestSha256: string;
  readonly status: "committed";
}

export interface LoadedActivationRecord {
  readonly record: ActivationRecord;
  readonly sha256: string;
  readonly path: string;
}

export interface ActivationChain {
  readonly records: readonly LoadedActivationRecord[];
  readonly current: LoadedActivationRecord | null;
  readonly previous: LoadedActivationRecord | null;
  readonly orphanTemporaryFiles: readonly string[];
}

export interface NewActivationIdentity {
  readonly channel: UpdateChannel;
  readonly platform: UpdatePlatform;
  readonly architecture: UpdateArchitecture;
  readonly releaseSequence: number;
  readonly productVersion: string;
  readonly goatEngineVersion: string;
  readonly artifactSha256: string;
  readonly slotName: string;
  readonly slotSealSha256: string;
  readonly treeSha256: string;
  readonly receiptSha256: string;
  readonly manifestSha256: string;
}

const CHANNELS = ["stable", "beta", "development"] as const;
const RECORD_PATTERN = /^(\d{16})-([a-f0-9]{64})\.json$/;
const TEMPORARY_PATTERN = /^\.tmp-[a-f0-9]{32}$/;
const MAX_ACTIVATION_BYTES = 64 * 1024;
const RECORD_KEYS = [
  "architecture",
  "artifactSha256",
  "channel",
  "committedAtUnixMs",
  "generation",
  "goatEngineVersion",
  "manifestSha256",
  "platform",
  "previousActivationGeneration",
  "previousRecordSha256",
  "productVersion",
  "reason",
  "receiptSha256",
  "releaseSequence",
  "rollbackSourceGeneration",
  "schema",
  "slotName",
  "slotSealSha256",
  "status",
  "treeSha256",
] as const;

export async function loadActivationChain(
  appDataDirectory: string,
  platform: UpdatePlatform,
  architecture: UpdateArchitecture,
): Promise<ActivationChain> {
  const candidates: {
    readonly name: string;
    readonly path: string;
    readonly generation: number;
    readonly digest: string;
  }[] = [];
  const temporary: string[] = [];
  for (const channel of CHANNELS) {
    const directory = activationDirectory(
      appDataDirectory,
      channel,
      platform,
      architecture,
    );
    let entries;
    try {
      entries = await readdir(directory, { withFileTypes: true });
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") continue;
      throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED", { cause: error });
    }
    for (const entry of entries) {
      if (entry.isFile() && TEMPORARY_PATTERN.test(entry.name)) {
        temporary.push(path.join(directory, entry.name));
        continue;
      }
      const match = RECORD_PATTERN.exec(entry.name);
      if (!entry.isFile() || !match) {
        throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
      }
      candidates.push({
        name: entry.name,
        path: path.join(directory, entry.name),
        generation: Number(match[1]),
        digest: match[2]!,
      });
    }
  }
  if (candidates.length > 1024) {
    throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
  }
  candidates.sort((left, right) => left.generation - right.generation);
  const records: LoadedActivationRecord[] = [];
  for (let index = 0; index < candidates.length; index += 1) {
    const candidate = candidates[index]!;
    if (candidate.generation !== index + 1) {
      throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
    }
    const bytes = await readImmutableFile(
      candidate.path,
      MAX_ACTIVATION_BYTES,
      "GOAT_UPDATE_RECOVERY_REQUIRED",
    );
    const digest = sha256(bytes);
    if (digest !== candidate.digest) {
      throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
    }
    const record = parseActivationRecord(bytes);
    const previous = records.at(-1);
    if (
      record.generation !== candidate.generation ||
      record.channel !==
        path.basename(
          path.dirname(path.dirname(path.dirname(candidate.path))),
        ) ||
      record.platform !== platform ||
      record.architecture !== architecture ||
      record.previousRecordSha256 !== (previous?.sha256 ?? null) ||
      record.previousActivationGeneration !==
        (previous?.record.generation ?? null)
    ) {
      throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
    }
    validateRecordInChain(record, records);
    records.push({ record, sha256: digest, path: candidate.path });
  }
  return {
    records,
    current: records.at(-1) ?? null,
    previous: records.at(-2) ?? null,
    orphanTemporaryFiles: temporary.sort(asciiCompare),
  };
}

export async function appendUpdateActivationRecord(
  appDataDirectory: string,
  identity: NewActivationIdentity,
  committedAtUnixMs = Date.now(),
): Promise<LoadedActivationRecord> {
  expectNonnegativeInteger(committedAtUnixMs);
  const chain = await loadActivationChain(
    appDataDirectory,
    identity.platform,
    identity.architecture,
  );
  const maxReleaseSequence = chain.records.reduce(
    (maximum, entry) => Math.max(maximum, entry.record.releaseSequence),
    0,
  );
  if (identity.releaseSequence <= maxReleaseSequence) {
    throw new UpdateError("GOAT_UPDATE_DOWNGRADE_BLOCKED");
  }
  const record: ActivationRecord = {
    schema: 1,
    generation: chain.records.length + 1,
    previousRecordSha256: chain.current?.sha256 ?? null,
    previousActivationGeneration: chain.current?.record.generation ?? null,
    reason: "update",
    rollbackSourceGeneration: null,
    committedAtUnixMs,
    ...identity,
    status: "committed",
  };
  return appendActivationRecord(appDataDirectory, chain, record);
}

export async function appendRollbackActivationRecord(
  appDataDirectory: string,
  platform: UpdatePlatform,
  architecture: UpdateArchitecture,
  sourceGeneration: number,
  committedAtUnixMs = Date.now(),
): Promise<LoadedActivationRecord> {
  expectNonnegativeInteger(committedAtUnixMs);
  const chain = await loadActivationChain(
    appDataDirectory,
    platform,
    architecture,
  );
  const source = chain.records.find(
    (entry) => entry.record.generation === sourceGeneration,
  );
  if (!chain.current || !source || source === chain.current) {
    throw new UpdateError("GOAT_UPDATE_ROLLBACK_INVALID");
  }
  const identity = activationIdentity(source.record);
  const record: ActivationRecord = {
    schema: 1,
    generation: chain.records.length + 1,
    previousRecordSha256: chain.current.sha256,
    previousActivationGeneration: chain.current.record.generation,
    reason: "automatic-rollback",
    rollbackSourceGeneration: sourceGeneration,
    committedAtUnixMs,
    ...identity,
    status: "committed",
  };
  return appendActivationRecord(appDataDirectory, chain, record);
}

export function activationIdentity(
  record: ActivationRecord,
): NewActivationIdentity {
  return {
    channel: record.channel,
    platform: record.platform,
    architecture: record.architecture,
    releaseSequence: record.releaseSequence,
    productVersion: record.productVersion,
    goatEngineVersion: record.goatEngineVersion,
    artifactSha256: record.artifactSha256,
    slotName: record.slotName,
    slotSealSha256: record.slotSealSha256,
    treeSha256: record.treeSha256,
    receiptSha256: record.receiptSha256,
    manifestSha256: record.manifestSha256,
  };
}

export function slotRoot(
  appDataDirectory: string,
  record: Pick<
    ActivationRecord,
    "channel" | "platform" | "architecture" | "slotName"
  >,
): string {
  return path.join(
    tupleRoot(
      appDataDirectory,
      record.channel,
      record.platform,
      record.architecture,
    ),
    "releases",
    record.slotName,
  );
}

export function expectedSlotName(identity: {
  readonly releaseSequence: number;
  readonly goatEngineVersion: string;
  readonly artifactSha256: string;
}): string {
  if (
    !Number.isSafeInteger(identity.releaseSequence) ||
    identity.releaseSequence <= 0 ||
    !isVersion(identity.goatEngineVersion) ||
    !isSha256(identity.artifactSha256)
  ) {
    throw new UpdateError("GOAT_UPDATE_ACTIVATION_FAILED");
  }
  return `${identity.releaseSequence}-${identity.goatEngineVersion}-${identity.artifactSha256.slice(0, 12)}`;
}

async function appendActivationRecord(
  appDataDirectory: string,
  chain: ActivationChain,
  record: ActivationRecord,
): Promise<LoadedActivationRecord> {
  validateActivationRecord(record);
  validateRecordInChain(record, chain.records);
  const bytes = canonicalJsonBytes(record as unknown as JsonValue);
  const digest = sha256(bytes);
  const name = `${String(record.generation).padStart(16, "0")}-${digest}.json`;
  const recordPath = await writeImmutableFile(
    activationDirectory(
      appDataDirectory,
      record.channel,
      record.platform,
      record.architecture,
    ),
    name,
    bytes,
    "GOAT_UPDATE_ACTIVATION_FAILED",
  );
  return { record, sha256: digest, path: recordPath };
}

function parseActivationRecord(bytes: Uint8Array): ActivationRecord {
  const value = parseCanonicalJson(bytes, {
    maxBytes: MAX_ACTIVATION_BYTES,
    errorCode: "GOAT_UPDATE_RECOVERY_REQUIRED",
  });
  const record = expectExactObject(value, RECORD_KEYS);
  const parsed: ActivationRecord = {
    schema: expectLiteral(record.schema, 1),
    generation: expectPositiveInteger(record.generation),
    previousRecordSha256: expectNullableSha256(record.previousRecordSha256),
    previousActivationGeneration: expectNullablePositiveInteger(
      record.previousActivationGeneration,
    ),
    reason: expectReason(record.reason),
    rollbackSourceGeneration: expectNullablePositiveInteger(
      record.rollbackSourceGeneration,
    ),
    committedAtUnixMs: expectNonnegativeInteger(record.committedAtUnixMs),
    channel: expectChannel(record.channel),
    platform: expectPlatform(record.platform),
    architecture: expectArchitecture(record.architecture),
    releaseSequence: expectPositiveInteger(record.releaseSequence),
    productVersion: expectVersion(record.productVersion),
    goatEngineVersion: expectVersion(record.goatEngineVersion),
    artifactSha256: expectSha256(record.artifactSha256),
    slotName: expectSlotName(record.slotName),
    slotSealSha256: expectSha256(record.slotSealSha256),
    treeSha256: expectSha256(record.treeSha256),
    receiptSha256: expectSha256(record.receiptSha256),
    manifestSha256: expectSha256(record.manifestSha256),
    status: expectLiteral(record.status, "committed"),
  };
  validateActivationRecord(parsed);
  return parsed;
}

function validateActivationRecord(record: ActivationRecord): void {
  if (
    record.schema !== 1 ||
    (record.generation === 1) !== (record.previousRecordSha256 === null) ||
    (record.generation === 1) !==
      (record.previousActivationGeneration === null) ||
    (record.reason === "update") !==
      (record.rollbackSourceGeneration === null) ||
    record.productVersion !== record.goatEngineVersion ||
    record.slotName !== expectedSlotName(record)
  ) {
    throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
  }
}

function validateRecordInChain(
  record: ActivationRecord,
  prior: readonly LoadedActivationRecord[],
): void {
  if (record.generation !== prior.length + 1) {
    throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
  }
  const previous = prior.at(-1);
  if (
    record.previousRecordSha256 !== (previous?.sha256 ?? null) ||
    record.previousActivationGeneration !==
      (previous?.record.generation ?? null)
  ) {
    throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
  }
  if (record.reason === "update") {
    const maximum = prior.reduce(
      (value, entry) => Math.max(value, entry.record.releaseSequence),
      0,
    );
    if (record.releaseSequence <= maximum) {
      throw new UpdateError("GOAT_UPDATE_DOWNGRADE_BLOCKED");
    }
    return;
  }
  const source = prior.find(
    (entry) => entry.record.generation === record.rollbackSourceGeneration,
  );
  if (!source || !sameActivationIdentity(source.record, record)) {
    throw new UpdateError("GOAT_UPDATE_ROLLBACK_INVALID");
  }
}

function sameActivationIdentity(
  left: ActivationRecord,
  right: ActivationRecord,
): boolean {
  const leftIdentity = activationIdentity(left);
  const rightIdentity = activationIdentity(right);
  return (Object.keys(leftIdentity) as (keyof NewActivationIdentity)[]).every(
    (key) => leftIdentity[key] === rightIdentity[key],
  );
}

function tupleRoot(
  appDataDirectory: string,
  channel: UpdateChannel,
  platform: UpdatePlatform,
  architecture: UpdateArchitecture,
): string {
  return path.join(
    path.resolve(appDataDirectory),
    "engines",
    channel,
    `${platform}-${architecture}`,
  );
}

function activationDirectory(
  appDataDirectory: string,
  channel: UpdateChannel,
  platform: UpdatePlatform,
  architecture: UpdateArchitecture,
): string {
  return path.join(
    tupleRoot(appDataDirectory, channel, platform, architecture),
    "activations",
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
  return value === null ? null : expectSha256(value);
}

function expectSha256(value: unknown): string {
  if (typeof value !== "string" || !isSha256(value)) {
    throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
  }
  return value;
}

function expectVersion(value: unknown): string {
  if (typeof value !== "string" || !isVersion(value)) {
    throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
  }
  return value;
}

function expectSlotName(value: unknown): string {
  if (
    typeof value !== "string" ||
    value.length > 128 ||
    !/^\d+-[0-9A-Za-z.-]+-[a-f0-9]{12}$/.test(value)
  ) {
    throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
  }
  return value;
}

function expectReason(value: unknown): ActivationReason {
  if (value !== "update" && value !== "automatic-rollback") {
    throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
  }
  return value;
}

function expectChannel(value: unknown): UpdateChannel {
  if (!CHANNELS.includes(value as UpdateChannel)) {
    throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
  }
  return value as UpdateChannel;
}

function expectPlatform(value: unknown): UpdatePlatform {
  if (value !== "win32" && value !== "darwin") {
    throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
  }
  return value;
}

function expectArchitecture(value: unknown): UpdateArchitecture {
  if (value !== "x64" && value !== "arm64") {
    throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
  }
  return value;
}

function isSha256(value: string): boolean {
  return /^[a-f0-9]{64}$/.test(value);
}

function isVersion(value: string): boolean {
  return (
    value.length > 0 &&
    value.length <= 64 &&
    /^[0-9]+\.[0-9]+\.[0-9]+(?:-(?:beta|dev)\.[0-9]+)?$/.test(value)
  );
}

function sha256(value: Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function asciiCompare(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
