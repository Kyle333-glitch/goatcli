import { createHash } from "node:crypto";
import path from "node:path";
import { lstat, readdir } from "node:fs/promises";
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
import type { MetadataCheckpointHead } from "./metadata-checkpoint.js";
import type { KnownReleaseIdentity } from "./selection.js";
import type { UpdateChannel } from "./schema.js";
import {
  emptyTrustedMetadataState,
  type TrustedMetadataDigests,
  type TrustedMetadataState,
  type TrustedMetadataVersions,
} from "./trust.js";

export interface UpdaterStateRecord {
  readonly schema: 1;
  readonly generation: number;
  readonly previousSha256: string | null;
  readonly configuredChannel: UpdateChannel;
  readonly metadataVersions: TrustedMetadataVersions;
  readonly metadataDigests: TrustedMetadataDigests;
  readonly trustedTimeUnixMs: number;
  readonly metadataCheckpointGeneration: number;
  readonly metadataCheckpointSha256: string | null;
  readonly maxAuthenticatedReleaseSequence: number;
  readonly maxActivatedReleaseSequence: number;
  readonly currentActivationGeneration: number | null;
  readonly previousActivationGeneration: number | null;
  readonly revokedKeyIds: readonly string[];
  readonly revokedArtifactSha256: readonly string[];
  readonly revokedReleaseSequences: readonly number[];
  readonly receiptDigests: readonly string[];
  readonly knownReleases: readonly KnownReleaseIdentity[];
}

export interface LoadedUpdaterState {
  readonly record: UpdaterStateRecord;
  readonly sha256: string;
  readonly path: string;
  readonly orphanTemporaryFiles: readonly string[];
}

export interface AuthenticatedStateAdvance {
  readonly release: KnownReleaseIdentity;
  readonly receiptSha256: string;
}

export interface MetadataStateAdvance {
  readonly trustedMetadata: TrustedMetadataState;
  readonly checkpoint: MetadataCheckpointHead;
}

export interface ActivatedStateAdvance {
  readonly activationGeneration: number;
  readonly release: KnownReleaseIdentity;
  readonly receiptSha256: string;
}

export interface RollbackStateAdvance {
  readonly activationGeneration: number;
  readonly release: KnownReleaseIdentity;
  readonly receiptSha256: string;
}

const STATE_RECORD_PATTERN = /^(\d{16})-([a-f0-9]{64})\.json$/;
const TEMPORARY_RECORD_PATTERN = /^\.tmp-[a-f0-9]{32}$/;
const MAX_STATE_RECORD_BYTES = 128 * 1024;
const METADATA_ROLES = [
  "root",
  "timestamp",
  "snapshot",
  "targets",
  "stable",
  "beta",
  "development",
] as const;

export function initialUpdaterState(
  trustedMetadata: TrustedMetadataState = emptyTrustedMetadataState(),
  configuredChannel: UpdateChannel = "stable",
): Omit<UpdaterStateRecord, "generation" | "previousSha256"> {
  return {
    schema: 1,
    configuredChannel,
    metadataVersions: trustedMetadata.versions,
    metadataDigests: trustedMetadata.digests,
    trustedTimeUnixMs: trustedMetadata.trustedTimeUnixMs,
    metadataCheckpointGeneration: 0,
    metadataCheckpointSha256: null,
    maxAuthenticatedReleaseSequence: 0,
    maxActivatedReleaseSequence: 0,
    currentActivationGeneration: null,
    previousActivationGeneration: null,
    revokedKeyIds: trustedMetadata.revokedKeyIds,
    revokedArtifactSha256: trustedMetadata.revokedArtifactSha256,
    revokedReleaseSequences: trustedMetadata.revokedReleaseSequences,
    receiptDigests: [],
    knownReleases: [],
  };
}

export async function initializeUpdaterState(
  appDataDirectory: string,
  initial: Omit<UpdaterStateRecord, "generation" | "previousSha256">,
): Promise<LoadedUpdaterState> {
  await assertPristineV04Layout(appDataDirectory);
  const record: UpdaterStateRecord = {
    ...initial,
    generation: 1,
    previousSha256: null,
  };
  validateStateRecord(record);
  return writeStateRecord(appDataDirectory, record);
}

export async function initializeReconstructedUpdaterState(
  appDataDirectory: string,
  reconstructed: Omit<UpdaterStateRecord, "generation" | "previousSha256">,
): Promise<LoadedUpdaterState> {
  if (
    reconstructed.metadataCheckpointGeneration === 0 &&
    (reconstructed.maxAuthenticatedReleaseSequence <= 0 ||
      reconstructed.receiptDigests.length === 0 ||
      reconstructed.knownReleases.length === 0)
  ) {
    throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
  }
  const existing = await loadUpdaterState(appDataDirectory);
  if (existing) throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
  const record: UpdaterStateRecord = {
    ...reconstructed,
    generation: 1,
    previousSha256: null,
  };
  validateStateRecord(record);
  return writeStateRecord(appDataDirectory, record);
}

export async function loadUpdaterState(
  appDataDirectory: string,
): Promise<LoadedUpdaterState | null> {
  const directory = stateDirectory(appDataDirectory);
  let entries;
  try {
    entries = await readdir(directory, { withFileTypes: true });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw new UpdateError("GOAT_UPDATE_STATE_INVALID", { cause: error });
  }
  const finalEntries: { name: string; generation: number; digest: string }[] =
    [];
  const temporary: string[] = [];
  for (const entry of entries) {
    if (entry.isFile() && TEMPORARY_RECORD_PATTERN.test(entry.name)) {
      temporary.push(path.join(directory, entry.name));
      continue;
    }
    const match = STATE_RECORD_PATTERN.exec(entry.name);
    if (!entry.isFile() || !match) {
      throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
    }
    const generation = Number(match[1]);
    if (!Number.isSafeInteger(generation) || generation <= 0) {
      throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
    }
    finalEntries.push({ name: entry.name, generation, digest: match[2]! });
  }
  if (finalEntries.length === 0) return null;
  finalEntries.sort((left, right) => left.generation - right.generation);
  let previousDigest: string | null = null;
  let loaded: LoadedUpdaterState | undefined;
  for (let index = 0; index < finalEntries.length; index += 1) {
    const entry = finalEntries[index]!;
    if (entry.generation !== index + 1) {
      throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
    }
    const recordPath = path.join(directory, entry.name);
    const bytes = await readImmutableFile(
      recordPath,
      MAX_STATE_RECORD_BYTES,
      "GOAT_UPDATE_STATE_INVALID",
    );
    const digest = sha256(bytes);
    if (digest !== entry.digest) {
      throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
    }
    const record = parseStateRecord(bytes);
    if (
      record.generation !== entry.generation ||
      record.previousSha256 !== previousDigest
    ) {
      throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
    }
    if (loaded) assertMonotonicStateTransition(loaded.record, record);
    loaded = {
      record,
      sha256: digest,
      path: recordPath,
      orphanTemporaryFiles: temporary.sort(asciiCompare),
    };
    previousDigest = digest;
  }
  return loaded!;
}

export async function listUpdaterStateOrphanTemporaryFiles(
  appDataDirectory: string,
): Promise<readonly string[]> {
  const directory = stateDirectory(appDataDirectory);
  let entries;
  try {
    entries = await readdir(directory, { withFileTypes: true });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw new UpdateError("GOAT_UPDATE_STATE_INVALID", { cause: error });
  }
  const temporary: string[] = [];
  for (const entry of entries) {
    if (entry.isFile() && TEMPORARY_RECORD_PATTERN.test(entry.name)) {
      temporary.push(path.join(directory, entry.name));
      continue;
    }
    const match = STATE_RECORD_PATTERN.exec(entry.name);
    const generation = match ? Number(match[1]) : 0;
    if (
      !entry.isFile() ||
      !match ||
      !Number.isSafeInteger(generation) ||
      generation <= 0
    ) {
      throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
    }
  }
  return temporary.sort(asciiCompare);
}

export async function appendUpdaterState(
  appDataDirectory: string,
  current: LoadedUpdaterState,
  next: Omit<UpdaterStateRecord, "generation" | "previousSha256">,
): Promise<LoadedUpdaterState> {
  const actual = await loadUpdaterState(appDataDirectory);
  if (!actual || actual.sha256 !== current.sha256) {
    throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
  }
  const record: UpdaterStateRecord = {
    ...next,
    generation: current.record.generation + 1,
    previousSha256: current.sha256,
  };
  validateStateRecord(record);
  assertMonotonicStateTransition(current.record, record);
  return writeStateRecord(appDataDirectory, record);
}

export function stateAfterAuthentication(
  current: UpdaterStateRecord,
  advance: AuthenticatedStateAdvance,
): Omit<UpdaterStateRecord, "generation" | "previousSha256"> {
  const release = advance.release;
  if (
    release.releaseSequence <= current.maxAuthenticatedReleaseSequence ||
    release.releaseSequence < current.maxActivatedReleaseSequence ||
    !isSha256(advance.receiptSha256)
  ) {
    throw new UpdateError("GOAT_UPDATE_DOWNGRADE_BLOCKED");
  }
  assertKnownReleaseCanAppend(current.knownReleases, release);
  return withoutChainFields({
    ...current,
    maxAuthenticatedReleaseSequence: release.releaseSequence,
    receiptDigests: sortedUniqueStrings([
      ...current.receiptDigests,
      advance.receiptSha256,
    ]),
    knownReleases: [...current.knownReleases, release].sort(
      (left, right) => left.releaseSequence - right.releaseSequence,
    ),
  });
}

export function stateAfterMetadataRefresh(
  current: UpdaterStateRecord,
  advance: MetadataStateAdvance,
): Omit<UpdaterStateRecord, "generation" | "previousSha256"> {
  return withoutChainFields({
    ...current,
    metadataCheckpointGeneration: advance.checkpoint.generation,
    metadataCheckpointSha256: advance.checkpoint.sha256,
    metadataVersions: advance.trustedMetadata.versions,
    metadataDigests: advance.trustedMetadata.digests,
    trustedTimeUnixMs: advance.trustedMetadata.trustedTimeUnixMs,
    revokedKeyIds: advance.trustedMetadata.revokedKeyIds,
    revokedArtifactSha256: advance.trustedMetadata.revokedArtifactSha256,
    revokedReleaseSequences: advance.trustedMetadata.revokedReleaseSequences,
  });
}

export function stateAfterActivation(
  current: UpdaterStateRecord,
  advance: ActivatedStateAdvance,
): Omit<UpdaterStateRecord, "generation" | "previousSha256"> {
  if (
    advance.release.releaseSequence !==
      current.maxAuthenticatedReleaseSequence ||
    advance.release.releaseSequence <= current.maxActivatedReleaseSequence ||
    advance.activationGeneration <= 0 ||
    !Number.isSafeInteger(advance.activationGeneration) ||
    !current.receiptDigests.includes(advance.receiptSha256) ||
    !sameRelease(
      current.knownReleases.find(
        (release) =>
          release.releaseSequence === advance.release.releaseSequence,
      ),
      advance.release,
    )
  ) {
    throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
  }
  return withoutChainFields({
    ...current,
    configuredChannel: advance.release.channel,
    maxActivatedReleaseSequence: advance.release.releaseSequence,
    previousActivationGeneration: current.currentActivationGeneration,
    currentActivationGeneration: advance.activationGeneration,
  });
}

export function stateAfterAutomaticRollback(
  current: UpdaterStateRecord,
  advance: RollbackStateAdvance,
): Omit<UpdaterStateRecord, "generation" | "previousSha256"> {
  const known = current.knownReleases.find(
    (release) => release.releaseSequence === advance.release.releaseSequence,
  );
  if (
    current.currentActivationGeneration === null ||
    advance.activationGeneration <= current.currentActivationGeneration ||
    advance.release.releaseSequence > current.maxActivatedReleaseSequence ||
    !sameRelease(known, advance.release) ||
    !current.receiptDigests.includes(advance.receiptSha256)
  ) {
    throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
  }
  return withoutChainFields({
    ...current,
    configuredChannel: advance.release.channel,
    previousActivationGeneration: current.currentActivationGeneration,
    currentActivationGeneration: advance.activationGeneration,
  });
}

export function trustedMetadataFromState(
  state: UpdaterStateRecord,
): TrustedMetadataState {
  return {
    versions: state.metadataVersions,
    digests: state.metadataDigests,
    trustedTimeUnixMs: state.trustedTimeUnixMs,
    revokedKeyIds: state.revokedKeyIds,
    revokedArtifactSha256: state.revokedArtifactSha256,
    revokedReleaseSequences: state.revokedReleaseSequences,
  };
}

export async function assertPristineV04Layout(
  appDataDirectory: string,
): Promise<void> {
  const appData = path.resolve(appDataDirectory);
  const updates = path.join(appData, "updates");
  if (await directoryContainsStateMarkers(updates)) {
    throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
  }
  const engines = path.join(appData, "engines");
  let channels;
  try {
    channels = await readdir(engines, { withFileTypes: true });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    throw new UpdateError("GOAT_UPDATE_STATE_INVALID", { cause: error });
  }
  for (const channel of channels) {
    if (!channel.isDirectory() || channel.isSymbolicLink()) continue;
    const channelPath = path.join(engines, channel.name);
    const tuples = await readdir(channelPath, { withFileTypes: true });
    for (const tuple of tuples) {
      if (!tuple.isDirectory() || tuple.isSymbolicLink()) continue;
      for (const marker of ["releases", "activations"]) {
        if (
          await directoryHasEntries(path.join(channelPath, tuple.name, marker))
        ) {
          throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
        }
      }
    }
  }
}

function parseStateRecord(bytes: Uint8Array): UpdaterStateRecord {
  const value = parseCanonicalJson(bytes, {
    maxBytes: MAX_STATE_RECORD_BYTES,
    errorCode: "GOAT_UPDATE_STATE_INVALID",
  });
  if (!isJsonObject(value)) throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
  const record = value as JsonObject;
  if (
    !hasExactJsonKeys(record, [
      "configuredChannel",
      "currentActivationGeneration",
      "generation",
      "knownReleases",
      "metadataCheckpointGeneration",
      "metadataCheckpointSha256",
      "maxActivatedReleaseSequence",
      "maxAuthenticatedReleaseSequence",
      "metadataDigests",
      "metadataVersions",
      "previousActivationGeneration",
      "previousSha256",
      "receiptDigests",
      "revokedArtifactSha256",
      "revokedKeyIds",
      "revokedReleaseSequences",
      "schema",
      "trustedTimeUnixMs",
    ])
  ) {
    throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
  }
  const parsed: UpdaterStateRecord = {
    schema: expectValue(record.schema, 1),
    generation: expectPositiveInteger(record.generation),
    previousSha256: expectNullableSha256(record.previousSha256),
    configuredChannel: expectChannel(record.configuredChannel),
    metadataCheckpointGeneration: expectNonnegativeInteger(
      record.metadataCheckpointGeneration,
    ),
    metadataCheckpointSha256: expectNullableSha256(
      record.metadataCheckpointSha256,
    ),
    metadataVersions: parseMetadataVersions(record.metadataVersions),
    metadataDigests: parseMetadataDigests(record.metadataDigests),
    trustedTimeUnixMs: expectNonnegativeInteger(record.trustedTimeUnixMs),
    maxAuthenticatedReleaseSequence: expectNonnegativeInteger(
      record.maxAuthenticatedReleaseSequence,
    ),
    maxActivatedReleaseSequence: expectNonnegativeInteger(
      record.maxActivatedReleaseSequence,
    ),
    currentActivationGeneration: expectNullablePositiveInteger(
      record.currentActivationGeneration,
    ),
    previousActivationGeneration: expectNullablePositiveInteger(
      record.previousActivationGeneration,
    ),
    revokedKeyIds: parseSortedSha256Array(record.revokedKeyIds),
    revokedArtifactSha256: parseSortedSha256Array(record.revokedArtifactSha256),
    revokedReleaseSequences: parseSortedIntegerArray(
      record.revokedReleaseSequences,
    ),
    receiptDigests: parseSortedSha256Array(record.receiptDigests),
    knownReleases: parseKnownReleases(record.knownReleases),
  };
  validateStateRecord(parsed);
  return parsed;
}

function validateStateRecord(record: UpdaterStateRecord): void {
  if (
    record.schema !== 1 ||
    record.generation <= 0 ||
    (record.metadataCheckpointGeneration === 0) !==
      (record.metadataCheckpointSha256 === null) ||
    (record.generation === 1) !== (record.previousSha256 === null) ||
    record.maxActivatedReleaseSequence >
      record.maxAuthenticatedReleaseSequence ||
    (record.currentActivationGeneration === null) !==
      (record.maxActivatedReleaseSequence === 0) ||
    (record.previousActivationGeneration !== null &&
      (record.currentActivationGeneration === null ||
        record.previousActivationGeneration >=
          record.currentActivationGeneration))
  ) {
    throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
  }
  parseMetadataVersions(toJsonObject(record.metadataVersions));
  parseMetadataDigests(toJsonObject(record.metadataDigests));
  parseSortedSha256Array([...record.revokedKeyIds]);
  parseSortedSha256Array([...record.revokedArtifactSha256]);
  parseSortedIntegerArray([...record.revokedReleaseSequences]);
  parseSortedSha256Array([...record.receiptDigests]);
  parseKnownReleases(record.knownReleases as unknown as JsonValue);
  const maximumKnown = record.knownReleases.at(-1)?.releaseSequence ?? 0;
  if (maximumKnown !== record.maxAuthenticatedReleaseSequence) {
    throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
  }
}

function assertMonotonicStateTransition(
  previous: UpdaterStateRecord,
  next: UpdaterStateRecord,
): void {
  if (
    next.generation !== previous.generation + 1 ||
    next.maxAuthenticatedReleaseSequence <
      previous.maxAuthenticatedReleaseSequence ||
    next.maxActivatedReleaseSequence < previous.maxActivatedReleaseSequence ||
    !(
      (next.metadataCheckpointGeneration ===
        previous.metadataCheckpointGeneration &&
        next.metadataCheckpointSha256 === previous.metadataCheckpointSha256) ||
      (next.metadataCheckpointGeneration ===
        previous.metadataCheckpointGeneration + 1 &&
        next.metadataCheckpointSha256 !== null &&
        next.metadataCheckpointSha256 !== previous.metadataCheckpointSha256)
    ) ||
    next.trustedTimeUnixMs < previous.trustedTimeUnixMs ||
    !isSuperset(next.revokedKeyIds, previous.revokedKeyIds) ||
    !isSuperset(next.revokedArtifactSha256, previous.revokedArtifactSha256) ||
    !isSuperset(
      next.revokedReleaseSequences,
      previous.revokedReleaseSequences,
    ) ||
    !isSuperset(next.receiptDigests, previous.receiptDigests)
  ) {
    throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
  }
  for (const role of METADATA_ROLES) {
    const oldVersion = previous.metadataVersions[role];
    const newVersion = next.metadataVersions[role];
    if (
      newVersion < oldVersion ||
      (newVersion === oldVersion &&
        previous.metadataDigests[role] !== next.metadataDigests[role])
    ) {
      throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
    }
  }
  if (
    previous.configuredChannel !== next.configuredChannel &&
    next.currentActivationGeneration === previous.currentActivationGeneration
  ) {
    throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
  }
  for (const known of previous.knownReleases) {
    const retained = next.knownReleases.find(
      (candidate) => candidate.releaseSequence === known.releaseSequence,
    );
    if (!sameRelease(retained, known)) {
      throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
    }
  }
}

async function writeStateRecord(
  appDataDirectory: string,
  record: UpdaterStateRecord,
): Promise<LoadedUpdaterState> {
  const bytes = canonicalJsonBytes(record as unknown as JsonValue);
  const digest = sha256(bytes);
  const name = `${String(record.generation).padStart(16, "0")}-${digest}.json`;
  const recordPath = await writeImmutableFile(
    stateDirectory(appDataDirectory),
    name,
    bytes,
    "GOAT_UPDATE_STATE_INVALID",
  );
  return {
    record,
    sha256: digest,
    path: recordPath,
    orphanTemporaryFiles: [],
  };
}

function stateDirectory(appDataDirectory: string): string {
  return path.join(path.resolve(appDataDirectory), "updates", "state");
}

async function directoryContainsStateMarkers(
  directory: string,
): Promise<boolean> {
  let entries;
  try {
    entries = await readdir(directory, { withFileTypes: true });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw new UpdateError("GOAT_UPDATE_STATE_INVALID", { cause: error });
  }
  for (const entry of entries) {
    if (
      ["state", "receipts", "transactions", "metadata"].includes(entry.name)
    ) {
      if (await directoryHasEntries(path.join(directory, entry.name)))
        return true;
    }
  }
  return false;
}

async function directoryHasEntries(directory: string): Promise<boolean> {
  try {
    const stats = await lstat(directory);
    if (!stats.isDirectory() || stats.isSymbolicLink()) return true;
    return (await readdir(directory)).length > 0;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw new UpdateError("GOAT_UPDATE_STATE_INVALID", { cause: error });
  }
}

function parseMetadataVersions(value: unknown): TrustedMetadataVersions {
  const record = expectExactObject(value, METADATA_ROLES);
  return Object.fromEntries(
    METADATA_ROLES.map((role) => [
      role,
      expectNonnegativeInteger(record[role]),
    ]),
  ) as unknown as TrustedMetadataVersions;
}

function parseMetadataDigests(value: unknown): TrustedMetadataDigests {
  if (!isJsonObject(value)) throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
  const actual = Object.keys(value);
  if (actual.some((role) => !METADATA_ROLES.includes(role as never))) {
    throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
  }
  const result: Record<string, string> = {};
  for (const role of METADATA_ROLES) {
    const digest = value[role];
    if (digest !== undefined) result[role] = expectSha256(digest);
  }
  return result;
}

function parseKnownReleases(
  value: JsonValue | unknown,
): KnownReleaseIdentity[] {
  if (!Array.isArray(value)) throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
  const parsed = value.map((entry) => {
    const record = expectExactObject(entry, [
      "artifactSha256",
      "channel",
      "productVersion",
      "releaseSequence",
    ]);
    return {
      releaseSequence: expectPositiveInteger(record.releaseSequence),
      channel: expectChannel(record.channel),
      productVersion: expectSafeString(record.productVersion, 64),
      artifactSha256: expectSha256(record.artifactSha256),
    };
  });
  if (
    parsed.length > 1024 ||
    parsed.some(
      (release, index) =>
        index > 0 &&
        release.releaseSequence <= parsed[index - 1]!.releaseSequence,
    )
  ) {
    throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
  }
  for (let left = 0; left < parsed.length; left += 1) {
    for (let right = left + 1; right < parsed.length; right += 1) {
      if (
        parsed[left]!.productVersion === parsed[right]!.productVersion &&
        parsed[left]!.artifactSha256 !== parsed[right]!.artifactSha256
      ) {
        throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
      }
    }
  }
  return parsed;
}

function parseSortedSha256Array(value: unknown): string[] {
  if (!Array.isArray(value) || value.length > 2048) {
    throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
  }
  const parsed = value.map(expectSha256);
  assertStrictlySorted(parsed);
  return parsed;
}

function parseSortedIntegerArray(value: unknown): number[] {
  if (!Array.isArray(value) || value.length > 2048) {
    throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
  }
  const parsed = value.map(expectPositiveInteger);
  assertStrictlySorted(parsed);
  return parsed;
}

function expectExactObject(
  value: unknown,
  keys: readonly string[],
): JsonObject {
  if (!isJsonObject(value) || !hasExactJsonKeys(value, keys)) {
    throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
  }
  return value;
}

function expectChannel(value: unknown): UpdateChannel {
  if (value !== "stable" && value !== "beta" && value !== "development") {
    throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
  }
  return value;
}

function expectValue<T extends JsonValue>(value: unknown, expected: T): T {
  if (value !== expected) throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
  return expected;
}

function expectPositiveInteger(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) <= 0) {
    throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
  }
  return value as number;
}

function expectNonnegativeInteger(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
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
    throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
  }
  return value;
}

function expectSafeString(value: unknown, maxLength: number): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > maxLength ||
    !/^[A-Za-z0-9._-]+$/.test(value)
  ) {
    throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
  }
  return value;
}

function assertKnownReleaseCanAppend(
  known: readonly KnownReleaseIdentity[],
  release: KnownReleaseIdentity,
): void {
  if (
    known.some(
      (candidate) =>
        candidate.releaseSequence === release.releaseSequence ||
        (candidate.productVersion === release.productVersion &&
          candidate.artifactSha256 !== release.artifactSha256),
    )
  ) {
    throw new UpdateError("GOAT_UPDATE_METADATA_REPLAYED");
  }
}

function sameRelease(
  left: KnownReleaseIdentity | undefined,
  right: KnownReleaseIdentity,
): boolean {
  return (
    left !== undefined &&
    left.releaseSequence === right.releaseSequence &&
    left.channel === right.channel &&
    left.productVersion === right.productVersion &&
    left.artifactSha256 === right.artifactSha256
  );
}

function withoutChainFields(
  record: UpdaterStateRecord,
): Omit<UpdaterStateRecord, "generation" | "previousSha256"> {
  const {
    generation: _generation,
    previousSha256: _previous,
    ...rest
  } = record;
  return rest;
}

function toJsonObject(value: object): JsonObject {
  return value as unknown as JsonObject;
}

function sortedUniqueStrings(values: readonly string[]): string[] {
  return [...new Set(values)].sort(asciiCompare);
}

function isSuperset<T>(
  candidate: readonly T[],
  required: readonly T[],
): boolean {
  const values = new Set(candidate);
  return required.every((value) => values.has(value));
}

function assertStrictlySorted(values: readonly (string | number)[]): void {
  for (let index = 1; index < values.length; index += 1) {
    if (values[index - 1]! >= values[index]!) {
      throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
    }
  }
}

function isSha256(value: string): boolean {
  return /^[a-f0-9]{64}$/.test(value);
}

function sha256(value: Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function asciiCompare(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
