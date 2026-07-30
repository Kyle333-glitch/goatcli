import { createHash } from "node:crypto";
import path from "node:path";
import { lstat, readdir, unlink } from "node:fs/promises";
import {
  canonicalJsonBytes,
  hasExactJsonKeys,
  isJsonObject,
  parseCanonicalJson,
  type JsonObject,
  type JsonValue,
} from "./canonical-json.js";
import {
  assertPrivateDirectory,
  readImmutableFile,
  syncDirectory,
  writeImmutableFile,
} from "./durable.js";
import { UpdateError } from "./errors.js";
import { parseRootMetadata } from "./metadata.js";
import type { UpdateMetadataBundle } from "./metadata-client.js";
import type { UpdateChannel } from "./schema.js";
import {
  emptyTrustedMetadataState,
  TufTrustStore,
  type AuthenticatedMetadataSet,
  type TrustedMetadataState,
  type TrustedMetadataVersions,
} from "./trust.js";

export interface MetadataCheckpointPolicy {
  readonly embeddedRootBytes: Uint8Array;
  readonly embeddedRootSha256: string;
}

export interface AuthenticatedMetadataBundleRecord {
  readonly schema: 1;
  readonly embeddedRootSha256: string;
  readonly sequentialRoots: readonly string[];
  readonly timestamp: string;
  readonly snapshot: string;
  readonly targets: string;
  readonly channel: string;
  readonly channelName: UpdateChannel;
}

export interface MetadataCheckpointRecord {
  readonly schema: 1;
  readonly generation: number;
  readonly previousSha256: string | null;
  readonly metadataBundleSha256: string;
  readonly trustedTimeUnixMs: number;
}

export interface MetadataCheckpointHead {
  readonly generation: number;
  readonly sha256: string | null;
}

export interface LoadedMetadataBundle {
  readonly record: AuthenticatedMetadataBundleRecord;
  readonly raw: UpdateMetadataBundle;
  readonly bytes: Buffer;
  readonly sha256: string;
  readonly path: string;
}

export interface LoadedMetadataCheckpoint {
  readonly record: MetadataCheckpointRecord;
  readonly bytes: Buffer;
  readonly sha256: string;
  readonly path: string;
  readonly bundle: LoadedMetadataBundle;
  readonly authenticated: AuthenticatedMetadataSet;
}

export interface LoadedMetadataCheckpointChain {
  readonly records: readonly LoadedMetadataCheckpoint[];
  readonly current: LoadedMetadataCheckpoint | null;
  readonly head: MetadataCheckpointHead;
  readonly trustedMetadata: TrustedMetadataState;
  readonly currentRootBytes: Buffer;
  readonly roleVersionDigests: ReadonlyMap<string, string>;
  readonly metadataBundleSha256s: ReadonlySet<string>;
  readonly orphanTemporaryFiles: readonly string[];
  readonly orphanBundlePaths: readonly string[];
}

export interface AppendAuthenticatedMetadataCheckpointOptions {
  readonly appDataDirectory: string;
  readonly current: LoadedMetadataCheckpointChain;
  readonly metadata: UpdateMetadataBundle;
  readonly policy: MetadataCheckpointPolicy;
  readonly nowUnixMs: number;
}

export interface AppendedAuthenticatedMetadataCheckpoint {
  readonly authenticated: AuthenticatedMetadataSet;
  readonly checkpoint: LoadedMetadataCheckpoint;
  readonly chain: LoadedMetadataCheckpointChain;
}

const BUNDLE_KEYS = [
  "channel",
  "channelName",
  "embeddedRootSha256",
  "schema",
  "sequentialRoots",
  "snapshot",
  "targets",
  "timestamp",
] as const;
const CHECKPOINT_KEYS = [
  "generation",
  "metadataBundleSha256",
  "previousSha256",
  "schema",
  "trustedTimeUnixMs",
] as const;
const BUNDLE_NAME_PATTERN = /^([a-f0-9]{64})\.json$/;
const CHECKPOINT_NAME_PATTERN = /^(\d{16})-([a-f0-9]{64})\.json$/;
const TEMPORARY_NAME_PATTERN = /^\.tmp-[a-f0-9]{32}$/;
const MAX_METADATA_OBJECT_BYTES = 256 * 1024;
const MAX_SEQUENTIAL_ROOTS = 32;
const MAX_SEQUENTIAL_ROOT_BYTES = 2 * 1024 * 1024;
const MAX_NORMAL_METADATA_BYTES = 1024 * 1024;
const MAX_BUNDLE_RECORD_BYTES = 12 * 1024 * 1024;
const MAX_CHECKPOINT_RECORD_BYTES = 16 * 1024;
const MAX_METADATA_RECORDS = 4_096;
const MAX_DATE_UNIX_MS = 8_640_000_000_000_000;

export async function loadMetadataCheckpointChain(
  appDataDirectory: string,
  policy: MetadataCheckpointPolicy,
): Promise<LoadedMetadataCheckpointChain> {
  // Validate the compiled trust anchor even when the checkpoint store is empty.
  // Instantiating TufTrustStore parses and verifies the embedded root.
  const _trustStore = new TufTrustStore(
    policy.embeddedRootBytes,
    policy.embeddedRootSha256,
  );
  void _trustStore;

  const layout = await loadMetadataLayout(appDataDirectory);
  if (!layout) return emptyChain(policy.embeddedRootBytes);

  const bundles = new Map<string, LoadedMetadataBundle>();
  const orphanTemporaryFiles: string[] = [];
  if (layout.bundleDirectory) {
    const entries = await readdir(layout.bundleDirectory, {
      withFileTypes: true,
    });
    if (entries.length > MAX_METADATA_RECORDS) throw stateInvalid();
    for (const entry of entries) {
      const entryPath = path.join(layout.bundleDirectory, entry.name);
      if (entry.isFile() && TEMPORARY_NAME_PATTERN.test(entry.name)) {
        orphanTemporaryFiles.push(entryPath);
        continue;
      }
      const match = BUNDLE_NAME_PATTERN.exec(entry.name);
      if (!entry.isFile() || !match) throw stateInvalid();
      const bundle = await loadBundle(entryPath, match[1]!);
      if (bundles.has(bundle.sha256)) throw stateInvalid();
      bundles.set(bundle.sha256, bundle);
    }
  }

  const checkpointFiles: {
    readonly generation: number;
    readonly sha256: string;
    readonly path: string;
  }[] = [];
  if (layout.checkpointDirectory) {
    const entries = await readdir(layout.checkpointDirectory, {
      withFileTypes: true,
    });
    if (entries.length > MAX_METADATA_RECORDS) throw stateInvalid();
    for (const entry of entries) {
      const entryPath = path.join(layout.checkpointDirectory, entry.name);
      if (entry.isFile() && TEMPORARY_NAME_PATTERN.test(entry.name)) {
        orphanTemporaryFiles.push(entryPath);
        continue;
      }
      const match = CHECKPOINT_NAME_PATTERN.exec(entry.name);
      if (!entry.isFile() || !match) throw stateInvalid();
      const generation = Number(match[1]);
      if (!Number.isSafeInteger(generation) || generation <= 0) {
        throw stateInvalid();
      }
      checkpointFiles.push({
        generation,
        sha256: match[2]!,
        path: entryPath,
      });
    }
  }
  checkpointFiles.sort((left, right) => left.generation - right.generation);

  let trustedMetadata = emptyTrustedMetadataState();
  let currentRootBytes = Buffer.from(policy.embeddedRootBytes);
  let previousSha256: string | null = null;
  const records: LoadedMetadataCheckpoint[] = [];
  const referencedBundles = new Set<string>();
  const roleVersionDigests = new Map<string, string>();

  for (let index = 0; index < checkpointFiles.length; index += 1) {
    const file = checkpointFiles[index]!;
    if (file.generation !== index + 1) throw stateInvalid();
    const bytes = await readImmutableFile(
      file.path,
      MAX_CHECKPOINT_RECORD_BYTES,
      "GOAT_UPDATE_STATE_INVALID",
    );
    if (sha256(bytes) !== file.sha256) throw stateInvalid();
    const record = parseCheckpointRecord(bytes);
    if (
      record.generation !== file.generation ||
      record.previousSha256 !== previousSha256
    ) {
      throw stateInvalid();
    }
    const bundle = bundles.get(record.metadataBundleSha256);
    if (
      !bundle ||
      bundle.record.embeddedRootSha256 !== policy.embeddedRootSha256
    )
      throw stateInvalid();

    let authenticated: AuthenticatedMetadataSet;
    try {
      const sequentialRoots = sequentialRootsAfterCurrent(
        bundle.raw.sequentialRoots,
        currentRootBytes,
        trustedMetadata,
        roleVersionDigests,
      );
      const store = new TufTrustStore(
        currentRootBytes,
        sha256(currentRootBytes),
      );
      authenticated = store.authenticate({
        sequentialRoots,
        timestamp: bundle.raw.timestamp,
        snapshot: bundle.raw.snapshot,
        targets: bundle.raw.targets,
        channel: bundle.raw.channel,
        channelName: bundle.raw.channelName,
        state: trustedMetadata,
        now: new Date(record.trustedTimeUnixMs),
      });
    } catch (error) {
      throw stateInvalid(error);
    }
    if (
      authenticated.nextState.trustedTimeUnixMs !== record.trustedTimeUnixMs
    ) {
      throw stateInvalid();
    }
    recordSequentialRootDigests(bundle.raw.sequentialRoots, roleVersionDigests);
    recordRoleVersionDigests(authenticated, roleVersionDigests);
    trustedMetadata = authenticated.nextState;
    currentRootBytes = Buffer.from(authenticated.root.bytes);
    referencedBundles.add(bundle.sha256);
    records.push({
      record,
      bytes,
      sha256: file.sha256,
      path: file.path,
      bundle,
      authenticated,
    });
    previousSha256 = file.sha256;
  }

  const current = records.at(-1) ?? null;
  return {
    records,
    current,
    head: {
      generation: current?.record.generation ?? 0,
      sha256: current?.sha256 ?? null,
    },
    trustedMetadata,
    currentRootBytes,
    roleVersionDigests,
    metadataBundleSha256s: referencedBundles,
    orphanTemporaryFiles: orphanTemporaryFiles.sort(asciiCompare),
    orphanBundlePaths: [...bundles.values()]
      .filter((bundle) => !referencedBundles.has(bundle.sha256))
      .map((bundle) => bundle.path)
      .sort(asciiCompare),
  };
}

export async function cleanupMetadataCheckpointOrphans(
  appDataDirectory: string,
  current: LoadedMetadataCheckpointChain,
  policy: MetadataCheckpointPolicy,
): Promise<LoadedMetadataCheckpointChain> {
  const actual = await loadMetadataCheckpointChain(appDataDirectory, policy);
  assertSameChain(current, actual);
  if (
    !samePaths(current.orphanTemporaryFiles, actual.orphanTemporaryFiles) ||
    !samePaths(current.orphanBundlePaths, actual.orphanBundlePaths)
  ) {
    throw stateInvalid();
  }
  const temporary = new Set(actual.orphanTemporaryFiles);
  const orphanBundles = new Set(actual.orphanBundlePaths);
  const candidates = [...temporary, ...orphanBundles].sort(asciiCompare);
  for (const candidate of candidates) {
    const parent = path.dirname(candidate);
    const name = path.basename(candidate);
    const isTemporary = temporary.has(candidate);
    const isOrphanBundle = orphanBundles.has(candidate);
    const expectedParent = isOrphanBundle
      ? bundleDirectory(appDataDirectory)
      : parent;
    if (
      path.resolve(parent) !== path.resolve(expectedParent) ||
      (isTemporary && !TEMPORARY_NAME_PATTERN.test(name)) ||
      (isOrphanBundle && !BUNDLE_NAME_PATTERN.test(name)) ||
      (!isTemporary && !isOrphanBundle) ||
      (isTemporary &&
        path.resolve(parent) !==
          path.resolve(bundleDirectory(appDataDirectory)) &&
        path.resolve(parent) !==
          path.resolve(checkpointDirectory(appDataDirectory)))
    ) {
      throw stateInvalid();
    }
    const stats = await lstat(candidate).catch((error) => {
      throw stateInvalid(error);
    });
    if (!stats.isFile() || stats.isSymbolicLink() || stats.nlink !== 1) {
      throw stateInvalid();
    }
    await unlink(candidate).catch((error) => {
      throw stateInvalid(error);
    });
    await syncDirectory(parent, "GOAT_UPDATE_STATE_INVALID");
  }
  const cleaned = await loadMetadataCheckpointChain(appDataDirectory, policy);
  assertSameChain(actual, cleaned);
  if (
    cleaned.orphanTemporaryFiles.length !== 0 ||
    cleaned.orphanBundlePaths.length !== 0
  ) {
    throw stateInvalid();
  }
  return cleaned;
}

export async function authenticateAndAppendMetadataCheckpoint(
  options: AppendAuthenticatedMetadataCheckpointOptions,
): Promise<AppendedAuthenticatedMetadataCheckpoint> {
  const nowUnixMs = expectTrustedTime(options.nowUnixMs);
  const bundleRecord = metadataBundleRecord(options.metadata, options.policy);
  const bundleBytes = canonicalJsonBytes(bundleRecord as unknown as JsonValue);
  if (bundleBytes.byteLength > MAX_BUNDLE_RECORD_BYTES) throw stateInvalid();

  const actual = await loadMetadataCheckpointChain(
    options.appDataDirectory,
    options.policy,
  );
  assertSameChain(options.current, actual);

  const sequentialRoots = sequentialRootsAfterCurrent(
    options.metadata.sequentialRoots,
    actual.currentRootBytes,
    actual.trustedMetadata,
    actual.roleVersionDigests,
  );
  const store = new TufTrustStore(
    actual.currentRootBytes,
    sha256(actual.currentRootBytes),
  );
  const authenticated = store.authenticate({
    sequentialRoots,
    timestamp: options.metadata.timestamp,
    snapshot: options.metadata.snapshot,
    targets: options.metadata.targets,
    channel: options.metadata.channel,
    channelName: options.metadata.channelName,
    state: actual.trustedMetadata,
    now: new Date(nowUnixMs),
  });

  // Authentication and capacity validation are both complete before the first
  // filesystem mutation. This prevents a capacity failure from leaving an
  // unreferenced bundle that makes the next strict reload exceed its limit.
  await assertAppendCapacity(options.appDataDirectory, sha256(bundleBytes));
  const bundle = await persistOrLoadBundle(
    options.appDataDirectory,
    bundleBytes,
  );
  const beforeAppend = await loadMetadataCheckpointChain(
    options.appDataDirectory,
    options.policy,
  );
  assertSameChain(actual, beforeAppend);

  const checkpointRecord: MetadataCheckpointRecord = {
    schema: 1,
    generation: beforeAppend.head.generation + 1,
    previousSha256: beforeAppend.head.sha256,
    metadataBundleSha256: bundle.sha256,
    trustedTimeUnixMs: authenticated.nextState.trustedTimeUnixMs,
  };
  const checkpointBytes = canonicalJsonBytes(
    checkpointRecord as unknown as JsonValue,
  );
  const checkpointSha256 = sha256(checkpointBytes);
  const checkpointName = `${String(checkpointRecord.generation).padStart(
    16,
    "0",
  )}-${checkpointSha256}.json`;
  await writeImmutableFile(
    checkpointDirectory(options.appDataDirectory),
    checkpointName,
    checkpointBytes,
    "GOAT_UPDATE_STATE_INVALID",
  );

  const chain = await loadMetadataCheckpointChain(
    options.appDataDirectory,
    options.policy,
  );
  if (
    chain.head.generation !== checkpointRecord.generation ||
    chain.head.sha256 !== checkpointSha256
  ) {
    throw stateInvalid();
  }
  return {
    authenticated,
    checkpoint: chain.current!,
    chain,
  };
}

function metadataBundleRecord(
  raw: UpdateMetadataBundle,
  policy: MetadataCheckpointPolicy,
): AuthenticatedMetadataBundleRecord {
  if (raw.sequentialRoots.length > MAX_SEQUENTIAL_ROOTS) throw stateInvalid();
  const sequentialBytes = raw.sequentialRoots.reduce(
    (total, root) => total + root.byteLength,
    0,
  );
  const normalBytes =
    raw.timestamp.byteLength +
    raw.snapshot.byteLength +
    raw.targets.byteLength +
    raw.channel.byteLength;
  if (
    sequentialBytes > MAX_SEQUENTIAL_ROOT_BYTES ||
    normalBytes > MAX_NORMAL_METADATA_BYTES
  ) {
    throw stateInvalid();
  }
  return {
    schema: 1,
    embeddedRootSha256: expectSha256(policy.embeddedRootSha256),
    sequentialRoots: raw.sequentialRoots.map(encodeMetadata),
    timestamp: encodeMetadata(raw.timestamp),
    snapshot: encodeMetadata(raw.snapshot),
    targets: encodeMetadata(raw.targets),
    channel: encodeMetadata(raw.channel),
    channelName: expectChannel(raw.channelName),
  };
}

async function assertAppendCapacity(
  appDataDirectory: string,
  bundleSha256: string,
): Promise<void> {
  const layout = await loadMetadataLayout(appDataDirectory);
  if (!layout) return;

  if (layout.checkpointDirectory) {
    const entries = await readdir(layout.checkpointDirectory, {
      withFileTypes: true,
    });
    if (entries.length >= MAX_METADATA_RECORDS) throw stateInvalid();
  }

  if (layout.bundleDirectory) {
    const entries = await readdir(layout.bundleDirectory, {
      withFileTypes: true,
    });
    const existingName = `${bundleSha256}.json`;
    const bundleAlreadyExists = entries.some(
      (entry) => entry.isFile() && entry.name === existingName,
    );
    if (entries.length >= MAX_METADATA_RECORDS && !bundleAlreadyExists) {
      throw stateInvalid();
    }
  }
}
async function persistOrLoadBundle(
  appDataDirectory: string,
  bytes: Buffer,
): Promise<LoadedMetadataBundle> {
  const digest = sha256(bytes);
  const destination = path.join(
    bundleDirectory(appDataDirectory),
    `${digest}.json`,
  );
  try {
    await lstat(destination);
    const existing = await loadBundle(destination, digest);
    if (!existing.bytes.equals(bytes)) throw stateInvalid();
    return existing;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  const written = await writeImmutableFile(
    bundleDirectory(appDataDirectory),
    `${digest}.json`,
    bytes,
    "GOAT_UPDATE_STATE_INVALID",
  );
  return loadBundle(written, digest);
}

async function loadBundle(
  bundlePath: string,
  expectedSha256: string,
): Promise<LoadedMetadataBundle> {
  const bytes = await readImmutableFile(
    bundlePath,
    MAX_BUNDLE_RECORD_BYTES,
    "GOAT_UPDATE_STATE_INVALID",
  );
  if (sha256(bytes) !== expectedSha256) throw stateInvalid();
  const record = parseBundleRecord(bytes);
  return {
    record,
    raw: {
      sequentialRoots: record.sequentialRoots.map(decodeMetadata),
      timestamp: decodeMetadata(record.timestamp),
      snapshot: decodeMetadata(record.snapshot),
      targets: decodeMetadata(record.targets),
      channel: decodeMetadata(record.channel),
      channelName: record.channelName,
    },
    bytes,
    sha256: expectedSha256,
    path: bundlePath,
  };
}

function parseBundleRecord(
  bytes: Uint8Array,
): AuthenticatedMetadataBundleRecord {
  const value = parseCanonicalJson(bytes, {
    maxBytes: MAX_BUNDLE_RECORD_BYTES,
    errorCode: "GOAT_UPDATE_STATE_INVALID",
  });
  const record = expectExactObject(value, BUNDLE_KEYS);
  if (
    !Array.isArray(record.sequentialRoots) ||
    record.sequentialRoots.length > MAX_SEQUENTIAL_ROOTS
  ) {
    throw stateInvalid();
  }
  const parsed: AuthenticatedMetadataBundleRecord = {
    schema: expectLiteral(record.schema, 1),
    embeddedRootSha256: expectSha256(record.embeddedRootSha256),
    sequentialRoots: record.sequentialRoots.map(expectEncodedMetadata),
    timestamp: expectEncodedMetadata(record.timestamp),
    snapshot: expectEncodedMetadata(record.snapshot),
    targets: expectEncodedMetadata(record.targets),
    channel: expectEncodedMetadata(record.channel),
    channelName: expectChannel(record.channelName),
  };
  const sequentialBytes = parsed.sequentialRoots.reduce(
    (total, encoded) => total + decodeMetadata(encoded).byteLength,
    0,
  );
  const normalBytes = [
    parsed.timestamp,
    parsed.snapshot,
    parsed.targets,
    parsed.channel,
  ].reduce((total, encoded) => total + decodeMetadata(encoded).byteLength, 0);
  if (
    sequentialBytes > MAX_SEQUENTIAL_ROOT_BYTES ||
    normalBytes > MAX_NORMAL_METADATA_BYTES
  ) {
    throw stateInvalid();
  }
  return parsed;
}

function parseCheckpointRecord(bytes: Uint8Array): MetadataCheckpointRecord {
  const value = parseCanonicalJson(bytes, {
    maxBytes: MAX_CHECKPOINT_RECORD_BYTES,
    errorCode: "GOAT_UPDATE_STATE_INVALID",
  });
  const record = expectExactObject(value, CHECKPOINT_KEYS);
  const generation = expectPositiveInteger(record.generation);
  const previousSha256 = expectNullableSha256(record.previousSha256);
  if ((generation === 1) !== (previousSha256 === null)) throw stateInvalid();
  return {
    schema: expectLiteral(record.schema, 1),
    generation,
    previousSha256,
    metadataBundleSha256: expectSha256(record.metadataBundleSha256),
    trustedTimeUnixMs: expectTrustedTime(record.trustedTimeUnixMs),
  };
}

async function loadMetadataLayout(appDataDirectory: string): Promise<{
  readonly bundleDirectory: string | null;
  readonly checkpointDirectory: string | null;
} | null> {
  const root = metadataDirectory(appDataDirectory);
  try {
    await lstat(root);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw stateInvalid(error);
  }
  await assertPrivateDirectory(root, "GOAT_UPDATE_STATE_INVALID");
  const entries = await readdir(root, { withFileTypes: true });
  let bundles: string | null = null;
  let checkpoints: string | null = null;
  for (const entry of entries) {
    if (
      !entry.isDirectory() ||
      entry.isSymbolicLink() ||
      (entry.name !== "bundles" && entry.name !== "checkpoints")
    ) {
      throw stateInvalid();
    }
    const candidate = path.join(root, entry.name);
    await assertPrivateDirectory(candidate, "GOAT_UPDATE_STATE_INVALID");
    if (entry.name === "bundles") bundles = candidate;
    else checkpoints = candidate;
  }
  return {
    bundleDirectory: bundles,
    checkpointDirectory: checkpoints,
  };
}

function sequentialRootsAfterCurrent(
  rawRoots: readonly Uint8Array[],
  currentRootBytes: Uint8Array,
  state: TrustedMetadataState,
  knownRoleVersionDigests: ReadonlyMap<string, string>,
): readonly Uint8Array[] {
  const currentRoot = parseRootMetadata(currentRootBytes);
  const currentVersion = currentRoot.metadata.signed.version;
  const currentDigest = sha256(currentRootBytes);
  const recordedCurrentDigest = knownRoleVersionDigests.get(
    `root:${currentVersion}`,
  );

  if (
    (state.versions.root > 0 &&
      (state.versions.root !== currentVersion ||
        state.digests.root !== currentDigest)) ||
    (recordedCurrentDigest !== undefined &&
      recordedCurrentDigest !== currentDigest)
  ) {
    throw metadataReplayed();
  }

  let previousVersion: number | null = null;
  let sawHistoricalRoot = false;
  let sawCurrentRoot = false;
  let firstFutureVersion: number | null = null;
  const futureRoots: Uint8Array[] = [];

  for (const rawRoot of rawRoots) {
    const parsed = parseRootMetadata(rawRoot);
    const version = parsed.metadata.signed.version;
    if (previousVersion !== null && version !== previousVersion + 1) {
      throw metadataReplayed();
    }
    previousVersion = version;

    if (version <= currentVersion) {
      sawHistoricalRoot = true;
      const expectedDigest =
        version === currentVersion
          ? currentDigest
          : knownRoleVersionDigests.get(`root:${version}`);
      if (expectedDigest === undefined || expectedDigest !== sha256(rawRoot)) {
        throw metadataReplayed();
      }
      if (version === currentVersion) sawCurrentRoot = true;
      continue;
    }

    firstFutureVersion ??= version;
    futureRoots.push(rawRoot);
  }

  if (
    (sawHistoricalRoot && !sawCurrentRoot) ||
    (firstFutureVersion !== null && firstFutureVersion !== currentVersion + 1)
  ) {
    throw metadataReplayed();
  }
  return futureRoots;
}

function recordSequentialRootDigests(
  rawRoots: readonly Uint8Array[],
  digests: Map<string, string>,
): void {
  for (const rawRoot of rawRoots) {
    const parsed = parseRootMetadata(rawRoot);
    recordRoleVersionDigest(
      `root:${parsed.metadata.signed.version}`,
      sha256(rawRoot),
      digests,
    );
  }
}

function recordRoleVersionDigest(
  identity: string,
  digest: string,
  digests: Map<string, string>,
): void {
  const existing = digests.get(identity);
  if (existing !== undefined && existing !== digest) throw stateInvalid();
  digests.set(identity, digest);
}

function recordRoleVersionDigests(
  authenticated: AuthenticatedMetadataSet,
  digests: Map<string, string>,
): void {
  for (const [role, parsed] of authenticatedRoles(authenticated)) {
    const identity = `${role}:${parsed.metadata.signed.version}`;
    recordRoleVersionDigest(identity, sha256(parsed.bytes), digests);
  }
}

type AuthenticatedRole =
  | AuthenticatedMetadataSet["root"]
  | AuthenticatedMetadataSet["timestamp"]
  | AuthenticatedMetadataSet["snapshot"]
  | AuthenticatedMetadataSet["targets"]
  | AuthenticatedMetadataSet["channel"];

function authenticatedRoles(
  metadata: AuthenticatedMetadataSet,
): readonly [keyof TrustedMetadataVersions, AuthenticatedRole][] {
  return [
    ["root", metadata.root],
    ["timestamp", metadata.timestamp],
    ["snapshot", metadata.snapshot],
    ["targets", metadata.targets],
    [metadata.channel.roleName as UpdateChannel, metadata.channel],
  ];
}

function assertSameChain(
  expected: LoadedMetadataCheckpointChain,
  actual: LoadedMetadataCheckpointChain,
): void {
  if (
    expected.head.generation !== actual.head.generation ||
    expected.head.sha256 !== actual.head.sha256
  ) {
    throw stateInvalid();
  }
}

function samePaths(left: readonly string[], right: readonly string[]): boolean {
  return (
    left.length === right.length &&
    left.every((value, index) => value === right[index])
  );
}

function emptyChain(
  embeddedRootBytes: Uint8Array,
): LoadedMetadataCheckpointChain {
  return {
    records: [],
    current: null,
    head: { generation: 0, sha256: null },
    trustedMetadata: emptyTrustedMetadataState(),
    currentRootBytes: Buffer.from(embeddedRootBytes),
    roleVersionDigests: new Map(),
    metadataBundleSha256s: new Set(),
    orphanTemporaryFiles: [],
    orphanBundlePaths: [],
  };
}

function expectExactObject(
  value: JsonValue | unknown,
  keys: readonly string[],
): JsonObject {
  if (!isJsonObject(value) || !hasExactJsonKeys(value, keys)) {
    throw stateInvalid();
  }
  return value;
}

function expectLiteral<T extends JsonValue>(value: unknown, expected: T): T {
  if (value !== expected) throw stateInvalid();
  return expected;
}

function expectChannel(value: unknown): UpdateChannel {
  if (value !== "stable" && value !== "beta" && value !== "development") {
    throw stateInvalid();
  }
  return value;
}

function expectPositiveInteger(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) <= 0) {
    throw stateInvalid();
  }
  return value as number;
}

function expectTrustedTime(value: unknown): number {
  if (
    !Number.isSafeInteger(value) ||
    (value as number) < 0 ||
    (value as number) > MAX_DATE_UNIX_MS
  ) {
    throw stateInvalid();
  }
  return value as number;
}

function expectNullableSha256(value: unknown): string | null {
  return value === null ? null : expectSha256(value);
}

function expectSha256(value: unknown): string {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) {
    throw stateInvalid();
  }
  return value;
}

function encodeMetadata(bytes: Uint8Array): string {
  if (bytes.byteLength === 0 || bytes.byteLength > MAX_METADATA_OBJECT_BYTES) {
    throw stateInvalid();
  }
  return Buffer.from(bytes).toString("base64url");
}

function expectEncodedMetadata(value: unknown): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > Math.ceil((MAX_METADATA_OBJECT_BYTES * 4) / 3) ||
    !/^[A-Za-z0-9_-]+$/.test(value)
  ) {
    throw stateInvalid();
  }
  decodeMetadata(value);
  return value;
}

function decodeMetadata(value: string): Buffer {
  const decoded = Buffer.from(value, "base64url");
  if (
    decoded.byteLength === 0 ||
    decoded.byteLength > MAX_METADATA_OBJECT_BYTES ||
    decoded.toString("base64url") !== value
  ) {
    throw stateInvalid();
  }
  return decoded;
}

function metadataDirectory(appDataDirectory: string): string {
  return path.join(path.resolve(appDataDirectory), "updates", "metadata");
}

function bundleDirectory(appDataDirectory: string): string {
  return path.join(metadataDirectory(appDataDirectory), "bundles");
}

function checkpointDirectory(appDataDirectory: string): string {
  return path.join(metadataDirectory(appDataDirectory), "checkpoints");
}

function sha256(value: Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function asciiCompare(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function metadataReplayed(): UpdateError {
  return new UpdateError("GOAT_UPDATE_METADATA_REPLAYED");
}

function stateInvalid(cause?: unknown): UpdateError {
  return new UpdateError("GOAT_UPDATE_STATE_INVALID", { cause });
}
