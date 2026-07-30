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
  ParsedTufMetadata,
  TopLevelRevocations,
  TufRoleName,
} from "./metadata.js";
import {
  selectAuthenticatedArtifact,
  type KnownReleaseIdentity,
} from "./selection.js";
import type {
  AuthenticatedTarget,
  UpdateArchitecture,
  UpdateChannel,
  UpdatePlatform,
} from "./schema.js";
import {
  emptyTrustedMetadataState,
  TufTrustStore,
  type AuthenticatedMetadataSet,
  type TrustedMetadataDigests,
  type TrustedMetadataState,
  type TrustedMetadataVersions,
} from "./trust.js";

export interface TargetReceiptInput {
  readonly embeddedRootSha256: string;
  readonly sequentialRoots: readonly Uint8Array[];
  readonly timestamp: Uint8Array;
  readonly snapshot: Uint8Array;
  readonly targets: Uint8Array;
  readonly channel: Uint8Array;
  readonly channelName: UpdateChannel;
  readonly targetPath: string;
  readonly authenticatedAtUnixMs: number;
}

export interface TargetReceiptRecord {
  readonly schema: 1;
  readonly embeddedRootSha256: string;
  readonly sequentialRoots: readonly string[];
  readonly timestamp: string;
  readonly snapshot: string;
  readonly targets: string;
  readonly channel: string;
  readonly channelName: UpdateChannel;
  readonly targetPath: string;
  readonly artifactLength: number;
  readonly artifactSha256: string;
  readonly releaseSequence: number;
  readonly productVersion: string;
  readonly authenticatedAtUnixMs: number;
}

export interface ReceiptVerificationPolicy {
  readonly embeddedRootBytes: Uint8Array;
  readonly embeddedRootSha256: string;
  readonly launcherVersion: string;
  readonly platform: UpdatePlatform;
  readonly architecture: UpdateArchitecture;
  readonly currentRevocations?: TopLevelRevocations;
}

export interface VerifiedTargetReceipt {
  readonly record: TargetReceiptRecord;
  readonly receiptSha256: string;
  readonly metadata: AuthenticatedMetadataSet;
  readonly target: AuthenticatedTarget;
  readonly release: KnownReleaseIdentity;
}

export interface PersistedTargetReceipt extends VerifiedTargetReceipt {
  readonly path: string;
  readonly bytes: Buffer;
}

export interface ReceiptReconstruction {
  readonly trustedMetadata: TrustedMetadataState;
  readonly maxAuthenticatedReleaseSequence: number;
  readonly knownReleases: readonly KnownReleaseIdentity[];
  readonly receiptDigests: readonly string[];
  readonly currentRevocations: TopLevelRevocations;
  readonly verifiedReceipts: readonly VerifiedTargetReceipt[];
  readonly orphanTemporaryFiles: readonly string[];
}

const MAX_RECEIPT_BYTES = 12 * 1024 * 1024;
const MAX_METADATA_BYTES = 256 * 1024;
const RECEIPT_NAME_PATTERN = /^([a-f0-9]{64})\.json$/;
const TEMPORARY_RECEIPT_PATTERN = /^\.tmp-[a-f0-9]{32}$/;
const RECEIPT_KEYS = [
  "artifactLength",
  "artifactSha256",
  "authenticatedAtUnixMs",
  "channel",
  "channelName",
  "embeddedRootSha256",
  "productVersion",
  "releaseSequence",
  "schema",
  "sequentialRoots",
  "snapshot",
  "targetPath",
  "targets",
  "timestamp",
] as const;
const ROLES = [
  "root",
  "timestamp",
  "snapshot",
  "targets",
  "stable",
  "beta",
  "development",
] as const;

export async function persistTargetReceipt(
  appDataDirectory: string,
  input: TargetReceiptInput,
  policy: ReceiptVerificationPolicy,
): Promise<PersistedTargetReceipt> {
  if (input.embeddedRootSha256 !== policy.embeddedRootSha256) {
    throw new UpdateError("GOAT_UPDATE_SIGNATURE_INVALID");
  }
  const provisional = provisionalRecord(input);
  const authenticated = authenticateReceiptRecord(provisional, policy);
  const record: TargetReceiptRecord = {
    ...provisional,
    artifactLength: authenticated.target.length,
    artifactSha256: authenticated.target.sha256,
    releaseSequence: authenticated.target.custom.releaseSequence,
    productVersion: authenticated.target.custom.productVersion,
  };
  const bytes = canonicalJsonBytes(record as unknown as JsonValue);
  const verified = verifyTargetReceiptBytes(bytes, policy);
  const receiptSha256 = sha256(bytes);
  const receiptPath = await writeImmutableFile(
    receiptDirectory(appDataDirectory),
    `${receiptSha256}.json`,
    bytes,
    "GOAT_UPDATE_STATE_INVALID",
  );
  return { ...verified, path: receiptPath, bytes };
}

export async function loadTargetReceipt(
  appDataDirectory: string,
  receiptSha256: string,
  policy: ReceiptVerificationPolicy,
): Promise<PersistedTargetReceipt> {
  assertSha256(receiptSha256);
  const receiptPath = path.join(
    receiptDirectory(appDataDirectory),
    `${receiptSha256}.json`,
  );
  const bytes = await readImmutableFile(
    receiptPath,
    MAX_RECEIPT_BYTES,
    "GOAT_UPDATE_STATE_INVALID",
  );
  const verified = verifyTargetReceiptBytes(bytes, policy);
  if (verified.receiptSha256 !== receiptSha256) {
    throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
  }
  return { ...verified, path: receiptPath, bytes };
}

export function verifyTargetReceiptBytes(
  bytes: Uint8Array,
  policy: ReceiptVerificationPolicy,
): VerifiedTargetReceipt {
  const receiptSha256 = sha256(bytes);
  const record = parseTargetReceipt(bytes);
  const authenticated = authenticateReceiptRecord(record, policy);
  const target = authenticated.target;
  if (
    target.targetPath !== record.targetPath ||
    target.length !== record.artifactLength ||
    target.sha256 !== record.artifactSha256 ||
    target.custom.releaseSequence !== record.releaseSequence ||
    target.custom.productVersion !== record.productVersion
  ) {
    throw new UpdateError("GOAT_UPDATE_METADATA_MISMATCH");
  }
  return {
    record,
    receiptSha256,
    metadata: authenticated.metadata,
    target,
    release: releaseIdentity(target),
  };
}

function authenticateReceiptRecord(
  record: TargetReceiptRecord,
  policy: ReceiptVerificationPolicy,
): {
  readonly metadata: AuthenticatedMetadataSet;
  readonly target: AuthenticatedTarget;
} {
  if (
    record.embeddedRootSha256 !== policy.embeddedRootSha256 ||
    sha256(policy.embeddedRootBytes) !== policy.embeddedRootSha256
  ) {
    throw new UpdateError("GOAT_UPDATE_SIGNATURE_INVALID");
  }
  const raw = decodeReceiptMetadata(record);
  const store = new TufTrustStore(
    policy.embeddedRootBytes,
    policy.embeddedRootSha256,
  );
  const metadata = store.authenticateInstalledReceipt({
    sequentialRoots: raw.sequentialRoots,
    timestamp: raw.timestamp,
    snapshot: raw.snapshot,
    targets: raw.targets,
    channel: raw.channel,
    channelName: record.channelName,
    state: emptyTrustedMetadataState(new Date(0)),
    now: new Date(record.authenticatedAtUnixMs),
  });
  const current = policy.currentRevocations ?? emptyRevocations();
  assertNoCurrentlyRevokedSigner(metadata, current.revokedKeyIds);
  const revocations = mergeRevocations(metadata.revocations, current);
  const selected = selectAuthenticatedArtifact(
    metadata.channel,
    {
      channel: record.channelName,
      platform: policy.platform,
      architecture: policy.architecture,
      launcherVersion: policy.launcherVersion,
      maxAuthenticatedReleaseSequence: 0,
      maxActivatedReleaseSequence: 0,
    },
    revocations,
  );
  return { metadata, target: selected.target };
}

export async function reconstructStateFromReceipts(
  appDataDirectory: string,
  policy: Omit<ReceiptVerificationPolicy, "currentRevocations">,
): Promise<ReceiptReconstruction | null> {
  const temporary =
    await listTargetReceiptOrphanTemporaryFiles(appDataDirectory);
  const directory = receiptDirectory(appDataDirectory);
  let entries;
  try {
    entries = await readdir(directory, { withFileTypes: true });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw new UpdateError("GOAT_UPDATE_STATE_INVALID", { cause: error });
  }
  const receipts: VerifiedTargetReceipt[] = [];
  for (const entry of entries) {
    if (entry.isFile() && TEMPORARY_RECEIPT_PATTERN.test(entry.name)) {
      continue;
    }
    const match = RECEIPT_NAME_PATTERN.exec(entry.name);
    if (!entry.isFile() || !match) {
      throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
    }
    const bytes = await readImmutableFile(
      path.join(directory, entry.name),
      MAX_RECEIPT_BYTES,
      "GOAT_UPDATE_STATE_INVALID",
    );
    const verified = verifyTargetReceiptBytes(bytes, policy);
    if (verified.receiptSha256 !== match[1]) {
      throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
    }
    receipts.push(verified);
  }
  if (receipts.length === 0) return null;
  receipts.sort(
    (left, right) =>
      left.release.releaseSequence - right.release.releaseSequence,
  );
  assertConsistentReceiptHistory(receipts);

  const currentRevocations = receipts
    .map((receipt) => receipt.metadata)
    .sort(
      (left, right) =>
        left.targets.metadata.signed.version -
        right.targets.metadata.signed.version,
    )
    .at(-1)!.revocations;
  const versions = emptyTrustedMetadataState().versions as Record<
    keyof TrustedMetadataVersions,
    number
  >;
  const digests: Record<string, string> = {};
  const seenVersions = new Map<string, string>();
  let trustedTimeUnixMs = 0;
  for (const receipt of receipts) {
    trustedTimeUnixMs = Math.max(
      trustedTimeUnixMs,
      receipt.record.authenticatedAtUnixMs,
    );
    for (const [role, parsed] of metadataRoles(receipt.metadata)) {
      const version = parsed.metadata.signed.version;
      const digest = sha256(parsed.bytes);
      const identity = `${role}:${version}`;
      const existing = seenVersions.get(identity);
      if (existing && existing !== digest) {
        throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
      }
      seenVersions.set(identity, digest);
      if (version > versions[role]) {
        versions[role] = version;
        digests[role] = digest;
      }
    }
  }
  const knownReleases = receipts.map((receipt) => receipt.release);
  return {
    trustedMetadata: {
      versions: versions as unknown as TrustedMetadataVersions,
      digests: digests as TrustedMetadataDigests,
      trustedTimeUnixMs,
      revokedKeyIds: currentRevocations.revokedKeyIds,
      revokedArtifactSha256: currentRevocations.revokedArtifactSha256,
      revokedReleaseSequences: currentRevocations.revokedReleaseSequences,
    },
    maxAuthenticatedReleaseSequence: knownReleases.at(-1)!.releaseSequence,
    knownReleases,
    receiptDigests: receipts
      .map((receipt) => receipt.receiptSha256)
      .sort(asciiCompare),
    currentRevocations,
    verifiedReceipts: receipts,
    orphanTemporaryFiles: temporary,
  };
}

export async function listTargetReceiptOrphanTemporaryFiles(
  appDataDirectory: string,
): Promise<readonly string[]> {
  const directory = receiptDirectory(appDataDirectory);
  let entries;
  try {
    entries = await readdir(directory, { withFileTypes: true });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw new UpdateError("GOAT_UPDATE_STATE_INVALID", { cause: error });
  }
  const temporary: string[] = [];
  for (const entry of entries) {
    if (entry.isFile() && TEMPORARY_RECEIPT_PATTERN.test(entry.name)) {
      temporary.push(path.join(directory, entry.name));
      continue;
    }
    if (!entry.isFile() || !RECEIPT_NAME_PATTERN.test(entry.name)) {
      throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
    }
  }
  return temporary.sort(asciiCompare);
}

function provisionalRecord(input: TargetReceiptInput): TargetReceiptRecord {
  if (
    input.sequentialRoots.length > 32 ||
    !Number.isSafeInteger(input.authenticatedAtUnixMs) ||
    input.authenticatedAtUnixMs < 0
  ) {
    throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
  }
  return {
    schema: 1,
    embeddedRootSha256: input.embeddedRootSha256,
    sequentialRoots: input.sequentialRoots.map(encodeMetadata),
    timestamp: encodeMetadata(input.timestamp),
    snapshot: encodeMetadata(input.snapshot),
    targets: encodeMetadata(input.targets),
    channel: encodeMetadata(input.channel),
    channelName: input.channelName,
    targetPath: input.targetPath,
    artifactLength: 1,
    artifactSha256: "0".repeat(64),
    releaseSequence: 1,
    productVersion: "0.0.0",
    authenticatedAtUnixMs: input.authenticatedAtUnixMs,
  };
}

function parseTargetReceipt(bytes: Uint8Array): TargetReceiptRecord {
  const value = parseCanonicalJson(bytes, {
    maxBytes: MAX_RECEIPT_BYTES,
    errorCode: "GOAT_UPDATE_STATE_INVALID",
  });
  const record = expectExactObject(value, RECEIPT_KEYS);
  if (
    !Array.isArray(record.sequentialRoots) ||
    record.sequentialRoots.length > 32
  ) {
    throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
  }
  return {
    schema: expectLiteral(record.schema, 1),
    embeddedRootSha256: expectSha256(record.embeddedRootSha256),
    sequentialRoots: record.sequentialRoots.map(expectEncodedMetadata),
    timestamp: expectEncodedMetadata(record.timestamp),
    snapshot: expectEncodedMetadata(record.snapshot),
    targets: expectEncodedMetadata(record.targets),
    channel: expectEncodedMetadata(record.channel),
    channelName: expectChannel(record.channelName),
    targetPath: expectTargetPath(record.targetPath),
    artifactLength: expectPositiveInteger(record.artifactLength),
    artifactSha256: expectSha256(record.artifactSha256),
    releaseSequence: expectPositiveInteger(record.releaseSequence),
    productVersion: expectVersionToken(record.productVersion),
    authenticatedAtUnixMs: expectNonnegativeInteger(
      record.authenticatedAtUnixMs,
    ),
  };
}

function decodeReceiptMetadata(record: TargetReceiptRecord) {
  return {
    sequentialRoots: record.sequentialRoots.map(decodeMetadata),
    timestamp: decodeMetadata(record.timestamp),
    snapshot: decodeMetadata(record.snapshot),
    targets: decodeMetadata(record.targets),
    channel: decodeMetadata(record.channel),
  };
}

function assertConsistentReceiptHistory(
  receipts: readonly VerifiedTargetReceipt[],
): void {
  const sequences = new Set<number>();
  const versions = new Map<string, string>();
  let previousRevocations = emptyRevocations();
  const byTargetsVersion = [...receipts].sort(
    (left, right) =>
      left.metadata.targets.metadata.signed.version -
      right.metadata.targets.metadata.signed.version,
  );
  for (const receipt of receipts) {
    if (sequences.has(receipt.release.releaseSequence)) {
      throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
    }
    sequences.add(receipt.release.releaseSequence);
    for (const known of receipts) {
      if (
        known !== receipt &&
        known.release.productVersion === receipt.release.productVersion &&
        known.release.artifactSha256 !== receipt.release.artifactSha256
      ) {
        throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
      }
    }
    for (const [role, parsed] of metadataRoles(receipt.metadata)) {
      const key = `${role}:${parsed.metadata.signed.version}`;
      const digest = sha256(parsed.bytes);
      if (versions.has(key) && versions.get(key) !== digest) {
        throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
      }
      versions.set(key, digest);
    }
  }
  for (const receipt of byTargetsVersion) {
    const next = receipt.metadata.revocations;
    if (
      !isSuperset(next.revokedKeyIds, previousRevocations.revokedKeyIds) ||
      !isSuperset(
        next.revokedArtifactSha256,
        previousRevocations.revokedArtifactSha256,
      ) ||
      !isSuperset(
        next.revokedReleaseSequences,
        previousRevocations.revokedReleaseSequences,
      )
    ) {
      throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
    }
    previousRevocations = next;
  }
}

function assertNoCurrentlyRevokedSigner(
  metadata: AuthenticatedMetadataSet,
  revokedKeyIds: readonly string[],
): void {
  const revoked = new Set(revokedKeyIds);
  for (const [, parsed] of metadataRoles(metadata)) {
    const signatures = parsed.json.signatures;
    if (!Array.isArray(signatures))
      throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
    for (const signature of signatures) {
      if (
        isJsonObject(signature) &&
        typeof signature.keyid === "string" &&
        revoked.has(signature.keyid)
      ) {
        throw new UpdateError("GOAT_UPDATE_SIGNING_KEY_REVOKED");
      }
    }
  }
}

function metadataRoles(
  metadata: AuthenticatedMetadataSet,
): readonly [keyof TrustedMetadataVersions, ParsedTufMetadata<any>][] {
  return [
    ["root", metadata.root],
    ["timestamp", metadata.timestamp],
    ["snapshot", metadata.snapshot],
    ["targets", metadata.targets],
    [metadata.channel.roleName as UpdateChannel, metadata.channel],
  ];
}

function releaseIdentity(target: AuthenticatedTarget): KnownReleaseIdentity {
  return {
    releaseSequence: target.custom.releaseSequence,
    channel: target.custom.channel,
    productVersion: target.custom.productVersion,
    artifactSha256: target.sha256,
  };
}

function mergeRevocations(
  left: TopLevelRevocations,
  right: TopLevelRevocations,
): TopLevelRevocations {
  return {
    goatRevocationSchema: 1,
    revokedKeyIds: union(left.revokedKeyIds, right.revokedKeyIds),
    revokedArtifactSha256: union(
      left.revokedArtifactSha256,
      right.revokedArtifactSha256,
    ),
    revokedReleaseSequences: unionNumbers(
      left.revokedReleaseSequences,
      right.revokedReleaseSequences,
    ),
  };
}

function emptyRevocations(): TopLevelRevocations {
  return {
    goatRevocationSchema: 1,
    revokedKeyIds: [],
    revokedArtifactSha256: [],
    revokedReleaseSequences: [],
  };
}

function encodeMetadata(bytes: Uint8Array): string {
  if (bytes.byteLength === 0 || bytes.byteLength > MAX_METADATA_BYTES) {
    throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
  }
  return Buffer.from(bytes).toString("base64url");
}

function decodeMetadata(value: string): Buffer {
  const decoded = Buffer.from(value, "base64url");
  if (
    decoded.byteLength === 0 ||
    decoded.byteLength > MAX_METADATA_BYTES ||
    decoded.toString("base64url") !== value
  ) {
    throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
  }
  return decoded;
}

function expectEncodedMetadata(value: unknown): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > Math.ceil((MAX_METADATA_BYTES * 4) / 3) ||
    !/^[A-Za-z0-9_-]+$/.test(value)
  ) {
    throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
  }
  decodeMetadata(value);
  return value;
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

function expectLiteral<T extends JsonValue>(value: unknown, expected: T): T {
  if (value !== expected) throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
  return expected;
}

function expectChannel(value: unknown): UpdateChannel {
  if (value !== "stable" && value !== "beta" && value !== "development") {
    throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
  }
  return value;
}

function expectTargetPath(value: unknown): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 256 ||
    !/^goat-engine\/(?:stable|beta|development)\/[A-Za-z0-9.-]+\/(?:win32|darwin)-(?:x64|arm64)\/goat-engine\.zip$/.test(
      value,
    )
  ) {
    throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
  }
  return value;
}

function expectVersionToken(value: unknown): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 64 ||
    !/^[0-9A-Za-z.-]+$/.test(value)
  ) {
    throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
  }
  return value;
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

function expectSha256(value: unknown): string {
  if (typeof value !== "string")
    throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
  assertSha256(value);
  return value;
}

function assertSha256(value: string): void {
  if (!/^[a-f0-9]{64}$/.test(value)) {
    throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
  }
}

function receiptDirectory(appDataDirectory: string): string {
  return path.join(path.resolve(appDataDirectory), "updates", "receipts");
}

function isSuperset<T>(
  candidate: readonly T[],
  previous: readonly T[],
): boolean {
  const values = new Set(candidate);
  return previous.every((value) => values.has(value));
}

function union(left: readonly string[], right: readonly string[]): string[] {
  return [...new Set([...left, ...right])].sort(asciiCompare);
}

function unionNumbers(
  left: readonly number[],
  right: readonly number[],
): number[] {
  return [...new Set([...left, ...right])].sort((a, b) => a - b);
}

function sha256(value: Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function asciiCompare(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
