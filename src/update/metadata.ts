import { createHash } from "node:crypto";
import { canonicalize } from "@tufjs/canonical-json";
import {
  Metadata,
  MetadataKind,
  type Root,
  type Snapshot,
  type Targets,
  type Timestamp,
} from "@tufjs/models";
import {
  hasExactJsonKeys,
  isJsonObject,
  parseCanonicalJson,
  type JsonObject,
  type JsonValue,
} from "./canonical-json.js";
import { UpdateError } from "./errors.js";
import { TUF_SPEC_VERSION } from "./schema.js";

export type TufRoleName =
  | "root"
  | "timestamp"
  | "snapshot"
  | "targets"
  | "stable"
  | "beta"
  | "development";

export interface ParsedTufMetadata<
  T extends Root | Timestamp | Snapshot | Targets,
> {
  readonly roleName: TufRoleName;
  readonly bytes: Buffer;
  readonly json: JsonObject;
  readonly metadata: Metadata<T>;
}

export interface TopLevelRevocations {
  readonly goatRevocationSchema: 1;
  readonly revokedKeyIds: readonly string[];
  readonly revokedArtifactSha256: readonly string[];
  readonly revokedReleaseSequences: readonly number[];
}

const TOP_LEVEL_ROLES = ["root", "targets", "snapshot", "timestamp"] as const;
const CHANNEL_ROLES = ["stable", "beta", "development"] as const;
const SNAPSHOT_META_NAMES = [
  "beta.json",
  "development.json",
  "stable.json",
  "targets.json",
] as const;

export function parseRootMetadata(bytes: Uint8Array): ParsedTufMetadata<Root> {
  const json = parseEnvelope(bytes, "root");
  validateRootSigned(expectSigned(json));
  return buildParsed("root", bytes, json, MetadataKind.Root);
}

export function parseTimestampMetadata(
  bytes: Uint8Array,
): ParsedTufMetadata<Timestamp> {
  const json = parseEnvelope(bytes, "timestamp");
  validateTimestampSigned(expectSigned(json));
  return buildParsed("timestamp", bytes, json, MetadataKind.Timestamp);
}

export function parseSnapshotMetadata(
  bytes: Uint8Array,
): ParsedTufMetadata<Snapshot> {
  const json = parseEnvelope(bytes, "snapshot");
  validateSnapshotSigned(expectSigned(json));
  return buildParsed("snapshot", bytes, json, MetadataKind.Snapshot);
}

export function parseTargetsMetadata(
  bytes: Uint8Array,
  roleName: "targets" | "stable" | "beta" | "development",
): ParsedTufMetadata<Targets> {
  const json = parseEnvelope(bytes, roleName);
  const signed = expectSigned(json);
  if (roleName === "targets") validateTopTargetsSigned(signed);
  else validateChannelTargetsSigned(signed, roleName);
  return buildParsed(roleName, bytes, json, MetadataKind.Targets);
}

export function topLevelRevocations(
  parsed: ParsedTufMetadata<Targets>,
): TopLevelRevocations {
  if (parsed.roleName !== "targets") throw invalidMetadata();
  const custom = expectObject(expectSigned(parsed.json).custom);
  return {
    goatRevocationSchema: 1,
    revokedKeyIds: expectStringArray(custom.revokedKeyIds),
    revokedArtifactSha256: expectStringArray(custom.revokedArtifactSha256),
    revokedReleaseSequences: expectIntegerArray(custom.revokedReleaseSequences),
  };
}

function parseEnvelope(bytes: Uint8Array, roleName: TufRoleName): JsonObject {
  const value = parseCanonicalJson(bytes);
  if (
    !isJsonObject(value) ||
    !hasExactJsonKeys(value, ["signatures", "signed"])
  ) {
    throw invalidMetadata();
  }
  validateSignatures(value.signatures, roleName);
  return value;
}

function validateSignatures(value: JsonValue, roleName: TufRoleName): void {
  if (!Array.isArray(value) || value.length === 0 || value.length > 8) {
    throw invalidMetadata();
  }
  const keyIds = new Set<string>();
  for (const entry of value) {
    const signature = expectObject(entry);
    if (
      !hasExactJsonKeys(signature, ["keyid", "sig"]) ||
      typeof signature.keyid !== "string" ||
      !isSha256(signature.keyid) ||
      typeof signature.sig !== "string" ||
      !/^[a-f0-9]{128}$/.test(signature.sig) ||
      keyIds.has(signature.keyid)
    ) {
      throw invalidMetadata();
    }
    keyIds.add(signature.keyid);
  }
  const expectedMinimum =
    roleName === "snapshot" || roleName === "timestamp" ? 1 : 2;
  if (keyIds.size < expectedMinimum) throw invalidMetadata();
}

function validateRootSigned(value: JsonObject): void {
  validateCommonSigned(value, "root", ["keys", "roles", "consistent_snapshot"]);
  if (value.consistent_snapshot !== true) unsupportedMetadata();
  const keys = validateKeyMap(value.keys, 8, 32);
  const roles = expectObject(value.roles);
  if (!hasExactJsonKeys(roles, TOP_LEVEL_ROLES)) throw invalidMetadata();

  const roleKeySets = new Map<string, Set<string>>();
  for (const roleName of TOP_LEVEL_ROLES) {
    const expectedThreshold =
      roleName === "root" || roleName === "targets" ? 2 : 1;
    const expectedKeyCount = expectedThreshold === 2 ? 3 : 1;
    const role = validateRole(
      roles[roleName],
      expectedThreshold,
      expectedKeyCount,
    );
    for (const keyId of role.keyids) {
      if (!keys.has(keyId)) throw invalidMetadata();
    }
    roleKeySets.set(roleName, new Set(role.keyids));
  }
  const used = new Set<string>();
  for (const roleName of TOP_LEVEL_ROLES) {
    for (const keyId of roleKeySets.get(roleName)!) {
      if (used.has(keyId)) throw invalidMetadata();
      used.add(keyId);
    }
  }
}

function validateTimestampSigned(value: JsonObject): void {
  validateCommonSigned(value, "timestamp", ["meta"]);
  const meta = expectObject(value.meta);
  if (!hasExactJsonKeys(meta, ["snapshot.json"])) throw invalidMetadata();
  validateMetaFile(meta["snapshot.json"]);
}

function validateSnapshotSigned(value: JsonObject): void {
  validateCommonSigned(value, "snapshot", ["meta"]);
  const meta = expectObject(value.meta);
  if (!hasExactJsonKeys(meta, SNAPSHOT_META_NAMES)) throw invalidMetadata();
  for (const name of SNAPSHOT_META_NAMES) validateMetaFile(meta[name]);
}

function validateTopTargetsSigned(value: JsonObject): void {
  validateCommonSigned(value, "targets", ["targets", "delegations", "custom"]);
  const targets = expectObject(value.targets);
  if (Object.keys(targets).length !== 0) throw invalidMetadata();
  validateRevocations(value.custom);
  validateDelegations(value.delegations);
}

function validateChannelTargetsSigned(
  value: JsonObject,
  roleName: (typeof CHANNEL_ROLES)[number],
): void {
  validateCommonSigned(value, "targets", ["targets"]);
  const targets = expectObject(value.targets);
  const paths = Object.keys(targets);
  if (paths.length === 0 || paths.length > 64) throw invalidMetadata();
  for (const targetPath of paths) {
    if (!targetPath.startsWith(`goat-engine/${roleName}/`)) {
      throw invalidMetadata();
    }
    validateTufTargetFile(targets[targetPath]);
  }
}

function validateCommonSigned(
  value: JsonObject,
  type: "root" | "timestamp" | "snapshot" | "targets",
  additional: readonly string[],
): void {
  if (
    !hasExactJsonKeys(value, [
      "_type",
      "spec_version",
      "version",
      "expires",
      ...additional,
    ]) ||
    value._type !== type ||
    value.spec_version !== TUF_SPEC_VERSION ||
    !Number.isSafeInteger(value.version) ||
    (value.version as number) <= 0 ||
    typeof value.expires !== "string" ||
    !isCanonicalExpiry(value.expires)
  ) {
    if (value.spec_version !== TUF_SPEC_VERSION) unsupportedMetadata();
    throw invalidMetadata();
  }
}

function validateKeyMap(
  value: JsonValue,
  minimum: number,
  maximum: number,
): Set<string> {
  const keys = expectObject(value);
  const entries = Object.entries(keys);
  if (entries.length < minimum || entries.length > maximum) {
    throw invalidMetadata();
  }
  const result = new Set<string>();
  for (const [keyId, rawKey] of entries) {
    if (!isSha256(keyId)) throw invalidMetadata();
    const key = expectObject(rawKey);
    if (
      !hasExactJsonKeys(key, ["keytype", "scheme", "keyval"]) ||
      key.keytype !== "ed25519" ||
      key.scheme !== "ed25519"
    ) {
      throw invalidMetadata();
    }
    const keyval = expectObject(key.keyval);
    if (
      !hasExactJsonKeys(keyval, ["public"]) ||
      typeof keyval.public !== "string" ||
      !/^[a-f0-9]{64}$/.test(keyval.public) ||
      keyId !== sha256(canonicalize(key))
    ) {
      throw invalidMetadata();
    }
    result.add(keyId);
  }
  return result;
}

function validateRole(
  value: JsonValue,
  expectedThreshold: number,
  expectedKeyCount: number,
): { readonly keyids: readonly string[]; readonly threshold: number } {
  const role = expectObject(value);
  if (
    !hasExactJsonKeys(role, ["keyids", "threshold"]) ||
    role.threshold !== expectedThreshold ||
    !Array.isArray(role.keyids) ||
    role.keyids.length !== expectedKeyCount
  ) {
    throw invalidMetadata();
  }
  const keyids = role.keyids.map(expectSha256String);
  if (!isSortedUnique(keyids)) throw invalidMetadata();
  return { keyids, threshold: expectedThreshold };
}

function validateDelegations(value: JsonValue): void {
  const delegations = expectObject(value);
  if (!hasExactJsonKeys(delegations, ["keys", "roles"])) {
    throw invalidMetadata();
  }
  const keys = validateKeyMap(delegations.keys, 9, 9);
  if (!Array.isArray(delegations.roles) || delegations.roles.length !== 3) {
    throw invalidMetadata();
  }
  const seen = new Set<string>();
  for (const rawRole of delegations.roles) {
    const role = expectObject(rawRole);
    if (
      !hasExactJsonKeys(role, [
        "name",
        "keyids",
        "threshold",
        "terminating",
        "paths",
      ]) ||
      typeof role.name !== "string" ||
      !CHANNEL_ROLES.includes(role.name as (typeof CHANNEL_ROLES)[number]) ||
      seen.has(role.name) ||
      role.terminating !== true ||
      !Array.isArray(role.paths) ||
      role.paths.length !== 1 ||
      role.paths[0] !== `goat-engine/${role.name}/*`
    ) {
      throw invalidMetadata();
    }
    const roleKeys = validateRoleFields(role, 2, 3);
    if (roleKeys.some((keyId) => !keys.has(keyId))) throw invalidMetadata();
    seen.add(role.name);
  }
  if (CHANNEL_ROLES.some((role) => !seen.has(role))) throw invalidMetadata();
}

function validateRoleFields(
  role: JsonObject,
  threshold: number,
  keyCount: number,
): readonly string[] {
  if (
    role.threshold !== threshold ||
    !Array.isArray(role.keyids) ||
    role.keyids.length !== keyCount
  ) {
    throw invalidMetadata();
  }
  const keyids = role.keyids.map(expectSha256String);
  if (!isSortedUnique(keyids)) throw invalidMetadata();
  return keyids;
}

function validateRevocations(value: JsonValue): void {
  const custom = expectObject(value);
  if (
    !hasExactJsonKeys(custom, [
      "goatRevocationSchema",
      "revokedKeyIds",
      "revokedArtifactSha256",
      "revokedReleaseSequences",
    ]) ||
    custom.goatRevocationSchema !== 1
  ) {
    throw invalidMetadata();
  }
  const keyIds = expectStringArray(custom.revokedKeyIds);
  const artifactHashes = expectStringArray(custom.revokedArtifactSha256);
  const sequences = expectIntegerArray(custom.revokedReleaseSequences);
  if (
    keyIds.some((value) => !isSha256(value)) ||
    artifactHashes.some((value) => !isSha256(value)) ||
    !isSortedUnique(keyIds) ||
    !isSortedUnique(artifactHashes) ||
    !isSortedUnique(sequences)
  ) {
    throw invalidMetadata();
  }
}

function validateMetaFile(value: JsonValue): void {
  const meta = expectObject(value);
  if (
    !hasExactJsonKeys(meta, ["version", "length", "hashes"]) ||
    !Number.isSafeInteger(meta.version) ||
    (meta.version as number) <= 0 ||
    !Number.isSafeInteger(meta.length) ||
    (meta.length as number) <= 0
  ) {
    throw invalidMetadata();
  }
  const hashes = expectObject(meta.hashes);
  if (
    !hasExactJsonKeys(hashes, ["sha256"]) ||
    typeof hashes.sha256 !== "string" ||
    !isSha256(hashes.sha256)
  ) {
    throw invalidMetadata();
  }
}

function validateTufTargetFile(value: JsonValue): void {
  const target = expectObject(value);
  if (!hasExactJsonKeys(target, ["length", "hashes", "custom"])) {
    throw invalidMetadata();
  }
  if (!Number.isSafeInteger(target.length) || (target.length as number) <= 0) {
    throw invalidMetadata();
  }
  const hashes = expectObject(target.hashes);
  if (
    !hasExactJsonKeys(hashes, ["sha256"]) ||
    typeof hashes.sha256 !== "string" ||
    !isSha256(hashes.sha256) ||
    !isJsonObject(target.custom)
  ) {
    throw invalidMetadata();
  }
}

function expectSigned(envelope: JsonObject): JsonObject {
  return expectObject(envelope.signed);
}

function expectObject(value: JsonValue | unknown): JsonObject {
  if (!isJsonObject(value)) throw invalidMetadata();
  return value;
}

function expectStringArray(value: JsonValue | unknown): string[] {
  if (!Array.isArray(value) || value.length > 256) throw invalidMetadata();
  return value.map((entry) => {
    if (typeof entry !== "string") throw invalidMetadata();
    return entry;
  });
}

function expectIntegerArray(value: JsonValue | unknown): number[] {
  if (!Array.isArray(value) || value.length > 256) throw invalidMetadata();
  return value.map((entry) => {
    if (!Number.isSafeInteger(entry) || (entry as number) <= 0) {
      throw invalidMetadata();
    }
    return entry as number;
  });
}

function expectSha256String(value: JsonValue): string {
  if (typeof value !== "string" || !isSha256(value)) throw invalidMetadata();
  return value;
}

function isCanonicalExpiry(value: string): boolean {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value)) {
    return false;
  }
  return Number.isFinite(Date.parse(value));
}

function isSha256(value: string): boolean {
  return /^[a-f0-9]{64}$/.test(value);
}

function isSortedUnique<T extends string | number>(
  values: readonly T[],
): boolean {
  for (let index = 1; index < values.length; index += 1) {
    if (values[index - 1]! >= values[index]!) return false;
  }
  return true;
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function buildParsed<T extends Root | Timestamp | Snapshot | Targets>(
  roleName: TufRoleName,
  bytes: Uint8Array,
  json: JsonObject,
  kind: MetadataKind,
): ParsedTufMetadata<T> {
  try {
    const metadata = Metadata.fromJSON(
      kind as MetadataKind.Targets,
      json,
    ) as Metadata<T>;
    return { roleName, bytes: Buffer.from(bytes), json, metadata };
  } catch (error) {
    throw new UpdateError("GOAT_UPDATE_MANIFEST_INVALID", { cause: error });
  }
}

function unsupportedMetadata(): never {
  throw new UpdateError("GOAT_UPDATE_MANIFEST_UNSUPPORTED");
}

function invalidMetadata(): UpdateError {
  return new UpdateError("GOAT_UPDATE_MANIFEST_INVALID");
}
