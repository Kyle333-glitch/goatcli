import { TargetFile } from "@tufjs/models";
import semver from "semver";
import {
  AUTHENTICATED_FRAME_PROTOCOL,
  ENGINE_CONTRACT_VERSION,
  PRIVACY_ACTIVATION_PROTOCOL,
} from "../version.js";
import { UpdateError } from "./errors.js";

export const UPDATE_TARGET_SCHEMA = 1 as const;
export const INNER_MANIFEST_SCHEMA = 2 as const;
export const TUF_SPEC_VERSION = "1.0.31" as const;
export const UPDATE_ARTIFACT_FORMAT = "goat-engine-zip-v1" as const;
export const MAX_ARTIFACT_BYTES = 512 * 1024 * 1024;

export type UpdateChannel = "stable" | "beta" | "development";
export type UpdatePlatform = "win32" | "darwin";
export type UpdateArchitecture = "x64" | "arm64";

export interface SignedContentEntry {
  readonly path: string;
  readonly type: "regular-file";
  readonly length: number;
  readonly sha256: string;
  readonly mode: 420 | 493;
}

export interface LauncherCompatibility {
  readonly minInclusive: string;
  readonly maxExclusive: string;
}

export interface EngineProtocolCompatibility {
  readonly launchContract: typeof ENGINE_CONTRACT_VERSION;
  readonly privacyActivation: typeof PRIVACY_ACTIVATION_PROTOCOL;
  readonly authenticatedFrame: typeof AUTHENTICATED_FRAME_PROTOCOL;
}

export type CodeSigningPolicy =
  | {
      readonly scheme: "authenticode-sha256";
      readonly identityId: string;
    }
  | {
      readonly scheme: "apple-developer-id";
      readonly identityId: string;
    };

export interface GoatUpdateTargetCustom {
  readonly goatUpdateSchema: typeof UPDATE_TARGET_SCHEMA;
  readonly product: "GOAT";
  readonly component: "goat-engine";
  readonly productVersion: string;
  readonly goatEngineVersion: string;
  readonly openCodeBaseline: string;
  readonly releaseSequence: number;
  readonly channel: UpdateChannel;
  readonly platform: UpdatePlatform;
  readonly architecture: UpdateArchitecture;
  readonly cpuFeatures: readonly [];
  readonly artifactFormat: typeof UPDATE_ARTIFACT_FORMAT;
  readonly launcherCompatibility: LauncherCompatibility;
  readonly engineProtocolCompatibility: EngineProtocolCompatibility;
  readonly innerManifestSchema: typeof INNER_MANIFEST_SCHEMA;
  readonly codeSigning: CodeSigningPolicy;
  readonly contents: readonly SignedContentEntry[];
}

export interface AuthenticatedTarget {
  readonly targetPath: string;
  readonly length: number;
  readonly sha256: string;
  readonly custom: GoatUpdateTargetCustom;
}

const CUSTOM_KEYS = [
  "goatUpdateSchema",
  "product",
  "component",
  "productVersion",
  "goatEngineVersion",
  "openCodeBaseline",
  "releaseSequence",
  "channel",
  "platform",
  "architecture",
  "cpuFeatures",
  "artifactFormat",
  "launcherCompatibility",
  "engineProtocolCompatibility",
  "innerManifestSchema",
  "codeSigning",
  "contents",
] as const;

export function parseAuthenticatedTarget(
  targetPath: string,
  target: TargetFile,
): AuthenticatedTarget {
  if (
    !Number.isSafeInteger(target.length) ||
    target.length <= 0 ||
    target.length > MAX_ARTIFACT_BYTES ||
    !hasExactKeys(target.hashes, ["sha256"]) ||
    !isLowercaseSha256(target.hashes.sha256) ||
    !hasExactKeys(target.unrecognizedFields, ["custom"])
  ) {
    throw invalidTarget();
  }

  const custom = parseTargetCustom(target.custom);
  const expectedPath = expectedTargetPath(custom);
  if (targetPath !== expectedPath || target.path !== targetPath) {
    throw invalidTarget();
  }

  return {
    targetPath,
    length: target.length,
    sha256: target.hashes.sha256,
    custom,
  };
}

export function parseTargetCustom(
  input: Record<string, unknown>,
): GoatUpdateTargetCustom {
  if (!hasExactKeys(input, CUSTOM_KEYS)) throw invalidTarget();

  const channel = parseChannel(input.channel);
  const platform = parsePlatform(input.platform);
  const architecture = parseArchitecture(input.architecture);
  const productVersion = parseChannelVersion(input.productVersion, channel);
  const goatEngineVersion = parseChannelVersion(
    input.goatEngineVersion,
    channel,
  );
  const openCodeBaseline = parseStrictSemver(input.openCodeBaseline);
  const releaseSequence = positiveSafeInteger(input.releaseSequence);

  if (
    input.goatUpdateSchema !== UPDATE_TARGET_SCHEMA ||
    input.product !== "GOAT" ||
    input.component !== "goat-engine" ||
    input.artifactFormat !== UPDATE_ARTIFACT_FORMAT ||
    input.innerManifestSchema !== INNER_MANIFEST_SCHEMA ||
    !Array.isArray(input.cpuFeatures) ||
    input.cpuFeatures.length !== 0
  ) {
    throw invalidTarget();
  }

  const launcherCompatibility = parseLauncherCompatibility(
    input.launcherCompatibility,
  );
  const engineProtocolCompatibility = parseEngineProtocolCompatibility(
    input.engineProtocolCompatibility,
  );
  const codeSigning = parseCodeSigning(input.codeSigning, platform);
  const contents = parseContents(input.contents, platform);

  return {
    goatUpdateSchema: UPDATE_TARGET_SCHEMA,
    product: "GOAT",
    component: "goat-engine",
    productVersion,
    goatEngineVersion,
    openCodeBaseline,
    releaseSequence,
    channel,
    platform,
    architecture,
    cpuFeatures: [],
    artifactFormat: UPDATE_ARTIFACT_FORMAT,
    launcherCompatibility,
    engineProtocolCompatibility,
    innerManifestSchema: INNER_MANIFEST_SCHEMA,
    codeSigning,
    contents,
  };
}

export function expectedTargetPath(custom: GoatUpdateTargetCustom): string {
  return `goat-engine/${custom.channel}/${custom.productVersion}/${custom.platform}-${custom.architecture}/goat-engine.zip`;
}

export function expectedArchivePaths(
  platform: UpdatePlatform,
): readonly string[] {
  return [
    `bin/${platform === "win32" ? "goat-engine.exe" : "goat-engine"}`,
    "goat-engine.json",
    "package.json",
    "LICENSE",
    "NOTICE",
    "THIRD_PARTY_NOTICES.txt",
    "sbom.spdx.json",
  ].sort(asciiCompare);
}

export function parseChannel(value: unknown): UpdateChannel {
  if (value !== "stable" && value !== "beta" && value !== "development") {
    throw invalidTarget();
  }
  return value;
}

export function parsePlatform(value: unknown): UpdatePlatform {
  if (value !== "win32" && value !== "darwin") throw invalidTarget();
  return value;
}

export function parseArchitecture(value: unknown): UpdateArchitecture {
  if (value !== "x64" && value !== "arm64") throw invalidTarget();
  return value;
}

export function parseStrictSemver(value: unknown): string {
  if (typeof value !== "string" || value.includes("+")) throw invalidTarget();
  const parsed = semver.parse(value, { loose: false });
  if (!parsed || parsed.version !== value) throw invalidTarget();
  return value;
}

function parseChannelVersion(value: unknown, channel: UpdateChannel): string {
  const version = parseStrictSemver(value);
  const parsed = semver.parse(version)!;
  const identifiers = parsed.prerelease;
  if (channel === "stable" && identifiers.length !== 0) throw invalidTarget();
  if (channel === "beta" && !isNumberedPrerelease(identifiers, "beta")) {
    throw invalidTarget();
  }
  if (channel === "development" && !isNumberedPrerelease(identifiers, "dev")) {
    throw invalidTarget();
  }
  return version;
}

function isNumberedPrerelease(
  identifiers: readonly (string | number)[],
  label: string,
): boolean {
  return (
    identifiers.length === 2 &&
    identifiers[0] === label &&
    typeof identifiers[1] === "number" &&
    Number.isSafeInteger(identifiers[1]) &&
    identifiers[1] >= 0
  );
}

function parseLauncherCompatibility(value: unknown): LauncherCompatibility {
  const record = expectRecord(value);
  if (!hasExactKeys(record, ["minInclusive", "maxExclusive"])) {
    throw invalidTarget();
  }
  const minInclusive = parseStrictSemver(record.minInclusive);
  const maxExclusive = parseStrictSemver(record.maxExclusive);
  if (!semver.lt(minInclusive, maxExclusive)) throw invalidTarget();
  return { minInclusive, maxExclusive };
}

function parseEngineProtocolCompatibility(
  value: unknown,
): EngineProtocolCompatibility {
  const record = expectRecord(value);
  if (
    !hasExactKeys(record, [
      "launchContract",
      "privacyActivation",
      "authenticatedFrame",
    ]) ||
    record.launchContract !== ENGINE_CONTRACT_VERSION ||
    record.privacyActivation !== PRIVACY_ACTIVATION_PROTOCOL ||
    record.authenticatedFrame !== AUTHENTICATED_FRAME_PROTOCOL
  ) {
    throw invalidTarget();
  }
  return {
    launchContract: ENGINE_CONTRACT_VERSION,
    privacyActivation: PRIVACY_ACTIVATION_PROTOCOL,
    authenticatedFrame: AUTHENTICATED_FRAME_PROTOCOL,
  };
}

function parseCodeSigning(
  value: unknown,
  platform: UpdatePlatform,
): CodeSigningPolicy {
  const record = expectRecord(value);
  if (
    !hasExactKeys(record, ["scheme", "identityId"]) ||
    typeof record.identityId !== "string" ||
    !/^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/.test(record.identityId)
  ) {
    throw invalidTarget();
  }
  const expectedScheme =
    platform === "win32" ? "authenticode-sha256" : "apple-developer-id";
  if (record.scheme !== expectedScheme) throw invalidTarget();
  return { scheme: expectedScheme, identityId: record.identityId };
}

function parseContents(
  value: unknown,
  platform: UpdatePlatform,
): readonly SignedContentEntry[] {
  if (!Array.isArray(value) || value.length > 32) throw invalidTarget();
  const entries = value.map((entry) => parseContentEntry(entry, platform));
  const expected = expectedArchivePaths(platform);
  if (
    entries.length !== expected.length ||
    entries.some((entry, index) => entry.path !== expected[index])
  ) {
    throw invalidTarget();
  }
  return entries;
}

function parseContentEntry(
  value: unknown,
  platform: UpdatePlatform,
): SignedContentEntry {
  const record = expectRecord(value);
  if (
    !hasExactKeys(record, ["path", "type", "length", "sha256", "mode"]) ||
    typeof record.path !== "string" ||
    record.type !== "regular-file" ||
    !Number.isSafeInteger(record.length) ||
    (record.length as number) < 0 ||
    (record.length as number) > MAX_ARTIFACT_BYTES ||
    typeof record.sha256 !== "string" ||
    !isLowercaseSha256(record.sha256) ||
    (record.mode !== 420 && record.mode !== 493)
  ) {
    throw invalidTarget();
  }
  const executable =
    record.path ===
    `bin/${platform === "win32" ? "goat-engine.exe" : "goat-engine"}`;
  if (
    (executable && record.mode !== 493) ||
    (!executable && record.mode !== 420)
  ) {
    throw invalidTarget();
  }
  return {
    path: record.path,
    type: "regular-file",
    length: record.length as number,
    sha256: record.sha256,
    mode: record.mode,
  };
}

function positiveSafeInteger(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) <= 0) {
    throw invalidTarget();
  }
  return value as number;
}

function expectRecord(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw invalidTarget();
  }
  return value as Record<string, unknown>;
}

function hasExactKeys(
  value: Record<string, unknown>,
  expected: readonly string[],
): boolean {
  const actual = Object.keys(value);
  return (
    actual.length === expected.length &&
    expected.every((key) => Object.prototype.hasOwnProperty.call(value, key))
  );
}

function isLowercaseSha256(value: string): boolean {
  return /^[a-f0-9]{64}$/.test(value);
}

function asciiCompare(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function invalidTarget(): UpdateError {
  return new UpdateError("GOAT_UPDATE_MANIFEST_INVALID");
}
