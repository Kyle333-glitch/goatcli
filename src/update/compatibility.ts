import {
  createHash,
  createPublicKey,
  verify as verifySignature,
} from "node:crypto";
import path from "node:path";
import semver from "semver";
import {
  canonicalJsonBytes,
  hasExactJsonKeys,
  isJsonObject,
  parseCanonicalJson,
  type JsonObject,
  type JsonValue,
} from "./canonical-json.js";
import { readImmutableFile } from "./durable.js";
import { UpdateError } from "./errors.js";
import type {
  AuthenticatedTarget,
  UpdateArchitecture,
  UpdateChannel,
  UpdatePlatform,
} from "./schema.js";
import type { StagedArchive } from "./archive.js";

export interface SignedEngineManifestV2 {
  readonly manifestVersion: 2;
  readonly releasePolicyDigest: string;
  readonly product: "GOAT";
  readonly productVersion: string;
  readonly goatEngineVersion: string;
  readonly openCodeBaseline: string;
  readonly releaseSequence: number;
  readonly channel: UpdateChannel;
  readonly platform: UpdatePlatform;
  readonly architecture: UpdateArchitecture;
  readonly executablePath: string;
  readonly checksum: {
    readonly algorithm: "sha256";
    readonly value: string;
  };
  readonly launcherCompatibility: {
    readonly minInclusive: string;
    readonly maxExclusive: string;
  };
  readonly protocols: {
    readonly launchContract: string;
    readonly privacyActivation: string;
    readonly authenticatedFrame: string;
  };
  readonly codeSigningIdentityId: string;
  readonly signature: {
    readonly status: "signed";
    readonly algorithm: "ed25519";
    readonly keyId: string;
    readonly publicKey: string;
    readonly value: string;
  };
}

export interface CandidateCompatibilityPolicy {
  readonly launcherVersion: string;
  readonly releasePolicyDigest: string;
  readonly engineManifestKeyIds: readonly string[];
  readonly revokedKeyIds: readonly string[];
  readonly platform: UpdatePlatform;
  readonly architecture: UpdateArchitecture;
}

export interface CompatibleCandidate {
  readonly staged: StagedArchive;
  readonly manifest: SignedEngineManifestV2;
  readonly executablePath: string;
  readonly manifestSha256: string;
}

const MAX_ENGINE_MANIFEST_BYTES = 64 * 1024;
const MANIFEST_KEYS = [
  "architecture",
  "channel",
  "checksum",
  "codeSigningIdentityId",
  "executablePath",
  "goatEngineVersion",
  "launcherCompatibility",
  "manifestVersion",
  "openCodeBaseline",
  "platform",
  "product",
  "productVersion",
  "protocols",
  "releasePolicyDigest",
  "releaseSequence",
  "signature",
] as const;

export async function validateCandidateCompatibility(
  staged: StagedArchive,
  policy: CandidateCompatibilityPolicy,
): Promise<CompatibleCandidate> {
  const manifestPath = path.join(staged.root, "goat-engine.json");
  const bytes = await readImmutableFile(
    manifestPath,
    MAX_ENGINE_MANIFEST_BYTES,
    "GOAT_UPDATE_COMPATIBILITY_FAILED",
  );
  return validateCandidateCompatibilityBytes(staged, bytes, policy);
}

export function validateCandidateCompatibilityBytes(
  staged: StagedArchive,
  bytes: Uint8Array,
  policy: CandidateCompatibilityPolicy,
): CompatibleCandidate {
  const manifest = parseEngineManifestV2(bytes);
  verifyEngineManifestSignature(manifest, policy);
  assertOuterInnerBinding(manifest, staged.target, policy);
  return {
    staged,
    manifest,
    executablePath: path.join(
      staged.root,
      "bin",
      policy.platform === "win32" ? "goat-engine.exe" : "goat-engine",
    ),
    manifestSha256: sha256(bytes),
  };
}

export function parseEngineManifestV2(
  bytes: Uint8Array,
): SignedEngineManifestV2 {
  const value = parseCanonicalJson(bytes, {
    maxBytes: MAX_ENGINE_MANIFEST_BYTES,
    errorCode: "GOAT_UPDATE_COMPATIBILITY_FAILED",
  });
  const record = expectExactObject(value, MANIFEST_KEYS);
  const checksum = expectExactObject(record.checksum, ["algorithm", "value"]);
  const launcherCompatibility = expectExactObject(
    record.launcherCompatibility,
    ["maxExclusive", "minInclusive"],
  );
  const protocols = expectExactObject(record.protocols, [
    "authenticatedFrame",
    "launchContract",
    "privacyActivation",
  ]);
  const signature = expectExactObject(record.signature, [
    "algorithm",
    "keyId",
    "publicKey",
    "status",
    "value",
  ]);
  const parsed: SignedEngineManifestV2 = {
    manifestVersion: expectLiteral(record.manifestVersion, 2),
    releasePolicyDigest: expectSha256(record.releasePolicyDigest),
    product: expectLiteral(record.product, "GOAT"),
    productVersion: expectSemver(record.productVersion),
    goatEngineVersion: expectSemver(record.goatEngineVersion),
    openCodeBaseline: expectSemver(record.openCodeBaseline),
    releaseSequence: expectPositiveInteger(record.releaseSequence),
    channel: expectChannel(record.channel),
    platform: expectPlatform(record.platform),
    architecture: expectArchitecture(record.architecture),
    executablePath: expectSafePath(record.executablePath),
    checksum: {
      algorithm: expectLiteral(checksum.algorithm, "sha256"),
      value: expectSha256(checksum.value),
    },
    launcherCompatibility: {
      minInclusive: expectSemver(launcherCompatibility.minInclusive),
      maxExclusive: expectSemver(launcherCompatibility.maxExclusive),
    },
    protocols: {
      launchContract: expectSafeToken(protocols.launchContract, 32),
      privacyActivation: expectSafeToken(protocols.privacyActivation, 32),
      authenticatedFrame: expectSafeToken(protocols.authenticatedFrame, 32),
    },
    codeSigningIdentityId: expectIdentity(record.codeSigningIdentityId),
    signature: {
      status: expectLiteral(signature.status, "signed"),
      algorithm: expectLiteral(signature.algorithm, "ed25519"),
      keyId: expectSha256(signature.keyId),
      publicKey: expectBase64Url(signature.publicKey, 256),
      value: expectBase64Url(signature.value, 128),
    },
  };
  if (
    !semver.lt(
      parsed.launcherCompatibility.minInclusive,
      parsed.launcherCompatibility.maxExclusive,
    ) ||
    decodedBase64Url(parsed.signature.value)?.byteLength !== 64
  ) {
    throw compatibilityError();
  }
  return parsed;
}

export function canonicalEngineManifestV2Payload(
  manifest: SignedEngineManifestV2,
): Buffer {
  const { signature: _signature, ...payload } = manifest;
  return canonicalJsonBytes(payload as unknown as JsonValue);
}

export function verifyEngineManifestSignature(
  manifest: SignedEngineManifestV2,
  policy: Pick<
    CandidateCompatibilityPolicy,
    "releasePolicyDigest" | "engineManifestKeyIds" | "revokedKeyIds"
  >,
): void {
  if (manifest.releasePolicyDigest !== policy.releasePolicyDigest) {
    throw new UpdateError("GOAT_UPDATE_SIGNATURE_INVALID");
  }
  if (policy.revokedKeyIds.includes(manifest.signature.keyId)) {
    throw new UpdateError("GOAT_UPDATE_SIGNING_KEY_REVOKED");
  }
  if (!policy.engineManifestKeyIds.includes(manifest.signature.keyId)) {
    throw new UpdateError("GOAT_UPDATE_SIGNING_KEY_UNKNOWN");
  }
  const publicKeyBytes = decodedBase64Url(manifest.signature.publicKey);
  const signatureBytes = decodedBase64Url(manifest.signature.value);
  if (!publicKeyBytes || !signatureBytes || signatureBytes.byteLength !== 64) {
    throw compatibilityError();
  }
  if (sha256(publicKeyBytes) !== manifest.signature.keyId) {
    throw new UpdateError("GOAT_UPDATE_SIGNATURE_INVALID");
  }
  try {
    const publicKey = createPublicKey({
      key: publicKeyBytes,
      format: "der",
      type: "spki",
    });
    const exported = publicKey.export({ format: "der", type: "spki" });
    if (
      publicKey.asymmetricKeyType !== "ed25519" ||
      !Buffer.isBuffer(exported) ||
      !exported.equals(publicKeyBytes) ||
      !verifySignature(
        null,
        canonicalEngineManifestV2Payload(manifest),
        publicKey,
        signatureBytes,
      )
    ) {
      throw new UpdateError("GOAT_UPDATE_SIGNATURE_INVALID");
    }
  } catch (error) {
    if (error instanceof UpdateError) throw error;
    throw new UpdateError("GOAT_UPDATE_SIGNATURE_INVALID", { cause: error });
  }
}

function assertOuterInnerBinding(
  manifest: SignedEngineManifestV2,
  target: AuthenticatedTarget,
  policy: CandidateCompatibilityPolicy,
): void {
  const custom = target.custom;
  const executable = custom.contents.find((entry) =>
    entry.path.startsWith("bin/"),
  );
  const expectedExecutablePath =
    custom.platform === "win32" ? "bin/goat-engine.exe" : "bin/goat-engine";
  if (
    policy.platform !== custom.platform ||
    policy.architecture !== custom.architecture ||
    manifest.product !== custom.product ||
    manifest.productVersion !== custom.productVersion ||
    manifest.goatEngineVersion !== custom.goatEngineVersion ||
    manifest.openCodeBaseline !== custom.openCodeBaseline ||
    manifest.releaseSequence !== custom.releaseSequence ||
    manifest.channel !== custom.channel ||
    manifest.platform !== custom.platform ||
    manifest.architecture !== custom.architecture ||
    manifest.executablePath !== expectedExecutablePath ||
    manifest.checksum.value !== executable?.sha256 ||
    manifest.launcherCompatibility.minInclusive !==
      custom.launcherCompatibility.minInclusive ||
    manifest.launcherCompatibility.maxExclusive !==
      custom.launcherCompatibility.maxExclusive ||
    manifest.protocols.launchContract !==
      custom.engineProtocolCompatibility.launchContract ||
    manifest.protocols.privacyActivation !==
      custom.engineProtocolCompatibility.privacyActivation ||
    manifest.protocols.authenticatedFrame !==
      custom.engineProtocolCompatibility.authenticatedFrame ||
    manifest.codeSigningIdentityId !== custom.codeSigning.identityId ||
    !semver.gte(
      policy.launcherVersion,
      manifest.launcherCompatibility.minInclusive,
    ) ||
    !semver.lt(
      policy.launcherVersion,
      manifest.launcherCompatibility.maxExclusive,
    )
  ) {
    throw compatibilityError();
  }
}

function expectExactObject(
  value: unknown,
  keys: readonly string[],
): JsonObject {
  if (!isJsonObject(value) || !hasExactJsonKeys(value, keys)) {
    throw compatibilityError();
  }
  return value;
}

function expectLiteral<T extends JsonValue>(value: unknown, expected: T): T {
  if (value !== expected) throw compatibilityError();
  return expected;
}

function expectSemver(value: unknown): string {
  if (typeof value !== "string" || value.includes("+"))
    throw compatibilityError();
  const parsed = semver.parse(value, { loose: false });
  if (!parsed || parsed.version !== value) throw compatibilityError();
  return value;
}

function expectPositiveInteger(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) <= 0) {
    throw compatibilityError();
  }
  return value as number;
}

function expectChannel(value: unknown): UpdateChannel {
  if (value !== "stable" && value !== "beta" && value !== "development") {
    throw compatibilityError();
  }
  return value;
}

function expectPlatform(value: unknown): UpdatePlatform {
  if (value !== "win32" && value !== "darwin") throw compatibilityError();
  return value;
}

function expectArchitecture(value: unknown): UpdateArchitecture {
  if (value !== "x64" && value !== "arm64") throw compatibilityError();
  return value;
}

function expectSafePath(value: unknown): string {
  if (value !== "bin/goat-engine" && value !== "bin/goat-engine.exe") {
    throw compatibilityError();
  }
  return value;
}

function expectIdentity(value: unknown): string {
  if (
    typeof value !== "string" ||
    !/^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/.test(value)
  ) {
    throw compatibilityError();
  }
  return value;
}

function expectSafeToken(value: unknown, maxLength: number): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > maxLength ||
    !/^[A-Za-z0-9.-]+$/.test(value)
  ) {
    throw compatibilityError();
  }
  return value;
}

function expectSha256(value: unknown): string {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) {
    throw compatibilityError();
  }
  return value;
}

function expectBase64Url(value: unknown, maxLength: number): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > maxLength ||
    !/^[A-Za-z0-9_-]+$/.test(value)
  ) {
    throw compatibilityError();
  }
  const decoded = decodedBase64Url(value);
  if (!decoded || decoded.toString("base64url") !== value) {
    throw compatibilityError();
  }
  return value;
}

function decodedBase64Url(value: string): Buffer | null {
  try {
    return Buffer.from(value, "base64url");
  } catch {
    return null;
  }
}

function sha256(value: Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function compatibilityError(): UpdateError {
  return new UpdateError("GOAT_UPDATE_COMPATIBILITY_FAILED");
}
