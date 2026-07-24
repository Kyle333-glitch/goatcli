import fs from "fs";
import { createHash, createPublicKey, verify as verifySignature } from "crypto";
import {
  EngineContractError,
  type EngineManifest,
  type EngineManifestTrustPolicy,
  type LauncherVersion,
  type ResolvedEngine,
} from "./contract.js";
import { engineManifestTrustPolicy } from "../privacy/release-policy.js";
import { getEngineExecutableName, getPathModule } from "../utils/paths.js";
import { getPlatformAdapter } from "../platform.js";

export interface ValidatedEngine {
  resolved: ResolvedEngine;
  manifest: EngineManifest | null;
  checksum: string;
}

export interface EngineFileSystem {
  constants: Pick<typeof fs.constants, "X_OK">;
  existsSync(path: string): boolean;
  statSync(path: string): Pick<fs.Stats, "isFile">;
  accessSync(path: string, mode?: number): void;
  readFileSync(path: string): Buffer | string;
}

export interface ValidateEngineOptions {
  fs?: EngineFileSystem;
  trustPolicy?: EngineManifestTrustPolicy;
}

export function validateEngine(
  resolved: ResolvedEngine,
  launcherVersion: LauncherVersion,
  options: ValidateEngineOptions = {},
): ValidatedEngine {
  const fileSystem = options.fs ?? fs;
  const trustPolicy = options.trustPolicy ?? engineManifestTrustPolicy();
  const pathModule = getPathModule(resolved.platform);
  const platform = getPlatformAdapter(resolved.platform);

  if (!pathModule.isAbsolute(resolved.executablePath)) {
    throw new EngineContractError(
      "GOAT_ENGINE_PATH_NOT_ABSOLUTE",
      `Engine path must be absolute: ${resolved.executablePath}`,
      "Reinstall the GOAT engine or use explicit development dependency injection.",
    );
  }

  const expectedExecutableName = getEngineExecutableName(resolved.platform);
  const actualExecutableName = pathModule.basename(resolved.executablePath);
  if (
    !resolved.developmentOverride &&
    actualExecutableName !== expectedExecutableName
  ) {
    const code =
      resolved.platform === "win32"
        ? "GOAT_ENGINE_WINDOWS_EXTENSION"
        : "GOAT_ENGINE_MISSING";
    throw new EngineContractError(
      code,
      `Expected engine executable ${expectedExecutableName}, but resolved ${actualExecutableName}.`,
      `Install the engine as ${expectedExecutableName} in the resolved bin directory.`,
    );
  }

  if (!fileSystem.existsSync(resolved.executablePath)) {
    throw new EngineContractError(
      "GOAT_ENGINE_MISSING",
      `GOAT engine executable was not found at ${resolved.executablePath}.`,
      "Install the local GOAT engine or use explicit development dependency injection.",
    );
  }

  let stats: Pick<fs.Stats, "isFile">;
  try {
    stats = fileSystem.statSync(resolved.executablePath);
  } catch {
    throw new EngineContractError(
      "GOAT_ENGINE_MISSING",
      `GOAT engine executable could not be inspected at ${resolved.executablePath}.`,
      "Check that the file exists and is readable, then run goat doctor.",
    );
  }

  if (!stats.isFile()) {
    throw new EngineContractError(
      "GOAT_ENGINE_NOT_FILE",
      `GOAT engine path is not a file: ${resolved.executablePath}`,
      "Replace the path with the GOAT engine executable file.",
    );
  }

  if (!platform.hasExecutablePermission(resolved.executablePath, fileSystem)) {
    const suggestion =
      resolved.platform === "win32"
        ? `Ensure the file has execute permissions and is not blocked by Windows. Run goat doctor again.`
        : `Run chmod +x "${resolved.executablePath}", then run goat doctor again.`;
    throw new EngineContractError(
      "GOAT_ENGINE_NOT_EXECUTABLE",
      `GOAT engine is not executable: ${resolved.executablePath}`,
      suggestion,
    );
  }

  if (resolved.developmentOverride) {
    if (
      !trustPolicy.allowUnsignedDevelopment ||
      resolved.releaseChannel !== "dev" ||
      resolved.source !== "development"
    ) {
      throw signatureInvalid(
        "Development engine overrides are not allowed by this release policy.",
      );
    }
    return { resolved, manifest: null, checksum: "development-override" };
  }

  let checksum: string;
  try {
    checksum = sha256(fileSystem.readFileSync(resolved.executablePath));
  } catch {
    throw new EngineContractError(
      "GOAT_ENGINE_MISSING",
      `GOAT engine executable could not be read at ${resolved.executablePath}.`,
      "Check that the file exists and is readable, then run goat doctor.",
    );
  }

  if (!resolved.manifestPath || !fileSystem.existsSync(resolved.manifestPath)) {
    throw new EngineContractError(
      "GOAT_ENGINE_MANIFEST_MISSING",
      `GOAT engine manifest was not found at ${resolved.manifestPath ?? "(none)"}.`,
      "Reinstall the GOAT engine so goat-engine.json is present beside the engine root.",
    );
  }

  const manifest = parseManifest(
    fileSystem.readFileSync(resolved.manifestPath),
  );
  validateManifestAgainstResolution(manifest, resolved, launcherVersion);
  validateManifestTrust(manifest, trustPolicy);

  if (manifest.checksum.value.toLowerCase() !== checksum) {
    throw new EngineContractError(
      "GOAT_ENGINE_CHECKSUM_MISMATCH",
      `GOAT engine checksum mismatch for ${resolved.executablePath}.`,
      "Reinstall the GOAT engine from a trusted GOAT release.",
    );
  }

  return { resolved, manifest, checksum };
}

export function parseManifest(raw: Buffer | string): EngineManifest {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw.toString());
  } catch {
    throw invalidManifest("Manifest is not valid JSON.");
  }

  if (!isRecord(parsed))
    throw invalidManifest("Manifest must be a JSON object.");
  const manifest = parsed as Record<string, unknown>;
  const checksum = manifest.checksum;
  const compatibility = manifest.compatibility;
  const signature = manifest.signature;

  if (
    !hasExactKeys(manifest, [
      "manifestVersion",
      "releasePolicyDigest",
      "engineVersion",
      "platform",
      "architecture",
      "executablePath",
      "releaseChannel",
      "checksum",
      "compatibility",
      "signature",
    ]) ||
    !isRecord(checksum) ||
    !isRecord(signature) ||
    !hasExactKeys(checksum, ["algorithm", "value"]) ||
    !isRecord(compatibility) ||
    !hasExactKeys(
      compatibility,
      ["minimumLauncherVersion"],
      ["maximumLauncherVersion"],
    )
  ) {
    throw invalidManifest(
      "Manifest fields do not match the GOAT engine contract.",
    );
  }

  if (
    manifest.manifestVersion !== 1 ||
    typeof manifest.releasePolicyDigest !== "string" ||
    !isLowercaseSha256(manifest.releasePolicyDigest) ||
    typeof manifest.engineVersion !== "string" ||
    typeof manifest.platform !== "string" ||
    typeof manifest.architecture !== "string" ||
    typeof manifest.executablePath !== "string" ||
    typeof manifest.releaseChannel !== "string" ||
    !isRecord(checksum) ||
    checksum.algorithm !== "sha256" ||
    typeof checksum.value !== "string" ||
    !isLowercaseSha256(checksum.value) ||
    !isRecord(compatibility) ||
    !isRecord(signature) ||
    typeof compatibility.minimumLauncherVersion !== "string" ||
    (compatibility.maximumLauncherVersion !== undefined &&
      typeof compatibility.maximumLauncherVersion !== "string")
  ) {
    throw invalidManifest(
      "Manifest fields do not match the GOAT engine contract.",
    );
  }

  const parsedSignature = parseManifestSignature(signature);

  if (manifest.platform !== "win32" && manifest.platform !== "darwin") {
    throw invalidManifest(
      `Unsupported manifest platform: ${manifest.platform}`,
    );
  }
  if (manifest.architecture !== "x64" && manifest.architecture !== "arm64") {
    throw invalidManifest(
      `Unsupported manifest architecture: ${manifest.architecture}`,
    );
  }
  if (
    manifest.releaseChannel !== "stable" &&
    manifest.releaseChannel !== "beta" &&
    manifest.releaseChannel !== "dev"
  ) {
    throw invalidManifest(
      `Unsupported manifest release channel: ${manifest.releaseChannel}`,
    );
  }
  if (!isVersionString(manifest.engineVersion)) {
    throw invalidManifest(`Invalid engine version: ${manifest.engineVersion}`);
  }
  if (!isVersionString(compatibility.minimumLauncherVersion)) {
    throw invalidManifest(
      `Invalid minimum launcher version: ${compatibility.minimumLauncherVersion}`,
    );
  }
  if (
    compatibility.maximumLauncherVersion !== undefined &&
    !isVersionString(compatibility.maximumLauncherVersion)
  ) {
    throw invalidManifest(
      `Invalid maximum launcher version: ${compatibility.maximumLauncherVersion}`,
    );
  }

  return {
    manifestVersion: 1,
    releasePolicyDigest: manifest.releasePolicyDigest,
    engineVersion: manifest.engineVersion,
    platform: manifest.platform,
    architecture: manifest.architecture,
    executablePath: manifest.executablePath,
    releaseChannel: manifest.releaseChannel,
    checksum: {
      algorithm: "sha256",
      value: checksum.value,
    },
    compatibility: {
      minimumLauncherVersion: compatibility.minimumLauncherVersion,
      maximumLauncherVersion: compatibility.maximumLauncherVersion,
    },
    signature: parsedSignature,
  };
}

function validateManifestAgainstResolution(
  manifest: EngineManifest,
  resolved: ResolvedEngine,
  launcherVersion: LauncherVersion,
): void {
  if (manifest.platform !== resolved.platform) {
    throw invalidManifest(
      `Manifest platform ${manifest.platform} does not match ${resolved.platform}.`,
    );
  }
  if (manifest.architecture !== resolved.architecture) {
    throw invalidManifest(
      `Manifest architecture ${manifest.architecture} does not match ${resolved.architecture}.`,
    );
  }
  if (manifest.releaseChannel !== resolved.releaseChannel) {
    throw invalidManifest(
      `Manifest release channel ${manifest.releaseChannel} does not match ${resolved.releaseChannel}.`,
    );
  }

  const expectedExecutablePath = `bin/${getEngineExecutableName(resolved.platform)}`;
  const normalizedManifestPath = manifest.executablePath.replaceAll("\\", "/");
  if (normalizedManifestPath !== expectedExecutablePath) {
    throw invalidManifest(
      `Manifest executable path must be ${expectedExecutablePath}.`,
    );
  }

  const minVersion = manifest.compatibility.minimumLauncherVersion;
  const maxVersion = manifest.compatibility.maximumLauncherVersion;
  if (compareVersions(launcherVersion, minVersion) < 0) {
    throw new EngineContractError(
      "GOAT_ENGINE_INCOMPATIBLE",
      `GOAT engine requires launcher ${minVersion} or newer; current launcher is ${launcherVersion}.`,
      "Update goatcli, then run goat doctor again.",
    );
  }
  if (maxVersion && compareVersions(launcherVersion, maxVersion) > 0) {
    throw new EngineContractError(
      "GOAT_ENGINE_INCOMPATIBLE",
      `GOAT engine supports launcher ${maxVersion} or older; current launcher is ${launcherVersion}.`,
      "Install a GOAT engine version compatible with this goatcli release.",
    );
  }
}

export function canonicalEngineManifestPayload(
  manifest: EngineManifest,
): string {
  return JSON.stringify({
    manifestVersion: manifest.manifestVersion,
    releasePolicyDigest: manifest.releasePolicyDigest,
    engineVersion: manifest.engineVersion,
    platform: manifest.platform,
    architecture: manifest.architecture,
    executablePath: manifest.executablePath,
    releaseChannel: manifest.releaseChannel,
    checksum: {
      algorithm: manifest.checksum.algorithm,
      value: manifest.checksum.value,
    },
    compatibility: {
      minimumLauncherVersion: manifest.compatibility.minimumLauncherVersion,
      ...(manifest.compatibility.maximumLauncherVersion === undefined
        ? {}
        : {
            maximumLauncherVersion:
              manifest.compatibility.maximumLauncherVersion,
          }),
    },
  });
}

function validateManifestTrust(
  manifest: EngineManifest,
  trustPolicy: EngineManifestTrustPolicy,
): void {
  if (
    manifest.manifestVersion !== trustPolicy.manifestVersion ||
    manifest.releasePolicyDigest !== trustPolicy.releasePolicyDigest
  ) {
    throw signatureInvalid(
      "Engine manifest is not bound to the active release policy.",
    );
  }

  if (manifest.signature.status === "unsigned-development") {
    if (
      manifest.releaseChannel !== "dev" ||
      !trustPolicy.allowUnsignedDevelopment
    ) {
      throw signatureInvalid(
        "Unsigned engine manifests are allowed only for approved development builds.",
      );
    }
    return;
  }

  const publicKeyBytes = decodeBase64Url(manifest.signature.publicKey);
  const signatureBytes = decodeBase64Url(manifest.signature.value);
  if (!publicKeyBytes || !signatureBytes || signatureBytes.length !== 64) {
    throw signatureInvalid("Engine manifest signature encoding is invalid.");
  }

  const computedKeyId = sha256(publicKeyBytes);
  if (
    computedKeyId !== manifest.signature.keyId ||
    !trustPolicy.engineManifestKeyIds.includes(computedKeyId)
  ) {
    throw signatureInvalid("Engine manifest signing key is not approved.");
  }

  try {
    const publicKey = createPublicKey({
      key: publicKeyBytes,
      format: "der",
      type: "spki",
    });
    const canonicalPublicKey = publicKey.export({
      format: "der",
      type: "spki",
    });
    if (
      publicKey.asymmetricKeyType !== "ed25519" ||
      !Buffer.isBuffer(canonicalPublicKey) ||
      !canonicalPublicKey.equals(publicKeyBytes) ||
      !verifySignature(
        null,
        Buffer.from(canonicalEngineManifestPayload(manifest), "utf8"),
        publicKey,
        signatureBytes,
      )
    ) {
      throw signatureInvalid("Engine manifest signature is invalid.");
    }
  } catch (error) {
    if (error instanceof EngineContractError) throw error;
    throw signatureInvalid("Engine manifest public key is invalid.");
  }
}

function parseManifestSignature(
  signature: Record<string, unknown>,
): EngineManifest["signature"] {
  if (
    signature.status === "unsigned-development" &&
    hasExactKeys(signature, ["status"])
  ) {
    return { status: "unsigned-development" };
  }
  if (
    signature.status === "signed" &&
    hasExactKeys(signature, [
      "status",
      "algorithm",
      "keyId",
      "publicKey",
      "value",
    ]) &&
    signature.algorithm === "ed25519" &&
    typeof signature.keyId === "string" &&
    isLowercaseSha256(signature.keyId) &&
    typeof signature.publicKey === "string" &&
    typeof signature.value === "string"
  ) {
    return {
      status: "signed",
      algorithm: "ed25519",
      keyId: signature.keyId,
      publicKey: signature.publicKey,
      value: signature.value,
    };
  }
  throw invalidManifest("Manifest signature fields are invalid.");
}

export function computeFileChecksum(
  filePath: string,
): { ok: true; checksum: string } | { ok: false; error: string } {
  try {
    const content = fs.readFileSync(filePath);
    return { ok: true, checksum: sha256(content) };
  } catch {
    return { ok: false, error: "checksum_failed" };
  }
}

function sha256(input: Buffer | string): string {
  return createHash("sha256").update(input).digest("hex");
}

function invalidManifest(message: string): EngineContractError {
  return new EngineContractError(
    "GOAT_ENGINE_MANIFEST_INVALID",
    message,
    "Reinstall the GOAT engine so goat-engine.json matches the launcher contract.",
  );
}

function signatureInvalid(message: string): EngineContractError {
  return new EngineContractError(
    "GOAT_ENGINE_SIGNATURE_INVALID",
    message,
    "Reinstall the GOAT engine from a release approved by the active GOAT policy.",
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasExactKeys(
  value: Record<string, unknown>,
  required: readonly string[],
  optional: readonly string[] = [],
): boolean {
  const allowed = new Set([...required, ...optional]);
  const actual = Object.keys(value);
  return (
    required.every((key) => Object.prototype.hasOwnProperty.call(value, key)) &&
    actual.every((key) => allowed.has(key))
  );
}

function isLowercaseSha256(value: string): boolean {
  return /^[a-f0-9]{64}$/.test(value);
}

function decodeBase64Url(value: string): Buffer | null {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) return null;
  try {
    const decoded = Buffer.from(value, "base64url");
    if (decoded.length === 0 || decoded.toString("base64url") !== value) {
      return null;
    }
    return decoded;
  } catch {
    return null;
  }
}

function isVersionString(value: string): boolean {
  return /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(value);
}

function compareVersions(left: string, right: string): number {
  const leftParts = parseVersion(left);
  const rightParts = parseVersion(right);
  for (let index = 0; index < 3; index += 1) {
    const diff = leftParts.version[index] - rightParts.version[index];
    if (diff !== 0) return diff > 0 ? 1 : -1;
  }
  if (leftParts.preRelease === rightParts.preRelease) return 0;
  if (!leftParts.preRelease) return 1;
  if (!rightParts.preRelease) return -1;

  const leftArr = leftParts.preRelease.split(".");
  const rightArr = rightParts.preRelease.split(".");
  const maxLength = Math.max(leftArr.length, rightArr.length);
  for (let i = 0; i < maxLength; i += 1) {
    const l = leftArr[i];
    const r = rightArr[i];
    if (l === undefined) return -1;
    if (r === undefined) return 1;
    if (l === r) continue;
    const lNum = Number(l);
    const rNum = Number(r);
    const lIsNum = !isNaN(lNum) && /^\d+$/.test(l);
    const rIsNum = !isNaN(rNum) && /^\d+$/.test(r);
    if (lIsNum && rIsNum) {
      return lNum - rNum > 0 ? 1 : -1;
    }
    if (lIsNum && !rIsNum) return -1;
    if (!lIsNum && rIsNum) return 1;
    const comp = l.localeCompare(r);
    if (comp !== 0) return comp > 0 ? 1 : -1;
  }
  return 0;
}

function parseVersion(version: string): {
  version: [number, number, number];
  preRelease: string | null;
} {
  const match = /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?/.exec(version);
  if (!match) return { version: [0, 0, 0], preRelease: null };
  return {
    version: [Number(match[1]), Number(match[2]), Number(match[3])],
    preRelease: match[4] || null,
  };
}
