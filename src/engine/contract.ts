export type LauncherVersion = string;
export type EngineVersion = string;
export type GoatPlatform = "win32" | "darwin";
export type GoatArchitecture = "x64" | "arm64";
export type ExecutablePath = string;
export type ReleaseChannel = "stable" | "beta" | "dev";

export interface Checksum {
  algorithm: "sha256";
  value: string;
}

export interface EngineCompatibilityRequirements {
  minimumLauncherVersion: LauncherVersion;
  maximumLauncherVersion?: LauncherVersion;
}

export interface UnsignedDevelopmentEngineManifestSignature {
  status: "unsigned-development";
}

export interface SignedEngineManifestSignature {
  status: "signed";
  algorithm: "ed25519";
  keyId: string;
  publicKey: string;
  value: string;
}

export type EngineManifestSignature =
  UnsignedDevelopmentEngineManifestSignature | SignedEngineManifestSignature;

export interface EngineManifestTrustPolicy {
  manifestVersion: 1;
  releasePolicyDigest: string;
  allowUnsignedDevelopment: boolean;
  engineManifestKeyIds: readonly string[];
}

export interface EngineManifest {
  manifestVersion: 1;
  releasePolicyDigest: string;
  engineVersion: EngineVersion;
  platform: GoatPlatform;
  architecture: GoatArchitecture;
  executablePath: ExecutablePath;
  releaseChannel: ReleaseChannel;
  checksum: Checksum;
  compatibility: EngineCompatibilityRequirements;
  signature: EngineManifestSignature;
}

export interface ResolvedEngine {
  executablePath: ExecutablePath;
  manifestPath: string | null;
  source: "local-install" | "development";
  releaseChannel: ReleaseChannel;
  platform: GoatPlatform;
  architecture: GoatArchitecture;
  developmentOverride: boolean;
}

export type EngineErrorCode =
  | "GOAT_UNSUPPORTED_PLATFORM"
  | "GOAT_UNSUPPORTED_ARCHITECTURE"
  | "GOAT_ENGINE_PATH_NOT_ABSOLUTE"
  | "GOAT_ENGINE_MISSING"
  | "GOAT_ENGINE_NOT_FILE"
  | "GOAT_ENGINE_WINDOWS_EXTENSION"
  | "GOAT_ENGINE_NOT_EXECUTABLE"
  | "GOAT_ENGINE_MANIFEST_MISSING"
  | "GOAT_ENGINE_MANIFEST_INVALID"
  | "GOAT_ENGINE_CHECKSUM_MISMATCH"
  | "GOAT_ENGINE_INCOMPATIBLE"
  | "GOAT_ENGINE_SIGNATURE_INVALID"
  | "GOAT_ENGINE_SPAWN_FAILED"
  | "GOAT_ENGINE_ARGS_TOO_LONG"
  | "GOAT_PRIVACY_AUTH_REQUIRED"
  | "GOAT_PRIVACY_IPC_FAILED"
  | "GOAT_NODE_VERSION_UNSUPPORTED";

export class EngineContractError extends Error {
  readonly code: EngineErrorCode;
  readonly suggestion: string;

  constructor(code: EngineErrorCode, message: string, suggestion: string) {
    super(message);
    this.name = "EngineContractError";
    this.code = code;
    this.suggestion = suggestion;
  }
}

const SAFE_ENGINE_ERRORS: Record<EngineErrorCode, readonly [string, string]> = {
  GOAT_UNSUPPORTED_PLATFORM: [
    "This GOAT launcher does not support the current operating system.",
    "Run GOAT on Windows or macOS.",
  ],
  GOAT_UNSUPPORTED_ARCHITECTURE: [
    "This GOAT launcher does not support the current architecture.",
    "Run GOAT on x64 or arm64.",
  ],
  GOAT_ENGINE_PATH_NOT_ABSOLUTE: [
    "The GOAT engine installation is invalid.",
    "Run `goat doctor`.",
  ],
  GOAT_ENGINE_MISSING: [
    "The GOAT engine is not installed correctly.",
    "Run `goat doctor`.",
  ],
  GOAT_ENGINE_NOT_FILE: [
    "The GOAT engine installation is invalid.",
    "Run `goat doctor`.",
  ],
  GOAT_ENGINE_WINDOWS_EXTENSION: [
    "The GOAT engine installation is invalid.",
    "Run `goat doctor`.",
  ],
  GOAT_ENGINE_NOT_EXECUTABLE: [
    "The GOAT engine cannot be executed.",
    "Run `goat doctor`.",
  ],
  GOAT_ENGINE_MANIFEST_MISSING: [
    "The GOAT engine manifest is missing.",
    "Run `goat doctor`.",
  ],
  GOAT_ENGINE_MANIFEST_INVALID: [
    "The GOAT engine manifest is invalid.",
    "Reinstall the GOAT engine.",
  ],
  GOAT_ENGINE_CHECKSUM_MISMATCH: [
    "The GOAT engine failed its integrity check.",
    "Reinstall the GOAT engine.",
  ],
  GOAT_ENGINE_INCOMPATIBLE: [
    "The GOAT engine is incompatible with this launcher.",
    "Install a compatible GOAT engine.",
  ],
  GOAT_ENGINE_SIGNATURE_INVALID: [
    "The GOAT engine manifest signature is missing or untrusted.",
    "Reinstall the GOAT engine from an approved GOAT release.",
  ],
  GOAT_ENGINE_SPAWN_FAILED: [
    "The GOAT engine could not be started.",
    "Run `goat doctor`.",
  ],
  GOAT_ENGINE_ARGS_TOO_LONG: [
    "The GOAT command is too large to launch safely.",
    "Reduce the command length.",
  ],
  GOAT_PRIVACY_AUTH_REQUIRED: [
    "GOAT privacy authentication is required.",
    "Run `goat login`.",
  ],
  GOAT_PRIVACY_IPC_FAILED: [
    "The GOAT privacy session could not be established.",
    "Run `goat doctor`.",
  ],
  GOAT_NODE_VERSION_UNSUPPORTED: [
    "This Node.js version cannot safely launch GOAT privacy IPC on Windows.",
    "Install Node.js 24.16.0 or newer.",
  ],
};

export function formatEngineContractError(error: EngineContractError): string {
  const [message, nextStep] = SAFE_ENGINE_ERRORS[error.code];
  return `GOAT launcher error [${error.code}]: ${message}\nNext step: ${nextStep}`;
}
