export type LauncherVersion = string;
export type EngineVersion = string;
export type GoatPlatform = 'win32' | 'darwin';
export type GoatArchitecture = 'x64' | 'arm64';
export type ExecutablePath = string;
export type ReleaseChannel = 'stable' | 'beta' | 'dev';

export interface Checksum {
  algorithm: 'sha256';
  value: string;
}

export interface EngineCompatibilityRequirements {
  minimumLauncherVersion: LauncherVersion;
  maximumLauncherVersion?: LauncherVersion;
}

export interface EngineManifest {
  engineVersion: EngineVersion;
  platform: GoatPlatform;
  architecture: GoatArchitecture;
  executablePath: ExecutablePath;
  releaseChannel: ReleaseChannel;
  checksum: Checksum;
  compatibility: EngineCompatibilityRequirements;
}

export interface ResolvedEngine {
  executablePath: ExecutablePath;
  manifestPath: string | null;
  source: 'local-install' | 'dev-env' | 'env';
  releaseChannel: ReleaseChannel;
  platform: GoatPlatform;
  architecture: GoatArchitecture;
  developmentOverride: boolean;
}

export type EngineErrorCode =
  | 'GOAT_UNSUPPORTED_PLATFORM'
  | 'GOAT_UNSUPPORTED_ARCHITECTURE'
  | 'GOAT_DEV_ENGINE_PATH_DISABLED'
  | 'GOAT_ENGINE_PATH_NOT_ABSOLUTE'
  | 'GOAT_ENGINE_MISSING'
  | 'GOAT_ENGINE_NOT_FILE'
  | 'GOAT_ENGINE_WINDOWS_EXTENSION'
  | 'GOAT_ENGINE_NOT_EXECUTABLE'
  | 'GOAT_ENGINE_MANIFEST_MISSING'
  | 'GOAT_ENGINE_MANIFEST_INVALID'
  | 'GOAT_ENGINE_CHECKSUM_MISMATCH'
  | 'GOAT_ENGINE_INCOMPATIBLE'
  | 'GOAT_ENGINE_SPAWN_FAILED'
  | 'GOAT_ENGINE_ARGS_TOO_LONG';

export class EngineContractError extends Error {
  readonly code: EngineErrorCode;
  readonly suggestion: string;

  constructor(code: EngineErrorCode, message: string, suggestion: string) {
    super(message);
    this.name = 'EngineContractError';
    this.code = code;
    this.suggestion = suggestion;
  }
}

export function formatEngineContractError(error: EngineContractError): string {
  return [
    `GOAT launcher error [${error.code}]: ${error.message}`,
    `Next step: ${error.suggestion}`,
  ].join('\n');
}
