import {
  EngineContractError,
  type GoatArchitecture,
  type GoatPlatform,
  type ReleaseChannel,
  type ResolvedEngine,
} from '../engine/contract.js';
import {
  getEngineExecutableName,
  getPathModule,
  getPlatformDirectories,
  getRuntimeArchitecture,
  getRuntimePlatform,
  getSupportedPlatform,
} from '../platform.js';

export interface EngineResolution {
  path: string | null;
  manifestPath: string | null;
  source: 'local-install' | 'dev-env' | 'env' | 'none';
  releaseChannel: ReleaseChannel;
  platform: GoatPlatform | null;
  architecture: GoatArchitecture | null;
  developmentOverride: boolean;
  error: EngineContractError | null;
}

export interface AppPathOptions {
  env?: NodeJS.ProcessEnv;
  homeDir?: string;
  platform?: NodeJS.Platform;
}

export interface EnginePathOptions extends AppPathOptions {
  architecture?: string;
  appDataDir?: string;
  releaseChannel?: ReleaseChannel;
}

export { getEngineExecutableName, getPathModule, getSupportedPlatform } from '../platform.js';

export function getSupportedArchitecture(architecture: string): GoatArchitecture | null {
  return architecture === 'x64' || architecture === 'arm64' ? architecture : null;
}

export function getAppDataDir(options: AppPathOptions = {}): string {
  return getPlatformDirectories(options).appData;
}

export function getConfigDir(options: AppPathOptions = {}): string {
  return getPlatformDirectories(options).config;
}

export function getCacheDir(options: AppPathOptions = {}): string {
  return getPlatformDirectories(options).cache;
}

export function getLegacyEngineConfigPath(options: AppPathOptions = {}): string {
  const platform = options.platform ?? getRuntimePlatform();
  const pathModule = getPathModule(platform);
  return pathModule.join(getAppDataDir(options), 'config.json');
}

export function getEngineInstallRoot(options: EnginePathOptions = {}): string | null {
  const platform = getSupportedPlatform(options.platform ?? getRuntimePlatform());
  const architecture = getSupportedArchitecture(options.architecture ?? getRuntimeArchitecture());
  if (!platform || !architecture) return null;

  const releaseChannel = options.releaseChannel ?? 'stable';
  const pathModule = getPathModule(platform);
  const appDataDir = options.appDataDir ?? getAppDataDir(options);
  return pathModule.join(appDataDir, 'engines', releaseChannel, `${platform}-${architecture}`);
}

export function getEnginePath(options: EnginePathOptions = {}): EngineResolution {
  const env = options.env ?? process.env;
  const rawPlatform = options.platform ?? getRuntimePlatform();
  const rawArchitecture = options.architecture ?? getRuntimeArchitecture();
  const platform = getSupportedPlatform(rawPlatform);
  const architecture = getSupportedArchitecture(rawArchitecture);

  if (!platform) {
    return noneResolution(
      'stable',
      null,
      architecture,
      new EngineContractError(
        'GOAT_UNSUPPORTED_PLATFORM',
        `GOAT supports Windows and macOS for v0.0.6, but this platform is ${rawPlatform}.`,
        'Run GOAT on Windows or macOS, or install a launcher version that supports this platform.',
      ),
    );
  }

  if (!architecture) {
    return noneResolution(
      'stable',
      platform,
      null,
      new EngineContractError(
        'GOAT_UNSUPPORTED_ARCHITECTURE',
        `GOAT supports x64 and arm64 for v0.0.6, but this architecture is ${rawArchitecture}.`,
        'Use an x64 or arm64 Windows/macOS machine, or install a compatible launcher version.',
      ),
    );
  }

  const pathModule = getPathModule(platform);
  const devPath = env.GOAT_DEV_ENGINE_PATH?.trim();
  if (devPath) {
    if (env.GOATCLI_DEV !== '1') {
      return noneResolution(
        'dev',
        platform,
        architecture,
        new EngineContractError(
          'GOAT_DEV_ENGINE_PATH_DISABLED',
          'GOAT_DEV_ENGINE_PATH is set, but GOATCLI_DEV=1 is not set.',
          'Set GOATCLI_DEV=1 for local launcher development, or unset GOAT_DEV_ENGINE_PATH for production launch.',
        ),
      );
    }

    return {
      path: devPath,
      manifestPath: null,
      source: 'dev-env',
      releaseChannel: 'dev',
      platform,
      architecture,
      developmentOverride: true,
      error: null,
    };
  }

  const legacyEnginePath = env.GOAT_ENGINE_PATH?.trim();
  if (legacyEnginePath) {
    return {
      path: legacyEnginePath,
      manifestPath: null,
      source: 'env',
      releaseChannel: 'stable',
      platform,
      architecture,
      developmentOverride: true,
      error: null,
    };
  }

  const releaseChannel = options.releaseChannel ?? 'stable';
  const installRoot = getEngineInstallRoot({
    ...options,
    platform,
    architecture,
    releaseChannel,
  });

  if (!installRoot) {
    return noneResolution(releaseChannel, platform, architecture, null);
  }

  const executablePath = pathModule.join(installRoot, 'bin', getEngineExecutableName(platform));
  return {
    path: executablePath,
    manifestPath: pathModule.join(installRoot, 'goat-engine.json'),
    source: 'local-install',
    releaseChannel,
    platform,
    architecture,
    developmentOverride: false,
    error: null,
  };
}

export function toResolvedEngine(resolution: EngineResolution): ResolvedEngine {
  if (resolution.error) throw resolution.error;
  if (!resolution.path || !resolution.platform || !resolution.architecture) {
    throw new EngineContractError(
      'GOAT_ENGINE_MISSING',
      'GOAT engine executable is not resolved for this platform.',
      'Install the GOAT engine locally, then run goat doctor to verify the installation.',
    );
  }

  return {
    executablePath: resolution.path,
    manifestPath: resolution.manifestPath,
    source: resolution.source === 'dev-env' || resolution.source === 'env' ? resolution.source : 'local-install',
    releaseChannel: resolution.releaseChannel,
    platform: resolution.platform,
    architecture: resolution.architecture,
    developmentOverride: resolution.developmentOverride,
  };
}

function noneResolution(
  releaseChannel: ReleaseChannel,
  platform: GoatPlatform | null,
  architecture: GoatArchitecture | null,
  error: EngineContractError | null,
): EngineResolution {
  return {
    path: null,
    manifestPath: null,
    source: 'none',
    releaseChannel,
    platform,
    architecture,
    developmentOverride: false,
    error,
  };
}
