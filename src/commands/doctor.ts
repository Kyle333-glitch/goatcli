import { intro, outro, spinner, note, log } from '@clack/prompts';
import fs from 'fs';
import { getAppDataDir, getCacheDir, getConfigDir, getEnginePath, getLegacyEngineConfigPath, toResolvedEngine } from '../utils/paths.js';
import {
  getGitVersion,
  getShell,
  checkDirectoryWritable,
  getWindowsLongPathsEnabled,
  checkPathLengthProblems,
  checkMacExecutable,
  checkWindowsPathProblems,
} from '../utils/system.js';
import { EngineContractError, formatEngineContractError, type LauncherVersion } from '../engine/contract.js';
import { validateEngine, type ValidatedEngine } from '../engine/validate.js';
import { getLauncherVersion } from '../version.js';
import { getPlatformAdapterForPlatform, getRuntimePlatform, getRuntimeArchitecture } from '../platform.js';

export interface DoctorOptions {
  launcherVersion?: LauncherVersion;
}

export async function runDoctor(options: DoctorOptions = {}): Promise<void> {
  const launcherVersion = options.launcherVersion ?? getLauncherVersion();
  intro('GOAT System Diagnostics (Doctor)');

  const s = spinner();
  s.start('Inspecting system environment...');

  const osPlatform = getRuntimePlatform();
  const osArch = getRuntimeArchitecture();
  const nodeVersion = process.version;
  const cwd = process.cwd();
  const shell = getShell({ platform: osPlatform });
  const gitVersion = await getGitVersion();
  const platform = getPlatformAdapterForPlatform(osPlatform);

  const engineResolution = getEnginePath();
  const appDataDir = getAppDataDir();
  const configDir = getConfigDir();
  const cacheDir = getCacheDir();
  const legacyConfigPath = getLegacyEngineConfigPath();
  const legacyConfigExists = fs.existsSync(legacyConfigPath);

  const appDataWritable = checkDirectoryWritable(appDataDir);
  const configWritable = checkDirectoryWritable(configDir);
  const cacheWritable = checkDirectoryWritable(cacheDir);

  const pathsToCheck = [
    { name: 'Application Data Directory', path: appDataDir },
    { name: 'Configuration Directory', path: configDir },
    { name: 'Cache Directory', path: cacheDir },
  ];
  if (engineResolution.path) {
    pathsToCheck.push({ name: 'Engine Executable Path', path: engineResolution.path });
  }
  if (engineResolution.manifestPath) {
    pathsToCheck.push({ name: 'Engine Manifest Path', path: engineResolution.manifestPath });
  }
  const pathLengthStatuses = checkPathLengthProblems(pathsToCheck, { platform: osPlatform });

  let windowsIssues = null;
  let macStatus = null;
  let longPathsEnabled: boolean | null = null;

  if (platform?.platform === 'win32') {
    windowsIssues = checkWindowsPathProblems(osPlatform);
    longPathsEnabled = await getWindowsLongPathsEnabled(osPlatform);
  } else if (platform?.platform === 'darwin' && engineResolution.path) {
    macStatus = await checkMacExecutable(engineResolution.path, osPlatform);
  }

  let validatedEngine: ValidatedEngine | null = null;
  let engineValidationError: EngineContractError | null = null;
  try {
    validatedEngine = validateEngine(toResolvedEngine(engineResolution), launcherVersion);
  } catch (error) {
    if (error instanceof EngineContractError) {
      engineValidationError = error;
    } else {
      throw error;
    }
  }

  s.stop('Diagnostics completed.');

  const sysInfoContent = [
    `- OS & Arch:       ${osPlatform} (${osArch})`,
    `- Node.js Version:  ${nodeVersion}`,
    `- GOAT CLI Version: ${launcherVersion}`,
    `- Git Version:      ${gitVersion ? gitVersion : 'NOT FOUND (Git is required for many features)'}`,
    `- Shell:            ${shell}`,
    `- Working Dir:      ${cwd}`,
  ].join('\n');
  note(sysInfoContent, 'System Information');

  const engineStatusText = engineResolution.path
    ? `${engineResolution.path} (${validatedEngine ? 'valid' : 'not valid'})`
    : 'not resolved';
  const manifestStatusText = engineResolution.manifestPath
    ? `${engineResolution.manifestPath} (${validatedEngine?.manifest ? 'valid' : 'not valid'})`
    : engineResolution.source === 'env'
      ? 'not required for legacy GOAT_ENGINE_PATH override'
      : engineResolution.developmentOverride
        ? 'not required for GOATCLI_DEV=1 development override'
        : 'not resolved';
  const sourceText = engineResolution.source === 'dev-env'
    ? 'GOAT_DEV_ENGINE_PATH with GOATCLI_DEV=1'
    : engineResolution.source === 'env'
      ? 'GOAT_ENGINE_PATH legacy override'
      : engineResolution.source === 'local-install'
        ? 'Local app-data engine install'
        : 'None';

  const pathsContent = [
    `- App Data Dir:     ${appDataDir} (${appDataWritable.writable ? 'writable' : 'read-only'}${appDataWritable.exists ? ', exists' : ', will create'})`,
    `- Config Dir:       ${configDir} (${configWritable.writable ? 'writable' : 'read-only'}${configWritable.exists ? ', exists' : ', will create'})`,
    `- Cache Dir:        ${cacheDir} (${cacheWritable.writable ? 'writable' : 'read-only'}${cacheWritable.exists ? ', exists' : ', will create'})`,
    `- Engine Path:      ${engineStatusText}`,
    `- Manifest Path:    ${manifestStatusText}`,
    `- Path Source:      ${sourceText}`,
    `- Release Channel:  ${engineResolution.releaseChannel}`,
    `- Engine Checksum:  ${validatedEngine?.checksum ?? 'not available'}`,
  ].join('\n');
  note(pathsContent, 'GOAT Configuration & Engine Contract');

  const warnings: string[] = [];
  const errors: string[] = [];

  if (!gitVersion) {
    errors.push('Git is not installed or not available in the system PATH. Please install Git.');
  }

  if (!appDataWritable.writable) {
    errors.push(`Application data directory is not writable: ${appDataWritable.error || 'Permission denied'}`);
  }
  if (!configWritable.writable) {
    errors.push(`Configuration directory is not writable: ${configWritable.error || 'Permission denied'}`);
  }
  if (!cacheWritable.writable) {
    errors.push(`Cache directory is not writable: ${cacheWritable.error || 'Permission denied'}`);
  }

  for (const status of pathLengthStatuses) {
    if (status.hasProblem) {
      warnings.push(`Path is too long on Windows and may cause issues: ${status.name} (${status.path})`);
    }
  }

  if (legacyConfigExists) {
    warnings.push(
      `Legacy ${legacyConfigPath} was found. goatcli v0.0.6 ignores config.json enginePath; use the local engine install path or GOATCLI_DEV=1 with GOAT_DEV_ENGINE_PATH.`,
    );
  }

  if (engineValidationError) {
    errors.push(formatEngineContractError(engineValidationError).replace('\n', ' '));
  }

  if (platform?.platform === 'win32') {
    if (longPathsEnabled === false) {
      warnings.push('Windows Registry LongPathsEnabled is disabled. Path operations longer than 260 characters might fail.');
    }
    if (windowsIssues) {
      if (!windowsIssues.pathExtHasExe) {
        errors.push('PATHEXT environment variable does not contain .EXE. Windows might fail to launch executables.');
      }
      if (!windowsIssues.npmBinInPath) {
        warnings.push('npm global binaries directory not detected in PATH. You may not be able to run goat globally.');
      }
    }
  }

  if (platform?.platform === 'darwin' && engineResolution.path && macStatus) {
    if (macStatus.isQuarantined) {
      warnings.push(`Engine binary is quarantined by macOS Gatekeeper. Run: xattr -d com.apple.quarantine "${engineResolution.path}"`);
    }
    if (macStatus.exists && !macStatus.codeSignValid) {
      warnings.push('Engine binary signature verification failed. The binary may be unsigned or modified.');
    }
  }

  if (errors.length > 0 || warnings.length > 0) {
    if (errors.length > 0) {
      log.error('Issues Detected (Critical):');
      errors.forEach((entry) => log.error(`  - ${entry}`));
    }
    if (warnings.length > 0) {
      log.warn('Recommendations (Warnings):');
      warnings.forEach((entry) => log.warn(`  - ${entry}`));
    }

    outro('GOAT Doctor finished with warnings or errors. See recommendations above.');
    return;
  }

  log.success('All system checks passed successfully.');
  outro('GOAT Doctor found no issues. Your environment is healthy.');
}
