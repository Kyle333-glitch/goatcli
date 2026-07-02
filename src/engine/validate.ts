import fs from 'fs';
import { createHash } from 'crypto';
import {
  EngineContractError,
  type EngineManifest,
  type LauncherVersion,
  type ResolvedEngine,
} from './contract.js';
import {
  getEngineExecutableName,
  getPathModule,
} from '../utils/paths.js';
import { getPlatformAdapter } from '../platform.js';

export interface ValidatedEngine {
  resolved: ResolvedEngine;
  manifest: EngineManifest | null;
  checksum: string;
}

export interface EngineFileSystem {
  constants: Pick<typeof fs.constants, 'X_OK'>;
  existsSync(path: string): boolean;
  statSync(path: string): Pick<fs.Stats, 'isFile'>;
  accessSync(path: string, mode?: number): void;
  readFileSync(path: string): Buffer | string;
}

export interface ValidateEngineOptions {
  fs?: EngineFileSystem;
}

export function validateEngine(
  resolved: ResolvedEngine,
  launcherVersion: LauncherVersion,
  options: ValidateEngineOptions = {},
): ValidatedEngine {
  const fileSystem = options.fs ?? fs;
  const pathModule = getPathModule(resolved.platform);
  const platform = getPlatformAdapter(resolved.platform);

  if (!pathModule.isAbsolute(resolved.executablePath)) {
    throw new EngineContractError(
      'GOAT_ENGINE_PATH_NOT_ABSOLUTE',
      `Engine path must be absolute: ${resolved.executablePath}`,
      'Reinstall the GOAT engine or use an absolute GOAT_DEV_ENGINE_PATH during local development.',
    );
  }

  const expectedExecutableName = getEngineExecutableName(resolved.platform);
  const actualExecutableName = pathModule.basename(resolved.executablePath);
  if (!resolved.developmentOverride && actualExecutableName !== expectedExecutableName) {
    const code = resolved.platform === 'win32' ? 'GOAT_ENGINE_WINDOWS_EXTENSION' : 'GOAT_ENGINE_MISSING';
    throw new EngineContractError(
      code,
      `Expected engine executable ${expectedExecutableName}, but resolved ${actualExecutableName}.`,
      `Install the engine as ${expectedExecutableName} in the resolved bin directory.`,
    );
  }

  if (!fileSystem.existsSync(resolved.executablePath)) {
    throw new EngineContractError(
      'GOAT_ENGINE_MISSING',
      `GOAT engine executable was not found at ${resolved.executablePath}.`,
      'Install the local GOAT engine, or set GOATCLI_DEV=1 with GOAT_DEV_ENGINE_PATH for development.',
    );
  }

  let stats: Pick<fs.Stats, 'isFile'>;
  try {
    stats = fileSystem.statSync(resolved.executablePath);
  } catch {
    throw new EngineContractError(
      'GOAT_ENGINE_MISSING',
      `GOAT engine executable could not be inspected at ${resolved.executablePath}.`,
      'Check that the file exists and is readable, then run goat doctor.',
    );
  }

  if (!stats.isFile()) {
    throw new EngineContractError(
      'GOAT_ENGINE_NOT_FILE',
      `GOAT engine path is not a file: ${resolved.executablePath}`,
      'Replace the path with the GOAT engine executable file.',
    );
  }

  if (!platform.hasExecutablePermission(resolved.executablePath, fileSystem)) {
    const suggestion = resolved.platform === 'win32'
      ? `Ensure the file has execute permissions and is not blocked by Windows. Run goat doctor again.`
      : `Run chmod +x "${resolved.executablePath}", then run goat doctor again.`;
    throw new EngineContractError(
      'GOAT_ENGINE_NOT_EXECUTABLE',
      `GOAT engine is not executable: ${resolved.executablePath}`,
      suggestion,
    );
  }

  if (resolved.developmentOverride) {
    return { resolved, manifest: null, checksum: 'development-override' };
  }

  let checksum: string;
  try {
    checksum = sha256(fileSystem.readFileSync(resolved.executablePath));
  } catch {
    throw new EngineContractError(
      'GOAT_ENGINE_MISSING',
      `GOAT engine executable could not be read at ${resolved.executablePath}.`,
      'Check that the file exists and is readable, then run goat doctor.',
    );
  }

  if (!resolved.manifestPath || !fileSystem.existsSync(resolved.manifestPath)) {
    throw new EngineContractError(
      'GOAT_ENGINE_MANIFEST_MISSING',
      `GOAT engine manifest was not found at ${resolved.manifestPath ?? '(none)'}.`,
      'Reinstall the GOAT engine so goat-engine.json is present beside the engine root.',
    );
  }

  const manifest = parseManifest(fileSystem.readFileSync(resolved.manifestPath));
  validateManifestAgainstResolution(manifest, resolved, launcherVersion);

  if (manifest.checksum.value.toLowerCase() !== checksum) {
    throw new EngineContractError(
      'GOAT_ENGINE_CHECKSUM_MISMATCH',
      `GOAT engine checksum mismatch for ${resolved.executablePath}.`,
      'Reinstall the GOAT engine from a trusted GOAT release.',
    );
  }

  return { resolved, manifest, checksum };
}

export function parseManifest(raw: Buffer | string): EngineManifest {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw.toString());
  } catch {
    throw invalidManifest('Manifest is not valid JSON.');
  }

  if (!isRecord(parsed)) throw invalidManifest('Manifest must be a JSON object.');
  const manifest = parsed as Record<string, unknown>;
  const checksum = manifest.checksum;
  const compatibility = manifest.compatibility;

  if (
    typeof manifest.engineVersion !== 'string' ||
    typeof manifest.platform !== 'string' ||
    typeof manifest.architecture !== 'string' ||
    typeof manifest.executablePath !== 'string' ||
    typeof manifest.releaseChannel !== 'string' ||
    !isRecord(checksum) ||
    checksum.algorithm !== 'sha256' ||
    typeof checksum.value !== 'string' ||
    !isSha256(checksum.value) ||
    !isRecord(compatibility) ||
    typeof compatibility.minimumLauncherVersion !== 'string' ||
    (
      compatibility.maximumLauncherVersion !== undefined &&
      typeof compatibility.maximumLauncherVersion !== 'string'
    )
  ) {
    throw invalidManifest('Manifest fields do not match the GOAT engine contract.');
  }

  if (manifest.platform !== 'win32' && manifest.platform !== 'darwin') {
    throw invalidManifest(`Unsupported manifest platform: ${manifest.platform}`);
  }
  if (manifest.architecture !== 'x64' && manifest.architecture !== 'arm64') {
    throw invalidManifest(`Unsupported manifest architecture: ${manifest.architecture}`);
  }
  if (
    manifest.releaseChannel !== 'stable' &&
    manifest.releaseChannel !== 'beta' &&
    manifest.releaseChannel !== 'dev'
  ) {
    throw invalidManifest(`Unsupported manifest release channel: ${manifest.releaseChannel}`);
  }
  if (!isVersionString(manifest.engineVersion)) {
    throw invalidManifest(`Invalid engine version: ${manifest.engineVersion}`);
  }
  if (!isVersionString(compatibility.minimumLauncherVersion)) {
    throw invalidManifest(`Invalid minimum launcher version: ${compatibility.minimumLauncherVersion}`);
  }
  if (
    compatibility.maximumLauncherVersion !== undefined &&
    !isVersionString(compatibility.maximumLauncherVersion)
  ) {
    throw invalidManifest(`Invalid maximum launcher version: ${compatibility.maximumLauncherVersion}`);
  }

  return {
    engineVersion: manifest.engineVersion,
    platform: manifest.platform,
    architecture: manifest.architecture,
    executablePath: manifest.executablePath,
    releaseChannel: manifest.releaseChannel,
    checksum: {
      algorithm: 'sha256',
      value: checksum.value.toLowerCase(),
    },
    compatibility: {
      minimumLauncherVersion: compatibility.minimumLauncherVersion,
      maximumLauncherVersion: compatibility.maximumLauncherVersion,
    },
  };
}

function validateManifestAgainstResolution(
  manifest: EngineManifest,
  resolved: ResolvedEngine,
  launcherVersion: LauncherVersion,
): void {
  if (manifest.platform !== resolved.platform) {
    throw invalidManifest(`Manifest platform ${manifest.platform} does not match ${resolved.platform}.`);
  }
  if (manifest.architecture !== resolved.architecture) {
    throw invalidManifest(`Manifest architecture ${manifest.architecture} does not match ${resolved.architecture}.`);
  }
  if (manifest.releaseChannel !== resolved.releaseChannel) {
    throw invalidManifest(`Manifest release channel ${manifest.releaseChannel} does not match ${resolved.releaseChannel}.`);
  }

  const expectedExecutablePath = `bin/${getEngineExecutableName(resolved.platform)}`;
  const normalizedManifestPath = manifest.executablePath.replaceAll('\\', '/');
  if (normalizedManifestPath !== expectedExecutablePath) {
    throw invalidManifest(`Manifest executable path must be ${expectedExecutablePath}.`);
  }

  const minVersion = manifest.compatibility.minimumLauncherVersion;
  const maxVersion = manifest.compatibility.maximumLauncherVersion;
  if (compareVersions(launcherVersion, minVersion) < 0) {
    throw new EngineContractError(
      'GOAT_ENGINE_INCOMPATIBLE',
      `GOAT engine requires launcher ${minVersion} or newer; current launcher is ${launcherVersion}.`,
      'Update goatcli, then run goat doctor again.',
    );
  }
  if (maxVersion && compareVersions(launcherVersion, maxVersion) > 0) {
    throw new EngineContractError(
      'GOAT_ENGINE_INCOMPATIBLE',
      `GOAT engine supports launcher ${maxVersion} or older; current launcher is ${launcherVersion}.`,
      'Install a GOAT engine version compatible with this goatcli release.',
    );
  }
}

export function computeFileChecksum(filePath: string): { ok: true; checksum: string } | { ok: false; error: string } {
  try {
    const content = fs.readFileSync(filePath);
    return { ok: true, checksum: sha256(content) };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { ok: false, error: message };
  }
}

function sha256(input: Buffer | string): string {
  return createHash('sha256').update(input).digest('hex');
}

function invalidManifest(message: string): EngineContractError {
  return new EngineContractError(
    'GOAT_ENGINE_MANIFEST_INVALID',
    message,
    'Reinstall the GOAT engine so goat-engine.json matches the launcher contract.',
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isSha256(value: string): boolean {
  return /^[a-f0-9]{64}$/i.test(value);
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

  const leftArr = leftParts.preRelease.split('.');
  const rightArr = rightParts.preRelease.split('.');
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

function parseVersion(version: string): { version: [number, number, number]; preRelease: string | null } {
  const match = /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?/.exec(version);
  if (!match) return { version: [0, 0, 0], preRelease: null };
  return {
    version: [Number(match[1]), Number(match[2]), Number(match[3])],
    preRelease: match[4] || null,
  };
}
