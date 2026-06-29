import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import { EngineContractError, type EngineManifest, type ResolvedEngine } from './contract.js';
import { validateEngine, type EngineFileSystem } from './validate.js';

test('validateEngine accepts a Windows engine path with spaces, .exe, manifest, checksum, and compatibility', () => {
  const executablePath = 'C:\\Users\\Test User\\AppData\\Local\\goat\\engines\\stable\\win32-x64\\bin\\goat-engine.exe';
  const manifestPath = 'C:\\Users\\Test User\\AppData\\Local\\goat\\engines\\stable\\win32-x64\\goat-engine.json';
  const engineBytes = Buffer.from('windows engine');
  const fakeFs = makeFakeFs({
    [executablePath]: { content: engineBytes, isFile: true },
    [manifestPath]: { content: JSON.stringify(makeManifest('win32', 'x64', 'bin/goat-engine.exe', sha256(engineBytes))), isFile: true },
  });

  const result = validateEngine(makeResolvedEngine({ executablePath, manifestPath, platform: 'win32', architecture: 'x64' }), '0.0.5', { fs: fakeFs });

  assert.equal(result.checksum, sha256(engineBytes));
  assert.equal(result.manifest?.engineVersion, '1.17.11');
});

test('validateEngine accepts a macOS path with spaces and Unicode when executable bit is set', () => {
  const executablePath = '/Users/Test User/Library/Application Support/goat-測試/engines/stable/darwin-arm64/bin/goat-engine';
  const manifestPath = '/Users/Test User/Library/Application Support/goat-測試/engines/stable/darwin-arm64/goat-engine.json';
  const engineBytes = Buffer.from('mac engine');
  const fakeFs = makeFakeFs({
    [executablePath]: { content: engineBytes, isFile: true, executable: true },
    [manifestPath]: { content: JSON.stringify(makeManifest('darwin', 'arm64', 'bin/goat-engine', sha256(engineBytes))), isFile: true },
  });

  const result = validateEngine(makeResolvedEngine({ executablePath, manifestPath, platform: 'darwin', architecture: 'arm64' }), '0.0.5', { fs: fakeFs });

  assert.equal(result.checksum, sha256(engineBytes));
  assert.equal(result.manifest?.platform, 'darwin');
});

test('validateEngine does not require a manifest for development override', () => {
  const executablePath = 'C:\\GOAT Dev\\goat-engine.exe';
  const engineBytes = Buffer.from('dev engine');
  const fakeFs = makeFakeFs({
    [executablePath]: { content: engineBytes, isFile: true },
  });

  const result = validateEngine(
    makeResolvedEngine({
      executablePath,
      manifestPath: null,
      platform: 'win32',
      architecture: 'x64',
      releaseChannel: 'dev',
      source: 'dev-env',
      developmentOverride: true,
    }),
    '0.0.5',
    { fs: fakeFs },
  );

  assert.equal(result.manifest, null);
  assert.equal(result.checksum, sha256(engineBytes));
});

test('validateEngine rejects Windows engine paths without .exe', () => {
  const executablePath = 'C:\\GOAT\\bin\\goat-engine';
  const fakeFs = makeFakeFs({
    [executablePath]: { content: 'engine', isFile: true },
  });

  assert.throws(
    () => validateEngine(makeResolvedEngine({ executablePath, platform: 'win32', architecture: 'x64' }), '0.0.5', { fs: fakeFs }),
    (error) => error instanceof EngineContractError && error.code === 'GOAT_ENGINE_WINDOWS_EXTENSION',
  );
});

test('validateEngine rejects macOS engines without executable bit', () => {
  const executablePath = '/Users/Test User/Library/Application Support/goat/engines/stable/darwin-x64/bin/goat-engine';
  const manifestPath = '/Users/Test User/Library/Application Support/goat/engines/stable/darwin-x64/goat-engine.json';
  const engineBytes = Buffer.from('mac engine');
  const fakeFs = makeFakeFs({
    [executablePath]: { content: engineBytes, isFile: true, executable: false },
    [manifestPath]: { content: JSON.stringify(makeManifest('darwin', 'x64', 'bin/goat-engine', sha256(engineBytes))), isFile: true },
  });

  assert.throws(
    () => validateEngine(makeResolvedEngine({ executablePath, manifestPath, platform: 'darwin', architecture: 'x64' }), '0.0.5', { fs: fakeFs }),
    (error) => error instanceof EngineContractError && error.code === 'GOAT_ENGINE_MACOS_NOT_EXECUTABLE',
  );
});

test('validateEngine rejects missing production manifest', () => {
  const executablePath = 'C:\\GOAT\\engines\\stable\\win32-x64\\bin\\goat-engine.exe';
  const fakeFs = makeFakeFs({
    [executablePath]: { content: 'engine', isFile: true },
  });

  assert.throws(
    () => validateEngine(makeResolvedEngine({ executablePath, manifestPath: 'C:\\GOAT\\engines\\stable\\win32-x64\\goat-engine.json' }), '0.0.5', { fs: fakeFs }),
    (error) => error instanceof EngineContractError && error.code === 'GOAT_ENGINE_MANIFEST_MISSING',
  );
});

test('validateEngine rejects checksum mismatch', () => {
  const executablePath = 'C:\\GOAT\\engines\\stable\\win32-x64\\bin\\goat-engine.exe';
  const manifestPath = 'C:\\GOAT\\engines\\stable\\win32-x64\\goat-engine.json';
  const fakeFs = makeFakeFs({
    [executablePath]: { content: 'actual engine', isFile: true },
    [manifestPath]: { content: JSON.stringify(makeManifest('win32', 'x64', 'bin/goat-engine.exe', sha256('different engine'))), isFile: true },
  });

  assert.throws(
    () => validateEngine(makeResolvedEngine({ executablePath, manifestPath }), '0.0.5', { fs: fakeFs }),
    (error) => error instanceof EngineContractError && error.code === 'GOAT_ENGINE_CHECKSUM_MISMATCH',
  );
});

test('validateEngine rejects incompatible launcher versions', () => {
  const executablePath = 'C:\\GOAT\\engines\\stable\\win32-x64\\bin\\goat-engine.exe';
  const manifestPath = 'C:\\GOAT\\engines\\stable\\win32-x64\\goat-engine.json';
  const engineBytes = Buffer.from('engine');
  const manifest = makeManifest('win32', 'x64', 'bin/goat-engine.exe', sha256(engineBytes));
  manifest.compatibility.minimumLauncherVersion = '0.0.6';
  const fakeFs = makeFakeFs({
    [executablePath]: { content: engineBytes, isFile: true },
    [manifestPath]: { content: JSON.stringify(manifest), isFile: true },
  });

  assert.throws(
    () => validateEngine(makeResolvedEngine({ executablePath, manifestPath }), '0.0.5', { fs: fakeFs }),
    (error) => error instanceof EngineContractError && error.code === 'GOAT_ENGINE_INCOMPATIBLE',
  );
});

test('validateEngine rejects incompatible pre-release launcher versions', () => {
  const executablePath = 'C:\\GOAT\\engines\\stable\\win32-x64\\bin\\goat-engine.exe';
  const manifestPath = 'C:\\GOAT\\engines\\stable\\win32-x64\\goat-engine.json';
  const engineBytes = Buffer.from('engine');
  const manifest = makeManifest('win32', 'x64', 'bin/goat-engine.exe', sha256(engineBytes));
  manifest.compatibility.minimumLauncherVersion = '0.0.5';
  const fakeFs = makeFakeFs({
    [executablePath]: { content: engineBytes, isFile: true },
    [manifestPath]: { content: JSON.stringify(manifest), isFile: true },
  });

  assert.throws(
    () => validateEngine(makeResolvedEngine({ executablePath, manifestPath }), '0.0.5-beta.1', { fs: fakeFs }),
    (error) => error instanceof EngineContractError && error.code === 'GOAT_ENGINE_INCOMPATIBLE',
  );
});

test('validateEngine rejects malformed manifests', () => {
  const executablePath = 'C:\\GOAT\\engines\\stable\\win32-x64\\bin\\goat-engine.exe';
  const manifestPath = 'C:\\GOAT\\engines\\stable\\win32-x64\\goat-engine.json';
  const fakeFs = makeFakeFs({
    [executablePath]: { content: 'engine', isFile: true },
    [manifestPath]: { content: '{"engineVersion": 5}', isFile: true },
  });

  assert.throws(
    () => validateEngine(makeResolvedEngine({ executablePath, manifestPath }), '0.0.5', { fs: fakeFs }),
    (error) => error instanceof EngineContractError && error.code === 'GOAT_ENGINE_MANIFEST_INVALID',
  );
});


test('validateEngine rejects relative development override paths', () => {
  const executablePath = 'relative\\goat-engine.exe';
  const fakeFs = makeFakeFs({
    [executablePath]: { content: 'engine', isFile: true },
  });

  assert.throws(
    () => validateEngine(
      makeResolvedEngine({
        executablePath,
        manifestPath: null,
        releaseChannel: 'dev',
        source: 'dev-env',
        developmentOverride: true,
      }),
      '0.0.5',
      { fs: fakeFs },
    ),
    (error) => error instanceof EngineContractError && error.code === 'GOAT_ENGINE_PATH_NOT_ABSOLUTE',
  );
});
function makeManifest(
  platform: EngineManifest['platform'],
  architecture: EngineManifest['architecture'],
  executablePath: string,
  checksum: string,
): EngineManifest {
  return {
    engineVersion: '1.17.11',
    platform,
    architecture,
    executablePath,
    releaseChannel: 'stable',
    checksum: {
      algorithm: 'sha256',
      value: checksum,
    },
    compatibility: {
      minimumLauncherVersion: '0.0.5',
      maximumLauncherVersion: '0.0.5',
    },
  };
}

function makeResolvedEngine(overrides: Partial<ResolvedEngine>): ResolvedEngine {
  return {
    executablePath: 'C:\\GOAT\\engines\\stable\\win32-x64\\bin\\goat-engine.exe',
    manifestPath: 'C:\\GOAT\\engines\\stable\\win32-x64\\goat-engine.json',
    source: 'local-install',
    releaseChannel: 'stable',
    platform: 'win32',
    architecture: 'x64',
    developmentOverride: false,
    ...overrides,
  };
}

interface FakeFile {
  content: Buffer | string;
  isFile: boolean;
  executable?: boolean;
}

function makeFakeFs(files: Record<string, FakeFile>): EngineFileSystem {
  return {
    constants: {
      X_OK: fs.constants.X_OK,
    },
    existsSync(filePath: string) {
      return files[filePath] !== undefined;
    },
    statSync(filePath: string) {
      const file = files[filePath];
      if (!file) throw new Error(`missing ${filePath}`);
      return {
        isFile: () => file.isFile,
      };
    },
    accessSync(filePath: string, mode?: number) {
      const file = files[filePath];
      if (!file) throw new Error(`missing ${filePath}`);
      if (mode === fs.constants.X_OK && !file.executable) {
        throw new Error(`not executable ${filePath}`);
      }
    },
    readFileSync(filePath: string) {
      const file = files[filePath];
      if (!file) throw new Error(`missing ${filePath}`);
      return file.content;
    },
  };
}

function sha256(input: Buffer | string): string {
  return createHash('sha256').update(input).digest('hex');
}

