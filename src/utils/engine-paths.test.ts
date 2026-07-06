import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  getEnginePath,
  getEngineExecutableName,
} from './paths.js';

test('getEnginePath resolves deterministic Windows install path with spaces and .exe', () => {
  const appDataDir = 'C:\\Users\\Test User\\AppData\\Local\\goat';
  const result = getEnginePath({
    platform: 'win32',
    architecture: 'x64',
    appDataDir,
    env: {},
  });

  assert.equal(result.error, null);
  assert.equal(result.source, 'local-install');
  assert.equal(result.releaseChannel, 'stable');
  assert.equal(result.path, 'C:\\Users\\Test User\\AppData\\Local\\goat\\engines\\stable\\win32-x64\\bin\\goat-engine.exe');
  assert.equal(result.manifestPath, 'C:\\Users\\Test User\\AppData\\Local\\goat\\engines\\stable\\win32-x64\\goat-engine.json');
});

test('getEnginePath resolves deterministic macOS POSIX path with spaces and Unicode', () => {
  const appDataDir = '/Users/Test User/Library/Application Support/goat-測試';
  const result = getEnginePath({
    platform: 'darwin',
    architecture: 'arm64',
    appDataDir,
    env: {},
  });

  assert.equal(result.error, null);
  assert.equal(result.source, 'local-install');
  assert.equal(result.path, '/Users/Test User/Library/Application Support/goat-測試/engines/stable/darwin-arm64/bin/goat-engine');
  assert.equal(result.manifestPath, '/Users/Test User/Library/Application Support/goat-測試/engines/stable/darwin-arm64/goat-engine.json');
});

test('getEnginePath rejects development override unless GOATCLI_DEV is enabled', () => {
  const result = getEnginePath({
    platform: 'win32',
    architecture: 'x64',
    env: {
      GOAT_DEV_ENGINE_PATH: 'C:\\GOAT Dev\\goat-engine.exe',
    },
  });

  assert.equal(result.source, 'none');
  assert.equal(result.error?.code, 'GOAT_DEV_ENGINE_PATH_DISABLED');
});

test('getEnginePath accepts gated GOAT_DEV_ENGINE_PATH', () => {
  const result = getEnginePath({
    platform: 'win32',
    architecture: 'x64',
    env: {
      GOATCLI_DEV: '1',
      GOAT_DEV_ENGINE_PATH: 'C:\\GOAT Dev\\goat-engine.exe',
    },
  });

  assert.equal(result.error, null);
  assert.equal(result.source, 'dev-env');
  assert.equal(result.releaseChannel, 'dev');
  assert.equal(result.developmentOverride, true);
  assert.equal(result.path, 'C:\\GOAT Dev\\goat-engine.exe');
  assert.equal(result.manifestPath, null);
});

test('getEnginePath preserves legacy GOAT_ENGINE_PATH override', () => {
  const result = getEnginePath({
    platform: 'win32',
    architecture: 'x64',
    appDataDir: 'C:\\Users\\Test User\\AppData\\Local\\goat',
    env: {
      GOAT_ENGINE_PATH: 'C:\\Ignored\\goat-engine.exe',
    },
  });

  assert.equal(result.error, null);
  assert.equal(result.source, 'env');
  assert.equal(result.releaseChannel, 'stable');
  assert.equal(result.developmentOverride, true);
  assert.equal(result.path, 'C:\\Ignored\\goat-engine.exe');
  assert.equal(result.manifestPath, null);
});

test('getEnginePath accepts gated GOAT_DEV_ENGINE_PATH on unsupported platforms (Linux dev mode)', () => {
  const result = getEnginePath({
    platform: 'linux',
    architecture: 'x64',
    env: {
      GOATCLI_DEV: '1',
      GOAT_DEV_ENGINE_PATH: '/usr/local/bin/node',
    },
  });

  assert.equal(result.error, null);
  assert.equal(result.source, 'dev-env');
  assert.equal(result.releaseChannel, 'dev');
  assert.equal(result.developmentOverride, true);
  assert.equal(result.path, '/usr/local/bin/node');
  assert.equal(result.platform, 'darwin');
  assert.equal(result.architecture, 'x64');
  assert.equal(result.manifestPath, null);
});

test('getEnginePath reports unsupported platforms explicitly (without dev override)', () => {
  const result = getEnginePath({
    platform: 'linux',
    architecture: 'x64',
    env: {},
  });

  assert.equal(result.source, 'none');
  assert.equal(result.error?.code, 'GOAT_UNSUPPORTED_PLATFORM');
});

test('getEngineExecutableName uses goat-engine executable names', () => {
  assert.equal(getEngineExecutableName('win32'), 'goat-engine.exe');
  assert.equal(getEngineExecutableName('darwin'), 'goat-engine');
});
