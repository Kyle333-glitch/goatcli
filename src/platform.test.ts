import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {
  getPlatformAdapter,
  getPlatformDirectories,
  getShellForPlatform,
  hasPathLengthProblem,
} from './platform.js';

const windowsHome = 'C:\\Users\\Test User';
const macHome = '/Users/Test User';

test('platform adapter resolves Windows directories and executable details', () => {
  const adapter = getPlatformAdapter('win32');
  const dirs = adapter.getDirectories({
    env: {
      LOCALAPPDATA: 'C:\\Users\\Test User\\AppData\\Local',
      APPDATA: 'C:\\Users\\Test User\\AppData\\Roaming',
    },
    homeDir: windowsHome,
  });

  assert.deepEqual(dirs, {
    appData: 'C:\\Users\\Test User\\AppData\\Local\\goat',
    config: 'C:\\Users\\Test User\\AppData\\Roaming\\goat',
    cache: 'C:\\Users\\Test User\\AppData\\Local\\goat\\Cache',
  });
  assert.equal(adapter.getEngineExecutableName(), 'goat-engine.exe');
  assert.equal(adapter.getShell({ COMSPEC: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe' }), 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe');
  assert.equal(adapter.credentialStorage.kind, 'windows-credential-manager');
});

test('platform adapter resolves Windows directory fallbacks from home', () => {
  const dirs = getPlatformDirectories({ platform: 'win32', env: {}, homeDir: windowsHome });

  assert.equal(dirs.appData, 'C:\\Users\\Test User\\AppData\\Local\\goat');
  assert.equal(dirs.config, 'C:\\Users\\Test User\\AppData\\Roaming\\goat');
  assert.equal(dirs.cache, 'C:\\Users\\Test User\\AppData\\Local\\goat\\Cache');
});

test('platform adapter resolves macOS directories and executable details', () => {
  const adapter = getPlatformAdapter('darwin');
  const dirs = adapter.getDirectories({ homeDir: macHome });

  assert.deepEqual(dirs, {
    appData: '/Users/Test User/Library/Application Support/goat',
    config: '/Users/Test User/Library/Application Support/goat/config',
    cache: '/Users/Test User/Library/Caches/goat',
  });
  assert.equal(adapter.getEngineExecutableName(), 'goat-engine');
  assert.equal(adapter.getShell({ SHELL: '/bin/zsh' }), '/bin/zsh');
  assert.equal(adapter.credentialStorage.kind, 'macos-keychain');
});

test('generic shell and path-length helpers stay centralized', () => {
  assert.equal(getShellForPlatform({ platform: 'linux', env: { SHELL: '/bin/bash' } }), '/bin/bash');
  assert.equal(hasPathLengthProblem('C:\\short', 'win32'), false);
  assert.equal(hasPathLengthProblem(`C:\\${'a'.repeat(300)}`, 'win32'), true);
  assert.equal(hasPathLengthProblem(`/${'a'.repeat(300)}`, 'darwin'), false);
});

test('executable permission handling is platform-specific', () => {
  const calls: Array<{ method: string; path: string; mode?: number }> = [];
  const fileSystem = {
    constants: { X_OK: 1 },
    accessSync(filePath: string, mode?: number) {
      calls.push({ method: 'access', path: filePath, mode });
      throw new Error('not executable');
    },
    chmodSync(filePath: string, mode: number) {
      calls.push({ method: 'chmod', path: filePath, mode });
    },
  };

  assert.equal(getPlatformAdapter('win32').hasExecutablePermission('C:\\GOAT\\goat-engine.exe', fileSystem), true);
  assert.equal(calls.length, 0);

  const mac = getPlatformAdapter('darwin');
  assert.equal(mac.hasExecutablePermission('/Applications/GOAT/goat-engine', fileSystem), false);
  mac.ensureExecutablePermission('/Applications/GOAT/goat-engine', fileSystem);
  assert.deepEqual(calls, [
    { method: 'access', path: '/Applications/GOAT/goat-engine', mode: 1 },
    { method: 'access', path: '/Applications/GOAT/goat-engine', mode: 1 },
    { method: 'chmod', path: '/Applications/GOAT/goat-engine', mode: 0o755 },
  ]);
});

test('atomic replacement writes a complete replacement in place', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'goatcli-platform-'));
  const target = path.join(dir, 'config.json');
  await fs.writeFile(target, 'old');

  await getPlatformAdapter('darwin').replaceFileAtomically(target, 'new', { tempSuffix: 'test' });

  assert.equal(await fs.readFile(target, 'utf8'), 'new');
  assert.equal(await fileExists(`${target}.test.tmp`), false);
});

test('Windows process termination uses taskkill for process trees and falls back to child kill', () => {
  const adapter = getPlatformAdapter('win32');
  const commandCalls: Array<{ command: string; args: string[] }> = [];
  const killedSignals: NodeJS.Signals[] = [];
  const child = {
    pid: 4242,
    kill(signal?: NodeJS.Signals | number) {
      if (typeof signal === 'string') killedSignals.push(signal);
      return true;
    },
  };

  adapter.terminateProcess(child, 'SIGTERM', {
    runCommand(command, args) {
      commandCalls.push({ command, args: [...args] });
      return { status: 0 };
    },
  });

  assert.deepEqual(commandCalls, [{ command: 'taskkill', args: ['/pid', '4242', '/T'] }]);
  assert.deepEqual(killedSignals, ['SIGTERM']);

  adapter.terminateProcess(child, 'SIGBREAK', {
    runCommand(command, args) {
      commandCalls.push({ command, args: [...args] });
      return { status: 1 };
    },
  });

  assert.deepEqual(killedSignals, ['SIGTERM', 'SIGBREAK']);
});

async function fileExists(filePath: string): Promise<boolean> {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}
