import { EventEmitter } from 'node:events';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { ChildProcess } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import { EngineContractError, type EngineManifest, type ResolvedEngine } from './contract.js';
import {
  getForwardedSignals,
  launchEngine,
  launchValidatedEngine,
  type ProcessLike,
  type SpawnEngine,
} from './launch.js';
import type { EngineFileSystem } from './validate.js';

test('launchEngine forwards args, cwd, inherited stdio, no shell, and propagates exit code', async () => {
  const executablePath = 'C:\\Program Files\\GOAT Engine\\goat-engine.exe';
  const manifestPath = 'C:\\Program Files\\GOAT Engine\\goat-engine.json';
  const engineBytes = Buffer.from('engine');
  const fakeFs = makeFakeFs({
    [executablePath]: { content: engineBytes, isFile: true },
    [manifestPath]: { content: JSON.stringify(makeManifest(sha256(engineBytes))), isFile: true },
  });
  const fakeProcess = new FakeProcess('win32', 'x64', 'D:\\work dir');
  const child = new FakeChild();
  let spawnCall: {
    command: string;
    args: readonly string[];
    options: Parameters<SpawnEngine>[2];
  } | null = null;
  const spawnEngine: SpawnEngine = (command, args, options) => {
    spawnCall = { command, args, options };
    queueMicrotask(() => child.emit('exit', 7, null));
    return child as unknown as ChildProcess;
  };

  const result = await launchEngine({
    args: ['run', '--flag', 'value with spaces', 'unicode-測試'],
    launcherVersion: '0.0.5',
    cwd: 'D:\\work dir',
    platform: 'win32',
    architecture: 'x64',
    resolvedEngine: makeResolvedEngine({ executablePath, manifestPath }),
    fs: fakeFs,
    spawnEngine,
    processLike: fakeProcess,
  });

  assert.deepEqual(result, { exitCode: 7, signal: null });
  assert.deepEqual(spawnCall, {
    command: executablePath,
    args: ['run', '--flag', 'value with spaces', 'unicode-測試'],
    options: {
      cwd: 'D:\\work dir',
      stdio: 'inherit',
      shell: false,
      windowsHide: true,
    },
  });
});

test('launchValidatedEngine forwards cancellation signals and removes listeners after exit', async () => {
  const fakeProcess = new FakeProcess('win32', 'x64', 'D:\\repo');
  const child = new FakeChild();
  const spawnEngine: SpawnEngine = () => child as unknown as ChildProcess;
  const resultPromise = launchValidatedEngine(
    { executablePath: 'C:\\GOAT\\goat-engine.exe', platform: 'win32' },
    [],
    { cwd: 'D:\\repo', spawnEngine, processLike: fakeProcess },
  );

  assert.equal(fakeProcess.listenerCount('SIGINT'), 1);
  fakeProcess.emit('SIGINT');
  assert.deepEqual(child.killedSignals, ['SIGINT']);

  child.emit('exit', 0, null);
  const result = await resultPromise;

  assert.deepEqual(result, { exitCode: 0, signal: null });
  assert.equal(fakeProcess.listenerCount('SIGINT'), 0);
  assert.equal(fakeProcess.listenerCount('SIGTERM'), 0);
  assert.equal(fakeProcess.listenerCount('SIGBREAK'), 0);
  assert.equal(fakeProcess.listenerCount('exit'), 0);
});

test('launchValidatedEngine cleans up child on launcher process exit without a shell', async () => {
  const fakeProcess = new FakeProcess('win32', 'x64', 'D:\\repo');
  const child = new FakeChild();
  const spawnEngine: SpawnEngine = () => child as unknown as ChildProcess;
  const resultPromise = launchValidatedEngine(
    { executablePath: 'C:\\GOAT\\goat-engine.exe', platform: 'win32' },
    [],
    { cwd: 'D:\\repo', spawnEngine, processLike: fakeProcess },
  );

  fakeProcess.emit('exit');
  assert.deepEqual(child.killedSignals, ['SIGTERM']);

  child.emit('exit', 0, null);
  await resultPromise;
});

test('launchValidatedEngine propagates child termination signal', async () => {
  const fakeProcess = new FakeProcess('darwin', 'arm64', '/Users/Test/repo');
  const child = new FakeChild();
  const spawnEngine: SpawnEngine = () => child as unknown as ChildProcess;
  const resultPromise = launchValidatedEngine(
    { executablePath: '/Users/Test/GOAT/goat-engine', platform: 'darwin' },
    [],
    { cwd: '/Users/Test/repo', spawnEngine, processLike: fakeProcess },
  );

  child.emit('exit', null, 'SIGTERM');
  const result = await resultPromise;

  assert.deepEqual(result, { exitCode: 1, signal: 'SIGTERM' });
});

test('launchEngine reports spawn failures with stable error code', async () => {
  const executablePath = 'C:\\GOAT\\engines\\stable\\win32-x64\\bin\\goat-engine.exe';
  const manifestPath = 'C:\\GOAT\\engines\\stable\\win32-x64\\goat-engine.json';
  const engineBytes = Buffer.from('engine');
  const fakeFs = makeFakeFs({
    [executablePath]: { content: engineBytes, isFile: true },
    [manifestPath]: { content: JSON.stringify(makeManifest(sha256(engineBytes))), isFile: true },
  });
  const child = new FakeChild();
  const spawnEngine: SpawnEngine = () => {
    queueMicrotask(() => child.emit('error', new Error('permission denied')));
    return child as unknown as ChildProcess;
  };

  await assert.rejects(
    () => launchEngine({
      args: [],
      launcherVersion: '0.0.5',
      platform: 'win32',
      architecture: 'x64',
      resolvedEngine: makeResolvedEngine({ executablePath, manifestPath }),
      fs: fakeFs,
      spawnEngine,
      processLike: new FakeProcess('win32', 'x64', 'D:\\repo'),
    }),
    (error) => error instanceof EngineContractError && error.code === 'GOAT_ENGINE_SPAWN_FAILED',
  );
});

test('getForwardedSignals includes supported platform termination signals', () => {
  assert.deepEqual(getForwardedSignals('win32'), ['SIGINT', 'SIGTERM', 'SIGBREAK']);
  assert.deepEqual(getForwardedSignals('darwin'), ['SIGINT', 'SIGTERM', 'SIGHUP']);
});

class FakeChild extends EventEmitter {
  readonly killedSignals: NodeJS.Signals[] = [];

  kill(signal?: NodeJS.Signals | number): boolean {
    if (typeof signal === 'string') {
      this.killedSignals.push(signal);
    }
    return true;
  }
}

class FakeProcess extends EventEmitter implements ProcessLike {
  readonly env: NodeJS.ProcessEnv = {};

  constructor(
    readonly platform: NodeJS.Platform,
    readonly arch: string,
    private readonly cwdValue: string,
  ) {
    super();
  }

  cwd(): string {
    return this.cwdValue;
  }
}

function makeManifest(checksum: string): EngineManifest {
  return {
    engineVersion: '1.17.11',
    platform: 'win32',
    architecture: 'x64',
    executablePath: 'bin/goat-engine.exe',
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
    accessSync(filePath: string) {
      if (!files[filePath]) throw new Error(`missing ${filePath}`);
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
