import { EventEmitter } from 'node:events';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { ChildProcess } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import { finishWithLaunchResult, runCli } from './cli.js';
import type { EngineManifest, ResolvedEngine } from './engine/contract.js';
import type { ProcessLike, SpawnEngine } from './engine/launch.js';
import type { EngineFileSystem } from './engine/validate.js';

test('runCli handles exact launcher-owned version command', async () => {
  let output = '';

  await runCli({
    argv: ['version'],
    stdout: {
      write(chunk: string | Uint8Array) {
        output += chunk.toString();
        return true;
      },
    },
    spawnEngine: () => {
      throw new Error('version should not spawn the engine');
    },
  });

  assert.equal(output, '0.0.5\n');
});

test('runCli handles version command with trailing arguments', async () => {
  let output = '';

  await runCli({
    argv: ['-v', 'some-argument'],
    stdout: {
      write(chunk: string | Uint8Array) {
        output += chunk.toString();
        return true;
      },
    },
    spawnEngine: () => {
      throw new Error('version should not spawn the engine');
    },
  });

  assert.equal(output, '0.0.5\n');
});

test('runCli forwards non-launcher-owned arguments to the engine unchanged', async () => {
  const executablePath = 'C:\\GOAT\\engines\\stable\\win32-x64\\bin\\goat-engine.exe';
  const manifestPath = 'C:\\GOAT\\engines\\stable\\win32-x64\\goat-engine.json';
  const engineBytes = Buffer.from('engine');
  const fakeFs = makeFakeFs({
    [executablePath]: { content: engineBytes, isFile: true },
    [manifestPath]: { content: JSON.stringify(makeManifest(sha256(engineBytes))), isFile: true },
  });
  const child = new FakeChild();
  let forwardedArgs: readonly string[] | null = null;
  const spawnEngine: SpawnEngine = (_command, args) => {
    forwardedArgs = args;
    queueMicrotask(() => child.emit('exit', 0, null));
    return child as unknown as ChildProcess;
  };
  let exitCode: number | undefined;

  await assert.rejects(
    () => runCli({
      argv: ['--help'],
      resolvedEngine: makeResolvedEngine({ executablePath, manifestPath }),
      fs: fakeFs,
      spawnEngine,
      processLike: new FakeProcess('win32', 'x64', 'D:\\repo'),
      exit(code?: number): never {
        exitCode = code;
        throw new Error('exit');
      },
    }),
    /exit/,
  );

  assert.deepEqual(forwardedArgs, ['--help']);
  assert.equal(exitCode, 0);
});

test('finishWithLaunchResult exits by code or re-signals the launcher', () => {
  const exitCodes: Array<number | undefined> = [];
  const signals: NodeJS.Signals[] = [];

  assert.throws(
    () => finishWithLaunchResult(
      { exitCode: 5, signal: null },
      {
        exit(code?: number): never {
          exitCodes.push(code);
          throw new Error('exit');
        },
        killSelf(signal) {
          signals.push(signal);
        },
      },
    ),
    /exit/,
  );
  finishWithLaunchResult(
    { exitCode: 0, signal: 'SIGTERM' },
    {
      exit(code?: number): never {
        exitCodes.push(code);
        throw new Error('exit');
      },
      killSelf(signal) {
        signals.push(signal);
      },
    },
  );

  assert.deepEqual(exitCodes, [5]);
  assert.deepEqual(signals, ['SIGTERM']);
});

class FakeChild extends EventEmitter {
  kill(): boolean {
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
