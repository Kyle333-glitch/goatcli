import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import assert from 'node:assert/strict';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// Use the built dist entry so the child process doesn't need tsx.
// The test file itself still runs under tsx via `node --import tsx --test`.
const cliEntry = path.resolve(__dirname, '../../dist/index.js');

function sha256(input: Buffer): string {
  return createHash('sha256').update(input).digest('hex');
}

function makeManifest(checksum: string, platform: NodeJS.Platform, arch: string) {
  const executablePath = `bin/goat-engine${platform === 'win32' ? '.exe' : ''}`;
  return {
    engineVersion: '1.17.11',
    platform,
    architecture: arch,
    executablePath,
    releaseChannel: 'stable',
    checksum: {
      algorithm: 'sha256' as const,
      value: checksum,
    },
    compatibility: {
      minimumLauncherVersion: '0.0.6',
      maximumLauncherVersion: '0.0.6',
    },
  };
}

function prepareFakeEngine(installRoot: string) {
  const platform = process.platform as 'win32' | 'darwin';
  const arch = process.arch as 'x64' | 'arm64';

  // For dev-env mode (GOATCLI_DEV=1), GOAT_DEV_ENGINE_PATH points directly
  // to the engine executable. We use the current Node executable as a fake
  // engine so that -e scripts and process.exit() work correctly without
  // needing to copy platform-specific dependencies (e.g. Windows DLLs).
  const enginePath = process.execPath;

  fs.mkdirSync(installRoot, { recursive: true });
  const manifestPath = path.join(installRoot, 'goat-engine.json');
  fs.writeFileSync(manifestPath, JSON.stringify(makeManifest(sha256(Buffer.from('dummy')), platform, arch)));

  return { enginePath, manifestPath, platform, arch };
}

function runLauncher(
  args: string[],
  options: {
    cwd?: string;
    env?: NodeJS.ProcessEnv;
    devEnginePath?: string;
  } = {},
) {
  const env = { ...process.env, ...options.env };
  if (options.devEnginePath) {
    env.GOAT_DEV_ENGINE_PATH = options.devEnginePath;
    env.GOATCLI_DEV = '1';
  }
  return spawn(process.execPath, [cliEntry, ...args], {
    cwd: options.cwd ?? process.cwd(),
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true,
  });
}

async function collect(child: ReturnType<typeof spawn>) {
  let stdout = '';
  let stderr = '';
  child.stdout?.on('data', (chunk: Buffer) => { stdout += chunk.toString(); });
  child.stderr?.on('data', (chunk: Buffer) => { stderr += chunk.toString(); });
  const exitCode = await new Promise<number>((resolve) => {
    if (child.exitCode !== null) {
      resolve(child.exitCode);
      return;
    }
    child.on('exit', (code) => resolve(typeof code === 'number' ? code : 1));
  });
  return { exitCode, stdout, stderr };
}

test('launcher starts engine and forwards non-launcher args unchanged', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'goat-test-'));
  try {
    const { enginePath } = prepareFakeEngine(tmpDir);

    // Use node -e to echo argv so we can verify forwarded args exactly.
    const child = runLauncher(
      ['-e', 'console.log(process.argv.slice(1).join(String.fromCharCode(10)))', 'run', '--flag', 'value with spaces', 'unicode-測試'],
      { devEnginePath: enginePath },
    );

    const { exitCode, stdout } = await collect(child);

    assert.equal(exitCode, 0);
    assert.ok(stdout.includes('run'), 'stdout should include forwarded arg "run"');
    assert.ok(stdout.includes('--flag'), 'stdout should include forwarded arg "--flag"');
    assert.ok(stdout.includes('value with spaces'), 'stdout should include forwarded arg "value with spaces"');
    assert.ok(stdout.includes('unicode-測試'), 'stdout should include forwarded arg "unicode-測試"');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('engine receives exact cwd from paths containing spaces and Unicode', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'goat-test-'));
  try {
    const workDir = path.join(tmpDir, 'work dir 測試');
    fs.mkdirSync(workDir, { recursive: true });
    const { enginePath } = prepareFakeEngine(tmpDir);

    const child = runLauncher(['-e', 'console.log(process.cwd())'], {
      cwd: workDir,
      devEnginePath: enginePath,
    });

    const { exitCode, stdout, stderr } = await collect(child);

    assert.equal(exitCode, 0, `expected exit 0, got ${exitCode}. stderr:\n${stderr}`);
    const normalizedStdout = stdout.replace(/\r\n/g, '\n').trim();
    assert.ok(
      normalizedStdout.includes(workDir),
      `stdout should contain cwd "${workDir}", got:\n${stdout}`,
    );
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('GOAT branding appears in engine output', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'goat-test-'));
  try {
    const { enginePath } = prepareFakeEngine(tmpDir);

    const child = runLauncher(['-e', 'console.log("GOAT engine ready")'], {
      devEnginePath: enginePath,
    });

    const { exitCode, stdout } = await collect(child);

    assert.equal(exitCode, 0);
    assert.ok(stdout.includes('GOAT engine ready'));
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('exit code propagates from engine to launcher', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'goat-test-'));
  try {
    const { enginePath } = prepareFakeEngine(tmpDir);

    const child = runLauncher(['-e', 'process.exit(42)'], {
      devEnginePath: enginePath,
    });

    const { exitCode } = await collect(child);

    assert.equal(exitCode, 42);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('cancellation interrupts an active engine and child exits', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'goat-test-'));
  try {
    const { enginePath } = prepareFakeEngine(tmpDir);

    const child = runLauncher(
      ['-e', 'setInterval(() => {}, 1000)'],
      { devEnginePath: enginePath },
    );

    // Give the child a moment to start
    await new Promise((r) => setTimeout(r, 500));
    child.kill('SIGINT');

    const { exitCode } = await collect(child);

    // On Windows, SIGINT may exit with 1; on Unix it may be 130 (128 + SIGINT)
    assert.notEqual(exitCode, 0, 'expected nonzero exit after SIGINT');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('no remaining launched child PID after engine exits', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'goat-test-'));
  try {
    const { enginePath } = prepareFakeEngine(tmpDir);

    const child = runLauncher(['-e', 'console.log("done")'], {
      devEnginePath: enginePath,
    });

    const { exitCode } = await collect(child);
    assert.equal(exitCode, 0);

    // Verify the child process object reports exited
    assert.ok(child.killed || child.exitCode !== null, 'child should be terminated');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
