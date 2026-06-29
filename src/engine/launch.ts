import { spawn, type ChildProcess } from 'child_process';
import process from 'process';
import {
  EngineContractError,
  type LauncherVersion,
  type ResolvedEngine,
} from './contract.js';
import { validateEngine, type ValidatedEngine, type ValidateEngineOptions } from './validate.js';
import {
  getEnginePath,
  toResolvedEngine,
  type EnginePathOptions,
} from '../utils/paths.js';

export interface EngineLaunchResult {
  exitCode: number;
  signal: NodeJS.Signals | null;
}

export type SpawnEngine = (
  command: string,
  args: readonly string[],
  options: {
    cwd: string;
    stdio: 'inherit';
    shell: false;
    windowsHide: boolean;
  },
) => ChildProcess;

export interface ProcessLike {
  platform: NodeJS.Platform;
  arch: string;
  env: NodeJS.ProcessEnv;
  cwd(): string;
  on(event: string | symbol, listener: (...args: unknown[]) => void): unknown;
  removeListener(event: string | symbol, listener: (...args: unknown[]) => void): unknown;
}

export interface LaunchEngineOptions extends EnginePathOptions, ValidateEngineOptions {
  launcherVersion: LauncherVersion;
  args: readonly string[];
  cwd?: string;
  spawnEngine?: SpawnEngine;
  processLike?: ProcessLike;
  resolvedEngine?: ResolvedEngine;
}

export async function launchEngine(options: LaunchEngineOptions): Promise<EngineLaunchResult> {
  const processLike = options.processLike ?? process;
  const cwd = options.cwd ?? processLike.cwd();
  const spawnEngine = options.spawnEngine ?? spawn;
  const resolved = options.resolvedEngine ?? toResolvedEngine(getEnginePath({
    env: options.env ?? processLike.env,
    platform: options.platform ?? processLike.platform,
    architecture: options.architecture ?? processLike.arch,
    appDataDir: options.appDataDir,
    homeDir: options.homeDir,
    releaseChannel: options.releaseChannel,
  }));

  validateEngine(resolved, options.launcherVersion, { fs: options.fs });

  return launchValidatedEngine(resolved, options.args, {
    cwd,
    spawnEngine,
    processLike,
  });
}

export function launchValidatedEngine(
  engine: Pick<ValidatedEngine['resolved'], 'executablePath' | 'platform'>,
  args: readonly string[],
  options: {
    cwd: string;
    spawnEngine?: SpawnEngine;
    processLike?: ProcessLike;
  },
): Promise<EngineLaunchResult> {
  const processLike = options.processLike ?? process;
  const spawnEngine = options.spawnEngine ?? spawn;
  const child = spawnEngine(engine.executablePath, [...args], {
    cwd: options.cwd,
    stdio: 'inherit',
    shell: false,
    windowsHide: true,
  });

  let settled = false;
  const signalListeners = new Map<NodeJS.Signals, () => void>();

  const cleanup = () => {
    for (const [signal, listener] of signalListeners) {
      processLike.removeListener(signal, listener);
    }
    signalListeners.clear();
    processLike.removeListener('exit', exitListener);
  };

  const forwardSignal = (signal: NodeJS.Signals) => {
    return () => {
      terminateChild(child, signal);
    };
  };

  for (const signal of getForwardedSignals(engine.platform)) {
    const listener = forwardSignal(signal);
    signalListeners.set(signal, listener);
    processLike.on(signal, listener);
  }

  const exitListener = () => {
    terminateChild(child, engine.platform === 'win32' ? 'SIGTERM' : 'SIGHUP');
  };
  processLike.on('exit', exitListener);

  return new Promise((resolve, reject) => {
    child.once('error', (error) => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(new EngineContractError(
        'GOAT_ENGINE_SPAWN_FAILED',
        `Failed to start GOAT engine: ${error.message}`,
        'Run goat doctor to verify the engine path and executable permissions.',
      ));
    });

    child.once('exit', (code, signal) => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve({
        exitCode: typeof code === 'number' ? code : 1,
        signal: signal ?? null,
      });
    });
  });
}

export function getForwardedSignals(platform: NodeJS.Platform): NodeJS.Signals[] {
  return platform === 'win32'
    ? ['SIGINT', 'SIGTERM', 'SIGBREAK']
    : ['SIGINT', 'SIGTERM', 'SIGHUP'];
}

function terminateChild(child: Pick<ChildProcess, 'kill'>, signal: NodeJS.Signals): void {
  try {
    child.kill(signal);
  } catch {
    // The child may already be gone.
  }
}


