import process from 'process';
import { createAuthApiClient, resolveControlPlaneUrl } from './auth/client.js';
import { createBrowserOpener } from './auth/browser.js';
import { createCredentialStore } from './auth/credentials.js';
import type { AuthApiClient, BrowserOpener, Clock, CredentialStore } from './auth/types.js';
import { runDoctor } from './commands/doctor.js';
import { runLogin } from './commands/login.js';
import { runLogout } from './commands/logout.js';
import { runUsage } from './commands/usage.js';
import {
  EngineContractError,
  formatEngineContractError,
} from './engine/contract.js';
import {
  launchEngine,
  type EngineLaunchResult,
  type LaunchEngineOptions,
} from './engine/launch.js';
import { getEngineContractVersion, getLauncherVersion } from './version.js';

export interface CliOptions extends Partial<Omit<LaunchEngineOptions, 'args' | 'launcherVersion'>> {
  argv?: readonly string[];
  exit?: (code?: number) => never;
  killSelf?: (signal: NodeJS.Signals) => void;
  stdout?: Pick<NodeJS.WriteStream, 'write'>;
  stderr?: Pick<NodeJS.WriteStream, 'write'>;
  env?: NodeJS.ProcessEnv;
  authClient?: AuthApiClient;
  credentialStore?: CredentialStore;
  browserOpener?: BrowserOpener;
  clock?: Clock;
}

export async function runCli(options: CliOptions = {}): Promise<void> {
  const argv = [...(options.argv ?? process.argv.slice(2))];
  const launcherVersion = getLauncherVersion();
  const engineContractVersion = getEngineContractVersion();
  const stdout = options.stdout ?? process.stdout;
  const stderr = options.stderr ?? process.stderr;
  const exit = options.exit ?? ((code?: number): never => process.exit(code));
  const killSelf = options.killSelf ?? ((signal: NodeJS.Signals) => process.kill(process.pid, signal));
  const env = options.env ?? process.env;

  const firstArg = argv[0];
  if (firstArg === '--version' || firstArg === '-v' || (argv.length === 1 && firstArg === 'version')) {
    stdout.write(`${launcherVersion}\n`);
    return;
  }

  if (firstArg === 'doctor') {
    try {
      await runDoctor({ launcherVersion, engineContractVersion });
    } catch (error) {
      stderr.write(`An error occurred during diagnostics: ${errorMessage(error)}\n`);
      exit(1);
    }
    return;
  }

  if (firstArg === 'login') {
    try {
      const code = await runLogin({
        client: options.authClient ?? createAuthApiClient(resolveControlPlaneUrl(env)),
        store: options.credentialStore ?? createCredentialStore({ env }),
        opener: options.browserOpener ?? createBrowserOpener(process.platform),
        stdout,
        stderr,
        clock: options.clock,
      });
      if (code !== 0) exit(code);
      return;
    } catch (error) {
      stderr.write(`GOAT login error: ${errorMessage(error)}\n`);
      exit(1);
      return;
    }
  }

  if (firstArg === 'logout') {
    const localOnly = argv.includes('--local-only');
    try {
      const code = await runLogout({
        client: options.authClient ?? (localOnly ? noopAuthClient() : createAuthApiClient(resolveControlPlaneUrl(env))),
        store: options.credentialStore ?? createCredentialStore({ env }),
        stdout,
        stderr,
        localOnly,
      });
      if (code !== 0) exit(code);
      return;
    } catch (error) {
      stderr.write(`GOAT logout error: ${errorMessage(error)}\n`);
      exit(1);
    }
  }

  if (firstArg === 'usage') {
    const json = argv.includes('--json');
    try {
      const code = await runUsage({
        client: options.authClient ?? createAuthApiClient(resolveControlPlaneUrl(env)),
        store: options.credentialStore ?? createCredentialStore({ env }),
        stdout,
        stderr,
        json,
        now: options.clock?.now ? () => options.clock!.now!() : undefined,
      });
      if (code !== 0) exit(code);
      return;
    } catch {
      const usageError = { code: 'unavailable', message: 'Unable to load GOAT usage right now. Try again later.' };
      if (json) stdout.write(`${JSON.stringify({ ok: false, error: usageError })}\n`);
      else stderr.write(`${usageError.message}\n`);
      exit(1);
      return;
    }
  }
  let result: EngineLaunchResult | undefined;
  try {
    result = await launchEngine({
      ...options,
      args: argv,
      launcherVersion: engineContractVersion,
    });
  } catch (error) {
    if (error instanceof EngineContractError) {
      stderr.write(`${formatEngineContractError(error)}\n`);
    } else {
      stderr.write(`GOAT launcher error: ${errorMessage(error)}\n`);
    }
    exit(1);
    return;
  }

  finishWithLaunchResult(result, { exit, killSelf });
}

export function finishWithLaunchResult(
  result: EngineLaunchResult,
  options: {
    exit: (code?: number) => never;
    killSelf: (signal: NodeJS.Signals) => void;
  },
): void {
  if (result.signal) {
    options.killSelf(result.signal);
    return;
  }

  options.exit(result.exitCode);
}

function noopAuthClient(): AuthApiClient {
  return {
    async createDeviceSession() {
      throw new Error('GOAT_CONTROL_PLANE_URL is required for goat login.');
    },
    async pollDeviceToken() {
      return { status: 'network_error', message: 'No control plane configured.' };
    },
    async cancelDeviceSession() {},
    async refresh() {
      return { status: 'network_error', message: 'No control plane configured.' };
    },
    async revoke() {},
    async getUsageSummary() {
      return { status: 'network_error', message: 'No control plane configured.' };
    },
  };
}

function errorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  if (typeof error === 'string') return error;
  return String(error);
}
