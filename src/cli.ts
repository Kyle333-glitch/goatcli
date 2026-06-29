import process from 'process';
import { runDoctor } from './commands/doctor.js';
import {
  EngineContractError,
  formatEngineContractError,
} from './engine/contract.js';
import {
  launchEngine,
  type EngineLaunchResult,
  type LaunchEngineOptions,
} from './engine/launch.js';
import { getLauncherVersion } from './version.js';

export interface CliOptions extends Partial<Omit<LaunchEngineOptions, 'args' | 'launcherVersion'>> {
  argv?: readonly string[];
  exit?: (code?: number) => never;
  killSelf?: (signal: NodeJS.Signals) => void;
  stdout?: Pick<NodeJS.WriteStream, 'write'>;
  stderr?: Pick<NodeJS.WriteStream, 'write'>;
}

export async function runCli(options: CliOptions = {}): Promise<void> {
  const argv = [...(options.argv ?? process.argv.slice(2))];
  const launcherVersion = getLauncherVersion();
  const stdout = options.stdout ?? process.stdout;
  const stderr = options.stderr ?? process.stderr;
  const exit = options.exit ?? ((code?: number): never => process.exit(code));
  const killSelf = options.killSelf ?? ((signal: NodeJS.Signals) => process.kill(process.pid, signal));

  const firstArg = argv[0];
  if (firstArg === '--version' || firstArg === '-v' || (argv.length === 1 && firstArg === 'version')) {
    stdout.write(`${launcherVersion}\n`);
    return;
  }

  if (firstArg === 'doctor') {
    try {
      await runDoctor({ launcherVersion });
    } catch (error) {
      stderr.write(`An error occurred during diagnostics: ${errorMessage(error)}\n`);
      exit(1);
    }
    return;
  }

  let result: EngineLaunchResult | undefined;
  try {
    result = await launchEngine({
      ...options,
      args: argv,
      launcherVersion,
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

function errorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  if (typeof error === 'string') return error;
  return String(error);
}


