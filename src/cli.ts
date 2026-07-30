import process from "node:process";
import { createAuthApiClient, resolveControlPlaneUrl } from "./auth/client.js";
import { createBrowserOpener } from "./auth/browser.js";
import { createCredentialStore } from "./auth/credentials.js";
import type {
  AuthApiClient,
  BrowserOpener,
  Clock,
  CredentialStore,
} from "./auth/types.js";
import { runDoctor, formatDiagnosticError } from "./commands/doctor.js";
import { runLogin } from "./commands/login.js";
import { runLogout } from "./commands/logout.js";
import { runUsage } from "./commands/usage.js";
import { runUpdateCommand } from "./commands/update.js";
import { runVersionCommand } from "./commands/version.js";
import {
  EngineContractError,
  formatEngineContractError,
} from "./engine/contract.js";
import {
  getPrivacyIpcMode,
  launchEngine,
  type EngineLaunchResult,
  type LaunchEngineOptions,
  type PrivacyLaunchCredential,
} from "./engine/launch.js";
import {
  preparePrivacyCredential,
  PrivacyCredentialError,
} from "./privacy/credential-session.js";
import { assertEmbeddedLauncherReleasePolicy } from "./privacy/release-policy.js";
import { zeroizeLauncherIpcBytes } from "./privacy/launcher-ipc.js";
import { getEngineContractVersion, getLauncherVersion } from "./version.js";
import { UpdateError, formatUpdateError } from "./update/errors.js";
import { compiledVerifiedUpdatePolicy } from "./update/policy.js";
import { LauncherUpdateRequiredError } from "./update/selection.js";
import type {
  RunVerifiedUpdateOptions,
  VerifiedUpdatePolicy,
  VerifiedUpdateResult,
} from "./update/updater.js";
import { getAppDataDir } from "./utils/paths.js";

export interface CliOptions extends Partial<
  Omit<
    LaunchEngineOptions,
    | "args"
    | "launcherVersion"
    | "privacyCredential"
    | "privacyCredentialProvider"
  >
> {
  argv?: readonly string[];
  exit?: (code?: number) => void;
  killSelf?: (signal: NodeJS.Signals) => void;
  stdout?: Pick<NodeJS.WriteStream, "write">;
  stderr?: Pick<NodeJS.WriteStream, "write">;
  env?: NodeJS.ProcessEnv;
  authClient?: AuthApiClient;
  credentialStore?: CredentialStore;
  browserOpener?: BrowserOpener;
  clock?: Clock;
  updatePolicy?: VerifiedUpdatePolicy | null;
  updateRunner?: (
    options: RunVerifiedUpdateOptions,
  ) => Promise<VerifiedUpdateResult>;
}
export async function runCli(options: CliOptions = {}): Promise<void> {
  const argv = [...(options.argv ?? process.argv.slice(2))];
  const launcherVersion = getLauncherVersion();
  const engineContractVersion = getEngineContractVersion();
  const stdout = options.stdout ?? process.stdout;
  const stderr = options.stderr ?? process.stderr;
  const exit = options.exit ?? ((code?: number): never => process.exit(code));
  const killSelf =
    options.killSelf ??
    ((signal: NodeJS.Signals) => process.kill(process.pid, signal));
  const env = options.env ?? process.env;
  const firstArg = argv[0];

  try {
    assertEmbeddedLauncherReleasePolicy();
  } catch {
    stderr.write(
      "GOAT launcher error: This build has an invalid release policy.\n",
    );
    exit(1);
    return;
  }

  if (firstArg === "--version" || firstArg === "-v") {
    stdout.write(`${launcherVersion}\n`);
    return;
  }

  let updatePolicy: VerifiedUpdatePolicy | null;
  try {
    updatePolicy = resolveUpdatePolicy(options, launcherVersion);
  } catch (error) {
    stderr.write(
      "GOAT launcher error: This build has invalid update trust material.\n",
    );
    exit(1);
    return;
  }
  const appDataDirectory =
    options.appDataDir ??
    getAppDataDir({
      env: env ?? options.processLike?.env ?? process.env,
      platform:
        options.platform ?? options.processLike?.platform ?? process.platform,
      homeDir: options.homeDir,
    });

  if (firstArg === "version") {
    if (argv.length !== 1) {
      stderr.write("GOAT version does not accept arguments.\n");
      exit(2);
      return;
    }
    try {
      await runVersionCommand({
        launcherVersion,
        platform:
          options.platform ?? options.processLike?.platform ?? process.platform,
        architecture:
          options.architecture ?? options.processLike?.arch ?? process.arch,
        appDataDirectory,
        policy: updatePolicy,
        stdout,
      });
    } catch (error) {
      if (error instanceof UpdateError) {
        stderr.write(`${formatUpdateError(error)}\n`);
      } else {
        stderr.write("GOAT version information is unavailable.\n");
      }
      exit(1);
    }
    return;
  }

  if (firstArg === "update") {
    try {
      await runUpdateCommand({
        args: argv.slice(1),
        appDataDirectory,
        policy: updatePolicy,
        stdout,
        stderr,
        runner: options.updateRunner,
      });
    } catch (error) {
      if (error instanceof LauncherUpdateRequiredError) {
        stderr.write(
          `${formatUpdateError(error)}\nNext step: npm install --global goatcli@${error.minimumLauncherVersion}\n`,
        );
      } else if (error instanceof UpdateError) {
        stderr.write(`${formatUpdateError(error)}\n`);
      } else {
        stderr.write(
          "GOAT update error: The verified update could not be completed.\n",
        );
      }
      exit(
        error instanceof UpdateError &&
          error.code === "GOAT_UPDATE_INVALID_ARGUMENT"
          ? 2
          : 1,
      );
    }
    return;
  }

  if (firstArg === "doctor") {
    try {
      await runDoctor({ launcherVersion, engineContractVersion });
    } catch (error) {
      // Doctor is an explicitly local-only diagnostic surface.
      stderr.write(
        `An error occurred during diagnostics: ${formatDiagnosticError(error)}\n`,
      );
      exit(1);
    }
    return;
  }

  if (firstArg === "login") {
    try {
      const code = await runLogin({
        client:
          options.authClient ??
          createAuthApiClient(resolveControlPlaneUrl(env)),
        store: options.credentialStore ?? createCredentialStore({ env }),
        opener: options.browserOpener ?? createBrowserOpener(process.platform),
        stdout,
        stderr,
        clock: options.clock,
      });
      if (code !== 0) exit(code);
    } catch {
      stderr.write("GOAT login is unavailable. Try again later.\n");
      exit(1);
    }
    return;
  }

  if (firstArg === "logout") {
    const localOnly = argv.includes("--local-only");
    try {
      const code = await runLogout({
        client:
          options.authClient ??
          (localOnly
            ? noopAuthClient()
            : createAuthApiClient(resolveControlPlaneUrl(env))),
        store: options.credentialStore ?? createCredentialStore({ env }),
        stdout,
        stderr,
        localOnly,
      });
      if (code !== 0) exit(code);
    } catch {
      stderr.write("GOAT logout is unavailable. Try again later.\n");
      exit(1);
    }
    return;
  }

  if (firstArg === "usage") {
    const json = argv.includes("--json");
    try {
      const code = await runUsage({
        client:
          options.authClient ??
          createAuthApiClient(resolveControlPlaneUrl(env)),
        store: options.credentialStore ?? createCredentialStore({ env }),
        stdout,
        stderr,
        json,
        now: options.clock?.now ? () => options.clock!.now!() : undefined,
      });
      if (code !== 0) exit(code);
    } catch {
      const usageError = {
        code: "unavailable",
        message: "Unable to load GOAT usage right now. Try again later.",
      };
      if (json) {
        stdout.write(`${JSON.stringify({ ok: false, error: usageError })}\n`);
      } else {
        stderr.write(`${usageError.message}\n`);
      }
      exit(1);
    }
    return;
  }

  let preparedCredential: PrivacyLaunchCredential | undefined;
  let launchResult: EngineLaunchResult | undefined;
  const privacyMode = getPrivacyIpcMode(argv);
  try {
    if (privacyMode === "authenticated") {
      preparedCredential = await preparePrivacyCredential({
        client:
          options.authClient ??
          createAuthApiClient(resolveControlPlaneUrl(env)),
        store: options.credentialStore ?? createCredentialStore({ env }),
        now: options.clock?.now
          ? () => options.clock!.now!().getTime()
          : undefined,
      });
    }

    launchResult = await launchEngine({
      ...options,
      args: argv,
      launcherVersion: engineContractVersion,
      installedUpdatePolicy:
        options.installedUpdatePolicy ?? updatePolicy?.activation,
      privacyCredential: preparedCredential,
      privacyCredentialProvider:
        privacyMode === "lazy"
          ? () =>
              preparePrivacyCredential({
                client:
                  options.authClient ??
                  createAuthApiClient(resolveControlPlaneUrl(env)),
                store:
                  options.credentialStore ?? createCredentialStore({ env }),
                now: options.clock?.now
                  ? () => options.clock!.now!().getTime()
                  : undefined,
              })
          : undefined,
    });
  } catch (error) {
    if (error instanceof EngineContractError) {
      stderr.write(`${formatEngineContractError(error)}\n`);
    } else if (error instanceof PrivacyCredentialError) {
      stderr.write(
        error.code === "GOAT_PRIVACY_LOGIN_REQUIRED"
          ? "GOAT privacy authentication is required. Run `goat login`.\n"
          : "GOAT privacy authentication is unavailable. Try again later.\n",
      );
    } else {
      stderr.write("GOAT launcher error: The command could not be started.\n");
    }
    exit(1);
  } finally {
    zeroizeLauncherIpcBytes(preparedCredential?.accessToken);
  }
  if (launchResult) finishWithLaunchResult(launchResult, { exit, killSelf });
}

function resolveUpdatePolicy(
  options: CliOptions,
  launcherVersion: string,
): VerifiedUpdatePolicy | null {
  if (options.updatePolicy !== undefined) return options.updatePolicy;
  const platform =
    options.platform ?? options.processLike?.platform ?? process.platform;
  const architecture =
    options.architecture ?? options.processLike?.arch ?? process.arch;
  if (
    (platform !== "win32" && platform !== "darwin") ||
    (architecture !== "x64" && architecture !== "arm64")
  ) {
    return null;
  }
  return compiledVerifiedUpdatePolicy({
    launcherVersion,
    platform,
    architecture,
  });
}
export function finishWithLaunchResult(
  result: EngineLaunchResult,
  options: {
    exit: (code?: number) => void;
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
  const unavailable = async () => {
    throw new Error("unavailable");
  };
  return {
    createDeviceSession: unavailable,
    async pollDeviceToken() {
      return {
        status: "network_error",
        message: "Authentication is unavailable.",
      };
    },
    async cancelDeviceSession() {},
    async refresh() {
      return {
        status: "network_error",
        message: "Authentication is unavailable.",
      };
    },
    async revoke() {},
    async getUsageSummary() {
      return {
        status: "network_error",
        message: "Authentication is unavailable.",
      };
    },
  };
}
