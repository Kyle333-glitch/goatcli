import { spawn, type ChildProcess } from "node:child_process";
import process from "node:process";
import { Readable, Writable } from "node:stream";
import {
  EngineContractError,
  type LauncherVersion,
  type ResolvedEngine,
} from "./contract.js";
import {
  validateEngine,
  type ValidatedEngine,
  type ValidateEngineOptions,
} from "./validate.js";
import {
  getEnginePath,
  toResolvedEngine,
  type EnginePathOptions,
} from "../utils/paths.js";
import {
  getForwardedSignals as getPlatformForwardedSignals,
  getParentExitSignal,
  getPlatformAdapter,
  type ProcessTerminatorCommand,
} from "../platform.js";
import {
  openLauncherIpcSession,
  type CredentialStoreStatus,
  type EngineIntegrityStatus,
  type LauncherIpcSession,
  zeroizeLauncherIpcBytes,
} from "../privacy/launcher-ipc.js";
import { createNodeLauncherIpcTransport } from "../privacy/node-transport.js";
import { waitForLauncherIpcV2Activation } from "../privacy/launcher-ipc-v2.js";
import { approvedEngineEnvironmentKeys } from "../privacy/release-policy.js";

export interface EngineLaunchResult {
  exitCode: number;
  signal: NodeJS.Signals | null;
}

export type EngineStdio =
  "inherit" | ["inherit", "inherit", "inherit", "pipe", "pipe"];

export type SpawnEngine = (
  command: string,
  args: readonly string[],
  options: {
    cwd: string;
    env: NodeJS.ProcessEnv;
    stdio: EngineStdio;
    shell: false;
    windowsHide: boolean;
  },
) => ChildProcess;

export interface ProcessLike {
  platform: NodeJS.Platform;
  arch: string;
  pid: number;
  env: NodeJS.ProcessEnv;
  cwd(): string;
  on(event: string | symbol, listener: (...args: unknown[]) => void): unknown;
  removeListener(
    event: string | symbol,
    listener: (...args: unknown[]) => void,
  ): unknown;
}

export type PrivacyIpcMode = "none" | "lazy" | "preview" | "authenticated";

export interface PrivacyLaunchCredential {
  readonly accessToken: Uint8Array;
  readonly expiresAtUnixMs: number;
}

interface PrivacyIpcLaunchOptions {
  readonly mode: "eager" | "lazy";
  readonly engineIntegrity: EngineIntegrityStatus;
  readonly credentialStore: CredentialStoreStatus;
  readonly credential?: Uint8Array;
  readonly credentialExpiresAtUnixMs?: number;
  readonly credentialProvider?: () => Promise<
    PrivacyLaunchCredential | undefined
  >;
  readonly launcherPid: number;
}

export interface LaunchEngineOptions
  extends EnginePathOptions, ValidateEngineOptions {
  launcherVersion: LauncherVersion;
  args: readonly string[];
  cwd?: string;
  spawnEngine?: SpawnEngine;
  processLike?: ProcessLike;
  processTerminator?: ProcessTerminatorCommand;
  resolvedEngine?: ResolvedEngine;
  privacyCredential?: PrivacyLaunchCredential;
  privacyCredentialProvider?: () => Promise<
    PrivacyLaunchCredential | undefined
  >;
  nodeVersion?: string;
}

const COMMON_ENGINE_ENVIRONMENT_KEYS = [
  "PATH",
  "HOME",
  "LANG",
  "LC_ALL",
  "LC_CTYPE",
  "TERM",
  "COLORTERM",
  "NO_COLOR",
  "FORCE_COLOR",
  "TZ",
  "TMP",
  "TEMP",
  "TMPDIR",
] as const;

const WINDOWS_ENGINE_ENVIRONMENT_KEYS = [
  "SYSTEMROOT",
  "WINDIR",
  "COMSPEC",
  "PATHEXT",
  "USERPROFILE",
  "HOMEDRIVE",
  "HOMEPATH",
  "APPDATA",
  "LOCALAPPDATA",
  "PROGRAMDATA",
  "PROGRAMFILES",
  "PROGRAMFILES(X86)",
  "PROGRAMW6432",
  "PUBLIC",
] as const;

const POSIX_ENGINE_ENVIRONMENT_KEYS = [
  "USER",
  "LOGNAME",
  "SHELL",
  "XDG_CONFIG_HOME",
  "XDG_DATA_HOME",
  "XDG_CACHE_HOME",
  "XDG_STATE_HOME",
  "XDG_RUNTIME_DIR",
] as const;

export async function launchEngine(
  options: LaunchEngineOptions,
): Promise<EngineLaunchResult> {
  const processLike = options.processLike ?? process;
  const maxArgLength = processLike.platform === "win32" ? 30_000 : 100_000;
  const totalArgLength = options.args.reduce(
    (sum, argument) => sum + argument.length,
    0,
  );
  if (totalArgLength > maxArgLength) {
    throw new EngineContractError(
      "GOAT_ENGINE_ARGS_TOO_LONG",
      "The GOAT command is too large to launch safely.",
      "Reduce the command length.",
    );
  }

  const privacyMode = getPrivacyIpcMode(options.args);
  if (privacyMode !== "none" && processLike.platform === "win32") {
    requireWindowsIpcRuntime(options.nodeVersion ?? process.versions.node);
  }
  validatePrivacyCredential(privacyMode, options.privacyCredential);

  const cwd = options.cwd ?? processLike.cwd();
  const resolved =
    options.resolvedEngine ??
    toResolvedEngine(
      getEnginePath({
        env: options.env ?? processLike.env,
        platform: options.platform ?? processLike.platform,
        architecture: options.architecture ?? processLike.arch,
        appDataDir: options.appDataDir,
        homeDir: options.homeDir,
        releaseChannel: options.releaseChannel,
      }),
    );
  const validated = validateEngine(resolved, options.launcherVersion, {
    fs: options.fs,
  });
  const engineEnvironment = createEngineEnvironment(
    options.env ?? processLike.env,
    validated.resolved.platform,
  );

  return launchValidatedEngine(validated.resolved, options.args, {
    cwd,
    environment: engineEnvironment,
    spawnEngine: options.spawnEngine,
    processLike,
    processTerminator: options.processTerminator,
    privacyIpc:
      privacyMode === "none"
        ? undefined
        : {
            mode: privacyMode === "lazy" ? "lazy" : "eager",
            engineIntegrity: validated.manifest
              ? "verified"
              : "development_unverified",
            credentialStore:
              privacyMode === "preview"
                ? "not_checked"
                : privacyMode === "lazy"
                  ? "unavailable"
                  : "available",
            credential: options.privacyCredential?.accessToken,
            credentialExpiresAtUnixMs:
              options.privacyCredential?.expiresAtUnixMs,
            credentialProvider: options.privacyCredentialProvider,
            launcherPid: processLike.pid,
          },
  });
}

export function launchValidatedEngine(
  engine: Pick<ValidatedEngine["resolved"], "executablePath" | "platform">,
  args: readonly string[],
  options: {
    cwd: string;
    environment?: NodeJS.ProcessEnv;
    spawnEngine?: SpawnEngine;
    processLike?: ProcessLike;
    processTerminator?: ProcessTerminatorCommand;
    privacyIpc?: PrivacyIpcLaunchOptions;
  },
): Promise<EngineLaunchResult> {
  const processLike = options.processLike ?? process;
  const spawnEngine = options.spawnEngine ?? spawn;
  const platform = getPlatformAdapter(engine.platform);
  const stdio: EngineStdio = options.privacyIpc
    ? ["inherit", "inherit", "inherit", "pipe", "pipe"]
    : "inherit";
  const child = spawnEngine(engine.executablePath, [...args], {
    cwd: options.cwd,
    env: createEngineEnvironment(
      options.environment ?? processLike.env,
      engine.platform,
    ),
    stdio,
    shell: false,
    windowsHide: true,
  });

  let settled = false;
  let ipcSession: LauncherIpcSession | undefined;
  let closePendingTransport: (() => void) | undefined;
  const ipcLifetime = new AbortController();
  const signalListeners = new Map<NodeJS.Signals, () => void>();

  const cleanup = (): void => {
    for (const [signal, listener] of signalListeners) {
      processLike.removeListener(signal, listener);
    }
    signalListeners.clear();
    processLike.removeListener("exit", exitListener);
    ipcLifetime.abort();
    ipcSession?.dispose();
    ipcSession = undefined;
    closePendingTransport?.();
    closePendingTransport = undefined;
  };

  const terminateChild = (signal: NodeJS.Signals): void => {
    platform.terminateProcess(child, signal, {
      runCommand: options.processTerminator,
    });
  };

  const forwardSignal = (signal: NodeJS.Signals): (() => void) => {
    return () => terminateChild(signal);
  };

  for (const signal of platform.getForwardedSignals()) {
    const listener = forwardSignal(signal);
    signalListeners.set(signal, listener);
    processLike.on(signal, listener);
  }

  const exitListener = (): void => {
    terminateChild(platform.getParentExitSignal());
  };
  processLike.on("exit", exitListener);

  return new Promise((resolve, reject) => {
    const fail = (error: EngineContractError): void => {
      if (settled) return;
      settled = true;
      cleanup();
      terminateChild(platform.getParentExitSignal());
      reject(error);
    };

    child.once("error", () => {
      fail(
        new EngineContractError(
          "GOAT_ENGINE_SPAWN_FAILED",
          "The GOAT engine could not be started.",
          "Run `goat doctor`.",
        ),
      );
    });

    child.once("exit", (code, signal) => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve({
        exitCode: typeof code === "number" ? code : 1,
        signal: signal ?? null,
      });
    });

    const privacyIpc = options.privacyIpc;
    if (!privacyIpc) return;
    void (async () => {
      if (!Number.isSafeInteger(child.pid) || (child.pid ?? 0) <= 0) {
        throw new EngineContractError(
          "GOAT_PRIVACY_IPC_FAILED",
          "The GOAT privacy session could not bind to the engine process.",
          "Run `goat doctor`.",
        );
      }
      const transport = childPipeTransport(child);
      closePendingTransport = () => transport.close?.();
      let providedCredential: PrivacyLaunchCredential | undefined;
      let credential = privacyIpc.credential;
      let credentialExpiresAtUnixMs = privacyIpc.credentialExpiresAtUnixMs;
      let credentialStore = privacyIpc.credentialStore;
      if (privacyIpc.mode === "lazy") {
        await waitForLauncherIpcV2Activation({
          transport,
          signal: ipcLifetime.signal,
        });
        providedCredential = await privacyIpc.credentialProvider?.();
        validateProvidedPrivacyCredential(providedCredential);
        credential = providedCredential?.accessToken;
        credentialExpiresAtUnixMs = providedCredential?.expiresAtUnixMs;
        credentialStore = providedCredential ? "available" : "unavailable";
      }

      const credentialCopy = credential?.slice();
      try {
        ipcSession = await openLauncherIpcSession({
          transport,
          engineIntegrity: privacyIpc.engineIntegrity,
          credentialStore,
          launcherPid: privacyIpc.launcherPid,
          enginePid: child.pid!,
          credential: credentialCopy,
          credentialExpiresAtUnixMs,
          signal: ipcLifetime.signal,
        });
        closePendingTransport = undefined;
      } finally {
        zeroizeLauncherIpcBytes(credentialCopy);
        zeroizeLauncherIpcBytes(providedCredential?.accessToken);
      }
    })().catch(() => {
      if (privacyIpc.mode === "lazy") {
        closePendingTransport?.();
        closePendingTransport = undefined;
        return;
      }
      fail(
        new EngineContractError(
          "GOAT_PRIVACY_IPC_FAILED",
          "The GOAT privacy session could not be established.",
          "Run `goat doctor`.",
        ),
      );
    });
  });
}

export function getPrivacyIpcMode(args: readonly string[]): PrivacyIpcMode {
  if (
    args.length === 3 &&
    args[0] === "privacy" &&
    args[1] === "diagnostics" &&
    args[2] === "preview"
  ) {
    return "preview";
  }
  if (
    args.length === 3 &&
    args[0] === "privacy" &&
    ((args[1] === "telemetry" && args[2] === "delete-remote") ||
      (args[1] === "diagnostics" && args[2] === "submit"))
  ) {
    return "authenticated";
  }
  if (
    args.length === 4 &&
    args[0] === "privacy" &&
    args[1] === "diagnostics" &&
    args[2] === "delete" &&
    args[3] !== ""
  ) {
    return "authenticated";
  }
  return "lazy";
}

export function createEngineEnvironment(
  environment: NodeJS.ProcessEnv,
  platform: NodeJS.Platform = process.platform,
): NodeJS.ProcessEnv {
  const normalizeKey = (key: string) =>
    platform === "win32" ? key.toUpperCase() : key;
  const allowed = new Set(
    [
      ...COMMON_ENGINE_ENVIRONMENT_KEYS,
      ...(platform === "win32"
        ? WINDOWS_ENGINE_ENVIRONMENT_KEYS
        : POSIX_ENGINE_ENVIRONMENT_KEYS),
      ...approvedEngineEnvironmentKeys(),
    ].map(normalizeKey),
  );
  const filtered: NodeJS.ProcessEnv = {};

  for (const [key, value] of Object.entries(environment)) {
    if (value === undefined) continue;
    const normalized = normalizeKey(key);
    if (!allowed.has(normalized)) continue;
    if (platform === "win32") {
      if (filtered[normalized] === undefined || key === normalized) {
        filtered[normalized] = value;
      }
      continue;
    }
    filtered[key] = value;
  }
  return filtered;
}

export function getForwardedSignals(
  platform: NodeJS.Platform,
): NodeJS.Signals[] {
  return getPlatformForwardedSignals(platform);
}

export function getLauncherExitSignal(
  platform: NodeJS.Platform,
): NodeJS.Signals {
  return getParentExitSignal(platform);
}

function childPipeTransport(child: ChildProcess) {
  const toEngine = child.stdio[3];
  const fromEngine = child.stdio[4];
  if (!(toEngine instanceof Writable) || !(fromEngine instanceof Readable)) {
    throw new EngineContractError(
      "GOAT_PRIVACY_IPC_FAILED",
      "The GOAT privacy session pipes were unavailable.",
      "Run `goat doctor`.",
    );
  }
  return createNodeLauncherIpcTransport(fromEngine, toEngine);
}

function validatePrivacyCredential(
  mode: PrivacyIpcMode,
  credential: PrivacyLaunchCredential | undefined,
): void {
  if (mode === "authenticated") {
    if (
      !credential ||
      !(credential.accessToken instanceof Uint8Array) ||
      credential.accessToken.byteLength !== 43 ||
      !/^[A-Za-z0-9_-]{43}$/.test(
        new TextDecoder().decode(credential.accessToken),
      ) ||
      !Number.isSafeInteger(credential.expiresAtUnixMs) ||
      credential.expiresAtUnixMs <= Date.now()
    ) {
      throw new EngineContractError(
        "GOAT_PRIVACY_AUTH_REQUIRED",
        "GOAT privacy authentication is required.",
        "Run `goat login`.",
      );
    }
    return;
  }
  if (credential) {
    throw new EngineContractError(
      "GOAT_PRIVACY_IPC_FAILED",
      "Credentials are not permitted for this GOAT command.",
      "Retry the command.",
    );
  }
}

function validateProvidedPrivacyCredential(
  credential: PrivacyLaunchCredential | undefined,
): void {
  if (!credential) return;
  if (
    !(credential.accessToken instanceof Uint8Array) ||
    credential.accessToken.byteLength !== 43 ||
    !/^[A-Za-z0-9_-]{43}$/.test(
      new TextDecoder().decode(credential.accessToken),
    ) ||
    !Number.isSafeInteger(credential.expiresAtUnixMs) ||
    credential.expiresAtUnixMs <= Date.now()
  ) {
    zeroizeLauncherIpcBytes(credential.accessToken);
    throw new EngineContractError(
      "GOAT_PRIVACY_AUTH_REQUIRED",
      "GOAT privacy authentication is required.",
      "Run `goat login`.",
    );
  }
}

function requireWindowsIpcRuntime(version: string): void {
  const match = /^(\d+)\.(\d+)\.(\d+)(?:-|$)/.exec(version);
  const supported =
    match !== null &&
    (Number(match[1]) > 24 ||
      (Number(match[1]) === 24 &&
        (Number(match[2]) > 16 ||
          (Number(match[2]) === 16 && Number(match[3]) >= 0))));
  if (!supported) {
    throw new EngineContractError(
      "GOAT_NODE_VERSION_UNSUPPORTED",
      "This Node.js version cannot safely launch GOAT privacy IPC on Windows.",
      "Install Node.js 24.16.0 or newer.",
    );
  }
}
