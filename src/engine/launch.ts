import { spawn, type ChildProcess } from "node:child_process";
import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { open, type FileHandle } from "node:fs/promises";
import path from "node:path";
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
  getAppDataDir,
  getEnginePath,
  toResolvedEngine,
  type EnginePathOptions,
} from "../utils/paths.js";
import {
  getForwardedSignals as getPlatformForwardedSignals,
  getParentExitSignal,
  getPlatformAdapter,
  type ProcessTerminatorCommand,
  type ProcessGroupTerminator,
} from "../platform.js";
import { createWindowsJobContainment } from "./process-containment.js";
import { createMacOsProcessContainment } from "./macos-process-containment.js";
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
import type { ActivationSecurityPolicy } from "../update/activation.js";
import { UpdateError } from "../update/errors.js";
import { inspectInstalledEngine } from "../update/installed.js";

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
    detached: boolean;
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
  /** Caller-owned input; launch copies and zeroizes only its private IPC copy. */
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
  processGroupTerminator?: ProcessGroupTerminator;
  resolvedEngine?: ResolvedEngine;
  privacyCredential?: PrivacyLaunchCredential;
  installedUpdatePolicy?: ActivationSecurityPolicy;
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
  let resolved: ResolvedEngine;
  let engineIntegrity: EngineIntegrityStatus;
  let expectedExecutableChecksum: string | undefined;
  if (!options.resolvedEngine && options.installedUpdatePolicy) {
    try {
      const appDataDirectory =
        options.appDataDir ??
        getAppDataDir({
          env: options.env ?? processLike.env,
          platform: options.platform ?? processLike.platform,
          homeDir: options.homeDir,
        });
      const installed = await inspectInstalledEngine(
        appDataDirectory,
        options.installedUpdatePolicy,
      );
      if (installed) {
        resolved = {
          executablePath: installed.active.candidate.executablePath,
          manifestPath: path.join(
            installed.active.slotRoot,
            "goat-engine.json",
          ),
          source: "local-install",
          releaseChannel:
            installed.active.activation.record.channel === "development"
              ? "dev"
              : installed.active.activation.record.channel,
          platform: installed.active.activation.record.platform,
          architecture: installed.active.activation.record.architecture,
          developmentOverride: false,
        };
        enforceInstalledEngineTrustPolicy(
          installed.active.candidate.manifest,
          options.trustPolicy,
        );
        engineIntegrity = "verified";
        expectedExecutableChecksum =
          installed.active.candidate.manifest.checksum.value;
      } else {
        ({
          resolved,
          engineIntegrity,
          checksum: expectedExecutableChecksum,
        } = resolveLegacyEngine(options, processLike));
      }
    } catch (error) {
      if (error instanceof UpdateError) {
        throw new EngineContractError(
          "GOAT_ENGINE_RECOVERY_REQUIRED",
          "The v0.4 engine activation could not be validated safely.",
          "Run `goat update`; reinstall GOAT if recovery remains unavailable.",
        );
      }
      throw error;
    }
  } else if (options.resolvedEngine) {
    const validated = validateEngine(
      options.resolvedEngine,
      options.launcherVersion,
      { fs: options.fs, trustPolicy: options.trustPolicy },
    );
    resolved = validated.resolved;
    if (!resolved.developmentOverride) {
      expectedExecutableChecksum = validated.checksum;
    }
    engineIntegrity = validated.manifest
      ? "verified"
      : "development_unverified";
  } else {
    ({
      resolved,
      engineIntegrity,
      checksum: expectedExecutableChecksum,
    } = resolveLegacyEngine(options, processLike));
  }
  const engineEnvironment = createEngineEnvironment(
    options.env ?? processLike.env,
    resolved.platform,
  );
  const executableHandle = await verifyExecutableAtLaunch(
    resolved.executablePath,
    resolved.developmentOverride ? undefined : expectedExecutableChecksum,
  );

  // Keep the verified descriptor open through spawn and process lifetime. On
  // Windows this prevents replacement/deletion while the executable is being
  // handed to CreateProcess; on POSIX it narrows the pathname race to the
  // unavoidable limitation that Node's spawn API accepts a pathname rather
  // than an executable descriptor.
  try {
    return await launchValidatedEngine(resolved, options.args, {
      cwd,
      environment: engineEnvironment,
      spawnEngine: options.spawnEngine,
      processLike,
      processTerminator: options.processTerminator,
      processGroupTerminator: options.processGroupTerminator,
      verifiedExecutable: executableHandle,
      privacyIpc:
        privacyMode === "none"
          ? undefined
          : {
              mode: privacyMode === "lazy" ? "lazy" : "eager",
              engineIntegrity,
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
  } finally {
    await executableHandle?.close().catch(() => undefined);
  }
}

// Installed v0.4 activation is still gated by the activation policy: receipt,
// compatibility, artifact/archive, code-signing, and rollback checks remain
// mandatory. A caller-supplied legacy manifest trustPolicy is an additional,
// authoritative allowlist for the v2 candidate's release digest and key ID;
// it cannot weaken activation policy, and its v1 manifestVersion is not compared
// with the v2 bundle schema version.
function enforceInstalledEngineTrustPolicy(
  manifest: {
    readonly releasePolicyDigest: string;
    readonly signature: { readonly keyId: string; readonly status: "signed" };
  },
  trustPolicy: ValidateEngineOptions["trustPolicy"] | undefined,
): void {
  if (!trustPolicy) return;
  if (
    manifest.releasePolicyDigest !== trustPolicy.releasePolicyDigest ||
    manifest.signature.status !== "signed" ||
    !trustPolicy.engineManifestKeyIds.includes(manifest.signature.keyId)
  ) {
    throw new EngineContractError(
      "GOAT_ENGINE_SIGNATURE_INVALID",
      "The installed GOAT engine is not trusted by the active launcher policy.",
      "Run `goat update`.",
    );
  }
}

function resolveLegacyEngine(
  options: LaunchEngineOptions,
  processLike: ProcessLike,
): {
  readonly resolved: ResolvedEngine;
  readonly engineIntegrity: EngineIntegrityStatus;
  readonly checksum: string;
} {
  const resolved = toResolvedEngine(
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
    trustPolicy: options.trustPolicy,
  });
  return {
    resolved: validated.resolved,
    engineIntegrity: validated.manifest ? "verified" : "development_unverified",
    checksum: validated.checksum,
  };
}

export async function launchValidatedEngine(
  engine: Pick<ValidatedEngine["resolved"], "executablePath" | "platform">,
  args: readonly string[],
  options: {
    cwd: string;
    environment?: NodeJS.ProcessEnv;
    spawnEngine?: SpawnEngine;
    processLike?: ProcessLike;
    processTerminator?: ProcessTerminatorCommand;
    processGroupTerminator?: ProcessGroupTerminator;
    privacyIpc?: PrivacyIpcLaunchOptions;
    /** Held from checksum verification until spawn returns. */
    verifiedExecutable?: FileHandle;
  },
): Promise<EngineLaunchResult> {
  const processLike = options.processLike ?? process;
  const spawnEngine = options.spawnEngine ?? spawn;
  const platform = getPlatformAdapter(engine.platform);
  let containment:
    | {
        bind?(processGroupId: number): void;
        release(): Promise<void>;
        terminate(): void;
      }
    | undefined;
  const useNativeContainment = processLike === process && spawnEngine === spawn;
  if (useNativeContainment) {
    try {
      containment =
        engine.platform === "win32"
          ? await createWindowsJobContainment({
              launcherPid: processLike.pid,
              environment: processLike.env,
            })
          : await createMacOsProcessContainment({
              runtimeExecutable: process.execPath,
            });
    } catch {
      throw new EngineContractError(
        "GOAT_ENGINE_SPAWN_FAILED",
        "The GOAT engine could not be contained safely.",
        "Run `goat doctor`.",
      );
    }
  }

  const stdio: EngineStdio = options.privacyIpc
    ? ["inherit", "inherit", "inherit", "pipe", "pipe"]
    : "inherit";
  let child: ChildProcess;
  try {
    child = spawnEngine(engine.executablePath, [...args], {
      cwd: options.cwd,
      env: createEngineEnvironment(
        options.environment ?? processLike.env,
        engine.platform,
      ),
      stdio,
      shell: false,
      windowsHide: true,
      // A detached Windows process is its own console process group, so a
      // forwarded SIGINT targets the engine instead of rebroadcasting through
      // the launcher's shared console. The Job Object still owns the full
      // descendant tree for fail-safe cleanup.
      detached: engine.platform === "darwin" || engine.platform === "win32",
    });
  } catch {
    await containment?.release().catch(() => undefined);
    throw new EngineContractError(
      "GOAT_ENGINE_SPAWN_FAILED",
      "The GOAT engine could not be started.",
      "Run `goat doctor`.",
    );
  }
  if (containment?.bind) {
    try {
      if (!Number.isSafeInteger(child.pid) || (child.pid ?? 0) <= 0) {
        throw new Error("missing process group");
      }
      containment.bind(child.pid!);
    } catch {
      platform.terminateProcess(child, platform.getParentExitSignal(), {
        runCommand: options.processTerminator,
        killGroup: options.processGroupTerminator,
      });
      containment.terminate();
      throw new EngineContractError(
        "GOAT_ENGINE_SPAWN_FAILED",
        "The GOAT engine could not be contained safely.",
        "Run `goat doctor`.",
      );
    }
  }

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
  const releaseContainment = async (): Promise<void> => {
    await containment?.release();
  };

  const terminateChild = (signal: NodeJS.Signals): void => {
    platform.terminateProcess(child, signal, {
      runCommand: options.processTerminator,
      killGroup: options.processGroupTerminator,
    });
  };

  const forwardSignal = (signal: NodeJS.Signals): (() => void) => {
    return () => {
      // Console interrupts on Windows can be consumed by Node before a
      // process-tree signal reaches the detached engine. The Job Object owns
      // the launcher and its descendants, so close it directly for the
      // user-interrupt signals; closing the guard is the only reliable
      // fail-safe on this path.
      if (
        engine.platform === "win32" &&
        containment &&
        (signal === "SIGINT" || signal === "SIGBREAK")
      ) {
        containment.terminate();
        return;
      }
      terminateChild(signal);
    };
  };

  for (const signal of platform.getForwardedSignals()) {
    const listener = forwardSignal(signal);
    signalListeners.set(signal, listener);
    processLike.on(signal, listener);
  }

  const exitListener = (): void => {
    containment?.terminate();
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
    const containmentError = (): EngineContractError =>
      new EngineContractError(
        "GOAT_ENGINE_SPAWN_FAILED",
        "The GOAT engine process tree did not close safely.",
        "Run `goat doctor`.",
      );

    child.once("error", () => {
      fail(
        new EngineContractError(
          "GOAT_ENGINE_SPAWN_FAILED",
          "The GOAT engine could not be started.",
          "Run `goat doctor`.",
        ),
      );
      void releaseContainment().catch(() => undefined);
    });

    child.once("exit", (code, signal) => {
      if (engine.platform === "darwin") {
        terminateChild(platform.getParentExitSignal());
      }
      const result = {
        exitCode: typeof code === "number" ? code : 1,
        signal: signal ?? null,
      };
      if (settled) {
        void releaseContainment().catch(() => undefined);
        return;
      }
      settled = true;
      cleanup();
      void releaseContainment().then(
        () => resolve(result),
        () => reject(containmentError()),
      );
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
      let providerCredentialCopy: Uint8Array | undefined;
      let credential = privacyIpc.credential;
      let credentialExpiresAtUnixMs = privacyIpc.credentialExpiresAtUnixMs;
      let credentialStore = privacyIpc.credentialStore;
      if (privacyIpc.mode === "lazy") {
        await waitForLauncherIpcV2Activation({
          transport,
          signal: ipcLifetime.signal,
        });
        const providedCredential = await privacyIpc.credentialProvider?.();
        validateProvidedPrivacyCredential(providedCredential);
        providerCredentialCopy = providedCredential?.accessToken.slice();
        credential = providerCredentialCopy;
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
        zeroizeLauncherIpcBytes(providerCredentialCopy);
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
  return "none";
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

async function verifyExecutableAtLaunch(
  executablePath: string,
  expectedSha256?: string,
): Promise<FileHandle | undefined> {
  const OPEN_READ_NOFOLLOW =
    constants.O_RDONLY |
    (typeof constants.O_NOFOLLOW === "number" ? constants.O_NOFOLLOW : 0);
  let handle: FileHandle | undefined;
  try {
    handle = await open(executablePath, OPEN_READ_NOFOLLOW);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    // If the executable does not exist, the subsequent spawn will fail with a
    // clearer error. We only perform the symlink/replacement check when the
    // path resolves to an existing file.
    if (code === "ENOENT") return undefined;
    throw new EngineContractError(
      "GOAT_ENGINE_SPAWN_FAILED",
      "The GOAT engine executable could not be opened for launch.",
      "Run `goat doctor`.",
    );
  }
  try {
    const stats = await handle.stat();
    if (!stats.isFile() || stats.isSymbolicLink()) {
      throw new EngineContractError(
        "GOAT_ENGINE_SPAWN_FAILED",
        "The GOAT engine executable is not a regular file.",
        "Run `goat update`.",
      );
    }
    if (expectedSha256 !== undefined) {
      const actual = await hashFileHandle(handle);
      if (actual !== expectedSha256) {
        throw new EngineContractError(
          "GOAT_ENGINE_CHECKSUM_MISMATCH",
          "The GOAT engine executable does not match its verified checksum.",
          "Run `goat update`.",
        );
      }
    }
  } catch (error) {
    await handle.close().catch(() => undefined);
    throw error;
  }
  return handle;
}

async function hashFileHandle(handle: FileHandle): Promise<string> {
  const hash = createHash("sha256");
  for await (const chunk of handle.createReadStream()) {
    hash.update(chunk as Buffer);
  }
  return hash.digest("hex");
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
