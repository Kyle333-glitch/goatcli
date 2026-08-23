import type { ChildProcess } from "node:child_process";
import { createRequire } from "node:module";
import { constants as osConstants } from "node:os";
import { closeSync, createReadStream, createWriteStream } from "node:fs";
import { EventEmitter } from "node:events";
import type { Readable, Writable } from "node:stream";
import { EngineContractError } from "./contract.js";
import type { SpawnEngine } from "./launch.js";

export const WINDOWS_PRIVACY_SPAWN_ABI_VERSION = 1;

const WINDOWS_PRIVACY_SPAWN_PACKAGE = "goatcli-windows-spawn";

export type LoadWindowsPrivacySpawner = () => Promise<SpawnEngine>;

interface WindowsPrivacySpawnRequest {
  readonly command: string;
  readonly args: readonly string[];
  readonly cwd: string;
  readonly env: readonly WindowsPrivacyEnvironmentEntry[];
  readonly windowsHide: true;
  readonly detached: true;
}

interface WindowsPrivacyEnvironmentEntry {
  readonly name: string;
  readonly value: string;
}

interface NativeWindowsPrivacyProcess {
  readonly pid: number;
  takeLauncherWriteFd(): number;
  takeLauncherReadFd(): number;
  terminate(): boolean;
  close(): void;
}

interface NativeWindowsPrivacyProcessControl {
  readonly pid: number;
  takeLauncherWriteFd(): number;
  takeLauncherReadFd(): number;
  terminate(): boolean;
  close(): void;
}

interface WindowsPrivacySpawnBinding {
  readonly WINDOWS_PRIVACY_SPAWN_ABI_VERSION: number;
  spawnWindowsPrivacyProcess(
    request: WindowsPrivacySpawnRequest,
    onExit: (exitCode: number | null, signal: null) => void,
  ): NativeWindowsPrivacyProcess;
}

interface WindowsPrivacyStreamFactory {
  createWrite(fd: number): Writable;
  createRead(fd: number): Readable;
  close(fd: number): void;
}

const nodeStreamFactory: WindowsPrivacyStreamFactory = {
  createWrite: (fd) =>
    createWriteStream("", {
      fd,
      autoClose: true,
    }),
  createRead: (fd) =>
    createReadStream("", {
      fd,
      autoClose: true,
    }),
  close: (fd) => closeSync(fd),
};

class WindowsPrivacyPipeSetupError extends Error {
  constructor() {
    super("The native Windows privacy pipes could not be attached.");
    this.name = "WindowsPrivacyPipeSetupError";
  }
}

class WindowsPrivacyProcessCreateError extends Error {
  constructor() {
    super("The native Windows privacy process could not be created.");
    this.name = "WindowsPrivacyProcessCreateError";
  }
}

export function isWindowsPrivacyPipeSetupError(
  error: unknown,
): error is WindowsPrivacyPipeSetupError {
  return error instanceof WindowsPrivacyPipeSetupError;
}

export function windowsPrivacySpawnUnavailableError(): EngineContractError {
  return new EngineContractError(
    "GOAT_WINDOWS_PRIVACY_SPAWN_UNAVAILABLE",
    "This GOAT installation cannot safely launch privacy IPC on Windows.",
    "Reinstall GOAT, then run `goat doctor`.",
  );
}

export const loadWindowsPrivacySpawner: LoadWindowsPrivacySpawner =
  async () => {
    let candidate: unknown;
    try {
      const require = createRequire(import.meta.url);
      candidate = require(WINDOWS_PRIVACY_SPAWN_PACKAGE);
    } catch {
      throw windowsPrivacySpawnUnavailableError();
    }

    try {
      const binding = parseBinding(candidate);
      return createWindowsPrivacySpawner(binding);
    } catch {
      throw windowsPrivacySpawnUnavailableError();
    }
  };

/**
 * Adapts the versioned native ABI to the narrow ChildProcess surface consumed
 * by the launcher. Exported only so the binding boundary can be tested without
 * loading a native binary.
 */
export function createWindowsPrivacySpawner(
  binding: WindowsPrivacySpawnBinding,
  streams: WindowsPrivacyStreamFactory = nodeStreamFactory,
): SpawnEngine {
  let spawnNative: WindowsPrivacySpawnBinding["spawnWindowsPrivacyProcess"];
  try {
    if (!isValidBinding(binding)) {
      throw new Error("invalid native binding");
    }
    spawnNative = binding.spawnWindowsPrivacyProcess.bind(binding);
  } catch {
    throw windowsPrivacySpawnUnavailableError();
  }

  return (command, args, options) => {
    if (
      !Array.isArray(options.stdio) ||
      options.stdio.length !== 5 ||
      options.stdio[0] !== "inherit" ||
      options.stdio[1] !== "inherit" ||
      options.stdio[2] !== "inherit" ||
      options.stdio[3] !== "pipe" ||
      options.stdio[4] !== "pipe" ||
      options.shell !== false ||
      options.windowsHide !== true ||
      options.detached !== true
    ) {
      throw new WindowsPrivacyPipeSetupError();
    }

    let child: WindowsPrivacyChildProcess | undefined;
    let pendingExit: readonly [number | null, null] | undefined;
    let abandoned = false;
    const onExit = (exitCode: number | null, signal: null): void => {
      if (abandoned) return;
      if (child) {
        child.notifyExit(exitCode, signal);
      } else if (!pendingExit) {
        pendingExit = [exitCode, signal];
      }
    };

    let nativeResult: unknown;
    try {
      nativeResult = spawnNative(
        {
          command,
          args: [...args],
          cwd: options.cwd,
          env: definedEnvironmentEntries(options.env),
          windowsHide: true,
          detached: true,
        },
        onExit,
      );
    } catch (error) {
      abandoned = true;
      if (classifyNativeSpawnFailure(error) === "privacy-pipe") {
        throw new WindowsPrivacyPipeSetupError();
      }
      // CreateProcessW failures and unknown native exceptions are both mapped
      // to the launcher's fixed spawn error. Never retain the raw exception:
      // native diagnostics can contain executable or working-directory paths.
      throw new WindowsPrivacyProcessCreateError();
    }

    const nativeProcess = parseNativeProcess(nativeResult);
    if (!nativeProcess) {
      abandoned = true;
      safelyDisposeMalformedProcess(nativeResult);
      throw windowsPrivacySpawnUnavailableError();
    }

    let launcherWriteFd: number | undefined;
    let launcherReadFd: number | undefined;
    let malformedDescriptors = false;
    try {
      launcherWriteFd = nativeProcess.takeLauncherWriteFd();
      if (!isNonNegativeSafeInteger(launcherWriteFd)) {
        malformedDescriptors = true;
        throw new Error("invalid launcher write descriptor");
      }
      launcherReadFd = nativeProcess.takeLauncherReadFd();
      if (
        !isNonNegativeSafeInteger(launcherReadFd) ||
        launcherReadFd === launcherWriteFd
      ) {
        malformedDescriptors = true;
        throw new Error("invalid launcher read descriptor");
      }
    } catch {
      abandoned = true;
      if (isNonNegativeSafeInteger(launcherWriteFd)) {
        safelyCloseFd(streams, launcherWriteFd);
      }
      if (
        isNonNegativeSafeInteger(launcherReadFd) &&
        launcherReadFd !== launcherWriteFd
      ) {
        safelyCloseFd(streams, launcherReadFd);
      }
      safelyTerminate(nativeProcess);
      safelyCloseProcess(nativeProcess);
      if (malformedDescriptors) throw windowsPrivacySpawnUnavailableError();
      throw new WindowsPrivacyPipeSetupError();
    }

    let launcherWrite: Writable | undefined;
    let launcherRead: Readable | undefined;
    try {
      launcherWrite = streams.createWrite(launcherWriteFd);
      launcherWriteFd = undefined;
      launcherRead = streams.createRead(launcherReadFd);
      launcherReadFd = undefined;
      child = new WindowsPrivacyChildProcess(
        nativeProcess,
        launcherWrite,
        launcherRead,
      );
    } catch {
      abandoned = true;
      if (launcherWrite) {
        launcherWrite.destroy();
      } else if (launcherWriteFd !== undefined) {
        safelyCloseFd(streams, launcherWriteFd);
      }
      if (launcherRead) {
        launcherRead.destroy();
      } else if (launcherReadFd !== undefined) {
        safelyCloseFd(streams, launcherReadFd);
      }
      safelyTerminate(nativeProcess);
      safelyCloseProcess(nativeProcess);
      throw new WindowsPrivacyPipeSetupError();
    }

    if (pendingExit) {
      const [exitCode, signal] = pendingExit;
      queueMicrotask(() => child?.notifyExit(exitCode, signal));
    }
    return child as unknown as ChildProcess;
  };
}

class WindowsPrivacyChildProcess extends EventEmitter {
  readonly pid: number;
  readonly stdio: ChildProcess["stdio"];
  private settled = false;
  private terminationSignal: NodeJS.Signals | null = null;

  constructor(
    private readonly nativeProcess: NativeWindowsPrivacyProcessControl,
    launcherWrite: Writable,
    launcherRead: Readable,
  ) {
    super();
    this.pid = nativeProcess.pid;
    this.stdio = [
      null,
      null,
      null,
      launcherWrite,
      launcherRead,
    ] as ChildProcess["stdio"];
  }

  kill(signal: NodeJS.Signals | number = "SIGTERM"): boolean {
    if (this.settled) return false;
    if (signal === 0) return true;

    const previousSignal = this.terminationSignal;
    this.terminationSignal = signalName(signal);
    try {
      const terminated = this.nativeProcess.terminate();
      if (!terminated) this.terminationSignal = previousSignal;
      return terminated;
    } catch {
      this.terminationSignal = previousSignal;
      return false;
    }
  }

  notifyExit(exitCode: number | null, _signal: null): void {
    if (this.settled) return;
    this.settled = true;
    safelyCloseProcess(this.nativeProcess);

    const signal = this.terminationSignal;
    const code = signal
      ? null
      : typeof exitCode === "number" &&
          Number.isSafeInteger(exitCode) &&
          exitCode >= 0
        ? exitCode
        : 1;
    this.emit("exit", code, signal);
  }
}

function parseBinding(candidate: unknown): WindowsPrivacySpawnBinding {
  const unwrapped =
    isRecord(candidate) && isRecord(candidate.default)
      ? candidate.default
      : candidate;
  if (!isValidBinding(unwrapped)) {
    throw windowsPrivacySpawnUnavailableError();
  }
  return unwrapped;
}

function isValidBinding(value: unknown): value is WindowsPrivacySpawnBinding {
  return (
    isRecord(value) &&
    value.WINDOWS_PRIVACY_SPAWN_ABI_VERSION ===
      WINDOWS_PRIVACY_SPAWN_ABI_VERSION &&
    typeof value.spawnWindowsPrivacyProcess === "function"
  );
}

function parseNativeProcess(
  value: unknown,
): NativeWindowsPrivacyProcessControl | undefined {
  try {
    if (!isRecord(value)) return undefined;
    const pid = value.pid;
    const takeLauncherWriteFd = value.takeLauncherWriteFd;
    const takeLauncherReadFd = value.takeLauncherReadFd;
    const terminate = value.terminate;
    const close = value.close;
    if (
      !isPositiveSafeInteger(pid) ||
      typeof takeLauncherWriteFd !== "function" ||
      typeof takeLauncherReadFd !== "function" ||
      typeof terminate !== "function" ||
      typeof close !== "function"
    ) {
      return undefined;
    }
    return {
      pid,
      takeLauncherWriteFd: () =>
        Reflect.apply(takeLauncherWriteFd, value, []) as number,
      takeLauncherReadFd: () =>
        Reflect.apply(takeLauncherReadFd, value, []) as number,
      terminate: () => Reflect.apply(terminate, value, []) === true,
      close: () => {
        Reflect.apply(close, value, []);
      },
    };
  } catch {
    return undefined;
  }
}

function definedEnvironmentEntries(
  environment: NodeJS.ProcessEnv,
): readonly WindowsPrivacyEnvironmentEntry[] {
  const defined: WindowsPrivacyEnvironmentEntry[] = [];
  for (const [key, value] of Object.entries(environment)) {
    if (value !== undefined) defined.push({ name: key, value });
  }
  return defined;
}

function signalName(signal: NodeJS.Signals | number): NodeJS.Signals | null {
  if (typeof signal === "string") return signal;
  for (const [name, number] of Object.entries(osConstants.signals)) {
    if (number === signal) return name as NodeJS.Signals;
  }
  return null;
}

function safelyDisposeMalformedProcess(value: unknown): void {
  try {
    if (!isRecord(value)) return;
    if (typeof value.terminate === "function") {
      Reflect.apply(value.terminate, value, []);
    }
  } catch {
    // Best effort: this is already a malformed native binding result.
  }
  try {
    if (isRecord(value) && typeof value.close === "function") {
      Reflect.apply(value.close, value, []);
    }
  } catch {
    // Best effort: the native finalizer remains the last cleanup backstop.
  }
}

function safelyTerminate(
  nativeProcess: NativeWindowsPrivacyProcessControl,
): void {
  try {
    nativeProcess.terminate();
  } catch {
    // The child may already have exited while its streams were being attached.
  }
}

function safelyCloseProcess(
  nativeProcess: NativeWindowsPrivacyProcessControl,
): void {
  try {
    nativeProcess.close();
  } catch {
    // Native resources are idempotently finalized by the binding as a fallback.
  }
}

function safelyCloseFd(streams: WindowsPrivacyStreamFactory, fd: number): void {
  try {
    streams.close(fd);
  } catch {
    // The native side or a partially constructed stream may already own it.
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function classifyNativeSpawnFailure(
  value: unknown,
): "process-create" | "privacy-pipe" {
  let code: string | undefined;
  try {
    code =
      isRecord(value) && typeof value.code === "string"
        ? value.code
        : undefined;
  } catch {
    return "process-create";
  }
  switch (code) {
    case "GOAT_NATIVE_PRIVACY_PIPE_FAILED":
      return "privacy-pipe";
    case "GOAT_NATIVE_PROCESS_CREATE_FAILED":
    default:
      return "process-create";
  }
}

function isPositiveSafeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

function isNonNegativeSafeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}
