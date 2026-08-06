import { randomBytes } from "crypto";
import { spawnSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";
import type { ChildProcess } from "child_process";
import type { GoatPlatform } from "./engine/contract.js";

export type CredentialStorageKind =
  "windows-credential-manager" | "macos-keychain";

export interface PlatformDirectories {
  appData: string;
  config: string;
  cache: string;
}

export interface PlatformDirectoryOptions {
  env?: NodeJS.ProcessEnv;
  homeDir?: string;
  platform?: NodeJS.Platform;
}

export interface CredentialStorageAdapter {
  kind: CredentialStorageKind;
  platform: GoatPlatform;
}

export interface ExecutablePermissionFileSystem {
  constants: Pick<typeof fs.constants, "X_OK">;
  accessSync(path: string, mode?: number): void;
  chmodSync?(path: string, mode: number): void;
}

export interface ProcessTerminatorResult {
  status: number | null;
  error?: Error;
}

export type ProcessTerminatorCommand = (
  command: string,
  args: readonly string[],
) => ProcessTerminatorResult;

export type ProcessGroupTerminator = (
  processGroupId: number,
  signal: NodeJS.Signals,
) => void;

export interface AtomicFileSystem {
  mkdir(path: string, options: { recursive: true }): Promise<unknown>;
  writeFile(
    path: string,
    data: string | Uint8Array,
    options?: { mode?: number },
  ): Promise<unknown>;
  chmod?(path: string, mode: number): Promise<unknown>;
  rename(oldPath: string, newPath: string): Promise<unknown>;
  rm?(path: string, options: { force: true }): Promise<unknown>;
  unlink?(path: string): Promise<unknown>;
}

export interface AtomicReplaceOptions {
  fs?: AtomicFileSystem;
  mode?: number;
  tempSuffix?: string;
}

export interface PlatformAdapter {
  platform: GoatPlatform;
  pathModule: typeof path.win32 | typeof path.posix;
  credentialStorage: CredentialStorageAdapter;
  getDirectories(options?: PlatformDirectoryOptions): PlatformDirectories;
  getEngineExecutableName(): string;
  getShell(env?: NodeJS.ProcessEnv): string;
  getForwardedSignals(): NodeJS.Signals[];
  getParentExitSignal(): NodeJS.Signals;
  hasPathLengthProblem(path: string): boolean;
  hasExecutablePermission(
    path: string,
    fileSystem?: ExecutablePermissionFileSystem,
  ): boolean;
  ensureExecutablePermission(
    path: string,
    fileSystem?: ExecutablePermissionFileSystem,
  ): void;
  terminateProcess(
    child: Pick<ChildProcess, "kill" | "pid">,
    signal: NodeJS.Signals,
    options?: {
      runCommand?: ProcessTerminatorCommand;
      killGroup?: ProcessGroupTerminator;
    },
  ): void;
  replaceFileAtomically(
    path: string,
    data: string | Uint8Array,
    options?: AtomicReplaceOptions,
  ): Promise<void>;
}

export function getRuntimePlatform(): NodeJS.Platform {
  return process.platform;
}

export function getRuntimeArchitecture(): string {
  return process.arch;
}

export function getPathModule(
  platform: NodeJS.Platform,
): typeof path.win32 | typeof path.posix {
  return platform === "win32" ? path.win32 : path.posix;
}

export function getSupportedPlatform(
  platform: NodeJS.Platform,
): GoatPlatform | null {
  return platform === "win32" || platform === "darwin" ? platform : null;
}

export function getPlatformAdapter(platform: GoatPlatform): PlatformAdapter {
  return platform === "win32" ? windowsAdapter : macosAdapter;
}

export function getPlatformAdapterForPlatform(
  platform: NodeJS.Platform,
): PlatformAdapter | null {
  const supported = getSupportedPlatform(platform);
  return supported ? getPlatformAdapter(supported) : null;
}

export function getPlatformDirectories(
  options: PlatformDirectoryOptions = {},
): PlatformDirectories {
  const platform = options.platform ?? getRuntimePlatform();
  const adapter = getPlatformAdapterForPlatform(platform);
  if (adapter) return adapter.getDirectories(options);

  const env = options.env ?? process.env;
  const home = options.homeDir ?? os.homedir();
  const pathModule = getPathModule(platform);
  return {
    appData: env.XDG_DATA_HOME
      ? pathModule.join(env.XDG_DATA_HOME, "goat")
      : pathModule.join(home, ".local", "share", "goat"),
    config: env.XDG_CONFIG_HOME
      ? pathModule.join(env.XDG_CONFIG_HOME, "goat")
      : pathModule.join(home, ".config", "goat"),
    cache: env.XDG_CACHE_HOME
      ? pathModule.join(env.XDG_CACHE_HOME, "goat")
      : pathModule.join(home, ".cache", "goat"),
  };
}

export function getEngineExecutableName(platform: GoatPlatform): string {
  return getPlatformAdapter(platform).getEngineExecutableName();
}

export function getShellForPlatform(
  options: PlatformDirectoryOptions = {},
): string {
  const platform = options.platform ?? getRuntimePlatform();
  const adapter = getPlatformAdapterForPlatform(platform);
  if (adapter) return adapter.getShell(options.env);

  return (options.env ?? process.env).SHELL || "/bin/sh";
}

export function getForwardedSignals(
  platform: NodeJS.Platform,
): NodeJS.Signals[] {
  return (
    getPlatformAdapterForPlatform(platform)?.getForwardedSignals() ?? [
      "SIGINT",
      "SIGTERM",
      "SIGHUP",
    ]
  );
}

export function getParentExitSignal(platform: NodeJS.Platform): NodeJS.Signals {
  return (
    getPlatformAdapterForPlatform(platform)?.getParentExitSignal() ?? "SIGHUP"
  );
}

export function hasPathLengthProblem(
  filePath: string,
  platform: NodeJS.Platform = getRuntimePlatform(),
): boolean {
  return (
    getPlatformAdapterForPlatform(platform)?.hasPathLengthProblem(filePath) ??
    false
  );
}

export async function replaceFileAtomically(
  filePath: string,
  data: string | Uint8Array,
  options: AtomicReplaceOptions & {
    pathModule?: typeof path.win32 | typeof path.posix;
  } = {},
): Promise<void> {
  const fileSystem = options.fs ?? fs.promises;
  const pathModule = options.pathModule ?? path;
  const tempPath = `${filePath}.${options.tempSuffix ?? `${process.pid}.${Date.now()}.${randomBytes(4).toString("hex")}`}.tmp`;
  await fileSystem.mkdir(pathModule.dirname(filePath), { recursive: true });

  try {
    await fileSystem.writeFile(
      tempPath,
      data,
      options.mode === undefined ? undefined : { mode: options.mode },
    );
    if (options.mode !== undefined && fileSystem.chmod) {
      await fileSystem.chmod(tempPath, options.mode);
    }
    await fileSystem.rename(tempPath, filePath);
  } catch (error) {
    await removeTempFile(fileSystem, tempPath);
    throw error;
  }
}

function windowsDirectories(
  options: PlatformDirectoryOptions = {},
): PlatformDirectories {
  const env = options.env ?? process.env;
  const home = options.homeDir ?? os.homedir();
  const appData = env.LOCALAPPDATA
    ? path.win32.join(env.LOCALAPPDATA, "goat")
    : path.win32.join(home, "AppData", "Local", "goat");
  const config = env.APPDATA
    ? path.win32.join(env.APPDATA, "goat")
    : path.win32.join(home, "AppData", "Roaming", "goat");
  return {
    appData,
    config,
    cache: path.win32.join(appData, "Cache"),
  };
}

function macosDirectories(
  options: PlatformDirectoryOptions = {},
): PlatformDirectories {
  const home = options.homeDir ?? os.homedir();
  return {
    appData: path.posix.join(home, "Library", "Application Support", "goat"),
    config: path.posix.join(
      home,
      "Library",
      "Application Support",
      "goat",
      "config",
    ),
    cache: path.posix.join(home, "Library", "Caches", "goat"),
  };
}

function hasExecutablePermission(
  platform: GoatPlatform,
  filePath: string,
  fileSystem: ExecutablePermissionFileSystem = fs,
): boolean {
  if (platform === "win32") return true;

  try {
    fileSystem.accessSync(filePath, fileSystem.constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

function ensureExecutablePermission(
  platform: GoatPlatform,
  filePath: string,
  fileSystem: ExecutablePermissionFileSystem = fs,
): void {
  if (
    platform === "win32" ||
    hasExecutablePermission(platform, filePath, fileSystem)
  )
    return;
  fileSystem.chmodSync?.(filePath, 0o755);
}

function terminateWindowsProcessTree(
  child: Pick<ChildProcess, "kill" | "pid">,
  signal: NodeJS.Signals,
  options: { runCommand?: ProcessTerminatorCommand } = {},
): void {
  if (!isValidProcessId(child.pid)) {
    terminateWithSignal(child, signal);
    return;
  }

  const run = options.runCommand ?? runProcessTerminator;
  const pid = child.pid;

  // Preserve the parent long enough for taskkill to traverse its descendants.
  const gracefulResult = run("taskkill", ["/pid", String(pid), "/T"]);
  if (gracefulResult.status === 0) {
    // Node processes can consume the console-control event used by SIGINT and
    // SIGBREAK. A successful graceful taskkill command is not proof that the
    // tree actually closed, so force the tree for those user-interrupt paths.
    if (signal !== "SIGINT" && signal !== "SIGBREAK") return;
    const forcefulInterruptResult = run("taskkill", [
      "/pid",
      String(pid),
      "/T",
      "/F",
    ]);
    if (forcefulInterruptResult.status === 0) return;
  }

  const forcefulResult = run("taskkill", ["/pid", String(pid), "/T", "/F"]);
  if (forcefulResult.status === 0) return;

  // Fall back to direct termination only when tree termination is unavailable.
  terminateWithSignal(child, signal);
}

function terminatePosixProcessGroup(
  child: Pick<ChildProcess, "kill" | "pid">,
  signal: NodeJS.Signals,
  options: { killGroup?: ProcessGroupTerminator } = {},
): void {
  if (isValidProcessId(child.pid)) {
    const killGroup =
      options.killGroup ??
      ((processGroupId, forwardedSignal) => {
        process.kill(processGroupId, forwardedSignal);
      });
    try {
      killGroup(-child.pid, signal);
      return;
    } catch {
      // Fall back to the exact child when its process group is already gone.
    }
  }
  terminateWithSignal(child, signal);
}

function isValidProcessId(value: number | undefined): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

function terminateWithSignal(
  child: Pick<ChildProcess, "kill">,
  signal: NodeJS.Signals,
): void {
  try {
    child.kill(signal);
  } catch {
    // The child may already be gone.
  }
}

function runProcessTerminator(
  command: string,
  args: readonly string[],
): ProcessTerminatorResult {
  const result = spawnSync(command, [...args], {
    stdio: "ignore",
    windowsHide: true,
    shell: false,
  });
  return {
    status: result.status,
    error: result.error,
  };
}

async function removeTempFile(
  fileSystem: AtomicFileSystem,
  tempPath: string,
): Promise<void> {
  try {
    if (fileSystem.rm) {
      await fileSystem.rm(tempPath, { force: true });
    } else if (fileSystem.unlink) {
      await fileSystem.unlink(tempPath);
    }
  } catch {
    // Best-effort cleanup; ignore errors to avoid shadowing the primary error.
  }
}

const windowsAdapter: PlatformAdapter = {
  platform: "win32",
  pathModule: path.win32,
  credentialStorage: {
    kind: "windows-credential-manager",
    platform: "win32",
  },
  getDirectories: windowsDirectories,
  getEngineExecutableName: () => "goat-engine.exe",
  getShell: (env = process.env) => env.COMSPEC || "cmd.exe",
  getForwardedSignals: () => ["SIGINT", "SIGTERM", "SIGBREAK"],
  getParentExitSignal: () => "SIGTERM",
  hasPathLengthProblem: (filePath) => filePath.length >= 260,
  hasExecutablePermission: (filePath, fileSystem) =>
    hasExecutablePermission("win32", filePath, fileSystem),
  ensureExecutablePermission: (filePath, fileSystem) =>
    ensureExecutablePermission("win32", filePath, fileSystem),
  terminateProcess: terminateWindowsProcessTree,
  replaceFileAtomically: (filePath, data, options = {}) =>
    replaceFileAtomically(filePath, data, {
      ...options,
      pathModule: path.win32,
    }),
};

const macosAdapter: PlatformAdapter = {
  platform: "darwin",
  pathModule: path.posix,
  credentialStorage: {
    kind: "macos-keychain",
    platform: "darwin",
  },
  getDirectories: macosDirectories,
  getEngineExecutableName: () => "goat-engine",
  getShell: (env = process.env) => env.SHELL || "/bin/sh",
  getForwardedSignals: () => ["SIGINT", "SIGTERM", "SIGHUP"],
  getParentExitSignal: () => "SIGHUP",
  hasPathLengthProblem: () => false,
  hasExecutablePermission: (filePath, fileSystem) =>
    hasExecutablePermission("darwin", filePath, fileSystem),
  ensureExecutablePermission: (filePath, fileSystem) =>
    ensureExecutablePermission("darwin", filePath, fileSystem),
  terminateProcess: terminatePosixProcessGroup,
  replaceFileAtomically: (filePath, data, options = {}) =>
    replaceFileAtomically(filePath, data, {
      ...options,
      pathModule: path.posix,
    }),
};
