export declare const WINDOWS_PRIVACY_SPAWN_ABI_VERSION: 1;

export interface SpawnWindowsPrivacyRequest {
  command: string;
  args: string[];
  cwd?: string;
  env: Array<{ name: string; value: string }>;
  windowsHide: true;
  detached: true;
}

export interface SpawnedWindowsPrivacyProcess {
  readonly pid: number;
  takeLauncherWriteFd(): number;
  takeLauncherReadFd(): number;
  terminate(): boolean;
  close(): void;
}

export declare function spawnWindowsPrivacyProcess(
  request: SpawnWindowsPrivacyRequest,
  onExit: (exitCode: number | null, signal: null) => void,
): SpawnedWindowsPrivacyProcess;
