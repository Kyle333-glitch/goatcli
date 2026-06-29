import fs from 'fs';
import path from 'path';
import { execa } from 'execa';
import {
  getPlatformAdapterForPlatform,
  getRuntimePlatform,
  getShellForPlatform,
  hasPathLengthProblem,
  type PlatformDirectoryOptions,
} from '../platform.js';

export interface DirectoryStatus {
  path: string;
  exists: boolean;
  writable: boolean;
  error?: string;
}

export interface PathLengthStatus {
  name: string;
  path: string;
  length: number;
  hasProblem: boolean;
}

export interface MacExecutableStatus {
  exists: boolean;
  isExecutable: boolean;
  isQuarantined: boolean;
  codeSignValid: boolean;
  mode?: number;
  quarantineError?: string;
  codeSignError?: string;
}

export async function getGitVersion(): Promise<string | null> {
  try {
    const { stdout } = await execa('git', ['--version']);
    return stdout.trim();
  } catch {
    return null;
  }
}

export function getShell(options: PlatformDirectoryOptions = {}): string {
  return getShellForPlatform(options);
}

export function checkDirectoryWritable(dirPath: string): DirectoryStatus {
  try {
    const exists = fs.existsSync(dirPath);
    if (!exists) {
      let current = dirPath;
      while (current && !fs.existsSync(current)) {
        const parent = path.dirname(current);
        if (parent === current) break;
        current = parent;
      }
      if (fs.statSync(current).isDirectory()) {
        fs.accessSync(current, fs.constants.W_OK);
      } else {
        return { path: dirPath, exists: false, writable: false, error: 'Closest existing parent is a file, not a directory' };
      }
      return { path: dirPath, exists: false, writable: true };
    }

    if (!fs.statSync(dirPath).isDirectory()) {
      return { path: dirPath, exists: true, writable: false, error: 'Path exists but is not a directory' };
    }
    fs.accessSync(dirPath, fs.constants.W_OK);
    return { path: dirPath, exists: true, writable: true };
  } catch (err) {
    return {
      path: dirPath,
      exists: fs.existsSync(dirPath),
      writable: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

export async function getWindowsLongPathsEnabled(platform: NodeJS.Platform = getRuntimePlatform()): Promise<boolean | null> {
  if (getPlatformAdapterForPlatform(platform)?.platform !== 'win32') return null;
  try {
    const { stdout } = await execa('reg', [
      'query',
      'HKLM\\SYSTEM\\CurrentControlSet\\Control\\FileSystem',
      '/v',
      'LongPathsEnabled',
    ]);
    if (stdout.includes('0x1')) {
      return true;
    }
    return false;
  } catch {
    return null;
  }
}

export function checkPathLengthProblems(
  pathsToCheck: { name: string; path: string }[],
  options: { platform?: NodeJS.Platform } = {},
): PathLengthStatus[] {
  const platform = options.platform ?? getRuntimePlatform();
  return pathsToCheck.map((p) => {
    const len = p.path.length;
    return {
      name: p.name,
      path: p.path,
      length: len,
      hasProblem: hasPathLengthProblem(p.path, platform),
    };
  });
}

export async function checkMacExecutable(filePath: string, platform: NodeJS.Platform = getRuntimePlatform()): Promise<MacExecutableStatus> {
  const status: MacExecutableStatus = {
    exists: false,
    isExecutable: false,
    isQuarantined: false,
    codeSignValid: false,
  };

  if (!fs.existsSync(filePath)) {
    return status;
  }
  status.exists = true;

  const adapter = getPlatformAdapterForPlatform(platform);
  status.isExecutable = adapter?.hasExecutablePermission(filePath) ?? true;

  if (adapter?.platform !== 'darwin') {
    return status;
  }

  try {
    const { stdout } = await execa('xattr', [filePath]);
    const attributes = stdout.split('\n').map((x) => x.trim()).filter(Boolean);
    status.isQuarantined = attributes.includes('com.apple.quarantine');
  } catch (err) {
    status.quarantineError = err instanceof Error ? err.message : String(err);
  }

  try {
    await execa('codesign', ['-v', filePath]);
    status.codeSignValid = true;
  } catch (err) {
    status.codeSignValid = false;
    status.codeSignError = err instanceof Error ? err.message : String(err);
  }

  return status;
}

export function checkWindowsPathProblems(platform: NodeJS.Platform = getRuntimePlatform()): {
  npmBinInPath: boolean;
  pathExtHasExe: boolean;
} {
  const issues = {
    npmBinInPath: true,
    pathExtHasExe: true,
  };

  if (getPlatformAdapterForPlatform(platform)?.platform !== 'win32') {
    return issues;
  }

  const pathext = process.env.PATHEXT || '';
  issues.pathExtHasExe = pathext.toUpperCase().split(';').includes('.EXE');

  const pathEnv = process.env.PATH || '';
  const paths = pathEnv.split(path.delimiter);
  issues.npmBinInPath = paths.some((p) =>
    p.toLowerCase().includes('npm') ||
    p.toLowerCase().includes('nodejs') ||
    p.toLowerCase().includes('nvm') ||
    p.toLowerCase().includes('yarn')
  );

  return issues;
}
