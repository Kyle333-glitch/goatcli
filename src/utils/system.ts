import os from 'os';
import fs from 'fs';
import path from 'path';
import { execa } from 'execa';

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

export function getShell(): string {
  if (process.platform === 'win32') {
    return process.env.COMSPEC || 'cmd.exe';
  }
  return process.env.SHELL || '/bin/sh';
}

export function checkDirectoryWritable(dirPath: string): DirectoryStatus {
  try {
    const exists = fs.existsSync(dirPath);
    if (!exists) {
      // Find closest existing parent directory to check writability
      let current = dirPath;
      while (current && !fs.existsSync(current)) {
        const parent = path.dirname(current);
        if (parent === current) break; // Reached root
        current = parent;
      }
      fs.accessSync(current, fs.constants.W_OK);
      return { path: dirPath, exists: false, writable: true };
    }

    fs.accessSync(dirPath, fs.constants.W_OK);
    return { path: dirPath, exists: true, writable: true };
  } catch (err: any) {
    return { path: dirPath, exists: fs.existsSync(dirPath), writable: false, error: err.message };
  }
}

export async function getWindowsLongPathsEnabled(): Promise<boolean | null> {
  if (process.platform !== 'win32') return null;
  try {
    const { stdout } = await execa('reg', [
      'query',
      'HKLM\\SYSTEM\\CurrentControlSet\\Control\\FileSystem',
      '/v',
      'LongPathsEnabled'
    ]);
    if (stdout.includes('0x1')) {
      return true;
    }
    return false;
  } catch {
    return null;
  }
}

export function checkPathLengthProblems(pathsToCheck: { name: string; path: string }[]): PathLengthStatus[] {
  return pathsToCheck.map((p) => {
    const len = p.path.length;
    // Max path on Windows is typically 260
    const hasProblem = process.platform === 'win32' && len >= 260;
    return {
      name: p.name,
      path: p.path,
      length: len,
      hasProblem,
    };
  });
}

export async function checkMacExecutable(filePath: string): Promise<MacExecutableStatus> {
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

  // 1. Check executable bit
  try {
    const stats = fs.statSync(filePath);
    status.mode = stats.mode;
    status.isExecutable = (stats.mode & fs.constants.S_IXUSR) !== 0;
  } catch {
    status.isExecutable = false;
  }

  if (process.platform !== 'darwin') {
    return status;
  }

  // 2. Check quarantine attribute
  try {
    const { stdout } = await execa('xattr', [filePath]);
    const attributes = stdout.split('\n').map(x => x.trim()).filter(Boolean);
    status.isQuarantined = attributes.includes('com.apple.quarantine');
  } catch (err: any) {
    status.quarantineError = err.message;
  }

  // 3. Check code sign status
  try {
    await execa('codesign', ['-v', filePath]);
    status.codeSignValid = true;
  } catch (err: any) {
    status.codeSignValid = false;
    status.codeSignError = err.message;
  }

  return status;
}

export function checkWindowsPathProblems(): {
  npmBinInPath: boolean;
  pathExtHasExe: boolean;
  engineHasSpaces: boolean;
} {
  const issues = {
    npmBinInPath: true,
    pathExtHasExe: true,
    engineHasSpaces: false,
  };

  if (process.platform !== 'win32') {
    return issues;
  }

  // Check PATHEXT
  const pathext = process.env.PATHEXT || '';
  issues.pathExtHasExe = pathext.toUpperCase().split(';').includes('.EXE');

  // Check npm bin directory in path
  const pathEnv = process.env.PATH || '';
  const paths = pathEnv.split(';');
  
  // Look for common npm global locations
  const hasNpmBin = paths.some(p => 
    p.toLowerCase().includes('npm') || 
    p.toLowerCase().includes('nodejs') || 
    p.toLowerCase().includes('nvm') ||
    p.toLowerCase().includes('yarn')
  );
  issues.npmBinInPath = hasNpmBin;

  return issues;
}
