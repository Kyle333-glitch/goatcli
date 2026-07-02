import { spawn } from 'node:child_process';
import type { BrowserOpener } from './types.js';
import { isAllowedControlPlaneUrl } from './client.js';

export interface SpawnLike {
  (command: string, args: readonly string[], options: { detached: boolean; stdio: 'ignore'; windowsHide: boolean }): { unref(): void };
}

export function createBrowserOpener(platform: NodeJS.Platform = process.platform, spawnImpl: SpawnLike = spawn): BrowserOpener {
  return {
    async open(url) {
      const parsed = new URL(url);
      if (!isAllowedControlPlaneUrl(parsed)) return false;
      const command = platform === 'win32' ? 'explorer.exe' : platform === 'darwin' ? 'open' : null;
      if (!command) return false;
      try {
        const child = spawnImpl(command, [parsed.toString()], { detached: true, stdio: 'ignore', windowsHide: true });
        child.unref();
        return true;
      } catch {
        return false;
      }
    },
  };
}