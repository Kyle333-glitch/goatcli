import { spawn } from "node:child_process";
import type { BrowserOpener } from "./types.js";
import {
  canonicalDeviceAuthorizationUrl,
  isAllowedControlPlaneUrl,
} from "./client.js";

export interface SpawnLike {
  (
    command: string,
    args: readonly string[],
    options: { detached: boolean; stdio: "ignore"; windowsHide: boolean },
  ): { unref(): void };
}

export function createBrowserOpener(
  platform: NodeJS.Platform = process.platform,
  spawnImpl: SpawnLike = spawn,
  expectedOrigin?: URL,
  systemRoot: string | undefined = process.env.SystemRoot,
): BrowserOpener {
  return {
    async open(value) {
      const canonicalUrl = canonicalBrowserUrl(value, expectedOrigin);
      if (!canonicalUrl) return false;

      const command =
        platform === "win32"
          ? windowsExplorerPath(systemRoot)
          : platform === "darwin"
            ? "/usr/bin/open"
            : null;
      if (!command) return false;

      try {
        const child = spawnImpl(command, [canonicalUrl], {
          detached: true,
          stdio: "ignore",
          windowsHide: true,
        });
        child.unref();
        return true;
      } catch {
        return false;
      }
    },
  };
}

function windowsExplorerPath(systemRoot: string | undefined): string {
  const normalized = systemRoot?.replace(/[\\/]+$/, "");
  const windowsDirectory =
    normalized && /^[A-Za-z]:\\Windows$/i.test(normalized)
      ? normalized
      : "C:\\Windows";
  return `${windowsDirectory}\\explorer.exe`;
}

function canonicalBrowserUrl(
  value: string,
  expectedOrigin?: URL,
): string | null {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return null;
  }
  if (
    parsed.username ||
    parsed.password ||
    parsed.search ||
    parsed.hash ||
    parsed.pathname !== "/auth/device"
  )
    return null;

  const candidateOrigin = new URL(parsed.origin);
  if (!isAllowedControlPlaneUrl(candidateOrigin)) return null;

  try {
    const canonical = canonicalDeviceAuthorizationUrl(
      expectedOrigin ?? candidateOrigin,
    );
    return parsed.toString() === canonical ? canonical : null;
  } catch {
    return null;
  }
}
