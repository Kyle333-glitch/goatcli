import { spawn } from "node:child_process";
import path from "node:path";
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
  const normalized = trimTrailingSeparators(systemRoot ?? "");
  let windowsDirectory: string;
  if (normalized && /^[A-Za-z]:\\Windows$/i.test(normalized)) {
    windowsDirectory = normalized;
  } else {
    windowsDirectory = "C:\\Windows";
  }
  return path.win32.join(windowsDirectory, "explorer.exe");
}

function trimTrailingSeparators(value: string): string {
  let end = value.length;
  while (end > 0 && (value[end - 1] === "\\" || value[end - 1] === "/")) {
    end -= 1;
  }
  return value.slice(0, end);
}

const USER_CODE_PATTERN = /^[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$/;

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
    parsed.hash ||
    parsed.pathname !== "/auth/device"
  )
    return null;

  // Only a single, exactly-formed `?code=` user-code pre-fill is permitted.
  // The code is already printed to the user, so carrying it in the URL adds no
  // secrecy loss; any other query parameter is rejected so the opener can never
  // be directed anywhere other than the canonical device page.
  const params = [...parsed.searchParams.entries()];
  if (params.length > 1) return null;
  if (params.length === 1) {
    const [name, code] = params[0];
    if (name !== "code" || !USER_CODE_PATTERN.test(code)) return null;
  }

  if (parsed.origin === "null") return null;
  const candidateOrigin = new URL(parsed.origin);
  if (!isAllowedControlPlaneUrl(candidateOrigin)) return null;

  try {
    const canonical = canonicalDeviceAuthorizationUrl(
      expectedOrigin ?? candidateOrigin,
    );
    const withoutQuery = new URL(parsed.toString());
    withoutQuery.search = "";
    return withoutQuery.toString() === canonical ? parsed.toString() : null;
  } catch {
    return null;
  }
}
