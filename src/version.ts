import { readFileSync } from "fs";
import path from "path";
import { fileURLToPath } from "url";
import type { LauncherVersion } from "./engine/contract.js";

export const FALLBACK_LAUNCHER_VERSION: LauncherVersion = "0.4.0";
export const GOAT_PRODUCT_VERSION = "0.4.0" as const;
export const GOAT_ENGINE_VERSION = "0.4.0" as const;
export const OPENCODE_BASELINE_VERSION = "1.17.11" as const;
export const ENGINE_CONTRACT_VERSION: LauncherVersion = "0.0.6";
export const PRIVACY_ACTIVATION_PROTOCOL = "GOATIPC2" as const;
export const AUTHENTICATED_FRAME_PROTOCOL = "GOATIPC1" as const;

export function getLauncherVersion(): LauncherVersion {
  const filename = fileURLToPath(import.meta.url);
  const dirname = path.dirname(filename);

  try {
    const packageJsonPath = path.resolve(dirname, "../package.json");
    const pkg = JSON.parse(readFileSync(packageJsonPath, "utf8")) as {
      version?: unknown;
    };
    return typeof pkg.version === "string"
      ? pkg.version
      : FALLBACK_LAUNCHER_VERSION;
  } catch {
    return FALLBACK_LAUNCHER_VERSION;
  }
}

export function getEngineContractVersion(): LauncherVersion {
  return ENGINE_CONTRACT_VERSION;
}
