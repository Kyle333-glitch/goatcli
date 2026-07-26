import { readFileSync } from "fs";
import path from "path";
import { fileURLToPath } from "url";
import type { LauncherVersion } from "./engine/contract.js";

export const FALLBACK_LAUNCHER_VERSION: LauncherVersion = "0.3.2";
export const ENGINE_CONTRACT_VERSION: LauncherVersion = "0.0.6";

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
