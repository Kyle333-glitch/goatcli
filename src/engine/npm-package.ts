import { createRequire } from "node:module";
import path from "node:path";
import type { GoatArchitecture, GoatPlatform } from "./contract.js";
import { getEngineExecutableName } from "../platform.js";

const packageRequire = createRequire(import.meta.url);

const ENGINE_PACKAGE_NAMES: Record<
  GoatPlatform,
  Record<GoatArchitecture, string>
> = {
  win32: {
    x64: "goat-engine-windows-x64",
    arm64: "goat-engine-windows-arm64",
  },
  darwin: {
    x64: "goat-engine-darwin-x64",
    arm64: "goat-engine-darwin-arm64",
  },
};

export function getEnginePackageName(
  platform: GoatPlatform,
  architecture: GoatArchitecture,
): string {
  return ENGINE_PACKAGE_NAMES[platform][architecture];
}

export interface NpmEnginePackageResolution {
  readonly packageName: string;
  readonly packageRoot: string;
  readonly executablePath: string;
  readonly manifestPath: string;
}

/**
 * Finds the engine package installed by npm next to the launcher. Package
 * resolution is intentionally static and package-name based: no environment
 * variable or user-provided path can select the executable.
 */
export function resolveNpmEnginePackage(
  platform: GoatPlatform,
  architecture: GoatArchitecture,
): NpmEnginePackageResolution | null {
  const packageName = getEnginePackageName(platform, architecture);
  try {
    const packageJsonPath = packageRequire.resolve(
      `${packageName}/package.json`,
    );
    const packageRoot = path.dirname(packageJsonPath);
    return {
      packageName,
      packageRoot,
      executablePath: path.join(
        packageRoot,
        "bin",
        getEngineExecutableName(platform),
      ),
      manifestPath: path.join(packageRoot, "goat-engine.json"),
    };
  } catch {
    return null;
  }
}
