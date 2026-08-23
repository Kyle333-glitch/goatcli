import assert from "node:assert/strict";
import path from "node:path";
import { launchEngine } from "../../src/engine/launch.js";
import { engineManifestTrustPolicy } from "../../src/privacy/release-policy.js";

if (process.platform !== "win32") {
  throw new Error("The cross-repository native launcher runs only on Windows.");
}

const executablePath = path.resolve(process.argv[2] ?? "");
if (!path.win32.isAbsolute(executablePath)) {
  throw new Error("A compiled engine responder path is required.");
}

const commands = [
  ["privacy", "telemetry", "delete-remote"],
  ["privacy", "diagnostics", "preview"],
  ["privacy", "diagnostics", "submit"],
  ["privacy", "diagnostics", "delete", "0192ec6c-0d58-7a49-9f5f-4e50bc72a769"],
] as const;

for (const args of commands) {
  const authenticated =
    args[1] === "telemetry" || args[2] === "submit" || args[2] === "delete";
  const result = await launchEngine({
    launcherVersion: "0.4.0",
    args,
    cwd: process.cwd(),
    resolvedEngine: {
      executablePath,
      manifestPath: null,
      source: "development",
      releaseChannel: "dev",
      platform: "win32",
      architecture: process.arch === "arm64" ? "arm64" : "x64",
      developmentOverride: true,
    },
    trustPolicy: {
      ...engineManifestTrustPolicy(),
      allowUnsignedDevelopment: true,
    },
    privacyCredential: authenticated
      ? {
          accessToken: new TextEncoder().encode("A".repeat(43)),
          expiresAtUnixMs: Date.now() + 60_000,
        }
      : undefined,
  });
  assert.deepEqual(result, { exitCode: 0, signal: null });
}

console.log("Native Windows GOATIPC1 cross-repository coverage passed.");
