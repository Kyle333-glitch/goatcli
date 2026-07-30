import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import type { ActivationSecurityPolicy } from "./activation.js";
import { validateInstalledActivation } from "./activation.js";
import { loadActivationChain } from "./activation-record.js";
import type { ApprovedCodeSigningIdentity } from "./code-signing.js";
import { UPDATE_PHASES } from "./journal.js";
import { acquireUpdateLock } from "./lock.js";
import { recoverInstallation } from "./recovery.js";
import { loadUpdaterState } from "./state.js";

interface SerializedCrashPolicy {
  readonly schema: 1;
  readonly platform: "win32" | "darwin";
  readonly architecture: "x64" | "arm64";
  readonly root: string;
  readonly rootSha256: string;
  readonly releasePolicyDigest: string;
  readonly engineManifestKeyIds: readonly string[];
  readonly approvedCodeSigningIdentities: readonly ApprovedCodeSigningIdentity[];
}

for (const [index, phase] of UPDATE_PHASES.entries()) {
  test(`killAtTransition${String(index + 1).padStart(2, "0")}KeepsCompleteOldOrNewInstallation`, async (context) => {
    const appData = await mkdtemp(
      path.join(os.tmpdir(), `goat-kill-${index + 1}-`),
    );
    context.after(() => rm(appData, { recursive: true, force: true }));
    const child = await runCrashWorker(appData, phase);
    assert.equal(
      child.code,
      91,
      `worker stderr: ${child.stderr.slice(0, 2_000)}`,
    );
    const serialized = JSON.parse(
      await readFile(path.join(appData, "test-only-crash-policy.json"), "utf8"),
    ) as SerializedCrashPolicy;
    const policy = activationPolicy(serialized);
    let recovered: Awaited<ReturnType<typeof recoverInstallation>> | undefined;
    const lock = await acquireUpdateLock(appData, {
      isProcessAlive: () => false,
      recoverStaleTransaction: async () => {
        recovered = await recoverInstallation({
          appDataDirectory: appData,
          policy,
          now: () => Date.parse("2030-01-01T00:00:01Z"),
        });
      },
    });
    try {
      recovered ??= await recoverInstallation({
        appDataDirectory: appData,
        policy,
        now: () => Date.parse("2030-01-01T00:00:01Z"),
      });
    } finally {
      await lock.release();
    }

    const expectsNew = index + 1 >= 13;
    assert.equal(
      recovered.active?.activation.record.releaseSequence,
      expectsNew ? 2 : 1,
    );
    assert.equal(
      recovered.active?.activation.record.channel,
      expectsNew ? "beta" : "stable",
    );
    const state = await loadUpdaterState(appData);
    assert.equal(
      state?.record.maxAuthenticatedReleaseSequence,
      index + 1 >= 5 ? 2 : 1,
    );
    assert.equal(state?.record.maxActivatedReleaseSequence, expectsNew ? 2 : 1);
    const chain = await loadActivationChain(
      appData,
      serialized.platform,
      serialized.architecture,
    );
    assert.equal(chain.records.length, expectsNew ? 2 : 1);
    assert.ok(chain.current);
    await validateInstalledActivation(appData, chain.current, policy);
    assert.equal(
      await countReleaseSlots(
        appData,
        serialized.platform,
        serialized.architecture,
      ),
      expectsNew ? 2 : 1,
    );
  });
}

async function runCrashWorker(
  appData: string,
  phase: string,
): Promise<{ readonly code: number | null; readonly stderr: string }> {
  const worker = path.resolve(
    "test",
    "v0.4.0-update",
    "update-crash-worker.ts",
  );
  const child = spawn(
    process.execPath,
    ["--import", "tsx", worker, appData, phase],
    {
      cwd: process.cwd(),
      windowsHide: true,
      stdio: ["ignore", "ignore", "pipe"],
    },
  );
  let stderr = "";
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk: string) => {
    if (stderr.length < 16 * 1024) stderr += chunk;
  });
  const code = await new Promise<number | null>((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", resolve);
  });
  return { code, stderr };
}

function activationPolicy(
  serialized: SerializedCrashPolicy,
): ActivationSecurityPolicy {
  const root = Buffer.from(serialized.root, "base64");
  return {
    receipt: {
      embeddedRootBytes: root,
      embeddedRootSha256: serialized.rootSha256,
      launcherVersion: "0.4.0",
      platform: serialized.platform,
      architecture: serialized.architecture,
    },
    compatibility: {
      launcherVersion: "0.4.0",
      releasePolicyDigest: serialized.releasePolicyDigest,
      engineManifestKeyIds: serialized.engineManifestKeyIds,
      revokedKeyIds: [],
      platform: serialized.platform,
      architecture: serialized.architecture,
    },
    approvedCodeSigningIdentities: serialized.approvedCodeSigningIdentities,
    runSigningCommand: (command) => {
      if (serialized.platform === "win32") {
        return {
          status: 0,
          stdout: JSON.stringify({
            status: "Valid",
            certificateSha256: "a".repeat(64),
          }),
          stderr: "",
        };
      }
      if (command === "/usr/bin/codesign") {
        return {
          status: 0,
          stdout: "",
          stderr: [
            "Authority=Developer ID Application: GOAT Test (TEST123456)",
            "Authority=Developer ID Certification Authority",
            "TeamIdentifier=TEST123456",
          ].join("\n"),
        };
      }
      return { status: 0, stdout: "", stderr: "" };
    },
  };
}

async function countReleaseSlots(
  appData: string,
  platform: "win32" | "darwin",
  architecture: "x64" | "arm64",
): Promise<number> {
  let count = 0;
  for (const channel of ["stable", "beta", "development"]) {
    const root = path.join(
      appData,
      "engines",
      channel,
      `${platform}-${architecture}`,
      "releases",
    );
    try {
      count += (await readdir(root)).length;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
  }
  return count;
}
