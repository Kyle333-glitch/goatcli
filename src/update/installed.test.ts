import assert from "node:assert/strict";
import type { ChildProcess } from "node:child_process";
import { EventEmitter } from "node:events";
import test from "node:test";
import {
  createTestBundleTrust,
  createTestUpdateBundle,
  type TestUpdateBundle,
} from "../../test/v0.4.0-update/update-bundle-fixture.js";
import { runVersionCommand } from "../commands/version.js";
import {
  launchEngine,
  type ProcessLike,
  type SpawnEngine,
} from "../engine/launch.js";
import { activateCandidate } from "./activation.js";
import { inspectInstalledEngine } from "./installed.js";
import { recoverInstallation } from "./recovery.js";

test("installed inspection reports authenticated identity and rollback readiness", async (context) => {
  const fixture = await installedPair(context);
  const inspected = await inspectInstalledEngine(
    fixture.first.appData,
    fixture.second.activationPolicy,
  );
  assert.ok(inspected);
  assert.equal(inspected.active.activation.record.releaseSequence, 2);
  assert.equal(inspected.active.activation.record.channel, "beta");
  assert.equal(inspected.rollbackReady, true);
  assert.equal(inspected.rootSigningKeyIds.length, 2);
  assert.equal(inspected.targetSigningKeyIds.length, 2);

  let report = "";
  await runVersionCommand({
    launcherVersion: "0.4.0",
    platform: fixture.second.platform,
    architecture: fixture.second.architecture,
    appDataDirectory: fixture.first.appData,
    policy: {
      launcherVersion: "0.4.0",
      platform: fixture.second.platform,
      architecture: fixture.second.architecture,
      metadataOrigin: "https://updates.example.invalid",
      artifactOrigin: "https://artifacts.example.invalid",
      embeddedRootBytes: fixture.second.tuf.root,
      embeddedRootSha256: fixture.second.tuf.rootSha256,
      activation: fixture.second.activationPolicy,
    },
    stdout: {
      write(value: string | Uint8Array) {
        report += value.toString();
        return true;
      },
    },
  });
  assert.match(report, /^GOAT engine: 0\.4\.0-beta\.2$/m);
  assert.match(report, /^Configured channel: beta$/m);
  assert.match(report, /^Release sequence: 2$/m);
  assert.match(report, /^Integrity: verified$/m);
  assert.match(report, /^Rollback: ready$/m);
});

test("launcher resolves and spawns the committed v0.4 slot without schema-1 reinterpretation", async (context) => {
  const fixture = await installedPair(context);
  const child = new FakeChild();
  const processLike = new FakeProcess(
    fixture.second.platform,
    fixture.second.architecture,
    fixture.first.appData,
  );
  let command = "";
  let forwarded: readonly string[] = [];
  const spawnEngine: SpawnEngine = (candidate, args) => {
    command = candidate;
    forwarded = args;
    queueMicrotask(() => child.emit("exit", 0, null));
    return child as unknown as ChildProcess;
  };

  const result = await launchEngine({
    args: ["--help"],
    launcherVersion: "0.0.6",
    appDataDir: fixture.first.appData,
    platform: fixture.second.platform,
    architecture: fixture.second.architecture,
    installedUpdatePolicy: fixture.second.activationPolicy,
    spawnEngine,
    processLike,
    nodeVersion: "24.16.0",
  });

  assert.deepEqual(result, { exitCode: 0, signal: null });
  assert.equal(
    command,
    (
      await inspectInstalledEngine(
        fixture.first.appData,
        fixture.second.activationPolicy,
      )
    )?.active.candidate.executablePath,
  );
  assert.deepEqual(forwarded, ["--help"]);
});

async function installedPair(context: test.TestContext): Promise<{
  readonly first: TestUpdateBundle;
  readonly second: TestUpdateBundle;
}> {
  const trust = createTestBundleTrust();
  const first = await createTestUpdateBundle(context, {
    trust,
    channel: "stable",
    releaseSequence: 1,
  });
  await activateCandidate({
    appDataDirectory: first.appData,
    staged: first.staged,
    receiptSha256: first.receipt.receiptSha256,
    policy: first.activationPolicy,
  });
  const second = await createTestUpdateBundle(context, {
    appData: first.appData,
    trust,
    channel: "beta",
    releaseSequence: 2,
  });
  await activateCandidate({
    appDataDirectory: second.appData,
    staged: second.staged,
    receiptSha256: second.receipt.receiptSha256,
    policy: second.activationPolicy,
  });
  await recoverInstallation({
    appDataDirectory: first.appData,
    policy: second.activationPolicy,
    now: () => Date.parse("2030-01-01T00:00:00Z"),
  });
  return { first, second };
}

class FakeChild extends EventEmitter {
  kill(): boolean {
    return true;
  }
}

class FakeProcess extends EventEmitter implements ProcessLike {
  readonly env: NodeJS.ProcessEnv = {};
  readonly pid = 4_001;

  constructor(
    readonly platform: NodeJS.Platform,
    readonly arch: string,
    private readonly cwdValue: string,
  ) {
    super();
  }

  cwd(): string {
    return this.cwdValue;
  }
}
