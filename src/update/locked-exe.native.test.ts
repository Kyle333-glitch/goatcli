import { spawnSync } from "node:child_process";
import { closeSync, openSync } from "node:fs";
import { mkdtemp, realpath, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import assert from "node:assert/strict";
import {
  createTestBundleTrust,
  createTestUpdateBundle,
} from "../../test/v0.4.0-update/update-bundle-fixture.js";
import { MockManifestServer } from "../../test/v0.4.0-update/mock-manifest-server.js";
import { consistentSnapshotArtifactPath } from "./download.js";
import { loadActivationChain } from "./activation-record.js";
import { cleanupUpdateTransaction } from "./temporary.js";
import { runVerifiedUpdate } from "./updater.js";
import type { VerifiedUpdatePolicy } from "./updater.js";

const SOURCE = fileURLToPath(
  new URL(
    "../../test/v0.4.0-update/fixtures/fixture-engine.c",
    import.meta.url,
  ),
);

function findCompiler():
  | {
      command: string;
      args: (output: string, source: string) => readonly string[];
    }
  | undefined {
  for (const compiler of [
    {
      command: "gcc",
      args: (output: string, source: string) => [source, "-o", output],
    },
    {
      command: "cc",
      args: (output: string, source: string) => [source, "-o", output],
    },
    {
      command: "cl",
      args: (output: string, source: string) => [source, `/Fe:${output}`],
    },
  ]) {
    const result = spawnSync(compiler.command, ["--version"], {
      shell: false,
      windowsHide: true,
      timeout: 5000,
    });
    if (!result.error && !result.signal && result.status === 0) return compiler;
  }
  return undefined;
}

function compileFixture(
  compiler: {
    command: string;
    args: (output: string, source: string) => readonly string[];
  },
  outputDirectory: string,
): string {
  const binaryName =
    process.platform === "win32" ? "fixture-engine.exe" : "fixture-engine";
  const outputPath = path.join(outputDirectory, binaryName);
  const result = spawnSync(
    compiler.command,
    [...compiler.args(outputPath, SOURCE)],
    {
      shell: false,
      windowsHide: true,
      encoding: "utf8",
      timeout: 30000,
    },
  );
  if (result.status !== 0) {
    throw new Error(
      `fixture engine compilation failed: ${result.stderr ?? result.error?.message ?? compiler.command}`,
    );
  }
  return outputPath;
}

test("Windows locked active executable preserves existing installation and defers cleanup", async (context) => {
  if (process.platform !== "win32") {
    context.skip("locked-executable test runs only on Windows");
    return;
  }
  const compiler = findCompiler();
  if (!compiler) {
    context.skip("no C compiler available for native fixture engine");
    return;
  }

  const trust = createTestBundleTrust();
  const first = await createTestUpdateBundle(context, {
    trust,
    channel: "stable",
    releaseSequence: 1,
    productVersion: "0.4.1",
    executableBytes: Buffer.from("v1"),
  });
  await cleanupUpdateTransaction(first.transaction);
  const firstServer = new MockManifestServer();
  firstServer.bytes("/metadata/timestamp.json", first.tuf.timestamp);
  firstServer.bytes("/metadata/snapshot.json", first.tuf.snapshot);
  firstServer.bytes("/metadata/targets.json", first.tuf.targets);
  firstServer.bytes("/metadata/stable.json", first.tuf.channels.stable);
  firstServer.bytes(
    consistentSnapshotArtifactPath(first.receipt.target),
    first.archive,
  );
  await firstServer.listen();
  context.after(() => firstServer.close());

  await runVerifiedUpdate({
    appDataDirectory: first.appData,
    policy: policyFor(first, firstServer.origin),
    now: () => Date.parse("2030-01-01T00:00:00Z"),
    waitBeforeRetry: async () => undefined,
    httpsAgent: firstServer.agent,
  });

  const chain1 = await loadActivationChain(
    first.appData,
    first.platform,
    first.architecture,
  );
  const activeRecord1 = chain1.current!;
  const activeSlot = path.join(
    first.appData,
    "engines",
    "stable",
    `${first.platform}-${first.architecture}`,
    "releases",
    activeRecord1.record.slotName,
  );
  const activeExe = path.join(
    activeSlot,
    ...first.engineManifest.executablePath.split("/"),
  );

  const handle = openSync(activeExe, "r");
  try {
    const second = await createTestUpdateBundle(context, {
      trust,
      appData: first.appData,
      channel: "stable",
      releaseSequence: 2,
      productVersion: "0.4.2",
      executableBytes: Buffer.from("v2"),
      persistReceipt: false,
    });
    await cleanupUpdateTransaction(second.transaction);
    const secondServer = new MockManifestServer();
    secondServer.bytes("/metadata/timestamp.json", second.tuf.timestamp);
    secondServer.bytes("/metadata/snapshot.json", second.tuf.snapshot);
    secondServer.bytes("/metadata/targets.json", second.tuf.targets);
    secondServer.bytes("/metadata/stable.json", second.tuf.channels.stable);
    secondServer.bytes(
      consistentSnapshotArtifactPath(second.receipt.target),
      second.archive,
    );
    await secondServer.listen();
    context.after(() => secondServer.close());

    const result2 = await runVerifiedUpdate({
      appDataDirectory: second.appData,
      policy: policyFor(second, secondServer.origin),
      now: () => Date.parse("2030-01-01T00:00:00Z"),
      waitBeforeRetry: async () => undefined,
      httpsAgent: secondServer.agent,
    });

    assert.equal(result2.status, "updated");
    assert.equal(result2.releaseSequence, 2);

    // The previous activation is always preserved for rollback, so a second
    // update leaves Release 1 in the keep set. Run a third update so Release 1
    // becomes truly superseded; while the handle keeps its executable locked,
    // cleanup defers removal.
    const third = await createTestUpdateBundle(context, {
      trust,
      appData: first.appData,
      channel: "stable",
      releaseSequence: 3,
      productVersion: "0.4.3",
      executableBytes: Buffer.from("v3"),
      persistReceipt: false,
    });
    await cleanupUpdateTransaction(third.transaction);
    const thirdServer = new MockManifestServer();
    thirdServer.bytes("/metadata/timestamp.json", third.tuf.timestamp);
    thirdServer.bytes("/metadata/snapshot.json", third.tuf.snapshot);
    thirdServer.bytes("/metadata/targets.json", third.tuf.targets);
    thirdServer.bytes("/metadata/stable.json", third.tuf.channels.stable);
    thirdServer.bytes(
      consistentSnapshotArtifactPath(third.receipt.target),
      third.archive,
    );
    await thirdServer.listen();
    context.after(() => thirdServer.close());

    const result3 = await runVerifiedUpdate({
      appDataDirectory: third.appData,
      policy: policyFor(third, thirdServer.origin),
      now: () => Date.parse("2030-01-01T00:00:00Z"),
      waitBeforeRetry: async () => undefined,
      httpsAgent: thirdServer.agent,
    });

    assert.equal(result3.status, "updated");
    assert.equal(result3.releaseSequence, 3);
    assert.ok(result3.deferredCleanupPaths.length > 0);
    assert.ok(
      result3.deferredCleanupPaths.some(
        (p) => path.resolve(p) === path.resolve(activeSlot),
      ),
    );
  } finally {
    closeSync(handle);
  }
});

function policyFor(
  bundle: Awaited<ReturnType<typeof createTestUpdateBundle>>,
  origin: string,
): VerifiedUpdatePolicy {
  return {
    launcherVersion: "0.4.0",
    platform: bundle.platform,
    architecture: bundle.architecture,
    metadataOrigin: origin,
    artifactOrigin: origin,
    embeddedRootBytes: bundle.tuf.root,
    embeddedRootSha256: bundle.tuf.rootSha256,
    activation: bundle.activationPolicy,
  };
}
