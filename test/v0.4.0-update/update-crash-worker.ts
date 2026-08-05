/**
 * TEST-ONLY native updater crash worker.
 *
 * The parent test starts this process and expects it to terminate itself at one
 * exact durable transition. No failure-injection switch is exposed by the
 * production CLI.
 */
import { lstat, realpath, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import type test from "node:test";
import {
  createTestBundleTrust,
  createTestUpdateBundle,
  type TestUpdateBundle,
} from "./update-bundle-fixture.js";
import { MockManifestServer } from "./mock-manifest-server.js";
import {
  consistentSnapshotArtifactPath,
  disposeHeldArtifact,
} from "../../src/update/download.js";
import { UPDATE_PHASES, type UpdatePhase } from "../../src/update/journal.js";
import { cleanupUpdateTransaction } from "../../src/update/temporary.js";
import {
  runVerifiedUpdate,
  type VerifiedUpdatePolicy,
} from "../../src/update/updater.js";

const killPhase = process.argv[2] as UpdatePhase | undefined;
if (!killPhase || !UPDATE_PHASES.includes(killPhase)) {
  process.exit(64);
}
// The parent test supplies the already-created app-data directory as the
// process working directory, not as attacker-controlled CLI data. Validate the
// OS-provided cwd before using it for any test fixture writes.
const appData = await validatedAppDataPath(process.cwd());
if (appData === null) {
  process.exit(64);
}
const context = {
  after() {},
} as unknown as test.TestContext;
const trust = createTestBundleTrust();
const first = await createTestUpdateBundle(context, {
  appData,
  trust,
  channel: "stable",
  releaseSequence: 1,
});
await makeRemoteOnly(first);
const firstServer = await repositoryServer(first);
await runVerifiedUpdate(updateOptions(first, firstServer));
await firstServer.close();

const second = await createTestUpdateBundle(context, {
  appData,
  trust,
  channel: "beta",
  releaseSequence: 2,
});
await makeRemoteOnly(second);
await writeFile(
  path.join(appData, "test-only-crash-policy.json"),
  JSON.stringify({
    schema: 1,
    platform: second.platform,
    architecture: second.architecture,
    root: second.tuf.root.toString("base64"),
    rootSha256: second.tuf.rootSha256,
    releasePolicyDigest: second.compatibilityPolicy.releasePolicyDigest,
    engineManifestKeyIds: second.compatibilityPolicy.engineManifestKeyIds,
    approvedCodeSigningIdentities: second.approvedCodeSigningIdentities,
  }),
  { flag: "wx", mode: 0o600 },
);
const secondServer = await repositoryServer(second);
await runVerifiedUpdate({
  ...updateOptions(second, secondServer),
  requestedChannel: "beta",
  afterTransition: ({ phase }) => {
    if (phase === killPhase) process.exit(91);
  },
});
process.exit(65);

async function makeRemoteOnly(bundle: TestUpdateBundle): Promise<void> {
  await disposeHeldArtifact(bundle.artifact);
  await cleanupUpdateTransaction(bundle.transaction);
  await import("node:fs/promises").then(({ rm }) =>
    rm(bundle.receipt.path, { force: true }),
  );
}

async function repositoryServer(
  bundle: TestUpdateBundle,
): Promise<MockManifestServer> {
  const server = new MockManifestServer();
  server.bytes("/metadata/timestamp.json", bundle.tuf.timestamp);
  server.bytes("/metadata/snapshot.json", bundle.tuf.snapshot);
  server.bytes("/metadata/targets.json", bundle.tuf.targets);
  server.bytes(
    `/metadata/${bundle.channel}.json`,
    bundle.tuf.channels[bundle.channel],
  );
  server.bytes(
    consistentSnapshotArtifactPath(bundle.receipt.target),
    bundle.archive,
  );
  await server.listen();
  return server;
}

async function validatedAppDataPath(rawPath: string): Promise<string | null> {
  try {
    const lexical = path.resolve(rawPath);
    const tmpRoot = await realpath(os.tmpdir());
    const [rawStats, canonical] = await Promise.all([
      lstat(lexical),
      realpath(lexical),
    ]);
    const canonicalStats = await lstat(canonical);
    const relative = path.relative(tmpRoot, canonical);
    const basename = path.basename(canonical);
    if (
      !rawStats.isDirectory() ||
      rawStats.isSymbolicLink() ||
      !canonicalStats.isDirectory() ||
      canonicalStats.isSymbolicLink() ||
      rawStats.dev !== canonicalStats.dev ||
      rawStats.ino !== canonicalStats.ino ||
      !/^goat-kill-[0-9]+-[A-Za-z0-9]+$/.test(basename) ||
      relative.length === 0 ||
      path.isAbsolute(relative) ||
      relative === ".." ||
      relative.startsWith(`..${path.sep}`) ||
      relative.includes(path.sep)
    ) {
      return null;
    }
    return canonical;
  } catch {
    return null;
  }
}

function updateOptions(bundle: TestUpdateBundle, server: MockManifestServer) {
  return {
    appDataDirectory: bundle.appData,
    policy: {
      launcherVersion: "0.4.0",
      platform: bundle.platform,
      architecture: bundle.architecture,
      metadataOrigin: server.origin,
      artifactOrigin: server.origin,
      embeddedRootBytes: bundle.tuf.root,
      embeddedRootSha256: bundle.tuf.rootSha256,
      activation: bundle.activationPolicy,
    } satisfies VerifiedUpdatePolicy,
    now: () => Date.parse("2030-01-01T00:00:00Z"),
    waitBeforeRetry: async () => undefined,
    httpsAgent: server.agent,
  };
}
