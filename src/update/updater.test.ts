import assert from "node:assert/strict";
import { readFile, rename, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { MockManifestServer } from "../../test/v0.4.0-update/mock-manifest-server.js";
import {
  createTestBundleTrust,
  createTestUpdateBundle,
  type TestUpdateBundle,
} from "../../test/v0.4.0-update/update-bundle-fixture.js";
import {
  createTestTufFixture,
  type TestTufFixture,
} from "../../test/v0.4.0-update/tuf-fixture.js";
import { loadActivationChain } from "./activation-record.js";
import { validateInstalledActivation } from "./activation.js";
import {
  consistentSnapshotArtifactPath,
  disposeHeldArtifact,
} from "./download.js";
import { UpdateError } from "./errors.js";
import { runEngineHealthCheck } from "./health.js";
import { inspectInstalledEngine } from "./installed.js";
import { UPDATE_PHASES, type UpdatePhase } from "./journal.js";
import {
  authenticateAndAppendMetadataCheckpoint,
  loadMetadataCheckpointChain,
} from "./metadata-checkpoint.js";
import { recoverInstallation } from "./recovery.js";
import { expectedArchivePaths } from "./schema.js";
import { loadUpdaterState } from "./state.js";
import { cleanupUpdateTransaction } from "./temporary.js";
import { runVerifiedUpdate, type VerifiedUpdatePolicy } from "./updater.js";

const NOW = Date.parse("2030-01-01T00:00:00Z");

test("full mocked-server update crosses all fifteen durable boundaries", async (context) => {
  const bundle = await remoteOnlyBundle(context);
  const server = await repositoryServer(context, bundle);
  const phases: UpdatePhase[] = [];

  const result = await runVerifiedUpdate({
    appDataDirectory: bundle.appData,
    policy: policyFor(bundle, server.origin),
    now: () => NOW,
    waitBeforeRetry: async () => undefined,
    httpsAgent: server.agent,
    afterTransition: ({ phase }) => {
      phases.push(phase);
    },
  });

  assert.equal(result.status, "updated");
  assert.equal(result.channel, "stable");
  assert.equal(result.releaseSequence, 1);
  assert.deepEqual(phases, UPDATE_PHASES);
  const state = await loadUpdaterState(bundle.appData);
  assert.equal(state?.record.maxAuthenticatedReleaseSequence, 1);
  assert.equal(state?.record.maxActivatedReleaseSequence, 1);
  assert.equal(state?.record.currentActivationGeneration, 1);
  const recovered = await recoverInstallation({
    appDataDirectory: bundle.appData,
    policy: bundle.activationPolicy,
    now: () => NOW,
  });
  assert.equal(recovered.status, "ready");
  assert.equal(recovered.active?.activation.record.releaseSequence, 1);
  await assertLaunchable(recovered.active!, bundle);
  assert.equal(
    server.requests.some(
      (request) =>
        request.headers.authorization !== undefined ||
        request.headers.cookie !== undefined,
    ),
    false,
  );
});

test("a second check authenticates metadata but does not redownload the active release", async (context) => {
  const bundle = await remoteOnlyBundle(context);
  const server = await repositoryServer(context, bundle);
  const options = {
    appDataDirectory: bundle.appData,
    policy: policyFor(bundle, server.origin),
    now: () => NOW,
    waitBeforeRetry: async () => undefined,
    httpsAgent: server.agent,
  };
  await runVerifiedUpdate(options);
  const phases: UpdatePhase[] = [];
  const second = await runVerifiedUpdate({
    ...options,
    afterTransition: ({ phase }) => {
      phases.push(phase);
    },
  });

  assert.equal(second.status, "already-current");
  assert.deepEqual(phases, [
    "check",
    "fetch-manifest",
    "authenticate-manifest",
    "select-artifact",
    "recover",
  ]);
  const artifactPath = consistentSnapshotArtifactPath(bundle.receipt.target);
  assert.equal(
    server.requests.filter((request) => request.url === artifactPath).length,
    1,
  );
});

test("wrong artifact bytes advance the authenticated floor but preserve a launchable current release", async (context) => {
  const trust = createTestBundleTrust();
  const first = await remoteOnlyBundle(context, { trust });
  const firstServer = await repositoryServer(context, first);
  await runVerifiedUpdate(updateOptions(first, firstServer));

  const second = await createTestUpdateBundle(context, {
    appData: first.appData,
    trust,
    channel: "beta",
    releaseSequence: 2,
  });
  await makeRemoteOnly(second);
  const corrupted = Buffer.from(second.archive);
  corrupted[Math.floor(corrupted.length / 2)] ^= 1;
  const secondServer = await repositoryServer(context, second, corrupted);

  await assert.rejects(
    runVerifiedUpdate({
      ...updateOptions(second, secondServer),
      requestedChannel: "beta",
    }),
    isUpdateError("GOAT_UPDATE_ARTIFACT_HASH_MISMATCH"),
  );

  const state = await loadUpdaterState(first.appData);
  assert.equal(state?.record.maxAuthenticatedReleaseSequence, 2);
  assert.equal(state?.record.maxActivatedReleaseSequence, 1);
  assert.equal(state?.record.configuredChannel, "stable");
  const chain = await loadActivationChain(
    first.appData,
    first.platform,
    first.architecture,
  );
  assert.equal(chain.records.length, 1);
  const active = await validateInstalledActivation(
    first.appData,
    chain.current!,
    first.activationPolicy,
  );
  await assertLaunchable(active, first);
});

test("authenticated revocations survive target-selection failure and block installed code plus replay", async (context) => {
  const trust = createTestBundleTrust();
  const first = await remoteOnlyBundle(context, { trust });
  const firstServer = await repositoryServer(context, first);
  await runVerifiedUpdate(updateOptions(first, firstServer));

  const revokedKeyIds = [trust.manifestSigner.keyId];
  const revokedArtifactSha256 = [first.receipt.target.sha256];
  const revokedReleaseSequences = [first.releaseSequence];
  const secondPlatform = oppositePlatform(first.platform);
  const secondMetadata = createTestTufFixture({
    keys: trust.tufKeys,
    metadataVersion: 2,
    platform: secondPlatform,
    architecture: first.architecture,
    contents: fixtureContents(secondPlatform),
    artifactLength: first.archive.byteLength,
    artifactSha256: "e".repeat(64),
    codeSigningIdentityId: first.receipt.target.custom.codeSigning.identityId,
    revokedKeyIds,
    revokedArtifactSha256,
    revokedReleaseSequences,
  });
  const secondServer = await metadataOnlyServer(context, secondMetadata);

  await assert.rejects(
    runVerifiedUpdate(updateOptions(first, secondServer)),
    isUpdateError("GOAT_UPDATE_TARGET_NOT_FOUND"),
  );

  const durableState = await loadUpdaterState(first.appData);
  assert.ok(durableState);
  assert.equal(durableState.record.metadataVersions.stable, 2);
  assert.equal(durableState.record.maxAuthenticatedReleaseSequence, 1);
  assert.equal(durableState.record.maxActivatedReleaseSequence, 1);
  assert.deepEqual(durableState.record.revokedKeyIds, revokedKeyIds);
  assert.deepEqual(
    durableState.record.revokedArtifactSha256,
    revokedArtifactSha256,
  );
  assert.deepEqual(
    durableState.record.revokedReleaseSequences,
    revokedReleaseSequences,
  );
  const checkpointBeforeReplay = await loadMetadataCheckpointChain(
    first.appData,
    first.receiptPolicy,
  );
  assert.equal(checkpointBeforeReplay.head.generation, 2);
  assert.equal(
    durableState.record.metadataCheckpointSha256,
    checkpointBeforeReplay.head.sha256,
  );

  await assert.rejects(
    inspectInstalledEngine(first.appData, first.activationPolicy),
    isUpdateError("GOAT_UPDATE_TARGET_NOT_FOUND"),
  );

  const replayMetadata = createTestTufFixture({
    keys: trust.tufKeys,
    metadataVersion: 1,
    platform: first.platform,
    architecture: first.architecture,
    contents: first.receipt.target.custom.contents,
    artifactLength: first.archive.byteLength,
    artifactSha256: first.receipt.target.sha256,
    codeSigningIdentityId: first.receipt.target.custom.codeSigning.identityId,
    revokedKeyIds,
    revokedArtifactSha256,
    revokedReleaseSequences,
  });
  await assert.rejects(
    authenticateAndAppendMetadataCheckpoint({
      appDataDirectory: first.appData,
      current: checkpointBeforeReplay,
      metadata: {
        sequentialRoots: [],
        timestamp: replayMetadata.timestamp,
        snapshot: replayMetadata.snapshot,
        targets: replayMetadata.targets,
        channel: replayMetadata.channels.stable,
        channelName: "stable",
      },
      policy: first.receiptPolicy,
      nowUnixMs: NOW,
    }),
    isUpdateError("GOAT_UPDATE_METADATA_REPLAYED"),
  );

  const checkpointAfterReplay = await loadMetadataCheckpointChain(
    first.appData,
    first.receiptPolicy,
  );
  assert.equal(
    checkpointAfterReplay.head.generation,
    checkpointBeforeReplay.head.generation,
  );
  assert.equal(
    checkpointAfterReplay.head.sha256,
    checkpointBeforeReplay.head.sha256,
  );
  const stateAfterReplay = await loadUpdaterState(first.appData);
  assert.equal(
    stateAfterReplay?.record.metadataCheckpointSha256,
    checkpointBeforeReplay.head.sha256,
  );
  assert.deepEqual(
    stateAfterReplay?.record.revokedReleaseSequences,
    revokedReleaseSequences,
  );

  // Reproduce the authenticated-checkpoint / pre-state-append crash without a
  // test-only production branch. Installed inspection must still consume the
  // one-ahead checkpoint and reject the revoked active engine.
  assert.ok(stateAfterReplay);
  await rm(stateAfterReplay.path);
  const stateOneCheckpointBehind = await loadUpdaterState(first.appData);
  assert.equal(
    stateOneCheckpointBehind?.record.metadataCheckpointGeneration,
    checkpointBeforeReplay.head.generation - 1,
  );
  assert.equal(
    stateOneCheckpointBehind?.record.metadataCheckpointSha256,
    checkpointBeforeReplay.current?.record.previousSha256,
  );
  await assert.rejects(
    inspectInstalledEngine(first.appData, first.activationPolicy),
    isUpdateError("GOAT_UPDATE_TARGET_NOT_FOUND"),
  );
});

test("a post-verification artifact pathname replacement cannot affect activated bytes", async (context) => {
  const bundle = await remoteOnlyBundle(context);
  const server = await repositoryServer(context, bundle);
  let heldPath = "";
  await runVerifiedUpdate({
    ...updateOptions(bundle, server),
    afterTransition: async ({ phase, transactionId }) => {
      if (phase !== "download-artifact") return;
      const transactionRoot = path.join(
        bundle.appData,
        "updates",
        "tmp",
        transactionId,
      );
      const entries = await import("node:fs/promises").then(({ readdir }) =>
        readdir(transactionRoot),
      );
      const partial = entries.find((entry) => entry.endsWith(".partial"));
      assert.ok(partial);
      const partialPath = path.join(transactionRoot, partial);
      heldPath = `${partialPath}.held-race`;
      await rename(partialPath, heldPath);
      await writeFile(partialPath, Buffer.alloc(bundle.archive.length, 0x41), {
        flag: "wx",
      });
    },
  });

  const chain = await loadActivationChain(
    bundle.appData,
    bundle.platform,
    bundle.architecture,
  );
  const active = await validateInstalledActivation(
    bundle.appData,
    chain.current!,
    bundle.activationPolicy,
  );
  const expectedExecutable = bundle.fileBytes.get(
    bundle.platform === "win32" ? "bin/goat-engine.exe" : "bin/goat-engine",
  )!;
  assert.deepEqual(
    await readFile(active.candidate.executablePath),
    expectedExecutable,
  );
  await rm(heldPath, { force: true });
});

async function remoteOnlyBundle(
  context: test.TestContext,
  options: Parameters<typeof createTestUpdateBundle>[1] = {},
): Promise<TestUpdateBundle> {
  const bundle = await createTestUpdateBundle(context, options);
  await makeRemoteOnly(bundle);
  return bundle;
}

async function makeRemoteOnly(bundle: TestUpdateBundle): Promise<void> {
  await disposeHeldArtifact(bundle.artifact);
  await cleanupUpdateTransaction(bundle.transaction);
  await rm(bundle.receipt.path, { force: true });
}

async function repositoryServer(
  context: test.TestContext,
  bundle: TestUpdateBundle,
  artifactBytes: Uint8Array = bundle.archive,
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
    artifactBytes,
  );
  await server.listen();
  context.after(() => server.close());
  return server;
}

async function metadataOnlyServer(
  context: test.TestContext,
  tuf: TestTufFixture,
): Promise<MockManifestServer> {
  const server = new MockManifestServer();
  server.bytes("/metadata/timestamp.json", tuf.timestamp);
  server.bytes("/metadata/snapshot.json", tuf.snapshot);
  server.bytes("/metadata/targets.json", tuf.targets);
  server.bytes("/metadata/stable.json", tuf.channels.stable);
  await server.listen();
  context.after(() => server.close());
  return server;
}

function policyFor(
  bundle: TestUpdateBundle,
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

function updateOptions(bundle: TestUpdateBundle, server: MockManifestServer) {
  return {
    appDataDirectory: bundle.appData,
    policy: policyFor(bundle, server.origin),
    now: () => NOW,
    waitBeforeRetry: async () => undefined,
    httpsAgent: server.agent,
  };
}

async function assertLaunchable(
  active: Awaited<ReturnType<typeof validateInstalledActivation>>,
  bundle: TestUpdateBundle,
): Promise<void> {
  await runEngineHealthCheck({
    executablePath: active.candidate.executablePath,
    expectedVersion: active.candidate.manifest.goatEngineVersion,
    platform: bundle.platform,
    runCommand: bundle.runHealthCommand,
  });
}

function fixtureContents(platform: TestUpdateBundle["platform"]) {
  return expectedArchivePaths(platform).map((entryPath, index) => ({
    path: entryPath,
    type: "regular-file" as const,
    length: 16,
    sha256: ((index + 1) % 10).toString(10).repeat(64),
    mode: entryPath.startsWith("bin/") ? (493 as const) : (420 as const),
  }));
}

function oppositePlatform(
  platform: TestUpdateBundle["platform"],
): TestUpdateBundle["platform"] {
  return platform === "win32" ? "darwin" : "win32";
}

function isUpdateError(code: UpdateError["code"]): (error: unknown) => boolean {
  return (error) => error instanceof UpdateError && error.code === code;
}
