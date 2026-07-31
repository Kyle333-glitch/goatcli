import assert from "node:assert/strict";
import test from "node:test";
import {
  createTestBundleTrust,
  createTestUpdateBundle,
} from "../../test/v0.4.0-update/update-bundle-fixture.js";
import { MockManifestServer } from "../../test/v0.4.0-update/mock-manifest-server.js";
import {
  consistentSnapshotArtifactPath,
  disposeHeldArtifact,
} from "./download.js";
import { UpdateError } from "./errors.js";
import { loadUpdaterState } from "./state.js";
import { rm } from "node:fs/promises";
import { cleanupUpdateTransaction } from "./temporary.js";
import { runVerifiedUpdate } from "./updater.js";
import type { VerifiedUpdatePolicy } from "./updater.js";

const NOW = Date.parse("2030-01-01T00:00:00Z");

async function makeRemoteOnly(
  bundle: Awaited<ReturnType<typeof createTestUpdateBundle>>,
): Promise<void> {
  await rm(bundle.receipt.path, { force: true });
  await disposeHeldArtifact(bundle.artifact);
  await cleanupUpdateTransaction(bundle.transaction);
}

async function repositoryServer(
  context: test.TestContext,
  bundle: Awaited<ReturnType<typeof createTestUpdateBundle>>,
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
  context.after(() => server.close());
  return server;
}

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

for (const channel of ["beta", "development"] as const) {
  test(`full ${channel} update authenticates and activates`, async (context) => {
    const trust = createTestBundleTrust();
    const bundle = await createTestUpdateBundle(context, {
      trust,
      channel,
      releaseSequence: 1,
    });
    await makeRemoteOnly(bundle);
    const server = await repositoryServer(context, bundle);
    const result = await runVerifiedUpdate({
      appDataDirectory: bundle.appData,
      policy: policyFor(bundle, server.origin),
      requestedChannel: channel,
      now: () => NOW,
      waitBeforeRetry: async () => undefined,
      httpsAgent: server.agent,
    });
    assert.equal(result.status, "updated");
    assert.equal(result.channel, channel);
    const state = await loadUpdaterState(bundle.appData);
    assert.equal(state?.record.configuredChannel, channel);
    assert.equal(state?.record.maxActivatedReleaseSequence, 1);
  });
}

test("channel is bound through policy and activation record", async (context) => {
  const trust = createTestBundleTrust();
  const bundle = await createTestUpdateBundle(context, {
    trust,
    channel: "beta",
    releaseSequence: 1,
  });
  await makeRemoteOnly(bundle);
  const server = await repositoryServer(context, bundle);
  const result = await runVerifiedUpdate({
    appDataDirectory: bundle.appData,
    policy: policyFor(bundle, server.origin),
    requestedChannel: "beta",
    now: () => NOW,
    waitBeforeRetry: async () => undefined,
    httpsAgent: server.agent,
  });
  assert.equal(result.channel, "beta");
  const state = await loadUpdaterState(bundle.appData);
  assert.equal(state?.record.configuredChannel, "beta");
});

test("switching channel updates configured channel and floor", async (context) => {
  const trust = createTestBundleTrust();
  const stable = await createTestUpdateBundle(context, {
    trust,
    channel: "stable",
    releaseSequence: 1,
  });
  await makeRemoteOnly(stable);
  const stableServer = await repositoryServer(context, stable);
  await runVerifiedUpdate({
    appDataDirectory: stable.appData,
    policy: policyFor(stable, stableServer.origin),
    requestedChannel: "stable",
    now: () => NOW,
    waitBeforeRetry: async () => undefined,
    httpsAgent: stableServer.agent,
  });

  const beta = await createTestUpdateBundle(context, {
    trust,
    appData: stable.appData,
    channel: "beta",
    releaseSequence: 2,
  });
  await makeRemoteOnly(beta);
  const betaServer = await repositoryServer(context, beta);
  const result = await runVerifiedUpdate({
    appDataDirectory: beta.appData,
    policy: policyFor(beta, betaServer.origin),
    requestedChannel: "beta",
    now: () => NOW,
    waitBeforeRetry: async () => undefined,
    httpsAgent: betaServer.agent,
  });
  assert.equal(result.channel, "beta");
  const state = await loadUpdaterState(beta.appData);
  assert.equal(state?.record.configuredChannel, "beta");
  assert.equal(state?.record.maxActivatedReleaseSequence, 2);
});

test("wrong-channel metadata is rejected", async (context) => {
  const trust = createTestBundleTrust();
  const bundle = await createTestUpdateBundle(context, {
    trust,
    channel: "beta",
    releaseSequence: 1,
  });
  await makeRemoteOnly(bundle);
  const server = await repositoryServer(context, bundle);
  await assert.rejects(
    runVerifiedUpdate({
      appDataDirectory: bundle.appData,
      policy: policyFor(bundle, server.origin),
      requestedChannel: "stable",
      now: () => NOW,
      waitBeforeRetry: async () => undefined,
      httpsAgent: server.agent,
    }),
    isUpdateError("GOAT_UPDATE_NETWORK_FAILED"),
  );
});

test("replay of an lower-sequence channel release is blocked", async (context) => {
  const trust = createTestBundleTrust();
  const beta2 = await createTestUpdateBundle(context, {
    trust,
    channel: "beta",
    releaseSequence: 2,
  });
  await makeRemoteOnly(beta2);
  const server2 = await repositoryServer(context, beta2);
  await runVerifiedUpdate({
    appDataDirectory: beta2.appData,
    policy: policyFor(beta2, server2.origin),
    requestedChannel: "beta",
    now: () => NOW,
    waitBeforeRetry: async () => undefined,
    httpsAgent: server2.agent,
  });

  const beta1 = await createTestUpdateBundle(context, {
    trust,
    appData: beta2.appData,
    channel: "beta",
    releaseSequence: 1,
  });
  await makeRemoteOnly(beta1);
  const server1 = await repositoryServer(context, beta1);
  await assert.rejects(
    runVerifiedUpdate({
      appDataDirectory: beta1.appData,
      policy: policyFor(beta1, server1.origin),
      requestedChannel: "beta",
      now: () => NOW,
      waitBeforeRetry: async () => undefined,
      httpsAgent: server1.agent,
    }),
    isUpdateError("GOAT_UPDATE_METADATA_REPLAYED"),
  );
});

function isUpdateError(code: UpdateError["code"]): (error: unknown) => boolean {
  return (error) => error instanceof UpdateError && error.code === code;
}
