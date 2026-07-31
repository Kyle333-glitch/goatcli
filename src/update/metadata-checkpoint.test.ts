import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  lstat,
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { canonicalize } from "@tufjs/canonical-json";
import {
  createTestTufFixture,
  parseFixtureEnvelope,
  signEnvelope,
  type TestTufFixture,
} from "../../test/v0.4.0-update/tuf-fixture.js";
import { UpdateError } from "./errors.js";
import {
  authenticateAndAppendMetadataCheckpoint,
  cleanupMetadataCheckpointOrphans,
  loadMetadataCheckpointChain,
  type MetadataCheckpointPolicy,
} from "./metadata-checkpoint.js";
import type { UpdateMetadataBundle } from "./metadata-client.js";

const NOW = Date.parse("2030-01-01T00:00:00Z");

test("checkpoint replay preserves exact authenticated role and rotated-root bytes", async (context) => {
  const appData = await temporaryAppData(context);
  const fixture = createTestTufFixture({ metadataVersion: 2 });
  const rootEnvelope = parseFixtureEnvelope(fixture.root);
  rootEnvelope.signed.version = 2;
  const rotatedRoot = signEnvelope(
    rootEnvelope.signed,
    fixture.keys.root.slice(0, 2),
  );
  const metadata = metadataBundle(fixture, [rotatedRoot]);
  const policy = checkpointPolicy(fixture);
  const initial = await loadMetadataCheckpointChain(appData, policy);

  const appended = await authenticateAndAppendMetadataCheckpoint({
    appDataDirectory: appData,
    current: initial,
    metadata,
    policy,
    nowUnixMs: NOW,
  });

  assert.deepEqual(appended.chain.head, {
    generation: 1,
    sha256: appended.checkpoint.sha256,
  });
  assert.equal(appended.chain.trustedMetadata.versions.root, 2);
  assert.equal(appended.chain.trustedMetadata.versions.timestamp, 2);
  assert.equal(appended.chain.trustedMetadata.versions.stable, 2);
  assert.equal(appended.chain.trustedMetadata.trustedTimeUnixMs, NOW);
  assert.deepEqual(appended.chain.currentRootBytes, rotatedRoot);
  assert.deepEqual(
    appended.checkpoint.bundle.raw.sequentialRoots,
    metadata.sequentialRoots,
  );
  assert.deepEqual(
    appended.checkpoint.bundle.raw.timestamp,
    metadata.timestamp,
  );
  assert.deepEqual(appended.checkpoint.bundle.raw.snapshot, metadata.snapshot);
  assert.deepEqual(appended.checkpoint.bundle.raw.targets, metadata.targets);
  assert.deepEqual(appended.checkpoint.bundle.raw.channel, metadata.channel);
  assert.equal(
    appended.chain.roleVersionDigests.get("root:2"),
    sha256(rotatedRoot),
  );

  const reloaded = await loadMetadataCheckpointChain(appData, policy);
  assert.deepEqual(reloaded.head, appended.chain.head);
  assert.deepEqual(reloaded.trustedMetadata, appended.chain.trustedMetadata);
  assert.deepEqual(reloaded.currentRootBytes, rotatedRoot);
  assert.deepEqual(reloaded.orphanBundlePaths, []);
  assert.deepEqual(reloaded.orphanTemporaryFiles, []);
});

test("replay starts from the trusted rotated root and validates a full historical root prefix", async (context) => {
  const appData = await temporaryAppData(context);
  const fixture = createTestTufFixture({ metadataVersion: 2 });
  const rootEnvelope = parseFixtureEnvelope(fixture.root);
  rootEnvelope.signed.version = 2;
  const rotatedRoot = signEnvelope(
    rootEnvelope.signed,
    fixture.keys.root.slice(0, 2),
  );
  const policy = checkpointPolicy(fixture);
  const initial = await loadMetadataCheckpointChain(appData, policy);
  const first = await authenticateAndAppendMetadataCheckpoint({
    appDataDirectory: appData,
    current: initial,
    metadata: metadataBundle(fixture, [rotatedRoot]),
    policy,
    nowUnixMs: NOW,
  });

  const later = createTestTufFixture({
    keys: fixture.keys,
    metadataVersion: 3,
    revokedKeyIds: [fixture.keys.root[0].keyId],
  });
  const conflictingEnvelope = parseFixtureEnvelope(rotatedRoot);
  conflictingEnvelope.signed.expires = "2034-12-31T00:00:00Z";
  const conflictingRoot = signEnvelope(
    conflictingEnvelope.signed,
    fixture.keys.root.slice(0, 2),
  );

  await assert.rejects(
    authenticateAndAppendMetadataCheckpoint({
      appDataDirectory: appData,
      current: first.chain,
      metadata: metadataBundle(later, [conflictingRoot]),
      policy,
      nowUnixMs: NOW + 1,
    }),
    isUpdateError("GOAT_UPDATE_METADATA_REPLAYED"),
  );
  assert.deepEqual(
    (await loadMetadataCheckpointChain(appData, policy)).head,
    first.chain.head,
  );

  const second = await authenticateAndAppendMetadataCheckpoint({
    appDataDirectory: appData,
    current: first.chain,
    metadata: metadataBundle(later, [rotatedRoot]),
    policy,
    nowUnixMs: NOW + 2,
  });

  assert.equal(second.chain.head.generation, 2);
  assert.deepEqual(second.chain.currentRootBytes, rotatedRoot);
  assert.deepEqual(second.chain.trustedMetadata.revokedKeyIds, [
    fixture.keys.root[0].keyId,
  ]);
  assert.equal(
    second.chain.roleVersionDigests.get("root:2"),
    sha256(rotatedRoot),
  );

  const reloaded = await loadMetadataCheckpointChain(appData, policy);
  assert.deepEqual(reloaded.head, second.chain.head);
  assert.deepEqual(reloaded.currentRootBytes, rotatedRoot);
  assert.deepEqual(reloaded.trustedMetadata, second.chain.trustedMetadata);
});
test("same metadata reuses exact bundle bytes while trusted time advances in the checkpoint chain", async (context) => {
  const appData = await temporaryAppData(context);
  const fixture = createTestTufFixture();
  const metadata = metadataBundle(fixture);
  const policy = checkpointPolicy(fixture);
  const initial = await loadMetadataCheckpointChain(appData, policy);
  const first = await authenticateAndAppendMetadataCheckpoint({
    appDataDirectory: appData,
    current: initial,
    metadata,
    policy,
    nowUnixMs: NOW,
  });
  const second = await authenticateAndAppendMetadataCheckpoint({
    appDataDirectory: appData,
    current: first.chain,
    metadata,
    policy,
    nowUnixMs: NOW + 60_000,
  });

  assert.equal(second.chain.head.generation, 2);
  assert.equal(second.chain.records.length, 2);
  assert.equal(
    second.chain.records[0]!.record.metadataBundleSha256,
    second.chain.records[1]!.record.metadataBundleSha256,
  );
  assert.equal(second.chain.metadataBundleSha256s.size, 1);
  assert.equal(second.chain.trustedMetadata.trustedTimeUnixMs, NOW + 60_000);
  assert.equal(
    second.checkpoint.record.previousSha256,
    first.checkpoint.sha256,
  );
  assert.deepEqual(second.chain.currentRootBytes, fixture.root);
});

test("failed authentication performs no metadata filesystem write", async (context) => {
  const appData = await temporaryAppData(context);
  const fixture = createTestTufFixture();
  const envelope = parseFixtureEnvelope(fixture.channels.stable);
  envelope.signatures[0]!.sig = "0".repeat(128);
  const invalidChannel = Buffer.from(canonicalize(envelope), "utf8");
  const policy = checkpointPolicy(fixture);
  const initial = await loadMetadataCheckpointChain(appData, policy);

  await assert.rejects(
    authenticateAndAppendMetadataCheckpoint({
      appDataDirectory: appData,
      current: initial,
      metadata: {
        ...metadataBundle(fixture),
        channel: invalidChannel,
      },
      policy,
      nowUnixMs: NOW,
    }),
    isUpdateError("GOAT_UPDATE_SIGNATURE_INVALID"),
  );

  await assert.rejects(
    lstat(path.join(appData, "updates", "metadata")),
    hasErrorCode("ENOENT"),
  );
});

test("replay with retained revocations is rejected before another bundle or checkpoint is persisted", async (context) => {
  const appData = await temporaryAppData(context);
  const revokedArtifact = "f".repeat(64);
  const higher = createTestTufFixture({
    metadataVersion: 2,
    revokedArtifactSha256: [revokedArtifact],
  });
  const lower = createTestTufFixture({
    keys: higher.keys,
    metadataVersion: 1,
    revokedArtifactSha256: [revokedArtifact],
  });
  const policy = checkpointPolicy(higher);
  const initial = await loadMetadataCheckpointChain(appData, policy);
  const accepted = await authenticateAndAppendMetadataCheckpoint({
    appDataDirectory: appData,
    current: initial,
    metadata: metadataBundle(higher),
    policy,
    nowUnixMs: NOW,
  });

  await assert.rejects(
    authenticateAndAppendMetadataCheckpoint({
      appDataDirectory: appData,
      current: accepted.chain,
      metadata: metadataBundle(lower),
      policy,
      nowUnixMs: NOW + 1,
    }),
    isUpdateError("GOAT_UPDATE_METADATA_REPLAYED"),
  );

  const reloaded = await loadMetadataCheckpointChain(appData, policy);
  assert.deepEqual(reloaded.head, accepted.chain.head);
  assert.equal(
    (await readdir(path.join(appData, "updates", "metadata", "bundles")))
      .length,
    1,
  );
  assert.equal(
    (await readdir(path.join(appData, "updates", "metadata", "checkpoints")))
      .length,
    1,
  );
});

test("revocation rollback is rejected before persistence", async (context) => {
  const appData = await temporaryAppData(context);
  const revokedArtifact = "e".repeat(64);
  const firstFixture = createTestTufFixture({
    metadataVersion: 1,
    revokedArtifactSha256: [revokedArtifact],
  });
  const removed = createTestTufFixture({
    keys: firstFixture.keys,
    metadataVersion: 2,
  });
  const policy = checkpointPolicy(firstFixture);
  const initial = await loadMetadataCheckpointChain(appData, policy);
  const first = await authenticateAndAppendMetadataCheckpoint({
    appDataDirectory: appData,
    current: initial,
    metadata: metadataBundle(firstFixture),
    policy,
    nowUnixMs: NOW,
  });

  await assert.rejects(
    authenticateAndAppendMetadataCheckpoint({
      appDataDirectory: appData,
      current: first.chain,
      metadata: metadataBundle(removed),
      policy,
      nowUnixMs: NOW + 1,
    }),
    isUpdateError("GOAT_UPDATE_METADATA_REPLAYED"),
  );
  const reloaded = await loadMetadataCheckpointChain(appData, policy);
  assert.deepEqual(reloaded.head, first.chain.head);
  assert.deepEqual(reloaded.trustedMetadata.revokedArtifactSha256, [
    revokedArtifact,
  ]);
});

test("checkpoint capacity fails before persisting an authenticated bundle", async (context) => {
  const appData = await temporaryAppData(context);
  const fixture = createTestTufFixture();
  const policy = checkpointPolicy(fixture);
  const checkpoints = path.join(appData, "updates", "metadata", "checkpoints");
  await fillDirectoryWithTemporaryFiles(checkpoints, 4_096);
  const initial = await loadMetadataCheckpointChain(appData, policy);
  const namesBefore = await readdir(checkpoints);

  await assert.rejects(
    authenticateAndAppendMetadataCheckpoint({
      appDataDirectory: appData,
      current: initial,
      metadata: metadataBundle(fixture),
      policy,
      nowUnixMs: NOW,
    }),
    isUpdateError("GOAT_UPDATE_STATE_INVALID"),
  );

  assert.deepEqual(await readdir(checkpoints), namesBefore);
  await assert.rejects(
    lstat(path.join(appData, "updates", "metadata", "bundles")),
    hasErrorCode("ENOENT"),
  );
  const reloaded = await loadMetadataCheckpointChain(appData, policy);
  assert.deepEqual(reloaded.head, { generation: 0, sha256: null });
  assert.equal(reloaded.orphanTemporaryFiles.length, 4_096);
});

test("full bundle capacity permits exact reuse but rejects a new bundle before checkpoint persistence", async (context) => {
  const appData = await temporaryAppData(context);
  const fixture = createTestTufFixture();
  const policy = checkpointPolicy(fixture);
  const initial = await loadMetadataCheckpointChain(appData, policy);
  const first = await authenticateAndAppendMetadataCheckpoint({
    appDataDirectory: appData,
    current: initial,
    metadata: metadataBundle(fixture),
    policy,
    nowUnixMs: NOW,
  });
  const bundles = path.join(appData, "updates", "metadata", "bundles");
  const checkpoints = path.join(appData, "updates", "metadata", "checkpoints");
  await fillDirectoryWithTemporaryFiles(bundles, 4_095);
  const bundleNamesAtCapacity = await readdir(bundles);

  const second = await authenticateAndAppendMetadataCheckpoint({
    appDataDirectory: appData,
    current: first.chain,
    metadata: metadataBundle(fixture),
    policy,
    nowUnixMs: NOW + 1,
  });
  assert.deepEqual(await readdir(bundles), bundleNamesAtCapacity);
  assert.equal(second.chain.head.generation, 2);

  const checkpointNamesBefore = await readdir(checkpoints);
  const later = createTestTufFixture({
    keys: fixture.keys,
    metadataVersion: 2,
  });
  await assert.rejects(
    authenticateAndAppendMetadataCheckpoint({
      appDataDirectory: appData,
      current: second.chain,
      metadata: metadataBundle(later),
      policy,
      nowUnixMs: NOW + 2,
    }),
    isUpdateError("GOAT_UPDATE_STATE_INVALID"),
  );

  assert.deepEqual(await readdir(bundles), bundleNamesAtCapacity);
  assert.deepEqual(await readdir(checkpoints), checkpointNamesBefore);
  const reloaded = await loadMetadataCheckpointChain(appData, policy);
  assert.deepEqual(reloaded.head, second.chain.head);
  assert.equal(reloaded.metadataBundleSha256s.size, 1);
});

test("checkpoint recovery removes only loader-reported temporary files and unreferenced bundles", async (context) => {
  const appData = await temporaryAppData(context);
  const firstFixture = createTestTufFixture({ metadataVersion: 1 });
  const policy = checkpointPolicy(firstFixture);
  const initial = await loadMetadataCheckpointChain(appData, policy);
  const first = await authenticateAndAppendMetadataCheckpoint({
    appDataDirectory: appData,
    current: initial,
    metadata: metadataBundle(firstFixture),
    policy,
    nowUnixMs: NOW,
  });
  const secondFixture = createTestTufFixture({
    keys: firstFixture.keys,
    metadataVersion: 2,
  });
  const second = await authenticateAndAppendMetadataCheckpoint({
    appDataDirectory: appData,
    current: first.chain,
    metadata: metadataBundle(secondFixture),
    policy,
    nowUnixMs: NOW + 1,
  });

  // This is the durable bundle / pre-checkpoint crash state. Removing the
  // just-created checkpoint reproduces the same on-disk combination without
  // relying on a test-only branch in production persistence.
  await rm(second.checkpoint.path);
  const bundleTemporary = path.join(
    path.dirname(second.checkpoint.bundle.path),
    `.tmp-${"a".repeat(32)}`,
  );
  const checkpointTemporary = path.join(
    path.dirname(first.checkpoint.path),
    `.tmp-${"b".repeat(32)}`,
  );
  await writeFile(bundleTemporary, "interrupted bundle write", { flag: "wx" });
  await writeFile(checkpointTemporary, "interrupted checkpoint write", {
    flag: "wx",
  });

  const interrupted = await loadMetadataCheckpointChain(appData, policy);
  assert.equal(interrupted.head.sha256, first.chain.head.sha256);
  assert.deepEqual(
    interrupted.orphanTemporaryFiles,
    [bundleTemporary, checkpointTemporary].sort(),
  );
  assert.deepEqual(interrupted.orphanBundlePaths, [
    second.checkpoint.bundle.path,
  ]);

  const cleaned = await cleanupMetadataCheckpointOrphans(
    appData,
    interrupted,
    policy,
  );
  assert.equal(cleaned.head.sha256, first.chain.head.sha256);
  assert.deepEqual(cleaned.orphanTemporaryFiles, []);
  assert.deepEqual(cleaned.orphanBundlePaths, []);
  await assert.rejects(lstat(bundleTemporary), { code: "ENOENT" });
  await assert.rejects(lstat(checkpointTemporary), { code: "ENOENT" });
  await assert.rejects(lstat(second.checkpoint.bundle.path), {
    code: "ENOENT",
  });

  const repeated = await cleanupMetadataCheckpointOrphans(
    appData,
    cleaned,
    policy,
  );
  assert.equal(repeated.head.sha256, cleaned.head.sha256);
});

test("tampered checkpoint and missing referenced bundle both fail closed", async (context) => {
  await testTamperedCheckpoint(context);
  await testMissingBundle(context);
});

async function testTamperedCheckpoint(
  context: test.TestContext,
): Promise<void> {
  const appData = await temporaryAppData(context);
  const fixture = createTestTufFixture();
  const policy = checkpointPolicy(fixture);
  const initial = await loadMetadataCheckpointChain(appData, policy);
  const appended = await authenticateAndAppendMetadataCheckpoint({
    appDataDirectory: appData,
    current: initial,
    metadata: metadataBundle(fixture),
    policy,
    nowUnixMs: NOW,
  });
  const bytes = await readFile(appended.checkpoint.path);
  bytes[bytes.length - 1] ^= 1;
  await writeFile(appended.checkpoint.path, bytes);

  await assert.rejects(
    loadMetadataCheckpointChain(appData, policy),
    isUpdateError("GOAT_UPDATE_STATE_INVALID"),
  );
}

async function testMissingBundle(context: test.TestContext): Promise<void> {
  const appData = await temporaryAppData(context);
  const fixture = createTestTufFixture();
  const policy = checkpointPolicy(fixture);
  const initial = await loadMetadataCheckpointChain(appData, policy);
  const appended = await authenticateAndAppendMetadataCheckpoint({
    appDataDirectory: appData,
    current: initial,
    metadata: metadataBundle(fixture),
    policy,
    nowUnixMs: NOW,
  });
  await rm(appended.checkpoint.bundle.path);

  await assert.rejects(
    loadMetadataCheckpointChain(appData, policy),
    isUpdateError("GOAT_UPDATE_STATE_INVALID"),
  );
}

async function fillDirectoryWithTemporaryFiles(
  directory: string,
  count: number,
): Promise<void> {
  await mkdir(directory, { recursive: true });
  const batchSize = 128;
  for (let offset = 0; offset < count; offset += batchSize) {
    const batchCount = Math.min(batchSize, count - offset);
    await Promise.all(
      Array.from({ length: batchCount }, async (_, index) => {
        const suffix = String(offset + index).padStart(32, "0");
        await writeFile(path.join(directory, `.tmp-${suffix}`), "", {
          flag: "wx",
        });
      }),
    );
  }
}
function metadataBundle(
  fixture: TestTufFixture,
  sequentialRoots: readonly Buffer[] = [],
): UpdateMetadataBundle {
  return {
    sequentialRoots,
    timestamp: fixture.timestamp,
    snapshot: fixture.snapshot,
    targets: fixture.targets,
    channel: fixture.channels.stable,
    channelName: "stable",
  };
}

function checkpointPolicy(fixture: TestTufFixture): MetadataCheckpointPolicy {
  return {
    embeddedRootBytes: fixture.root,
    embeddedRootSha256: fixture.rootSha256,
  };
}

async function temporaryAppData(context: test.TestContext): Promise<string> {
  const root = await mkdtemp(
    path.join(os.tmpdir(), "goat-metadata-checkpoint-test-"),
  );
  context.after(() => rm(root, { recursive: true, force: true }));
  return root;
}

function sha256(value: Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function isUpdateError(code: UpdateError["code"]): (error: unknown) => boolean {
  return (error) => error instanceof UpdateError && error.code === code;
}

function hasErrorCode(code: string): (error: unknown) => boolean {
  return (error) => (error as NodeJS.ErrnoException).code === code;
}
