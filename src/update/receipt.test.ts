import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { canonicalize } from "@tufjs/canonical-json";
import {
  createTestTufFixture,
  type TestTufFixture,
} from "../../test/v0.4.0-update/tuf-fixture.js";
import { UpdateError } from "./errors.js";
import {
  loadTargetReceipt,
  persistTargetReceipt,
  reconstructStateFromReceipts,
  verifyTargetReceiptBytes,
  type ReceiptVerificationPolicy,
} from "./receipt.js";

test("authenticated target receipt stores and reauthenticates exact TUF bytes", async (context) => {
  const appData = await temporaryAppData(context);
  const fixture = createTestTufFixture({ metadataVersion: 4 });
  const policy = receiptPolicy(fixture);
  const persisted = await persistFixtureReceipt(appData, fixture, policy);
  assert.equal(persisted.target.custom.releaseSequence, 4);
  assert.equal(persisted.record.artifactSha256, persisted.target.sha256);
  assert.equal(persisted.receiptSha256, sha256(persisted.bytes));

  const loaded = await loadTargetReceipt(
    appData,
    persisted.receiptSha256,
    policy,
  );
  assert.equal(loaded.receiptSha256, persisted.receiptSha256);
  assert.deepEqual(loaded.release, persisted.release);
});

test("receipt metadata expiry does not revoke an already authenticated installation", async (context) => {
  const appData = await temporaryAppData(context);
  const fixture = createTestTufFixture({
    metadataVersion: 3,
    expires: "2020-01-01T00:00:00Z",
  });
  const policy = receiptPolicy(fixture);
  const persisted = await persistFixtureReceipt(appData, fixture, policy, {
    authenticatedAtUnixMs: Date.parse("2030-01-01T00:00:00Z"),
  });
  assert.equal(
    verifyTargetReceiptBytes(persisted.bytes, policy).target.custom
      .releaseSequence,
    3,
  );
});

test("current key, artifact, and release revocations override stored receipts", async (context) => {
  const appData = await temporaryAppData(context);
  const fixture = createTestTufFixture({ metadataVersion: 5 });
  const policy = receiptPolicy(fixture);
  const persisted = await persistFixtureReceipt(appData, fixture, policy);

  assert.throws(
    () =>
      verifyTargetReceiptBytes(persisted.bytes, {
        ...policy,
        currentRevocations: {
          goatRevocationSchema: 1,
          revokedKeyIds: [fixture.keys.stable[0].keyId],
          revokedArtifactSha256: [],
          revokedReleaseSequences: [],
        },
      }),
    isUpdateError("GOAT_UPDATE_SIGNING_KEY_REVOKED"),
  );
  for (const currentRevocations of [
    {
      goatRevocationSchema: 1 as const,
      revokedKeyIds: [],
      revokedArtifactSha256: [persisted.target.sha256],
      revokedReleaseSequences: [],
    },
    {
      goatRevocationSchema: 1 as const,
      revokedKeyIds: [],
      revokedArtifactSha256: [],
      revokedReleaseSequences: [5],
    },
  ]) {
    assert.throws(
      () =>
        verifyTargetReceiptBytes(persisted.bytes, {
          ...policy,
          currentRevocations,
        }),
      isUpdateError("GOAT_UPDATE_TARGET_NOT_FOUND"),
    );
  }
});

test("receipt field modification and filename substitution are rejected", async (context) => {
  const appData = await temporaryAppData(context);
  const fixture = createTestTufFixture({ metadataVersion: 6 });
  const policy = receiptPolicy(fixture);
  const persisted = await persistFixtureReceipt(appData, fixture, policy);
  const parsed = JSON.parse(persisted.bytes.toString("utf8")) as Record<
    string,
    unknown
  >;
  parsed.releaseSequence = 7;
  const modified = Buffer.from(canonicalize(parsed), "utf8");
  assert.throws(
    () => verifyTargetReceiptBytes(modified, policy),
    isUpdateError("GOAT_UPDATE_METADATA_MISMATCH"),
  );

  const original = await readFile(persisted.path);
  original[original.length - 1] ^= 1;
  await writeFile(persisted.path, original);
  await assert.rejects(
    loadTargetReceipt(appData, persisted.receiptSha256, policy),
    isUpdateError("GOAT_UPDATE_STATE_INVALID"),
  );
});

test("missing anti-downgrade state reconstructs floors and revocations from receipts", async (context) => {
  const appData = await temporaryAppData(context);
  const base = createTestTufFixture({ metadataVersion: 1 });
  const higher = createTestTufFixture({
    keys: base.keys,
    metadataVersion: 2,
    revokedArtifactSha256: ["e".repeat(64)],
  });
  const policy = receiptPolicy(base);
  const first = await persistFixtureReceipt(appData, base, policy, {
    authenticatedAtUnixMs: 100,
  });
  const second = await persistFixtureReceipt(appData, higher, policy, {
    authenticatedAtUnixMs: 200,
  });

  const reconstructed = await reconstructStateFromReceipts(appData, policy);
  assert.equal(reconstructed?.maxAuthenticatedReleaseSequence, 2);
  assert.equal(reconstructed?.trustedMetadata.versions.timestamp, 2);
  assert.equal(reconstructed?.trustedMetadata.trustedTimeUnixMs, 200);
  assert.deepEqual(reconstructed?.trustedMetadata.revokedArtifactSha256, [
    "e".repeat(64),
  ]);
  assert.deepEqual(
    reconstructed?.receiptDigests,
    [first.receiptSha256, second.receiptSha256].sort(),
  );
});

test("conflicting or rollback receipt history fails reconstruction safely", async (context) => {
  const appData = await temporaryAppData(context);
  const base = createTestTufFixture({
    metadataVersion: 1,
    revokedArtifactSha256: ["f".repeat(64)],
  });
  const removed = createTestTufFixture({
    keys: base.keys,
    metadataVersion: 2,
  });
  const policy = receiptPolicy(base);
  await persistFixtureReceipt(appData, base, policy);
  await persistFixtureReceipt(appData, removed, policy);
  await assert.rejects(
    reconstructStateFromReceipts(appData, policy),
    isUpdateError("GOAT_UPDATE_STATE_INVALID"),
  );
});

test("wrong receipt platform or architecture cannot select an installed target", async (context) => {
  const appData = await temporaryAppData(context);
  const fixture = createTestTufFixture();
  const policy = receiptPolicy(fixture);
  const persisted = await persistFixtureReceipt(appData, fixture, policy);
  for (const changed of [
    { platform: "darwin" as const },
    { architecture: "arm64" as const },
  ]) {
    assert.throws(
      () =>
        verifyTargetReceiptBytes(persisted.bytes, { ...policy, ...changed }),
      isUpdateError("GOAT_UPDATE_TARGET_NOT_FOUND"),
    );
  }
});

async function persistFixtureReceipt(
  appData: string,
  fixture: TestTufFixture,
  policy: ReceiptVerificationPolicy,
  options: { readonly authenticatedAtUnixMs?: number } = {},
) {
  return persistTargetReceipt(
    appData,
    {
      embeddedRootSha256: fixture.rootSha256,
      sequentialRoots: [],
      timestamp: fixture.timestamp,
      snapshot: fixture.snapshot,
      targets: fixture.targets,
      channel: fixture.channels.stable,
      channelName: "stable",
      targetPath: fixture.targetPaths.stable,
      authenticatedAtUnixMs: options.authenticatedAtUnixMs ?? 1_000,
    },
    policy,
  );
}

function receiptPolicy(fixture: TestTufFixture): ReceiptVerificationPolicy {
  return {
    embeddedRootBytes: fixture.root,
    embeddedRootSha256: fixture.rootSha256,
    launcherVersion: "0.4.0",
    platform: "win32",
    architecture: "x64",
  };
}

async function temporaryAppData(context: test.TestContext): Promise<string> {
  const root = await mkdtemp(path.join(os.tmpdir(), "goat-receipt-test-"));
  context.after(() => rm(root, { recursive: true, force: true }));
  return root;
}

function sha256(value: Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function isUpdateError(code: UpdateError["code"]): (error: unknown) => boolean {
  return (error) => error instanceof UpdateError && error.code === code;
}
