import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rename,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { MockManifestServer } from "../../test/v0.4.0-update/mock-manifest-server.js";
import { createTestTufFixture } from "../../test/v0.4.0-update/tuf-fixture.js";
import {
  assertHeldArtifactUnchanged,
  consistentSnapshotArtifactPath,
  disposeHeldArtifact,
  downloadVerifiedArtifact,
} from "./download.js";
import { UpdateError } from "./errors.js";
import { FixedOriginTransport, METADATA_NETWORK_LIMITS } from "./network.js";
import { selectAuthenticatedArtifact } from "./selection.js";
import type { AuthenticatedTarget } from "./schema.js";
import {
  cleanupUpdateTransaction,
  createUpdateTransactionPaths,
} from "./temporary.js";
import { emptyTrustedMetadataState, TufTrustStore } from "./trust.js";

test("verified artifact remains non-executable and held until extraction", async (context) => {
  const bytes = Buffer.from("verified update archive bytes");
  const target = targetForBytes(bytes);
  const server = new MockManifestServer();
  server.bytes(consistentSnapshotArtifactPath(target), bytes);
  await server.listen();
  context.after(() => server.close());
  const transaction = await testTransaction(context);
  const artifact = await downloadVerifiedArtifact(
    testTransport(server),
    target,
    transaction,
  );
  context.after(() => disposeHeldArtifact(artifact));
  assert.equal(artifact.sha256, sha256(bytes));
  assert.equal((await stat(artifact.path)).mode & 0o111, 0);
  await assertHeldArtifactUnchanged(artifact);
});

test("artifactHashMismatchIsRejected and current installation stays usable", async (context) => {
  const bytes = Buffer.from("correct file with wrong signed checksum");
  const target = { ...targetForBytes(bytes), sha256: "0".repeat(64) };
  const server = new MockManifestServer();
  server.bytes(consistentSnapshotArtifactPath(target), bytes);
  await server.listen();
  context.after(() => server.close());
  const transaction = await testTransaction(context);
  const current = path.join(
    path.dirname(transaction.updatesRoot),
    "current-engine",
  );
  await writeFile(current, "known-good");

  await assert.rejects(
    downloadVerifiedArtifact(testTransport(server), target, transaction),
    isUpdateError("GOAT_UPDATE_ARTIFACT_HASH_MISMATCH"),
  );
  assert.equal(await readFile(current, "utf8"), "known-good");
  assert.deepEqual(await readdir(transaction.transactionRoot), ["staging"]);
});

test("interruptedDownloadLeavesCurrentInstallationUsable", async (context) => {
  const bytes = Buffer.alloc(4_096, 0x61);
  const target = targetForBytes(bytes);
  const server = new MockManifestServer();
  server.interrupted(consistentSnapshotArtifactPath(target), bytes, 128);
  await server.listen();
  context.after(() => server.close());
  const transaction = await testTransaction(context);
  const current = path.join(
    path.dirname(transaction.updatesRoot),
    "current-engine",
  );
  await writeFile(current, "launchable-known-good");

  await assert.rejects(
    downloadVerifiedArtifact(testTransport(server), target, transaction, {
      waitBeforeRetry: async () => {},
    }),
    (error: unknown) =>
      error instanceof UpdateError &&
      (error.code === "GOAT_UPDATE_NETWORK_FAILED" ||
        error.code === "GOAT_UPDATE_ARTIFACT_SIZE_MISMATCH"),
  );
  assert.equal(server.requests.length, 2);
  assert.equal(await readFile(current, "utf8"), "launchable-known-good");
  assert.deepEqual(await readdir(transaction.transactionRoot), ["staging"]);
});

test("artifactPathReplacementCannotChangeHeldBytes", async (context) => {
  const bytes = Buffer.from("authenticated held descriptor bytes");
  const target = targetForBytes(bytes);
  const server = new MockManifestServer();
  server.bytes(consistentSnapshotArtifactPath(target), bytes);
  await server.listen();
  context.after(() => server.close());
  const transaction = await testTransaction(context);
  const artifact = await downloadVerifiedArtifact(
    testTransport(server),
    target,
    transaction,
  );
  const heldPath = `${artifact.path}.held-for-test`;
  await rename(artifact.path, heldPath);
  await writeFile(artifact.path, "substituted path bytes", { flag: "wx" });
  await assertHeldArtifactUnchanged(artifact);
  assert.equal(await readFile(artifact.path, "utf8"), "substituted path bytes");
  await disposeHeldArtifact(artifact);
  await rm(heldPath, { force: true });
});

test("signed length is enforced before and during download", async (context) => {
  const bytes = Buffer.from("length-bound artifact");
  const target = targetForBytes(bytes);
  const server = new MockManifestServer();
  server.bytes(consistentSnapshotArtifactPath(target), bytes, {
    headers: { "Content-Length": String(bytes.length + 1) },
  });
  await server.listen();
  context.after(() => server.close());
  const transaction = await testTransaction(context);
  await assert.rejects(
    downloadVerifiedArtifact(testTransport(server), target, transaction),
    isUpdateError("GOAT_UPDATE_ARTIFACT_SIZE_MISMATCH"),
  );
  assert.deepEqual(await readdir(transaction.transactionRoot), ["staging"]);
});

test("artifact body exceeding signed length reaches the streaming guard", async (context) => {
  const bytes = Buffer.from("length-bound artifact");
  const target = targetForBytes(bytes);
  const artifactPath = consistentSnapshotArtifactPath(target);
  const server = new MockManifestServer();
  server.route(artifactPath, (_request, response) => {
    response.writeHead(200);
    response.write(bytes);
    response.write(Buffer.alloc(16, 0x41));
    response.end();
  });
  await server.listen();
  context.after(() => server.close());
  const transaction = await testTransaction(context);
  await assert.rejects(
    downloadVerifiedArtifact(testTransport(server), target, transaction),
    isUpdateError("GOAT_UPDATE_ARTIFACT_SIZE_MISMATCH"),
  );
  assert.deepEqual(await readdir(transaction.transactionRoot), ["staging"]);
});

test("chunked metadata stream without Content-Length is bounded by maxBytes", async (context) => {
  const server = new MockManifestServer();
  const huge = Buffer.alloc(METADATA_NETWORK_LIMITS.maxBytes + 1, 0x61);
  server.route("/metadata/large.json", (_request, response) => {
    response.writeHead(200);
    response.write(huge);
    response.end();
  });
  await server.listen();
  context.after(() => server.close());
  const transport = new FixedOriginTransport({
    origin: server.origin,
    launcherVersion: "0.4.0",
    channel: "stable",
    platform: "win32",
    architecture: "x64",
    agent: server.agent,
  });
  await assert.rejects(
    transport.readResource("/metadata/large.json", METADATA_NETWORK_LIMITS),
    isUpdateError("GOAT_UPDATE_DOWNLOAD_TOO_LARGE"),
  );
});

function targetForBytes(bytes: Buffer): AuthenticatedTarget {
  const fixture = createTestTufFixture();
  const authenticated = new TufTrustStore(
    fixture.root,
    fixture.rootSha256,
  ).authenticate({
    timestamp: fixture.timestamp,
    snapshot: fixture.snapshot,
    targets: fixture.targets,
    channel: fixture.channels.stable,
    channelName: "stable",
    state: emptyTrustedMetadataState(),
    now: new Date("2030-01-01T00:00:00Z"),
  });
  const selected = selectAuthenticatedArtifact(
    authenticated.channel,
    {
      channel: "stable",
      platform: "win32",
      architecture: "x64",
      launcherVersion: "0.4.0",
      maxAuthenticatedReleaseSequence: 0,
      maxActivatedReleaseSequence: 0,
    },
    authenticated.revocations,
  ).target;
  return { ...selected, length: bytes.length, sha256: sha256(bytes) };
}

async function testTransaction(context: test.TestContext) {
  const temporaryBase = await realpath(os.tmpdir());
  const appData = await mkdtemp(path.join(temporaryBase, "goat-update-test-"));
  const transaction = await createUpdateTransactionPaths(appData);
  context.after(async () => {
    await cleanupUpdateTransaction(transaction).catch(() => undefined);
    await rm(appData, { recursive: true, force: true });
  });
  return transaction;
}

function testTransport(server: MockManifestServer): FixedOriginTransport {
  return new FixedOriginTransport({
    origin: server.origin,
    launcherVersion: "0.4.0",
    channel: "stable",
    platform: "win32",
    architecture: "x64",
    agent: server.agent,
  });
}

function sha256(value: Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function isUpdateError(code: UpdateError["code"]): (error: unknown) => boolean {
  return (error) => error instanceof UpdateError && error.code === code;
}
