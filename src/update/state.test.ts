import assert from "node:assert/strict";
import {
  mkdtemp,
  mkdir,
  readFile,
  rm,
  unlink,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { UpdateError } from "./errors.js";
import {
  appendUpdaterState,
  assertPristineV04Layout,
  initialUpdaterState,
  initializeUpdaterState,
  loadUpdaterState,
  stateAfterActivation,
  stateAfterAuthentication,
  stateAfterMetadataRefresh,
  trustedMetadataFromState,
} from "./state.js";
import {
  emptyTrustedMetadataState,
  type TrustedMetadataState,
} from "./trust.js";

test("append-only state persists authentication before activation", async (context) => {
  const appData = await temporaryAppData(context);
  const initial = await initializeUpdaterState(
    appData,
    initialUpdaterState(emptyTrustedMetadataState(new Date(1_000))),
  );
  const release = releaseIdentity(7);
  const receiptSha256 = "a".repeat(64);
  const metadata = await appendUpdaterState(
    appData,
    initial,
    stateAfterMetadataRefresh(initial.record, {
      trustedMetadata: advancedMetadata(7),
      checkpoint: { generation: 1, sha256: "f".repeat(64) },
    }),
  );
  const authenticated = await appendUpdaterState(
    appData,
    metadata,
    stateAfterAuthentication(metadata.record, {
      release,
      receiptSha256,
    }),
  );
  assert.equal(authenticated.record.maxAuthenticatedReleaseSequence, 7);
  assert.equal(authenticated.record.maxActivatedReleaseSequence, 0);
  assert.equal(authenticated.record.configuredChannel, "stable");

  const activated = await appendUpdaterState(
    appData,
    authenticated,
    stateAfterActivation(authenticated.record, {
      activationGeneration: 1,
      release,
      receiptSha256,
    }),
  );
  assert.equal(activated.record.currentActivationGeneration, 1);
  assert.equal(activated.record.maxActivatedReleaseSequence, 7);
  assert.deepEqual(
    trustedMetadataFromState(activated.record),
    advancedMetadata(7),
  );

  const reloaded = await loadUpdaterState(appData);
  assert.equal(reloaded?.sha256, activated.sha256);
  assert.equal(reloaded?.record.generation, 4);
});

test("state transitions reject downgrade and same-version byte replacement", async (context) => {
  const appData = await temporaryAppData(context);
  const initial = await initializeUpdaterState(appData, initialUpdaterState());
  const first = stateAfterAuthentication(initial.record, {
    release: releaseIdentity(5),
    receiptSha256: "b".repeat(64),
  });
  const current = await appendUpdaterState(appData, initial, first);

  assert.throws(
    () =>
      stateAfterAuthentication(current.record, {
        release: releaseIdentity(4),
        receiptSha256: "c".repeat(64),
      }),
    isUpdateError("GOAT_UPDATE_DOWNGRADE_BLOCKED"),
  );
  assert.throws(
    () =>
      stateAfterAuthentication(current.record, {
        release: {
          ...releaseIdentity(6),
          productVersion: "0.4.5",
          artifactSha256: "d".repeat(64),
        },
        receiptSha256: "e".repeat(64),
      }),
    isUpdateError("GOAT_UPDATE_METADATA_REPLAYED"),
  );
});

test("corrupt final state record fails closed instead of falling back", async (context) => {
  const appData = await temporaryAppData(context);
  const initialized = await initializeUpdaterState(
    appData,
    initialUpdaterState(),
  );
  const original = await readFile(initialized.path);
  const corrupted = Buffer.from(original);
  corrupted[corrupted.length - 1] ^= 1;
  await writeFile(initialized.path, corrupted);

  await assert.rejects(
    loadUpdaterState(appData),
    isUpdateError("GOAT_UPDATE_STATE_INVALID"),
  );
});

test("missing anti-downgrade state with v0.4 receipts cannot bootstrap as pristine", async (context) => {
  const appData = await temporaryAppData(context);
  const receiptDirectory = path.join(appData, "updates", "receipts");
  await mkdir(receiptDirectory, { recursive: true });
  await writeFile(
    path.join(receiptDirectory, `${"f".repeat(64)}.json`),
    "receipt",
  );

  await assert.rejects(
    initializeUpdaterState(appData, initialUpdaterState()),
    isUpdateError("GOAT_UPDATE_STATE_INVALID"),
  );
  await assert.rejects(
    assertPristineV04Layout(appData),
    isUpdateError("GOAT_UPDATE_STATE_INVALID"),
  );
});

test("missing state with an immutable release slot cannot reset sequence floors", async (context) => {
  const appData = await temporaryAppData(context);
  await mkdir(
    path.join(
      appData,
      "engines",
      "stable",
      `${runtimePlatform()}-${runtimeArchitecture()}`,
      "releases",
      "8-0.4.0-aaaaaaaaaaaa",
    ),
    { recursive: true },
  );
  await assert.rejects(
    initializeUpdaterState(appData, initialUpdaterState()),
    isUpdateError("GOAT_UPDATE_STATE_INVALID"),
  );
});

test("uncommitted temporary state file is ignored but reported for recovery", async (context) => {
  const appData = await temporaryAppData(context);
  const initialized = await initializeUpdaterState(
    appData,
    initialUpdaterState(),
  );
  const temporaryPath = path.join(
    path.dirname(initialized.path),
    `.tmp-${"1".repeat(32)}`,
  );
  await writeFile(temporaryPath, "partial");
  const loaded = await loadUpdaterState(appData);
  assert.equal(loaded?.sha256, initialized.sha256);
  assert.deepEqual(loaded?.orphanTemporaryFiles, [temporaryPath]);
  await unlink(temporaryPath);
});

test("channel changes only as part of a higher committed activation", async (context) => {
  const appData = await temporaryAppData(context);
  const initial = await initializeUpdaterState(appData, initialUpdaterState());
  await assert.rejects(
    appendUpdaterState(appData, initial, {
      ...initialUpdaterState(),
      configuredChannel: "beta",
    }),
    isUpdateError("GOAT_UPDATE_STATE_INVALID"),
  );
});

test("same-release metadata refresh advances trust without changing release floors", async (context) => {
  const appData = await temporaryAppData(context);
  const initial = await initializeUpdaterState(appData, initialUpdaterState());
  const refreshed = await appendUpdaterState(
    appData,
    initial,
    stateAfterMetadataRefresh(initial.record, {
      trustedMetadata: advancedMetadata(1),
      checkpoint: { generation: 1, sha256: "f".repeat(64) },
    }),
  );
  assert.equal(refreshed.record.maxAuthenticatedReleaseSequence, 0);
  assert.equal(refreshed.record.maxActivatedReleaseSequence, 0);
  assert.equal(refreshed.record.currentActivationGeneration, null);
  assert.equal(refreshed.record.metadataVersions.timestamp, 1);
  assert.equal(refreshed.record.metadataCheckpointGeneration, 1);
  assert.equal(refreshed.record.metadataCheckpointSha256, "f".repeat(64));
});

async function temporaryAppData(context: test.TestContext): Promise<string> {
  const root = await mkdtemp(path.join(os.tmpdir(), "goat-state-test-"));
  context.after(() => rm(root, { recursive: true, force: true }));
  return root;
}

function advancedMetadata(version: number): TrustedMetadataState {
  return {
    versions: {
      root: 1,
      timestamp: version,
      snapshot: version,
      targets: version,
      stable: version,
      beta: 0,
      development: 0,
    },
    digests: {
      root: "1".repeat(64),
      timestamp: "2".repeat(64),
      snapshot: "3".repeat(64),
      targets: "4".repeat(64),
      stable: "5".repeat(64),
    },
    trustedTimeUnixMs: 1_000 + version,
    revokedKeyIds: [],
    revokedArtifactSha256: [],
    revokedReleaseSequences: [],
  };
}

function releaseIdentity(releaseSequence: number) {
  return {
    releaseSequence,
    channel: "stable" as const,
    productVersion: `0.4.${releaseSequence}`,
    artifactSha256: String(releaseSequence % 10).repeat(64),
  };
}

function runtimePlatform(): "win32" | "darwin" {
  return process.platform === "darwin" ? "darwin" : "win32";
}

function runtimeArchitecture(): "x64" | "arm64" {
  return process.arch === "arm64" ? "arm64" : "x64";
}

function isUpdateError(code: UpdateError["code"]): (error: unknown) => boolean {
  return (error) => error instanceof UpdateError && error.code === code;
}
