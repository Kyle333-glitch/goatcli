import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  appendRollbackActivationRecord,
  appendUpdateActivationRecord,
  expectedSlotName,
  loadActivationChain,
  slotRoot,
  type NewActivationIdentity,
} from "./activation-record.js";
import { UpdateError } from "./errors.js";

test("activation chain remains contiguous across channel switches", async (context) => {
  const appData = await temporaryAppData(context);
  const firstIdentity = identity(1, "stable");
  const first = await appendUpdateActivationRecord(appData, firstIdentity, 10);
  const secondIdentity = identity(2, "beta");
  const second = await appendUpdateActivationRecord(
    appData,
    secondIdentity,
    20,
  );
  const chain = await loadActivationChain(appData, "win32", "x64");
  assert.equal(chain.records.length, 2);
  assert.equal(chain.current?.record.channel, "beta");
  assert.equal(chain.current?.record.previousRecordSha256, first.sha256);
  assert.equal(chain.previous?.sha256, first.sha256);
  assert.equal(second.record.generation, 2);
  assert.equal(
    slotRoot(appData, second.record),
    path.join(
      appData,
      "engines",
      "beta",
      "win32-x64",
      "releases",
      secondIdentity.slotName,
    ),
  );
});

test("automatic rollback appends a new selection without lowering release history", async (context) => {
  const appData = await temporaryAppData(context);
  const first = await appendUpdateActivationRecord(
    appData,
    identity(3, "stable"),
    10,
  );
  await appendUpdateActivationRecord(appData, identity(4, "beta"), 20);
  const rollback = await appendRollbackActivationRecord(
    appData,
    "win32",
    "x64",
    first.record.generation,
    30,
  );
  assert.equal(rollback.record.reason, "automatic-rollback");
  assert.equal(rollback.record.releaseSequence, 3);
  assert.equal(rollback.record.rollbackSourceGeneration, 1);
  assert.equal(rollback.record.slotSealSha256, first.record.slotSealSha256);
  assert.equal(rollback.record.generation, 3);

  await assert.rejects(
    appendUpdateActivationRecord(appData, identity(4, "stable"), 40),
    isUpdateError("GOAT_UPDATE_DOWNGRADE_BLOCKED"),
  );
  const higher = await appendUpdateActivationRecord(
    appData,
    identity(5, "stable"),
    50,
  );
  assert.equal(higher.record.generation, 4);
});

test("corrupted latest activation record fails closed instead of falling back", async (context) => {
  const appData = await temporaryAppData(context);
  await appendUpdateActivationRecord(appData, identity(1, "stable"));
  const second = await appendUpdateActivationRecord(
    appData,
    identity(2, "stable"),
  );
  const bytes = await readFile(second.path);
  bytes[bytes.length - 1] ^= 1;
  await writeFile(second.path, bytes);
  await assert.rejects(
    loadActivationChain(appData, "win32", "x64"),
    isUpdateError("GOAT_UPDATE_RECOVERY_REQUIRED"),
  );
});

test("invalid slot identity and duplicate release sequence are rejected", async (context) => {
  const appData = await temporaryAppData(context);
  const first = identity(7, "stable");
  await appendUpdateActivationRecord(appData, first);
  await assert.rejects(
    appendUpdateActivationRecord(appData, {
      ...identity(8, "stable"),
      slotName: "attacker-slot",
    }),
    isUpdateError("GOAT_UPDATE_RECOVERY_REQUIRED"),
  );
  await assert.rejects(
    appendUpdateActivationRecord(appData, {
      ...first,
      artifactSha256: "f".repeat(64),
      slotName: expectedSlotName({
        releaseSequence: first.releaseSequence,
        goatEngineVersion: first.goatEngineVersion,
        artifactSha256: "f".repeat(64),
      }),
    }),
    isUpdateError("GOAT_UPDATE_DOWNGRADE_BLOCKED"),
  );
});

test("rollback source must be a prior committed activation", async (context) => {
  const appData = await temporaryAppData(context);
  await appendUpdateActivationRecord(appData, identity(1, "stable"));
  await assert.rejects(
    appendRollbackActivationRecord(appData, "win32", "x64", 99),
    isUpdateError("GOAT_UPDATE_ROLLBACK_INVALID"),
  );
  await assert.rejects(
    appendRollbackActivationRecord(appData, "win32", "x64", 1),
    isUpdateError("GOAT_UPDATE_ROLLBACK_INVALID"),
  );
});

test("torn temporary activation record is ignored and reported", async (context) => {
  const appData = await temporaryAppData(context);
  const record = await appendUpdateActivationRecord(
    appData,
    identity(1, "stable"),
  );
  const temporary = path.join(
    path.dirname(record.path),
    `.tmp-${"a".repeat(32)}`,
  );
  await writeFile(temporary, "partial");
  const chain = await loadActivationChain(appData, "win32", "x64");
  assert.equal(chain.current?.sha256, record.sha256);
  assert.deepEqual(chain.orphanTemporaryFiles, [temporary]);
});

function identity(
  releaseSequence: number,
  channel: "stable" | "beta",
): NewActivationIdentity {
  const version =
    channel === "stable"
      ? `0.4.${releaseSequence}`
      : `0.4.0-beta.${releaseSequence}`;
  const artifactSha256 = String(releaseSequence % 10).repeat(64);
  return {
    channel,
    platform: "win32",
    architecture: "x64",
    releaseSequence,
    productVersion: version,
    goatEngineVersion: version,
    artifactSha256,
    slotName: expectedSlotName({
      releaseSequence,
      goatEngineVersion: version,
      artifactSha256,
    }),
    slotSealSha256: "d".repeat(64),
    treeSha256: "a".repeat(64),
    receiptSha256: "b".repeat(64),
    manifestSha256: "c".repeat(64),
  };
}

async function temporaryAppData(context: test.TestContext): Promise<string> {
  const root = await mkdtemp(
    path.join(os.tmpdir(), "goat-activation-record-test-"),
  );
  context.after(() => rm(root, { recursive: true, force: true }));
  return root;
}

function isUpdateError(code: UpdateError["code"]): (error: unknown) => boolean {
  return (error) => error instanceof UpdateError && error.code === code;
}
