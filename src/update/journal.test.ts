import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { UpdateError } from "./errors.js";
import {
  UPDATE_PHASES,
  appendJournalTransition,
  createTransactionJournal,
  emptyJournalData,
  listTransactionJournals,
  loadTransactionJournal,
  type JournalData,
} from "./journal.js";

test("all fifteen update transitions form a contiguous immutable hash chain", async (context) => {
  const appData = await temporaryAppData(context);
  const transactionId = "a".repeat(32);
  let journal = await createTransactionJournal(appData, transactionId);
  let data: JournalData = emptyJournalData();
  for (let index = 0; index < UPDATE_PHASES.length; index += 1) {
    const transition = index + 1;
    if (transition === 3) data = { ...data, releaseSequence: 11 };
    if (transition === 6) data = { ...data, receiptSha256: "b".repeat(64) };
    if (transition === 10)
      data = { ...data, slotName: "11-0.4.0-cccccccccccc" };
    if (transition === 12) data = { ...data, slotSealSha256: "d".repeat(64) };
    if (transition === 13) data = { ...data, activationGeneration: 2 };
    journal = await appendJournalTransition(
      journal,
      UPDATE_PHASES[index]!,
      data,
      transition,
    );
  }
  assert.equal(journal.records.length, 15);
  assert.equal(journal.records.at(-1)?.record.phase, "recover");
  const reloaded = await loadTransactionJournal(appData, transactionId);
  assert.deepEqual(
    reloaded.records.map((record) => record.sha256),
    journal.records.map((record) => record.sha256),
  );
  assert.equal((await listTransactionJournals(appData)).length, 1);
});

test("skipped or reordered transitions are rejected", async (context) => {
  const appData = await temporaryAppData(context);
  const journal = await createTransactionJournal(appData, "c".repeat(32));
  await assert.rejects(
    appendJournalTransition(journal, "fetch-manifest", emptyJournalData(), 1),
    isUpdateError("GOAT_UPDATE_RECOVERY_REQUIRED"),
  );
});

test("recovery can terminate an incomplete journal but nothing follows recovery", async (context) => {
  const appData = await temporaryAppData(context);
  let journal = await createTransactionJournal(appData, "b".repeat(32));
  journal = await appendJournalTransition(
    journal,
    "check",
    emptyJournalData(),
    1,
  );
  journal = await appendJournalTransition(
    journal,
    "recover",
    emptyJournalData(),
    2,
  );
  assert.equal(journal.records.at(-1)?.record.phase, "recover");
  await assert.rejects(
    appendJournalTransition(
      journal,
      "authenticate-manifest",
      { ...emptyJournalData(), releaseSequence: 1 },
      3,
    ),
    isUpdateError("GOAT_UPDATE_RECOVERY_REQUIRED"),
  );
});

test("security-relevant journal data cannot change after it is recorded", async (context) => {
  const appData = await temporaryAppData(context);
  let journal = await createTransactionJournal(appData, "d".repeat(32));
  journal = await appendJournalTransition(
    journal,
    "check",
    emptyJournalData(),
    1,
  );
  journal = await appendJournalTransition(
    journal,
    "fetch-manifest",
    emptyJournalData(),
    2,
  );
  journal = await appendJournalTransition(
    journal,
    "authenticate-manifest",
    { ...emptyJournalData(), releaseSequence: 5 },
    3,
  );
  await assert.rejects(
    appendJournalTransition(
      journal,
      "select-artifact",
      { ...emptyJournalData(), releaseSequence: 6 },
      4,
    ),
    isUpdateError("GOAT_UPDATE_RECOVERY_REQUIRED"),
  );
});

test("activation identity data appears only at its exact durable phase", async (context) => {
  const appData = await temporaryAppData(context);
  let journal = await createTransactionJournal(appData, "4".repeat(32));
  let data: JournalData = emptyJournalData();
  for (let transition = 1; transition <= 9; transition += 1) {
    if (transition === 3) data = { ...data, releaseSequence: 9 };
    if (transition === 6) data = { ...data, receiptSha256: "a".repeat(64) };
    journal = await appendJournalTransition(
      journal,
      UPDATE_PHASES[transition - 1]!,
      data,
      transition,
    );
  }

  await assert.rejects(
    appendJournalTransition(journal, "prepare-activation", data, 10),
    isUpdateError("GOAT_UPDATE_RECOVERY_REQUIRED"),
  );
  data = { ...data, slotName: "9-0.4.9-aaaaaaaaaaaa" };
  journal = await appendJournalTransition(
    journal,
    "prepare-activation",
    data,
    10,
  );
  await assert.rejects(
    appendJournalTransition(
      journal,
      "place-provisional-slot",
      { ...data, slotSealSha256: "b".repeat(64) },
      11,
    ),
    isUpdateError("GOAT_UPDATE_RECOVERY_REQUIRED"),
  );
  journal = await appendJournalTransition(
    journal,
    "place-provisional-slot",
    data,
    11,
  );
  await assert.rejects(
    appendJournalTransition(journal, "validate-provisional-slot", data, 12),
    isUpdateError("GOAT_UPDATE_RECOVERY_REQUIRED"),
  );
  data = { ...data, slotSealSha256: "b".repeat(64) };
  journal = await appendJournalTransition(
    journal,
    "validate-provisional-slot",
    data,
    12,
  );
  await assert.rejects(
    appendJournalTransition(journal, "commit-activation", data, 13),
    isUpdateError("GOAT_UPDATE_RECOVERY_REQUIRED"),
  );
});

test("recovery cannot introduce data absent from the interrupted phase", async (context) => {
  const appData = await temporaryAppData(context);
  let journal = await createTransactionJournal(appData, "5".repeat(32));
  journal = await appendJournalTransition(
    journal,
    "check",
    emptyJournalData(),
    1,
  );
  await assert.rejects(
    appendJournalTransition(
      journal,
      "recover",
      { ...emptyJournalData(), releaseSequence: 1 },
      2,
    ),
    isUpdateError("GOAT_UPDATE_RECOVERY_REQUIRED"),
  );
});

test("corrupted recovery journal fails safely", async (context) => {
  const appData = await temporaryAppData(context);
  const transactionId = "e".repeat(32);
  let journal = await createTransactionJournal(appData, transactionId);
  journal = await appendJournalTransition(
    journal,
    "check",
    emptyJournalData(),
    1,
  );
  const recordPath = journal.records[0]!.path;
  const bytes = await readFile(recordPath);
  bytes[bytes.length - 1] ^= 1;
  await writeFile(recordPath, bytes);
  await assert.rejects(
    loadTransactionJournal(appData, transactionId),
    isUpdateError("GOAT_UPDATE_RECOVERY_REQUIRED"),
  );
});

test("torn temporary journal records are untrusted and never advance phase", async (context) => {
  const appData = await temporaryAppData(context);
  const transactionId = "f".repeat(32);
  let journal = await createTransactionJournal(appData, transactionId);
  journal = await appendJournalTransition(
    journal,
    "check",
    emptyJournalData(),
    1,
  );
  const temporary = path.join(journal.root, `.tmp-${"1".repeat(32)}`);
  await writeFile(temporary, "partial");
  const loaded = await loadTransactionJournal(appData, transactionId);
  assert.equal(loaded.records.length, 1);
  assert.deepEqual(loaded.orphanTemporaryFiles, [temporary]);
});

test("unknown transaction files and IDs are rejected", async (context) => {
  const appData = await temporaryAppData(context);
  const transactionId = "2".repeat(32);
  const journal = await createTransactionJournal(appData, transactionId);
  await writeFile(path.join(journal.root, "unexpected"), "x");
  await assert.rejects(
    loadTransactionJournal(appData, transactionId),
    isUpdateError("GOAT_UPDATE_RECOVERY_REQUIRED"),
  );
  await assert.rejects(
    loadTransactionJournal(appData, "../escape"),
    isUpdateError("GOAT_UPDATE_RECOVERY_REQUIRED"),
  );
});

test("journal timestamps are monotonic", async (context) => {
  const appData = await temporaryAppData(context);
  let journal = await createTransactionJournal(appData, "3".repeat(32));
  journal = await appendJournalTransition(
    journal,
    "check",
    emptyJournalData(),
    5,
  );
  await assert.rejects(
    appendJournalTransition(journal, "fetch-manifest", emptyJournalData(), 4),
    isUpdateError("GOAT_UPDATE_RECOVERY_REQUIRED"),
  );
});

async function temporaryAppData(context: test.TestContext): Promise<string> {
  const root = await mkdtemp(path.join(os.tmpdir(), "goat-journal-test-"));
  context.after(() => rm(root, { recursive: true, force: true }));
  return root;
}

function isUpdateError(code: UpdateError["code"]): (error: unknown) => boolean {
  return (error) => error instanceof UpdateError && error.code === code;
}
