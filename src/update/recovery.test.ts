import assert from "node:assert/strict";
import {
  lstat,
  mkdtemp,
  mkdir,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  createTestBundleTrust,
  createTestUpdateBundle,
  type TestUpdateBundle,
} from "../../test/v0.4.0-update/update-bundle-fixture.js";
import {
  loadActivationChain,
  slotRoot,
  type LoadedActivationRecord,
} from "./activation-record.js";
import {
  activateCandidate,
  validateInstalledActivation,
  type ValidatedInstalledActivation,
} from "./activation.js";
import { disposeHeldArtifact } from "./download.js";
import { UpdateError } from "./errors.js";
import { runEngineHealthCheck } from "./health.js";
import {
  appendJournalTransition,
  UPDATE_PHASES,
  createTransactionJournal,
  emptyJournalData,
  loadTransactionJournal,
  type JournalData,
  type TransactionJournal,
} from "./journal.js";
import {
  authenticateAndAppendMetadataCheckpoint,
  loadMetadataCheckpointChain,
} from "./metadata-checkpoint.js";
import { recoverInstallation } from "./recovery.js";
import {
  appendUpdaterState,
  initialUpdaterState,
  initializeUpdaterState,
  loadUpdaterState,
  stateAfterAuthentication,
  stateAfterMetadataRefresh,
} from "./state.js";
import {
  cleanupUpdateTransaction,
  createUpdateTransactionPaths,
} from "./temporary.js";

test("missing anti-downgrade state is reconstructed from authenticated receipts", async (context) => {
  const fixture = await twoInstalledReleases(context);
  assert.equal(await loadUpdaterState(fixture.appData), null);

  const recovered = await recoverInstallation({
    appDataDirectory: fixture.appData,
    policy: fixture.second.activationPolicy,
    now: () => 500,
  });

  assert.equal(recovered.status, "ready");
  assert.equal(recovered.quarantinedStatePath, null);
  assert.equal(recovered.state?.record.maxAuthenticatedReleaseSequence, 2);
  assert.equal(recovered.state?.record.maxActivatedReleaseSequence, 2);
  assert.equal(recovered.state?.record.currentActivationGeneration, 2);
  assert.equal(recovered.state?.record.previousActivationGeneration, 1);
  assert.equal(recovered.active?.activation.record.releaseSequence, 2);
  await assertLaunchable(recovered.active, fixture.second);
});

test("corrupt anti-downgrade state is quarantined and reconstructed without lowering floors", async (context) => {
  const fixture = await twoInstalledReleases(context);
  const initial = await recoverInstallation({
    appDataDirectory: fixture.appData,
    policy: fixture.second.activationPolicy,
  });
  assert.ok(initial.state);
  await writeFile(initial.state.path, "{}");

  const recovered = await recoverInstallation({
    appDataDirectory: fixture.appData,
    policy: fixture.second.activationPolicy,
  });

  assert.equal(recovered.status, "ready");
  assert.ok(recovered.quarantinedStatePath);
  assert.ok((await lstat(recovered.quarantinedStatePath)).isDirectory());
  assert.equal(recovered.state?.record.maxAuthenticatedReleaseSequence, 2);
  assert.equal(recovered.state?.record.maxActivatedReleaseSequence, 2);
  assert.equal(recovered.active?.activation.record.releaseSequence, 2);
  await assertLaunchable(recovered.active, fixture.second);
});

test("recovery persists an authenticated checkpoint left one transition ahead of state", async (context) => {
  const appData = await temporaryAppData(context);
  const initial = await initializeUpdaterState(appData, initialUpdaterState());
  const bundle = await createTestUpdateBundle(context, { appData });
  const checkpointed = await appendBundleCheckpoint(bundle);
  assert.equal(initial.record.metadataCheckpointGeneration, 0);
  assert.equal(checkpointed.chain.head.generation, 1);

  const recovered = await recoverInstallation({
    appDataDirectory: appData,
    policy: bundle.activationPolicy,
  });

  assert.equal(recovered.status, "ready");
  assert.equal(
    recovered.state?.record.metadataCheckpointGeneration,
    checkpointed.chain.head.generation,
  );
  assert.equal(
    recovered.state?.record.metadataCheckpointSha256,
    checkpointed.chain.head.sha256,
  );
  assert.equal(recovered.state?.record.maxAuthenticatedReleaseSequence, 1);
  assert.equal(recovered.state?.record.maxActivatedReleaseSequence, 0);
  assert.equal(
    recovered.state?.record.generation,
    initial.record.generation + 2,
  );

  const repeated = await recoverInstallation({
    appDataDirectory: appData,
    policy: bundle.activationPolicy,
  });
  assert.equal(
    repeated.state?.record.generation,
    recovered.state?.record.generation,
  );
});

test("recovery appends a durable receipt left one transition ahead of authenticated release state", async (context) => {
  const appData = await temporaryAppData(context);
  let state = await initializeUpdaterState(appData, initialUpdaterState());
  const bundle = await createTestUpdateBundle(context, { appData });
  const checkpointed = await appendBundleCheckpoint(bundle);
  state = await appendUpdaterState(
    appData,
    state,
    stateAfterMetadataRefresh(state.record, {
      trustedMetadata: checkpointed.authenticated.nextState,
      checkpoint: checkpointed.chain.head,
    }),
  );
  assert.equal(state.record.maxAuthenticatedReleaseSequence, 0);

  const recovered = await recoverInstallation({
    appDataDirectory: appData,
    policy: bundle.activationPolicy,
  });

  assert.equal(recovered.status, "ready");
  assert.equal(recovered.state?.record.generation, state.record.generation + 1);
  assert.equal(recovered.state?.record.maxAuthenticatedReleaseSequence, 1);
  assert.deepEqual(recovered.state?.record.receiptDigests, [
    bundle.receipt.receiptSha256,
  ]);
  assert.deepEqual(recovered.state?.record.knownReleases, [
    bundle.receipt.release,
  ]);
});

test("empty journal and pre-journal transaction directories recover idempotently", async (context) => {
  const bundle = await createTestUpdateBundle(context);
  await disposeHeldArtifact(bundle.artifact);
  await cleanupUpdateTransaction(bundle.transaction);
  await rm(bundle.receipt.path, { force: true });

  const journalTransaction = await createUpdateTransactionPaths(bundle.appData);
  const emptyJournal = await createTransactionJournal(
    bundle.appData,
    journalTransaction.transactionId,
  );
  assert.equal(emptyJournal.records.length, 0);
  const preJournalTransaction = await createUpdateTransactionPaths(
    bundle.appData,
  );

  const recovered = await recoverInstallation({
    appDataDirectory: bundle.appData,
    policy: bundle.activationPolicy,
    now: () => 10,
  });

  assert.equal(recovered.status, "pristine");
  assert.deepEqual(recovered.recoveredTransactionIds, [
    journalTransaction.transactionId,
  ]);
  const completed = await loadTransactionJournal(
    bundle.appData,
    journalTransaction.transactionId,
  );
  assert.deepEqual(
    completed.records.map((entry) => entry.record.phase),
    ["check", "recover"],
  );
  await assert.rejects(lstat(journalTransaction.transactionRoot), {
    code: "ENOENT",
  });
  await assert.rejects(lstat(preJournalTransaction.transactionRoot), {
    code: "ENOENT",
  });

  const repeated = await recoverInstallation({
    appDataDirectory: bundle.appData,
    policy: bundle.activationPolicy,
    now: () => 11,
  });
  assert.deepEqual(repeated.recoveredTransactionIds, []);
  assert.equal(
    (
      await loadTransactionJournal(
        bundle.appData,
        journalTransaction.transactionId,
      )
    ).records.length,
    completed.records.length,
  );
});

test("recovery removes only recognized immutable-record temporary files after validating every store", async (context) => {
  const fixture = await oneInstalledRelease(context);
  const initial = await recoverInstallation({
    appDataDirectory: fixture.appData,
    policy: fixture.bundle.activationPolicy,
  });
  assert.ok(initial.state);

  let journal = await createTransactionJournal(fixture.appData, "7".repeat(32));
  journal = await appendJournalTransition(
    journal,
    "check",
    emptyJournalData(),
    1,
  );
  const temporaryFiles = [
    path.join(path.dirname(initial.state.path), `.tmp-${"1".repeat(32)}`),
    path.join(
      path.dirname(fixture.bundle.receipt.path),
      `.tmp-${"2".repeat(32)}`,
    ),
    path.join(journal.root, `.tmp-${"3".repeat(32)}`),
    path.join(path.dirname(fixture.activation.path), `.tmp-${"4".repeat(32)}`),
  ];
  for (const temporary of temporaryFiles) {
    await writeFile(temporary, "interrupted immutable write", { flag: "wx" });
  }

  const recovered = await recoverInstallation({
    appDataDirectory: fixture.appData,
    policy: fixture.bundle.activationPolicy,
    now: () => 2,
  });

  assert.equal(recovered.status, "ready");
  assert.deepEqual(recovered.recoveredTransactionIds, ["7".repeat(32)]);
  assert.equal(recovered.active?.activation.sha256, fixture.activation.sha256);
  for (const temporary of temporaryFiles) {
    await assert.rejects(lstat(temporary), { code: "ENOENT" });
  }
  const repeated = await recoverInstallation({
    appDataDirectory: fixture.appData,
    policy: fixture.bundle.activationPolicy,
    now: () => 3,
  });
  assert.deepEqual(repeated.recoveredTransactionIds, []);
  assert.equal(repeated.active?.activation.sha256, fixture.activation.sha256);
});

test("corrupt current installation atomically rolls back to known-good material", async (context) => {
  const fixture = await twoInstalledReleases(context);
  await recoverInstallation({
    appDataDirectory: fixture.appData,
    policy: fixture.second.activationPolicy,
  });
  await writeFile(
    executablePath(fixture.appData, fixture.secondActivation),
    "corrupt current engine",
  );

  const recovered = await recoverInstallation({
    appDataDirectory: fixture.appData,
    policy: fixture.second.activationPolicy,
    now: () => 600,
  });

  assert.equal(recovered.status, "rolled-back");
  assert.equal(recovered.active?.activation.record.releaseSequence, 1);
  assert.equal(recovered.state?.record.maxAuthenticatedReleaseSequence, 2);
  assert.equal(recovered.state?.record.maxActivatedReleaseSequence, 2);
  assert.equal(recovered.state?.record.currentActivationGeneration, 3);
  const chain = await loadActivationChain(
    fixture.appData,
    fixture.first.platform,
    fixture.first.architecture,
  );
  assert.equal(chain.current?.record.reason, "automatic-rollback");
  assert.equal(chain.current?.record.releaseSequence, 1);
  await assertLaunchable(recovered.active, fixture.first);
});

test("a corrupt journal blocks recovery before changing the active installation", async (context) => {
  const fixture = await oneInstalledRelease(context);
  await recoverInstallation({
    appDataDirectory: fixture.appData,
    policy: fixture.bundle.activationPolicy,
  });
  let journal = await createTransactionJournal(fixture.appData, "a".repeat(32));
  journal = await appendJournalTransition(
    journal,
    "check",
    emptyJournalData(),
    1,
  );
  const bytes = await readFile(journal.records[0]!.path);
  bytes[bytes.length - 1] ^= 1;
  await writeFile(journal.records[0]!.path, bytes);

  await assert.rejects(
    recoverInstallation({
      appDataDirectory: fixture.appData,
      policy: fixture.bundle.activationPolicy,
    }),
    isUpdateError("GOAT_UPDATE_RECOVERY_REQUIRED"),
  );
  const chain = await loadActivationChain(
    fixture.appData,
    fixture.bundle.platform,
    fixture.bundle.architecture,
  );
  assert.equal(chain.current?.sha256, fixture.activation.sha256);
  const active = await validateInstalledActivation(
    fixture.appData,
    fixture.activation,
    fixture.bundle.activationPolicy,
  );
  await assertLaunchable(active, fixture.bundle);
});

test("recovery completes state after an activation-record commit interruption", async (context) => {
  const appData = await temporaryAppData(context);
  let state = await initializeUpdaterState(appData, initialUpdaterState());
  const bundle = await createTestUpdateBundle(context, { appData });
  state = await appendUpdaterState(
    bundle.appData,
    state,
    stateAfterAuthentication(state.record, {
      release: bundle.receipt.release,
      receiptSha256: bundle.receipt.receiptSha256,
    }),
  );
  const activated = await activateCandidate({
    appDataDirectory: bundle.appData,
    staged: bundle.staged,
    receiptSha256: bundle.receipt.receiptSha256,
    policy: bundle.activationPolicy,
  });
  assert.equal(state.record.currentActivationGeneration, null);

  const recovered = await recoverInstallation({
    appDataDirectory: bundle.appData,
    policy: bundle.activationPolicy,
  });

  assert.equal(recovered.status, "ready");
  assert.equal(recovered.state?.record.currentActivationGeneration, 1);
  assert.equal(recovered.state?.record.maxActivatedReleaseSequence, 1);
  assert.equal(
    recovered.active?.activation.sha256,
    activated.activation.sha256,
  );
  await assertLaunchable(recovered.active, bundle);
});

test("recovery durably closes the exact J12 plus activation-record crash gap", async (context) => {
  const bundle = await createTestUpdateBundle(context);
  const transactionId = "d".repeat(32);
  let journal = await createTransactionJournal(bundle.appData, transactionId);
  journal = await appendJournalPrefix(journal, 8, {
    releaseSequence: bundle.receipt.release.releaseSequence,
    receiptSha256: bundle.receipt.receiptSha256,
  });
  let data: JournalData = {
    ...emptyJournalData(),
    releaseSequence: bundle.receipt.release.releaseSequence,
    receiptSha256: bundle.receipt.receiptSha256,
  };
  class CrashAfterActivationRecord extends Error {}

  await assert.rejects(
    activateCandidate({
      appDataDirectory: bundle.appData,
      staged: bundle.staged,
      receiptSha256: bundle.receipt.receiptSha256,
      policy: bundle.activationPolicy,
      transactionId,
      observer: {
        preparedRollback: async () => {
          journal = await appendJournalTransition(
            journal,
            "prepare-rollback",
            data,
            9,
          );
        },
        preparedActivation: async (slotName) => {
          data = { ...data, slotName };
          journal = await appendJournalTransition(
            journal,
            "prepare-activation",
            data,
            10,
          );
        },
        provisionalSlotPlaced: async () => {
          journal = await appendJournalTransition(
            journal,
            "place-provisional-slot",
            data,
            11,
          );
        },
        provisionalSlotValidated: async (_slotName, slotSealSha256) => {
          data = { ...data, slotSealSha256 };
          journal = await appendJournalTransition(
            journal,
            "validate-provisional-slot",
            data,
            12,
          );
        },
        activationCommitted: () => {
          throw new CrashAfterActivationRecord();
        },
      },
    }),
    (error) => error instanceof CrashAfterActivationRecord,
  );

  const interrupted = await loadTransactionJournal(
    bundle.appData,
    transactionId,
  );
  assert.equal(
    interrupted.records.at(-1)?.record.phase,
    "validate-provisional-slot",
  );
  const committedChain = await loadActivationChain(
    bundle.appData,
    bundle.platform,
    bundle.architecture,
  );
  assert.equal(committedChain.records.length, 1);
  assert.equal(
    committedChain.current?.record.slotSealSha256,
    interrupted.records.at(-1)?.record.data.slotSealSha256,
  );

  const recovered = await recoverInstallation({
    appDataDirectory: bundle.appData,
    policy: bundle.activationPolicy,
    now: () => 20,
  });
  assert.equal(recovered.status, "ready");
  assert.deepEqual(recovered.recoveredTransactionIds, [transactionId]);
  assert.equal(
    recovered.active?.activation.sha256,
    committedChain.current?.sha256,
  );
  const completed = await loadTransactionJournal(bundle.appData, transactionId);
  assert.deepEqual(
    completed.records.slice(-2).map((entry) => entry.record.phase),
    ["commit-activation", "recover"],
  );
  assert.equal(
    completed.records.at(-2)?.record.data.activationGeneration,
    committedChain.current?.record.generation,
  );

  const repeated = await recoverInstallation({
    appDataDirectory: bundle.appData,
    policy: bundle.activationPolicy,
    now: () => 21,
  });
  assert.deepEqual(repeated.recoveredTransactionIds, []);
  assert.equal(
    (await loadTransactionJournal(bundle.appData, transactionId)).records
      .length,
    completed.records.length,
  );
});

test("a journal-to-activation seal mismatch fails before recovery mutation", async (context) => {
  const fixture = await oneInstalledRelease(context);
  await recoverInstallation({
    appDataDirectory: fixture.appData,
    policy: fixture.bundle.activationPolicy,
  });
  const transactionId = "e".repeat(32);
  const record = fixture.activation.record;
  const mismatchedSeal = `${record.slotSealSha256[0] === "f" ? "e" : "f"}${record.slotSealSha256.slice(1)}`;
  let journal = await createTransactionJournal(fixture.appData, transactionId);
  journal = await appendJournalPrefix(journal, 12, {
    releaseSequence: record.releaseSequence,
    receiptSha256: record.receiptSha256,
    slotName: record.slotName,
    slotSealSha256: mismatchedSeal,
  });

  await assert.rejects(
    recoverInstallation({
      appDataDirectory: fixture.appData,
      policy: fixture.bundle.activationPolicy,
    }),
    isUpdateError("GOAT_UPDATE_RECOVERY_REQUIRED"),
  );
  const unchanged = await loadTransactionJournal(
    fixture.appData,
    transactionId,
  );
  assert.equal(unchanged.records.length, 12);
  assert.equal(
    unchanged.records.at(-1)?.record.phase,
    "validate-provisional-slot",
  );
  assert.equal(
    (
      await loadActivationChain(
        fixture.appData,
        fixture.bundle.platform,
        fixture.bundle.architecture,
      )
    ).current?.sha256,
    fixture.activation.sha256,
  );
});

test("multiple nonterminal transactions are rejected before either can mutate", async (context) => {
  const fixture = await oneInstalledRelease(context);
  const transactionIds = ["f".repeat(32), "1".repeat(32)] as const;
  for (const transactionId of transactionIds) {
    let journal = await createTransactionJournal(
      fixture.appData,
      transactionId,
    );
    journal = await appendJournalTransition(
      journal,
      "check",
      emptyJournalData(),
      1,
    );
  }

  await assert.rejects(
    recoverInstallation({
      appDataDirectory: fixture.appData,
      policy: fixture.bundle.activationPolicy,
    }),
    isUpdateError("GOAT_UPDATE_RECOVERY_REQUIRED"),
  );
  for (const transactionId of transactionIds) {
    const journal = await loadTransactionJournal(
      fixture.appData,
      transactionId,
    );
    assert.equal(journal.records.length, 1);
    assert.equal(journal.records[0]?.record.phase, "check");
  }
});
test("incomplete provisional activation is removed and the prior installation remains launchable", async (context) => {
  const fixture = await oneInstalledRelease(context);
  await recoverInstallation({
    appDataDirectory: fixture.appData,
    policy: fixture.bundle.activationPolicy,
  });
  const provisionalSlotName = "2-0.4.1-aaaaaaaaaaaa";
  const provisionalRoot = path.join(
    fixture.appData,
    "engines",
    "beta",
    `${fixture.bundle.platform}-${fixture.bundle.architecture}`,
    "releases",
    provisionalSlotName,
  );
  await mkdir(provisionalRoot, { recursive: true });
  const pendingRoot = path.join(
    path.dirname(provisionalRoot),
    `.pending-${"c".repeat(32)}-${provisionalSlotName}`,
  );
  await mkdir(pendingRoot, { recursive: true });
  let data = emptyJournalData();
  let journal = await createTransactionJournal(fixture.appData, "c".repeat(32));
  const phases = [
    "check",
    "fetch-manifest",
    "authenticate-manifest",
    "select-artifact",
    "download-artifact",
    "verify-artifact",
    "stage-archive",
    "check-compatibility",
    "prepare-rollback",
    "prepare-activation",
    "place-provisional-slot",
  ] as const;
  for (let index = 0; index < phases.length; index += 1) {
    const transition = index + 1;
    if (transition === 3) data = { ...data, releaseSequence: 2 };
    if (transition === 6) data = { ...data, receiptSha256: "b".repeat(64) };
    if (transition === 10) data = { ...data, slotName: provisionalSlotName };
    journal = await appendJournalTransition(journal, phases[index]!, data, 10);
  }

  const recovered = await recoverInstallation({
    appDataDirectory: fixture.appData,
    policy: fixture.bundle.activationPolicy,
    now: () => 20,
  });

  await assert.rejects(lstat(provisionalRoot), { code: "ENOENT" });
  await assert.rejects(lstat(pendingRoot), { code: "ENOENT" });
  assert.deepEqual(recovered.recoveredTransactionIds, ["c".repeat(32)]);
  assert.equal(recovered.active?.activation.sha256, fixture.activation.sha256);
  await assertLaunchable(recovered.active, fixture.bundle);
});

test("a final slot durable after J10 but before J11 is removed as uncommitted", async (context) => {
  const fixture = await oneInstalledRelease(context);
  await recoverInstallation({
    appDataDirectory: fixture.appData,
    policy: fixture.bundle.activationPolicy,
  });
  const orphanRoot = path.join(
    fixture.appData,
    "engines",
    "beta",
    `${fixture.bundle.platform}-${fixture.bundle.architecture}`,
    "releases",
    "2-0.4.1-bbbbbbbbbbbb",
  );
  await mkdir(orphanRoot, { recursive: true });
  const transactionId = "b".repeat(32);
  let journal = await createTransactionJournal(fixture.appData, transactionId);
  journal = await appendJournalPrefix(journal, 10, {
    releaseSequence: 2,
    receiptSha256: "c".repeat(64),
    slotName: path.basename(orphanRoot),
  });
  assert.equal(journal.records.at(-1)?.record.phase, "prepare-activation");

  const recovered = await recoverInstallation({
    appDataDirectory: fixture.appData,
    policy: fixture.bundle.activationPolicy,
  });

  await assert.rejects(lstat(orphanRoot), { code: "ENOENT" });
  assert.deepEqual(recovered.recoveredTransactionIds, [transactionId]);
  assert.equal(recovered.active?.activation.sha256, fixture.activation.sha256);
  await assertLaunchable(recovered.active, fixture.bundle);
});

test("corrupt current and rollback copies fail closed without selecting either", async (context) => {
  const fixture = await twoInstalledReleases(context);
  await recoverInstallation({
    appDataDirectory: fixture.appData,
    policy: fixture.second.activationPolicy,
  });
  await writeFile(
    executablePath(fixture.appData, fixture.secondActivation),
    "corrupt current",
  );
  await writeFile(
    executablePath(fixture.appData, fixture.firstActivation),
    "corrupt rollback",
  );

  await assert.rejects(
    recoverInstallation({
      appDataDirectory: fixture.appData,
      policy: fixture.second.activationPolicy,
    }),
    isUpdateError("GOAT_UPDATE_RECOVERY_REQUIRED"),
  );
  const chain = await loadActivationChain(
    fixture.appData,
    fixture.first.platform,
    fixture.first.architecture,
  );
  assert.equal(chain.records.length, 2);
  assert.equal(chain.current?.record.releaseSequence, 2);
});

interface JournalPrefixIdentity {
  readonly releaseSequence: number;
  readonly receiptSha256: string;
  readonly slotName?: string;
  readonly slotSealSha256?: string;
  readonly activationGeneration?: number;
}

async function appendJournalPrefix(
  journal: TransactionJournal,
  throughTransition: number,
  identity: JournalPrefixIdentity,
): Promise<TransactionJournal> {
  let data = emptyJournalData();
  for (let transition = 1; transition <= throughTransition; transition += 1) {
    if (transition === 3) {
      data = { ...data, releaseSequence: identity.releaseSequence };
    }
    if (transition === 6) {
      data = { ...data, receiptSha256: identity.receiptSha256 };
    }
    if (transition === 10) {
      assert.ok(identity.slotName);
      data = { ...data, slotName: identity.slotName };
    }
    if (transition === 12) {
      assert.ok(identity.slotSealSha256);
      data = { ...data, slotSealSha256: identity.slotSealSha256 };
    }
    if (transition === 13) {
      assert.ok(identity.activationGeneration);
      data = {
        ...data,
        activationGeneration: identity.activationGeneration,
      };
    }
    journal = await appendJournalTransition(
      journal,
      UPDATE_PHASES[transition - 1]!,
      data,
      transition,
    );
  }
  return journal;
}

async function appendBundleCheckpoint(bundle: TestUpdateBundle) {
  const current = await loadMetadataCheckpointChain(
    bundle.appData,
    bundle.receiptPolicy,
  );
  return authenticateAndAppendMetadataCheckpoint({
    appDataDirectory: bundle.appData,
    current,
    metadata: {
      sequentialRoots: [],
      timestamp: bundle.tuf.timestamp,
      snapshot: bundle.tuf.snapshot,
      targets: bundle.tuf.targets,
      channel: bundle.tuf.channels[bundle.channel],
      channelName: bundle.channel,
    },
    policy: bundle.receiptPolicy,
    nowUnixMs: bundle.receipt.record.authenticatedAtUnixMs,
  });
}

async function oneInstalledRelease(context: test.TestContext) {
  const bundle = await createTestUpdateBundle(context);
  const activated = await activateCandidate({
    appDataDirectory: bundle.appData,
    staged: bundle.staged,
    receiptSha256: bundle.receipt.receiptSha256,
    policy: bundle.activationPolicy,
  });
  return {
    appData: bundle.appData,
    bundle,
    activation: activated.activation,
  };
}

async function twoInstalledReleases(context: test.TestContext) {
  const trust = createTestBundleTrust();
  const first = await createTestUpdateBundle(context, {
    trust,
    channel: "stable",
    releaseSequence: 1,
  });
  const firstActivated = await activateCandidate({
    appDataDirectory: first.appData,
    staged: first.staged,
    receiptSha256: first.receipt.receiptSha256,
    policy: first.activationPolicy,
  });
  const second = await createTestUpdateBundle(context, {
    appData: first.appData,
    trust,
    channel: "beta",
    releaseSequence: 2,
  });
  const secondActivated = await activateCandidate({
    appDataDirectory: second.appData,
    staged: second.staged,
    receiptSha256: second.receipt.receiptSha256,
    policy: second.activationPolicy,
  });
  return {
    appData: first.appData,
    first,
    second,
    firstActivation: firstActivated.activation,
    secondActivation: secondActivated.activation,
  };
}

async function assertLaunchable(
  active: ValidatedInstalledActivation | null,
  bundle: TestUpdateBundle,
): Promise<void> {
  assert.ok(active);
  await runEngineHealthCheck({
    executablePath: active.candidate.executablePath,
    expectedVersion: active.candidate.manifest.goatEngineVersion,
    platform: bundle.platform,
    runCommand: bundle.runHealthCommand,
  });
}

function executablePath(
  appDataDirectory: string,
  activation: LoadedActivationRecord,
): string {
  return path.join(
    slotRoot(appDataDirectory, activation.record),
    activation.record.platform === "win32"
      ? "bin/goat-engine.exe"
      : "bin/goat-engine",
  );
}

function isUpdateError(code: UpdateError["code"]): (error: unknown) => boolean {
  return (error) => error instanceof UpdateError && error.code === code;
}

async function temporaryAppData(context: test.TestContext): Promise<string> {
  const root = await mkdtemp(path.join(os.tmpdir(), "goat-recovery-test-"));
  context.after(() => rm(root, { recursive: true, force: true }));
  return root;
}
