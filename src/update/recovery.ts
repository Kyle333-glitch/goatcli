import { randomBytes } from "node:crypto";
import path from "node:path";
import { lstat, readdir, realpath, rename, rm, unlink } from "node:fs/promises";
import {
  loadActivationChain,
  type ActivationChain,
  type LoadedActivationRecord,
} from "./activation-record.js";
import {
  cleanupSupersededSlots,
  validateInstalledActivation,
  type ActivationSecurityPolicy,
  type ValidatedInstalledActivation,
} from "./activation.js";
import {
  assertPrivateDirectory,
  ensurePrivateDirectory,
  syncDirectory,
} from "./durable.js";
import { UpdateError } from "./errors.js";
import {
  appendJournalTransition,
  emptyJournalData,
  listTransactionJournals,
  UPDATE_PHASES,
  type TransactionJournal,
  type JournalData,
} from "./journal.js";
import {
  cleanupMetadataCheckpointOrphans,
  loadMetadataCheckpointChain,
  type LoadedMetadataCheckpointChain,
} from "./metadata-checkpoint.js";
import {
  reconstructStateFromReceipts,
  listTargetReceiptOrphanTemporaryFiles,
  type ReceiptReconstruction,
  type ReceiptVerificationPolicy,
} from "./receipt.js";
import { performAutomaticRollback } from "./rollback.js";
import type { KnownReleaseIdentity } from "./selection.js";
import {
  appendUpdaterState,
  initialUpdaterState,
  initializeReconstructedUpdaterState,
  loadUpdaterState,
  listUpdaterStateOrphanTemporaryFiles,
  stateAfterActivation,
  stateAfterAutomaticRollback,
  type LoadedUpdaterState,
  stateAfterAuthentication,
  stateAfterMetadataRefresh,
  trustedMetadataFromState,
  type UpdaterStateRecord,
} from "./state.js";
import {
  emptyTrustedMetadataState,
  type TrustedMetadataState,
} from "./trust.js";

export interface RecoverInstallationOptions {
  readonly appDataDirectory: string;
  readonly policy: ActivationSecurityPolicy;
  readonly now?: () => number;
}

export interface RecoveryResult {
  readonly status: "pristine" | "ready" | "rolled-back";
  readonly state: LoadedUpdaterState | null;
  readonly active: ValidatedInstalledActivation | null;
  readonly recoveredTransactionIds: readonly string[];
  readonly quarantinedStatePath: string | null;
}

type JournalRecoveryAction =
  "empty" | "terminal" | "precommit" | "commit-gap" | "committed";

interface PlannedJournalRecovery {
  readonly journal: TransactionJournal;
  readonly action: JournalRecoveryAction;
  readonly activation: LoadedActivationRecord | null;
}

interface VerifiedReceiptAdvance {
  readonly release: KnownReleaseIdentity;
  readonly receiptSha256: string;
}

export interface EffectiveCheckpointState {
  readonly record: UpdaterStateRecord;
  readonly requiresPersistence: boolean;
}

export async function recoverInstallation(
  options: RecoverInstallationOptions,
): Promise<RecoveryResult> {
  const appData = path.resolve(options.appDataDirectory);
  const now = options.now ?? Date.now;

  // Phase one is deliberately read-only. Every durable authority is loaded and
  // cross-checked before recovery is allowed to change any of them.
  const journals = await listTransactionJournals(appData);
  const chain = await loadActivationChain(
    appData,
    options.policy.receipt.platform,
    options.policy.receipt.architecture,
  );
  let recoveryPlan = planJournalRecovery(journals, chain);
  let checkpoints = await loadMetadataCheckpointChain(
    appData,
    options.policy.receipt,
  );

  let loadedState: LoadedUpdaterState | null = null;
  let stateLoadError: unknown;
  try {
    loadedState = await loadUpdaterState(appData);
  } catch (error) {
    stateLoadError = error;
  }

  const { currentRevocations: _ignored, ...receiptPolicy } =
    options.policy.receipt;
  const reconstruction = await reconstructStateFromReceipts(
    appData,
    receiptPolicy,
  );
  const receiptTemporaryFiles =
    await listTargetReceiptOrphanTemporaryFiles(appData);
  if (
    reconstruction &&
    !samePaths(reconstruction.orphanTemporaryFiles, receiptTemporaryFiles)
  ) {
    throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
  }
  const stateTemporaryFiles =
    await listUpdaterStateOrphanTemporaryFiles(appData);
  const interruptedTemporaryDirectories =
    await listInterruptedTemporaryDirectories(appData);

  if (reconstruction) {
    validateReconstructionAgainstActivationChain(reconstruction, chain);
    validateCheckpointCoversReceipts(checkpoints, reconstruction);
  } else if (chain.records.length !== 0) {
    throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
  }

  let checkpointState: EffectiveCheckpointState | null = null;
  let receiptAdvances: readonly VerifiedReceiptAdvance[] = [];
  let reconstructed: Omit<
    UpdaterStateRecord,
    "generation" | "previousSha256"
  > | null = null;
  if (loadedState) {
    checkpointState = effectiveStateForMetadataCheckpoint(
      loadedState.record,
      checkpoints,
    );
    receiptAdvances = planReceiptStateAdvances(
      loadedState.record,
      reconstruction,
    );
  } else if (checkpoints.head.generation !== 0 || reconstruction !== null) {
    reconstructed = reconstructedStateRecord(
      reconstruction,
      checkpoints,
      chain,
    );
  } else if (stateLoadError !== undefined) {
    throw new UpdateError("GOAT_UPDATE_STATE_INVALID", {
      cause: stateLoadError,
    });
  }

  // Phase two only materializes states already proven to be unambiguous.
  recoveryPlan = await materializeEmptyJournals(recoveryPlan, now);
  recoveryPlan = await materializeActivationCommitGaps(recoveryPlan);
  checkpoints = await cleanupMetadataCheckpointOrphans(
    appData,
    checkpoints,
    options.policy.receipt,
  );
  await cleanupRecognizedTemporaryFiles(
    appData,
    [
      ...journals.flatMap((journal) => journal.orphanTemporaryFiles),
      ...chain.orphanTemporaryFiles,
      ...stateTemporaryFiles,
      ...receiptTemporaryFiles,
    ],
    options.policy.receipt,
  );
  await cleanupInterruptedTemporaryDirectories(
    appData,
    interruptedTemporaryDirectories,
  );
  await verifyRecoveryCleanup(
    appData,
    recoveryPlan,
    chain,
    checkpoints,
    options.policy.receipt,
  );

  let quarantinedStatePath: string | null = null;
  if (stateLoadError !== undefined) {
    if (!reconstructed) throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
    quarantinedStatePath = await quarantineCorruptState(appData);
    loadedState = await initializeReconstructedUpdaterState(
      appData,
      reconstructed,
    );
  } else if (!loadedState && reconstructed) {
    loadedState = await initializeReconstructedUpdaterState(
      appData,
      reconstructed,
    );
  } else if (loadedState && checkpointState) {
    if (checkpointState.requiresPersistence) {
      loadedState = await appendUpdaterState(
        appData,
        loadedState,
        stateAfterMetadataRefresh(loadedState.record, {
          trustedMetadata: checkpoints.trustedMetadata,
          checkpoint: checkpoints.head,
        }),
      );
    }
    for (const advance of receiptAdvances) {
      loadedState = await appendUpdaterState(
        appData,
        loadedState,
        stateAfterAuthentication(loadedState.record, advance),
      );
    }
  }

  if (!loadedState) {
    if (chain.records.length !== 0) {
      throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
    }
    const recoveredTransactionIds = await recoverJournals(
      appData,
      recoveryPlan,
      chain,
      options.policy.receipt.platform,
      options.policy.receipt.architecture,
      now,
    );
    await cleanupSupersededSlots(
      appData,
      chain,
      options.policy.receipt.platform,
      options.policy.receipt.architecture,
    );
    return {
      status: "pristine",
      state: null,
      active: null,
      recoveredTransactionIds,
      quarantinedStatePath,
    };
  }

  loadedState = await synchronizeStateWithActivationChain(
    appData,
    loadedState,
    chain,
  );
  let effectivePolicy = activationPolicyForState(
    options.policy,
    loadedState.record,
  );
  let active: ValidatedInstalledActivation | null = null;
  let status: RecoveryResult["status"] = "ready";
  if (chain.current) {
    try {
      active = await validateInstalledActivation(
        appData,
        chain.current,
        effectivePolicy,
      );
    } catch (currentError) {
      try {
        const rolledBack = await performAutomaticRollback({
          appDataDirectory: appData,
          state: loadedState,
          policy: effectivePolicy,
          committedAtUnixMs: checkedNow(now()),
        });
        loadedState = rolledBack.state;
        active = rolledBack.validatedSource;
        status = "rolled-back";
        effectivePolicy = activationPolicyForState(
          options.policy,
          loadedState.record,
        );
      } catch (rollbackError) {
        throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED", {
          cause: new AggregateError(
            [currentError, rollbackError],
            "No valid current or rollback activation",
          ),
        });
      }
    }
  } else if (loadedState.record.currentActivationGeneration !== null) {
    throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
  }

  const currentChain = await loadActivationChain(
    appData,
    effectivePolicy.receipt.platform,
    effectivePolicy.receipt.architecture,
  );
  const recoveredTransactionIds = await recoverJournals(
    appData,
    recoveryPlan,
    currentChain,
    effectivePolicy.receipt.platform,
    effectivePolicy.receipt.architecture,
    now,
  );
  await cleanupSupersededSlots(
    appData,
    currentChain,
    effectivePolicy.receipt.platform,
    effectivePolicy.receipt.architecture,
  );
  return {
    status,
    state: loadedState,
    active,
    recoveredTransactionIds,
    quarantinedStatePath,
  };
}

const TRUSTED_METADATA_ROLES = [
  "root",
  "timestamp",
  "snapshot",
  "targets",
  "stable",
  "beta",
  "development",
] as const;

export function effectiveStateForMetadataCheckpoint(
  state: UpdaterStateRecord,
  checkpoints: LoadedMetadataCheckpointChain,
): EffectiveCheckpointState {
  if (checkpoints.head.generation === 0) {
    if (
      state.metadataCheckpointGeneration !== 0 ||
      state.metadataCheckpointSha256 !== null
    ) {
      throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
    }
    return { record: state, requiresPersistence: false };
  }

  const current = checkpoints.current;
  if (!current || checkpoints.head.sha256 === null) {
    throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
  }
  if (
    state.metadataCheckpointGeneration === checkpoints.head.generation &&
    state.metadataCheckpointSha256 === checkpoints.head.sha256
  ) {
    assertSameTrustedMetadata(
      trustedMetadataFromState(state),
      checkpoints.trustedMetadata,
    );
    return { record: state, requiresPersistence: false };
  }

  if (
    state.metadataCheckpointGeneration !== checkpoints.head.generation - 1 ||
    state.metadataCheckpointSha256 !== current.record.previousSha256
  ) {
    throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
  }
  const previousTrusted =
    checkpoints.records.at(-2)?.authenticated.nextState ??
    emptyTrustedMetadataState();
  assertSameTrustedMetadata(trustedMetadataFromState(state), previousTrusted);
  const refreshed = stateAfterMetadataRefresh(state, {
    trustedMetadata: checkpoints.trustedMetadata,
    checkpoint: checkpoints.head,
  });
  return {
    record: {
      ...refreshed,
      generation: state.generation,
      previousSha256: state.previousSha256,
    },
    requiresPersistence: true,
  };
}

function validateCheckpointCoversReceipts(
  checkpoints: LoadedMetadataCheckpointChain,
  reconstruction: ReceiptReconstruction,
): void {
  if (checkpoints.head.generation === 0) return;
  const checkpoint = checkpoints.trustedMetadata;
  const receipt = reconstruction.trustedMetadata;
  if (checkpoint.trustedTimeUnixMs < receipt.trustedTimeUnixMs) {
    throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
  }
  for (const role of TRUSTED_METADATA_ROLES) {
    const checkpointVersion = checkpoint.versions[role];
    const receiptVersion = receipt.versions[role];
    if (
      checkpointVersion < receiptVersion ||
      (checkpointVersion === receiptVersion &&
        checkpoint.digests[role] !== receipt.digests[role])
    ) {
      throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
    }
  }
  if (
    !isSuperset(checkpoint.revokedKeyIds, receipt.revokedKeyIds) ||
    !isSuperset(
      checkpoint.revokedArtifactSha256,
      receipt.revokedArtifactSha256,
    ) ||
    !isSuperset(
      checkpoint.revokedReleaseSequences,
      receipt.revokedReleaseSequences,
    )
  ) {
    throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
  }
}

function planReceiptStateAdvances(
  state: UpdaterStateRecord,
  reconstruction: ReceiptReconstruction | null,
): readonly VerifiedReceiptAdvance[] {
  if (!reconstruction) {
    if (
      state.maxAuthenticatedReleaseSequence !== 0 ||
      state.knownReleases.length !== 0 ||
      state.receiptDigests.length !== 0
    ) {
      throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
    }
    return [];
  }
  const persistedCount = state.knownReleases.length;
  if (persistedCount > reconstruction.verifiedReceipts.length) {
    throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
  }
  const expectedReleases = reconstruction.verifiedReceipts
    .slice(0, persistedCount)
    .map((receipt) => receipt.release);
  const expectedDigests = reconstruction.verifiedReceipts
    .slice(0, persistedCount)
    .map((receipt) => receipt.receiptSha256)
    .sort(asciiCompare);
  if (
    !sameReleases(state.knownReleases, expectedReleases) ||
    !samePaths(state.receiptDigests, expectedDigests)
  ) {
    throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
  }
  return reconstruction.verifiedReceipts
    .slice(persistedCount)
    .map((receipt) => ({
      release: receipt.release,
      receiptSha256: receipt.receiptSha256,
    }));
}

async function synchronizeStateWithActivationChain(
  appDataDirectory: string,
  state: LoadedUpdaterState,
  chain: ActivationChain,
): Promise<LoadedUpdaterState> {
  const stateGeneration = state.record.currentActivationGeneration ?? 0;
  const chainGeneration = chain.current?.record.generation ?? 0;
  if (stateGeneration > chainGeneration) {
    throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
  }
  let current = state;
  for (const activation of chain.records.slice(stateGeneration)) {
    const release = releaseIdentity(activation);
    if (activation.record.reason === "update") {
      current = await appendUpdaterState(
        appDataDirectory,
        current,
        stateAfterActivation(current.record, {
          activationGeneration: activation.record.generation,
          release,
          receiptSha256: activation.record.receiptSha256,
        }),
      );
    } else {
      current = await appendUpdaterState(
        appDataDirectory,
        current,
        stateAfterAutomaticRollback(current.record, {
          activationGeneration: activation.record.generation,
          release,
          receiptSha256: activation.record.receiptSha256,
        }),
      );
    }
  }
  if (
    (current.record.currentActivationGeneration ?? 0) !== chainGeneration ||
    (chain.current &&
      current.record.configuredChannel !== chain.current.record.channel)
  ) {
    throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
  }
  return current;
}

function planJournalRecovery(
  journals: readonly TransactionJournal[],
  chain: ActivationChain,
): readonly PlannedJournalRecovery[] {
  if (
    journals.filter(
      (journal) =>
        journal.records.length === 0 ||
        journal.records.at(-1)?.record.phase !== "recover",
    ).length > 1
  ) {
    throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
  }
  return journals.map((journal) => planSingleJournalRecovery(journal, chain));
}

function planSingleJournalRecovery(
  journal: TransactionJournal,
  chain: ActivationChain,
): PlannedJournalRecovery {
  const last = journal.records.at(-1);
  if (!last) {
    return { journal, action: "empty", activation: null };
  }
  const data = last.record.data;
  if (last.record.phase === "recover") {
    if (data.activationGeneration !== null) {
      const activation = chain.records.find(
        (entry) => entry.record.generation === data.activationGeneration,
      );
      if (!activation || !activationMatchesJournal(activation, data)) {
        throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
      }
    }
    return { journal, action: "terminal", activation: null };
  }

  const validateTransition =
    UPDATE_PHASES.indexOf("validate-provisional-slot") + 1;
  const commitTransition = UPDATE_PHASES.indexOf("commit-activation") + 1;
  if (validateTransition <= 0 || commitTransition !== validateTransition + 1) {
    throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
  }

  if (last.record.transition < validateTransition) {
    if (
      last.record.transition >=
        UPDATE_PHASES.indexOf("prepare-activation") + 1 &&
      relatedActivations(chain, data).length !== 0
    ) {
      throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
    }
    return { journal, action: "precommit", activation: null };
  }

  if (last.record.transition === validateTransition) {
    const related = relatedActivations(chain, data);
    if (related.length === 0) {
      return { journal, action: "precommit", activation: null };
    }
    if (related.length !== 1 || !activationMatchesJournal(related[0]!, data)) {
      throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
    }
    return { journal, action: "commit-gap", activation: related[0]! };
  }

  const generation = data.activationGeneration;
  const activation = chain.records.find(
    (entry) => entry.record.generation === generation,
  );
  if (!activation || !activationMatchesJournal(activation, data)) {
    throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
  }
  return { journal, action: "committed", activation };
}

function relatedActivations(
  chain: ActivationChain,
  data: JournalData,
): readonly LoadedActivationRecord[] {
  return chain.records.filter(
    (entry) =>
      entry.record.reason === "update" &&
      ((data.releaseSequence !== null &&
        entry.record.releaseSequence === data.releaseSequence) ||
        (data.receiptSha256 !== null &&
          entry.record.receiptSha256 === data.receiptSha256) ||
        (data.slotName !== null && entry.record.slotName === data.slotName)),
  );
}

function activationMatchesJournal(
  activation: LoadedActivationRecord,
  data: JournalData,
): boolean {
  return (
    activation.record.reason === "update" &&
    data.releaseSequence !== null &&
    activation.record.releaseSequence === data.releaseSequence &&
    data.receiptSha256 !== null &&
    activation.record.receiptSha256 === data.receiptSha256 &&
    data.slotName !== null &&
    activation.record.slotName === data.slotName &&
    data.slotSealSha256 !== null &&
    activation.record.slotSealSha256 === data.slotSealSha256 &&
    (data.activationGeneration === null ||
      activation.record.generation === data.activationGeneration)
  );
}

async function materializeEmptyJournals(
  plan: readonly PlannedJournalRecovery[],
  now: () => number,
): Promise<readonly PlannedJournalRecovery[]> {
  const materialized: PlannedJournalRecovery[] = [];
  for (const item of plan) {
    if (item.action !== "empty") {
      materialized.push(item);
      continue;
    }
    if (item.journal.records.length !== 0) {
      throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
    }
    const journal = await appendJournalTransition(
      item.journal,
      "check",
      emptyJournalData(),
      checkedNow(now()),
    );
    materialized.push({
      journal,
      action: "precommit",
      activation: null,
    });
  }
  return materialized;
}

async function materializeActivationCommitGaps(
  plan: readonly PlannedJournalRecovery[],
): Promise<readonly PlannedJournalRecovery[]> {
  const materialized: PlannedJournalRecovery[] = [];
  for (const item of plan) {
    if (item.action !== "commit-gap") {
      materialized.push(item);
      continue;
    }
    const last = item.journal.records.at(-1);
    if (!last || !item.activation) {
      throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
    }
    const journal = await appendJournalTransition(
      item.journal,
      "commit-activation",
      {
        ...last.record.data,
        activationGeneration: item.activation.record.generation,
      },
      last.record.recordedAtUnixMs,
    );
    materialized.push({
      journal,
      action: "committed",
      activation: item.activation,
    });
  }
  return materialized;
}

async function recoverJournals(
  appDataDirectory: string,
  plan: readonly PlannedJournalRecovery[],
  chain: ActivationChain,
  platform: "win32" | "darwin",
  architecture: "x64" | "arm64",
  now: () => number,
): Promise<readonly string[]> {
  const recovered: string[] = [];
  for (const item of plan) {
    if (item.action === "terminal") continue;
    if (item.action === "commit-gap") {
      throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
    }
    const last = item.journal.records.at(-1);
    if (!last) {
      throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
    }
    if (item.action === "precommit" && last.record.data.slotName) {
      await removeUncommittedProvisionalSlot(
        appDataDirectory,
        item.journal.transactionId,
        last.record.data.slotName,
        chain,
        platform,
        architecture,
      );
    }
    await removeInterruptedTemporaryDirectory(
      appDataDirectory,
      item.journal.transactionId,
    );
    await appendJournalTransition(
      item.journal,
      "recover",
      last.record.data,
      Math.max(checkedNow(now()), last.record.recordedAtUnixMs),
    );
    recovered.push(item.journal.transactionId);
  }
  return recovered.sort(asciiCompare);
}

async function removeUncommittedProvisionalSlot(
  appDataDirectory: string,
  transactionId: string,
  slotName: string,
  chain: ActivationChain,
  platform: "win32" | "darwin",
  architecture: "x64" | "arm64",
): Promise<void> {
  if (
    chain.records.some((entry) => entry.record.slotName === slotName) ||
    !/^[a-f0-9]{32}$/.test(transactionId) ||
    !/^\d+-[0-9A-Za-z.-]+-[a-f0-9]{12}$/.test(slotName)
  ) {
    throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
  }
  const pendingSlotName = `.pending-${transactionId}-${slotName}`;
  for (const channel of ["stable", "beta", "development"] as const) {
    const releaseDirectory = await canonicalReleaseDirectory(
      appDataDirectory,
      channel,
      platform,
      architecture,
    );
    if (!releaseDirectory) continue;
    for (const name of [pendingSlotName, slotName]) {
      const candidate = path.join(releaseDirectory, name);
      if (path.dirname(candidate) !== releaseDirectory) {
        throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
      }
      if (!(await removePrivateDirectoryIfPresent(candidate))) continue;
      await syncDirectory(releaseDirectory, "GOAT_UPDATE_RECOVERY_REQUIRED");
    }
  }
}

async function removeInterruptedTemporaryDirectory(
  appDataDirectory: string,
  transactionId: string,
): Promise<void> {
  if (!/^[a-f0-9]{32}$/.test(transactionId)) {
    throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
  }
  const temporaryRoot = path.join(
    path.resolve(appDataDirectory),
    "updates",
    "tmp",
  );
  if (!(await isPrivateDirectoryIfPresent(temporaryRoot))) return;
  const candidate = path.join(temporaryRoot, transactionId);
  if (path.dirname(candidate) !== temporaryRoot) {
    throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
  }
  if (await removePrivateDirectoryIfPresent(candidate)) {
    await syncDirectory(temporaryRoot, "GOAT_UPDATE_RECOVERY_REQUIRED");
  }
}

async function listInterruptedTemporaryDirectories(
  appDataDirectory: string,
): Promise<readonly string[]> {
  const root = path.join(path.resolve(appDataDirectory), "updates", "tmp");
  let entries;
  try {
    entries = await readdir(root, { withFileTypes: true });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED", { cause: error });
  }
  await assertPrivateDirectory(root, "GOAT_UPDATE_RECOVERY_REQUIRED");
  const directories: string[] = [];
  for (const entry of entries) {
    if (
      !entry.isDirectory() ||
      entry.isSymbolicLink() ||
      !/^[a-f0-9]{32}$/.test(entry.name)
    ) {
      throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
    }
    const candidate = path.join(root, entry.name);
    if (path.dirname(candidate) !== root) {
      throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
    }
    await assertPrivateDirectory(candidate, "GOAT_UPDATE_RECOVERY_REQUIRED");
    directories.push(candidate);
  }
  return directories.sort(asciiCompare);
}

async function cleanupInterruptedTemporaryDirectories(
  appDataDirectory: string,
  expected: readonly string[],
): Promise<void> {
  const actual = await listInterruptedTemporaryDirectories(appDataDirectory);
  if (!samePaths(actual, expected)) {
    throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
  }
  if (actual.length === 0) return;
  const root = path.join(path.resolve(appDataDirectory), "updates", "tmp");
  for (const candidate of actual) {
    if (
      path.dirname(candidate) !== root ||
      !/^[a-f0-9]{32}$/.test(path.basename(candidate)) ||
      !(await removePrivateDirectoryIfPresent(candidate))
    ) {
      throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
    }
    await syncDirectory(root, "GOAT_UPDATE_RECOVERY_REQUIRED");
  }
  if (
    (await listInterruptedTemporaryDirectories(appDataDirectory)).length !== 0
  ) {
    throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
  }
}

async function cleanupRecognizedTemporaryFiles(
  appDataDirectory: string,
  expected: readonly string[],
  policy: ReceiptVerificationPolicy,
): Promise<void> {
  const appData = path.resolve(appDataDirectory);
  const expectedSorted = [...expected].sort(asciiCompare);
  const actual = await listRecognizedTemporaryFiles(appData, policy);
  if (!samePaths(expectedSorted, actual)) {
    throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
  }
  const unique = [...new Set(expected)].sort(asciiCompare);
  if (unique.length !== expected.length) {
    throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
  }
  for (const candidate of unique) {
    const resolved = path.resolve(candidate);
    const relative = path.relative(appData, resolved);
    const parts = relative.split(path.sep);
    const name = parts.at(-1) ?? "";
    if (
      relative.length === 0 ||
      path.isAbsolute(relative) ||
      relative === ".." ||
      relative.startsWith(`..${path.sep}`) ||
      !/^\.tmp-[a-f0-9]{32}$/.test(name) ||
      !isRecognizedTemporaryPath(parts)
    ) {
      throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
    }
    const parent = path.dirname(resolved);
    await assertPrivateDirectory(parent, "GOAT_UPDATE_RECOVERY_REQUIRED");
    const stats = await lstat(resolved).catch((error) => {
      throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED", {
        cause: error,
      });
    });
    if (!stats.isFile() || stats.isSymbolicLink() || stats.nlink !== 1) {
      throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
    }
    const canonical = await realpath(resolved).catch((error) => {
      throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED", {
        cause: error,
      });
    });
    if (path.resolve(canonical) !== resolved) {
      throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
    }
    await unlink(resolved).catch((error) => {
      throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED", {
        cause: error,
      });
    });
    await syncDirectory(parent, "GOAT_UPDATE_RECOVERY_REQUIRED");
  }
}

async function listRecognizedTemporaryFiles(
  appDataDirectory: string,
  policy: ReceiptVerificationPolicy,
): Promise<readonly string[]> {
  const journals = await listTransactionJournals(appDataDirectory);
  const chain = await loadActivationChain(
    appDataDirectory,
    policy.platform,
    policy.architecture,
  );
  return [
    ...journals.flatMap((journal) => journal.orphanTemporaryFiles),
    ...chain.orphanTemporaryFiles,
    ...(await listUpdaterStateOrphanTemporaryFiles(appDataDirectory)),
    ...(await listTargetReceiptOrphanTemporaryFiles(appDataDirectory)),
  ].sort(asciiCompare);
}

function isRecognizedTemporaryPath(parts: readonly string[]): boolean {
  if (parts[0] === "updates") {
    if (
      parts.length === 3 &&
      (parts[1] === "state" || parts[1] === "receipts")
    ) {
      return true;
    }
    return (
      parts.length === 4 &&
      parts[1] === "transactions" &&
      /^[a-f0-9]{32}$/.test(parts[2] ?? "")
    );
  }
  return (
    parts.length === 5 &&
    parts[0] === "engines" &&
    /^(?:stable|beta|development)$/.test(parts[1] ?? "") &&
    /^(?:win32|darwin)-(?:x64|arm64)$/.test(parts[2] ?? "") &&
    parts[3] === "activations"
  );
}

async function verifyRecoveryCleanup(
  appDataDirectory: string,
  plan: readonly PlannedJournalRecovery[],
  chain: ActivationChain,
  checkpoints: LoadedMetadataCheckpointChain,
  policy: ReceiptVerificationPolicy,
): Promise<void> {
  const journals = await listTransactionJournals(appDataDirectory);
  if (journals.length !== plan.length) {
    throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
  }
  for (const item of plan) {
    const actual = journals.find(
      (journal) => journal.transactionId === item.journal.transactionId,
    );
    if (
      !actual ||
      actual.records.at(-1)?.sha256 !== item.journal.records.at(-1)?.sha256 ||
      actual.orphanTemporaryFiles.length !== 0
    ) {
      throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
    }
  }
  const actualChain = await loadActivationChain(
    appDataDirectory,
    policy.platform,
    policy.architecture,
  );
  if (
    !samePaths(
      actualChain.records.map((entry) => entry.sha256),
      chain.records.map((entry) => entry.sha256),
    ) ||
    actualChain.orphanTemporaryFiles.length !== 0
  ) {
    throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
  }
  const actualCheckpoints = await loadMetadataCheckpointChain(
    appDataDirectory,
    policy,
  );
  if (
    actualCheckpoints.head.generation !== checkpoints.head.generation ||
    actualCheckpoints.head.sha256 !== checkpoints.head.sha256 ||
    actualCheckpoints.orphanTemporaryFiles.length !== 0 ||
    actualCheckpoints.orphanBundlePaths.length !== 0 ||
    (await listUpdaterStateOrphanTemporaryFiles(appDataDirectory)).length !==
      0 ||
    (await listTargetReceiptOrphanTemporaryFiles(appDataDirectory)).length !==
      0 ||
    (await listInterruptedTemporaryDirectories(appDataDirectory)).length !== 0
  ) {
    throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
  }
}

async function canonicalReleaseDirectory(
  appDataDirectory: string,
  channel: string,
  platform: "win32" | "darwin",
  architecture: "x64" | "arm64",
): Promise<string | null> {
  const expected = path.join(
    path.resolve(appDataDirectory),
    "engines",
    channel,
    `${platform}-${architecture}`,
    "releases",
  );
  if (!(await isPrivateDirectoryIfPresent(expected))) return null;

  let canonical: string;
  try {
    canonical = await realpath(expected);
  } catch (error) {
    throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED", { cause: error });
  }
  const expectedRoot = path.join(path.resolve(appDataDirectory), "engines");
  const canonicalRoot = await realpath(expectedRoot);
  if (
    canonical !== canonicalRoot &&
    !canonical.startsWith(`${canonicalRoot}${path.sep}`)
  ) {
    throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
  }
  const actualSegments = path
    .relative(canonicalRoot, canonical)
    .split(path.sep);
  const expectedSegments = [channel, `${platform}-${architecture}`, "releases"];
  if (
    actualSegments.length !== expectedSegments.length ||
    actualSegments.some((segment, index) => segment !== expectedSegments[index])
  ) {
    throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
  }
  return canonical;
}

async function isPrivateDirectoryIfPresent(
  directory: string,
): Promise<boolean> {
  let stats;
  try {
    stats = await lstat(directory);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED", { cause: error });
  }
  if (!stats.isDirectory() || stats.isSymbolicLink()) {
    throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
  }
  return true;
}

async function removePrivateDirectoryIfPresent(
  directory: string,
): Promise<boolean> {
  if (!(await isPrivateDirectoryIfPresent(directory))) return false;
  try {
    await rm(directory, { recursive: true, force: true, maxRetries: 1 });
  } catch (error) {
    throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED", { cause: error });
  }
  return true;
}

function validateReconstructionAgainstActivationChain(
  reconstruction: ReceiptReconstruction,
  chain: ActivationChain,
): void {
  const receipts = new Map(
    reconstruction.verifiedReceipts.map((receipt) => [
      receipt.receiptSha256,
      receipt,
    ]),
  );
  for (const entry of chain.records) {
    const receipt = receipts.get(entry.record.receiptSha256);
    if (
      !receipt ||
      receipt.target.custom.releaseSequence !== entry.record.releaseSequence ||
      receipt.target.custom.channel !== entry.record.channel ||
      receipt.target.custom.productVersion !== entry.record.productVersion ||
      receipt.target.sha256 !== entry.record.artifactSha256
    ) {
      throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
    }
  }
  const maxActivated = chain.records.reduce(
    (maximum, entry) => Math.max(maximum, entry.record.releaseSequence),
    0,
  );
  if (maxActivated > reconstruction.maxAuthenticatedReleaseSequence) {
    throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
  }
}

function reconstructedStateRecord(
  reconstruction: ReceiptReconstruction | null,
  checkpoints: LoadedMetadataCheckpointChain,
  chain: ActivationChain,
): Omit<UpdaterStateRecord, "generation" | "previousSha256"> {
  const maxActivatedReleaseSequence = chain.records.reduce(
    (maximum, entry) => Math.max(maximum, entry.record.releaseSequence),
    0,
  );
  const trustedMetadata =
    checkpoints.head.generation === 0
      ? (reconstruction?.trustedMetadata ?? emptyTrustedMetadataState())
      : checkpoints.trustedMetadata;
  const knownReleases = reconstruction?.knownReleases ?? [];
  const receiptDigests = reconstruction?.receiptDigests ?? [];
  const maxAuthenticatedReleaseSequence =
    reconstruction?.maxAuthenticatedReleaseSequence ?? 0;
  return {
    ...initialUpdaterState(
      trustedMetadata,
      chain.current?.record.channel ?? "stable",
    ),
    metadataCheckpointGeneration: checkpoints.head.generation,
    metadataCheckpointSha256: checkpoints.head.sha256,
    maxAuthenticatedReleaseSequence,
    maxActivatedReleaseSequence,
    currentActivationGeneration: chain.current?.record.generation ?? null,
    previousActivationGeneration: chain.previous?.record.generation ?? null,
    receiptDigests,
    knownReleases,
  };
}

export function activationPolicyForState(
  policy: ActivationSecurityPolicy,
  state: UpdaterStateRecord,
): ActivationSecurityPolicy {
  return {
    ...policy,
    receipt: {
      ...policy.receipt,
      currentRevocations: {
        goatRevocationSchema: 1,
        revokedKeyIds: state.revokedKeyIds,
        revokedArtifactSha256: state.revokedArtifactSha256,
        revokedReleaseSequences: state.revokedReleaseSequences,
      },
    },
    compatibility: {
      ...policy.compatibility,
      revokedKeyIds: union(
        policy.compatibility.revokedKeyIds,
        state.revokedKeyIds,
      ),
    },
  };
}

async function quarantineCorruptState(
  appDataDirectory: string,
): Promise<string> {
  const updatesRoot = path.join(path.resolve(appDataDirectory), "updates");
  const statePath = path.join(updatesRoot, "state");
  const stats = await lstat(statePath).catch((error) => {
    throw new UpdateError("GOAT_UPDATE_STATE_INVALID", { cause: error });
  });
  if (!stats.isDirectory() || stats.isSymbolicLink()) {
    throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
  }
  const quarantineRoot = await ensurePrivateDirectory(
    path.join(updatesRoot, "quarantine"),
    "GOAT_UPDATE_STATE_INVALID",
  );
  const destination = path.join(
    quarantineRoot,
    `state-${randomBytes(16).toString("hex")}`,
  );
  await rename(statePath, destination);
  await syncDirectory(quarantineRoot, "GOAT_UPDATE_STATE_INVALID");
  await syncDirectory(updatesRoot, "GOAT_UPDATE_STATE_INVALID");
  return destination;
}

function releaseIdentity(
  activation: LoadedActivationRecord,
): KnownReleaseIdentity {
  return {
    releaseSequence: activation.record.releaseSequence,
    channel: activation.record.channel,
    productVersion: activation.record.productVersion,
    artifactSha256: activation.record.artifactSha256,
  };
}

function assertSameTrustedMetadata(
  left: TrustedMetadataState,
  right: TrustedMetadataState,
): void {
  if (
    left.trustedTimeUnixMs !== right.trustedTimeUnixMs ||
    TRUSTED_METADATA_ROLES.some(
      (role) =>
        left.versions[role] !== right.versions[role] ||
        left.digests[role] !== right.digests[role],
    ) ||
    !samePaths(left.revokedKeyIds, right.revokedKeyIds) ||
    !samePaths(left.revokedArtifactSha256, right.revokedArtifactSha256) ||
    !sameNumbers(left.revokedReleaseSequences, right.revokedReleaseSequences)
  ) {
    throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
  }
}

function sameReleases(
  left: readonly KnownReleaseIdentity[],
  right: readonly KnownReleaseIdentity[],
): boolean {
  return (
    left.length === right.length &&
    left.every(
      (release, index) =>
        release.releaseSequence === right[index]?.releaseSequence &&
        release.channel === right[index]?.channel &&
        release.productVersion === right[index]?.productVersion &&
        release.artifactSha256 === right[index]?.artifactSha256,
    )
  );
}

function samePaths(left: readonly string[], right: readonly string[]): boolean {
  return (
    left.length === right.length &&
    left.every((value, index) => value === right[index])
  );
}

function sameNumbers(
  left: readonly number[],
  right: readonly number[],
): boolean {
  return (
    left.length === right.length &&
    left.every((value, index) => value === right[index])
  );
}

function isSuperset<T>(
  candidate: readonly T[],
  previous: readonly T[],
): boolean {
  const values = new Set(candidate);
  return previous.every((value) => values.has(value));
}

function union(left: readonly string[], right: readonly string[]): string[] {
  return [...new Set([...left, ...right])].sort(asciiCompare);
}

function checkedNow(value: number): number {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
  }
  return value;
}

function asciiCompare(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
