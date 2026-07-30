import {
  activateCandidate,
  cleanupSupersededSlots,
  validateInstalledActivation,
  type ActivationSecurityPolicy,
  type ValidatedInstalledActivation,
} from "./activation.js";
import { loadActivationChain } from "./activation-record.js";
import { extractVerifiedArchive } from "./archive.js";
import { validateCandidateCompatibility } from "./compatibility.js";
import {
  assertHeldArtifactUnchanged,
  disposeHeldArtifact,
  downloadVerifiedArtifact,
  type HeldVerifiedArtifact,
} from "./download.js";
import { UpdateError } from "./errors.js";
import {
  appendJournalTransition,
  createTransactionJournal,
  emptyJournalData,
  type JournalData,
  type TransactionJournal,
  type UpdatePhase,
} from "./journal.js";
import { acquireUpdateLock } from "./lock.js";
import {
  fetchUpdateMetadata,
  type UpdateMetadataBundle,
} from "./metadata-client.js";
import {
  authenticateAndAppendMetadataCheckpoint,
  loadMetadataCheckpointChain,
  type LoadedMetadataCheckpointChain,
} from "./metadata-checkpoint.js";
import { FixedOriginTransport, type HttpsAgent } from "./network.js";
import {
  loadTargetReceipt,
  persistTargetReceipt,
  reconstructStateFromReceipts,
  type PersistedTargetReceipt,
} from "./receipt.js";
import { recoverInstallation } from "./recovery.js";
import {
  selectAuthenticatedArtifact,
  type ArtifactSelection,
} from "./selection.js";
import type {
  AuthenticatedTarget,
  UpdateArchitecture,
  UpdateChannel,
  UpdatePlatform,
} from "./schema.js";
import {
  appendUpdaterState,
  initialUpdaterState,
  initializeUpdaterState,
  stateAfterActivation,
  stateAfterAuthentication,
  stateAfterMetadataRefresh,
  type LoadedUpdaterState,
} from "./state.js";
import {
  cleanupUpdateTransaction,
  createUpdateTransactionPaths,
  type UpdateTransactionPaths,
} from "./temporary.js";
import type { TrustedMetadataState } from "./trust.js";

export interface VerifiedUpdatePolicy {
  readonly launcherVersion: string;
  readonly platform: UpdatePlatform;
  readonly architecture: UpdateArchitecture;
  readonly metadataOrigin: string;
  readonly artifactOrigin: string;
  readonly embeddedRootBytes: Uint8Array;
  readonly embeddedRootSha256: string;
  readonly activation: ActivationSecurityPolicy;
}

export interface UpdateTransitionEvent {
  readonly phase: UpdatePhase;
  readonly transactionId: string;
  readonly data: JournalData;
}

export interface RunVerifiedUpdateOptions {
  readonly appDataDirectory: string;
  readonly policy: VerifiedUpdatePolicy;
  readonly requestedChannel?: UpdateChannel;
  readonly httpsAgent?: HttpsAgent;
  readonly now?: () => number;
  readonly waitBeforeRetry?: () => Promise<void>;
  readonly isProcessAlive?: (pid: number) => boolean | Promise<boolean>;
  /** Audit/progress hook. Tests may terminate a child process at this boundary. */
  readonly afterTransition?: (
    event: UpdateTransitionEvent,
  ) => void | Promise<void>;
}

export interface VerifiedUpdateResult {
  readonly status: "updated" | "already-current";
  readonly channel: UpdateChannel;
  readonly productVersion: string;
  readonly goatEngineVersion: string;
  readonly releaseSequence: number;
  readonly activationGeneration: number;
  readonly recoveredBeforeUpdate: boolean;
  readonly deferredCleanupPaths: readonly string[];
}

export async function runVerifiedUpdate(
  options: RunVerifiedUpdateOptions,
): Promise<VerifiedUpdateResult> {
  assertPolicyBinding(options.policy);
  const now = options.now ?? Date.now;
  const recovery = () =>
    recoverInstallation({
      appDataDirectory: options.appDataDirectory,
      policy: options.policy.activation,
      now,
    });
  let recovered: Awaited<ReturnType<typeof recoverInstallation>> | undefined;
  const lock = await acquireUpdateLock(options.appDataDirectory, {
    now,
    isProcessAlive: options.isProcessAlive,
    recoverStaleTransaction: async () => {
      recovered = await recovery();
    },
  });
  let failed = false;
  try {
    if (!recovered) {
      throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
    }
    return await runLockedUpdate(options, recovered, now);
  } catch (error) {
    failed = true;
    throw error;
  } finally {
    try {
      await lock.release();
    } catch (error) {
      if (!failed) throw error;
    }
  }
}

async function runLockedUpdate(
  options: RunVerifiedUpdateOptions,
  recovered: Awaited<ReturnType<typeof recoverInstallation>>,
  now: () => number,
): Promise<VerifiedUpdateResult> {
  let state =
    recovered.state ??
    (await initializeUpdaterState(
      options.appDataDirectory,
      initialUpdaterState(),
    ));
  let metadataCheckpoints = await loadMetadataCheckpointChain(
    options.appDataDirectory,
    options.policy,
  );
  assertStateCheckpoint(state, metadataCheckpoints);
  const channel = options.requestedChannel ?? state.record.configuredChannel;
  const transportOptions = {
    launcherVersion: options.policy.launcherVersion,
    channel,
    platform: options.policy.platform,
    architecture: options.policy.architecture,
    agent: options.httpsAgent,
  };
  const metadataTransport = new FixedOriginTransport({
    ...transportOptions,
    origin: options.policy.metadataOrigin,
  });
  const artifactTransport = new FixedOriginTransport({
    ...transportOptions,
    origin: options.policy.artifactOrigin,
  });

  let transaction: UpdateTransactionPaths | undefined;
  let artifact: HeldVerifiedArtifact | undefined;
  try {
    transaction = await createUpdateTransactionPaths(options.appDataDirectory);
    let journal = await createTransactionJournal(
      options.appDataDirectory,
      transaction.transactionId,
    );
    let journalData = emptyJournalData();
    const transition = async (
      phase: UpdatePhase,
      additions: Partial<JournalData> = {},
    ): Promise<void> => {
      journalData = { ...journalData, ...additions };
      journal = await appendJournalTransition(
        journal,
        phase,
        journalData,
        checkedNow(now()),
      );
      await options.afterTransition?.({
        phase,
        transactionId: transaction!.transactionId,
        data: journalData,
      });
    };

    await transition("check");
    const raw = await fetchUpdateMetadata(
      metadataTransport,
      options.policy.embeddedRootBytes,
      channel,
      { waitBeforeRetry: options.waitBeforeRetry },
    );
    await transition("fetch-manifest");

    const checkpointed = await authenticateAndAppendMetadataCheckpoint({
      appDataDirectory: options.appDataDirectory,
      current: metadataCheckpoints,
      metadata: raw,
      policy: options.policy,
      nowUnixMs: checkedNow(now()),
    });
    metadataCheckpoints = checkpointed.chain;
    const authenticated = checkpointed.authenticated;
    state = await appendUpdaterState(
      options.appDataDirectory,
      state,
      stateAfterMetadataRefresh(state.record, {
        trustedMetadata: authenticated.nextState,
        checkpoint: metadataCheckpoints.head,
      }),
    );
    const releaseSequence = authenticated.channel.metadata.signed.version;
    await transition("authenticate-manifest", { releaseSequence });

    const selection = selectAuthenticatedArtifact(
      authenticated.channel,
      {
        channel,
        platform: options.policy.platform,
        architecture: options.policy.architecture,
        launcherVersion: options.policy.launcherVersion,
        maxAuthenticatedReleaseSequence:
          state.record.maxAuthenticatedReleaseSequence,
        maxActivatedReleaseSequence: state.record.maxActivatedReleaseSequence,
        knownReleases: state.record.knownReleases,
      },
      authenticated.revocations,
    );
    await transition("select-artifact");

    const effectiveActivationPolicy = withTrustedRevocations(
      options.policy.activation,
      authenticated.nextState,
    );
    const receipt = await findOrPersistReceipt(
      options.appDataDirectory,
      options.policy,
      effectiveActivationPolicy,
      raw,
      selection.target,
      authenticated.nextState.trustedTimeUnixMs,
    );
    if (
      selection.target.custom.releaseSequence >
      state.record.maxAuthenticatedReleaseSequence
    ) {
      state = await appendUpdaterState(
        options.appDataDirectory,
        state,
        stateAfterAuthentication(state.record, {
          release: receipt.release,
          receiptSha256: receipt.receiptSha256,
        }),
      );
    }

    if (selection.status === "already-current") {
      const active = requireMatchingActive(recovered.active, selection);
      await validateInstalledActivation(
        options.appDataDirectory,
        active.activation,
        effectiveActivationPolicy,
      );
      await cleanupUpdateTransaction(transaction);
      await transition("recover");
      return resultForCurrent(active, recovered.status !== "ready");
    }

    artifact = await downloadVerifiedArtifact(
      artifactTransport,
      selection.target,
      transaction,
      { waitBeforeRetry: options.waitBeforeRetry },
    );
    await transition("download-artifact");
    await assertHeldArtifactUnchanged(artifact);
    await transition("verify-artifact", {
      receiptSha256: receipt.receiptSha256,
    });

    const staged = await extractVerifiedArchive(
      artifact,
      selection.target,
      transaction,
    );
    await transition("stage-archive");
    await disposeHeldArtifact(artifact);
    artifact = undefined;

    await validateCandidateCompatibility(
      staged,
      effectiveActivationPolicy.compatibility,
    );
    await transition("check-compatibility");

    const activated = await activateCandidate({
      appDataDirectory: options.appDataDirectory,
      staged,
      receiptSha256: receipt.receiptSha256,
      transactionId: transaction.transactionId,
      policy: effectiveActivationPolicy,
      committedAtUnixMs: checkedNow(now()),
      observer: {
        preparedRollback: () => transition("prepare-rollback"),
        preparedActivation: (slotName) =>
          transition("prepare-activation", { slotName }),
        provisionalSlotPlaced: (slotName) =>
          transition("place-provisional-slot", { slotName }),
        provisionalSlotValidated: (slotName, slotSealSha256) =>
          transition("validate-provisional-slot", {
            slotName,
            slotSealSha256,
          }),
        activationCommitted: (activation) =>
          transition("commit-activation", {
            activationGeneration: activation.record.generation,
          }),
      },
    });
    state = await appendUpdaterState(
      options.appDataDirectory,
      state,
      stateAfterActivation(state.record, {
        activationGeneration: activated.activation.record.generation,
        release: receipt.release,
        receiptSha256: receipt.receiptSha256,
      }),
    );

    await cleanupUpdateTransaction(transaction);
    const chain = await loadActivationChain(
      options.appDataDirectory,
      options.policy.platform,
      options.policy.architecture,
    );
    const deferredCleanupPaths = await cleanupSupersededSlots(
      options.appDataDirectory,
      chain,
      options.policy.platform,
      options.policy.architecture,
    );
    await transition("cleanup");
    await transition("recover");
    return {
      status: "updated",
      channel: activated.activation.record.channel,
      productVersion: activated.activation.record.productVersion,
      goatEngineVersion: activated.activation.record.goatEngineVersion,
      releaseSequence: activated.activation.record.releaseSequence,
      activationGeneration: activated.activation.record.generation,
      recoveredBeforeUpdate: recovered.status !== "ready",
      deferredCleanupPaths,
    };
  } catch (error) {
    if (artifact) await disposeHeldArtifact(artifact);
    if (transaction) {
      await cleanupUpdateTransaction(transaction).catch(() => undefined);
    }
    throw error;
  }
}

async function findOrPersistReceipt(
  appDataDirectory: string,
  policy: VerifiedUpdatePolicy,
  activationPolicy: ActivationSecurityPolicy,
  raw: UpdateMetadataBundle,
  target: AuthenticatedTarget,
  authenticatedAtUnixMs: number,
): Promise<PersistedTargetReceipt> {
  const { currentRevocations: _ignored, ...reconstructionPolicy } =
    activationPolicy.receipt;
  const reconstruction = await reconstructStateFromReceipts(
    appDataDirectory,
    reconstructionPolicy,
  );
  const existing = reconstruction?.verifiedReceipts.find(
    (receipt) =>
      receipt.target.targetPath === target.targetPath &&
      receipt.target.sha256 === target.sha256 &&
      receipt.target.custom.releaseSequence === target.custom.releaseSequence,
  );
  if (existing) {
    return loadTargetReceipt(
      appDataDirectory,
      existing.receiptSha256,
      activationPolicy.receipt,
    );
  }
  return persistTargetReceipt(
    appDataDirectory,
    {
      embeddedRootSha256: policy.embeddedRootSha256,
      sequentialRoots: raw.sequentialRoots,
      timestamp: raw.timestamp,
      snapshot: raw.snapshot,
      targets: raw.targets,
      channel: raw.channel,
      channelName: raw.channelName,
      targetPath: target.targetPath,
      authenticatedAtUnixMs,
    },
    activationPolicy.receipt,
  );
}

function requireMatchingActive(
  active: ValidatedInstalledActivation | null,
  selection: ArtifactSelection,
): ValidatedInstalledActivation {
  if (
    !active ||
    active.activation.record.releaseSequence !==
      selection.target.custom.releaseSequence ||
    active.activation.record.channel !== selection.target.custom.channel ||
    active.activation.record.productVersion !==
      selection.target.custom.productVersion ||
    active.activation.record.artifactSha256 !== selection.target.sha256
  ) {
    throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
  }
  return active;
}

function resultForCurrent(
  active: ValidatedInstalledActivation,
  recoveredBeforeUpdate: boolean,
): VerifiedUpdateResult {
  const record = active.activation.record;
  return {
    status: "already-current",
    channel: record.channel,
    productVersion: record.productVersion,
    goatEngineVersion: record.goatEngineVersion,
    releaseSequence: record.releaseSequence,
    activationGeneration: record.generation,
    recoveredBeforeUpdate,
    deferredCleanupPaths: [],
  };
}

function assertStateCheckpoint(
  state: LoadedUpdaterState,
  checkpoints: LoadedMetadataCheckpointChain,
): void {
  const record = state.record;
  const trusted = checkpoints.trustedMetadata;
  const roles = [
    "root",
    "timestamp",
    "snapshot",
    "targets",
    "stable",
    "beta",
    "development",
  ] as const;
  if (
    record.metadataCheckpointGeneration !== checkpoints.head.generation ||
    record.metadataCheckpointSha256 !== checkpoints.head.sha256 ||
    record.trustedTimeUnixMs !== trusted.trustedTimeUnixMs ||
    roles.some(
      (role) =>
        record.metadataVersions[role] !== trusted.versions[role] ||
        record.metadataDigests[role] !== trusted.digests[role],
    ) ||
    !sameStrings(record.revokedKeyIds, trusted.revokedKeyIds) ||
    !sameStrings(record.revokedArtifactSha256, trusted.revokedArtifactSha256) ||
    !sameNumbers(
      record.revokedReleaseSequences,
      trusted.revokedReleaseSequences,
    )
  ) {
    throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
  }
}

function sameStrings(
  left: readonly string[],
  right: readonly string[],
): boolean {
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

function withTrustedRevocations(
  policy: ActivationSecurityPolicy,
  trusted: TrustedMetadataState,
): ActivationSecurityPolicy {
  return {
    ...policy,
    receipt: {
      ...policy.receipt,
      currentRevocations: {
        goatRevocationSchema: 1,
        revokedKeyIds: trusted.revokedKeyIds,
        revokedArtifactSha256: trusted.revokedArtifactSha256,
        revokedReleaseSequences: trusted.revokedReleaseSequences,
      },
    },
    compatibility: {
      ...policy.compatibility,
      revokedKeyIds: union(
        policy.compatibility.revokedKeyIds,
        trusted.revokedKeyIds,
      ),
    },
  };
}

function assertPolicyBinding(policy: VerifiedUpdatePolicy): void {
  if (
    policy.activation.receipt.embeddedRootSha256 !==
      policy.embeddedRootSha256 ||
    policy.activation.receipt.launcherVersion !== policy.launcherVersion ||
    policy.activation.receipt.platform !== policy.platform ||
    policy.activation.receipt.architecture !== policy.architecture ||
    policy.activation.compatibility.launcherVersion !==
      policy.launcherVersion ||
    policy.activation.compatibility.platform !== policy.platform ||
    policy.activation.compatibility.architecture !== policy.architecture
  ) {
    throw new UpdateError("GOAT_UPDATE_DISABLED");
  }
}

function checkedNow(value: number): number {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
  }
  return value;
}

function union(left: readonly string[], right: readonly string[]): string[] {
  return [...new Set([...left, ...right])].sort(asciiCompare);
}

function asciiCompare(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
