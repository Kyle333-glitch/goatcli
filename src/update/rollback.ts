import {
  appendRollbackActivationRecord,
  loadActivationChain,
  type LoadedActivationRecord,
} from "./activation-record.js";
import {
  validateInstalledActivation,
  type ActivationSecurityPolicy,
  type ValidatedInstalledActivation,
} from "./activation.js";
import { UpdateError } from "./errors.js";
import type { KnownReleaseIdentity } from "./selection.js";
import {
  appendUpdaterState,
  stateAfterAutomaticRollback,
  type LoadedUpdaterState,
} from "./state.js";

export interface AutomaticRollbackInput {
  readonly appDataDirectory: string;
  readonly state: LoadedUpdaterState;
  readonly policy: ActivationSecurityPolicy;
  readonly committedAtUnixMs?: number;
}

export interface AutomaticRollbackResult {
  readonly activation: LoadedActivationRecord;
  readonly state: LoadedUpdaterState;
  readonly validatedSource: ValidatedInstalledActivation;
}

export async function performAutomaticRollback(
  input: AutomaticRollbackInput,
): Promise<AutomaticRollbackResult> {
  const platform = input.policy.receipt.platform;
  const architecture = input.policy.receipt.architecture;
  const chain = await loadActivationChain(
    input.appDataDirectory,
    platform,
    architecture,
  );
  if (
    !chain.current ||
    input.state.record.currentActivationGeneration !==
      chain.current.record.generation ||
    input.state.record.previousActivationGeneration === null
  ) {
    throw new UpdateError("GOAT_UPDATE_ROLLBACK_INVALID");
  }
  const source = chain.records.find(
    (entry) =>
      entry.record.generation ===
      input.state.record.previousActivationGeneration,
  );
  if (!source || sameSlot(source, chain.current)) {
    throw new UpdateError("GOAT_UPDATE_ROLLBACK_INVALID");
  }
  let validatedSource: ValidatedInstalledActivation;
  try {
    validatedSource = await validateInstalledActivation(
      input.appDataDirectory,
      source,
      input.policy,
    );
  } catch (error) {
    throw new UpdateError("GOAT_UPDATE_ROLLBACK_INVALID", { cause: error });
  }
  const activation = await appendRollbackActivationRecord(
    input.appDataDirectory,
    platform,
    architecture,
    source.record.generation,
    input.committedAtUnixMs,
  );
  const release = releaseIdentity(source);
  const state = await appendUpdaterState(
    input.appDataDirectory,
    input.state,
    stateAfterAutomaticRollback(input.state.record, {
      activationGeneration: activation.record.generation,
      release,
      receiptSha256: source.record.receiptSha256,
    }),
  );
  return { activation, state, validatedSource };
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

function sameSlot(
  left: LoadedActivationRecord,
  right: LoadedActivationRecord,
): boolean {
  return (
    left.record.channel === right.record.channel &&
    left.record.slotName === right.record.slotName &&
    left.record.artifactSha256 === right.record.artifactSha256
  );
}
