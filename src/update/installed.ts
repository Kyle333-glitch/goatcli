import type { JsonObject } from "./canonical-json.js";
import {
  loadActivationChain,
  type ActivationChain,
} from "./activation-record.js";
import {
  validateInstalledActivation,
  type ActivationSecurityPolicy,
  type ValidatedInstalledActivation,
} from "./activation.js";
import { UpdateError } from "./errors.js";
import { loadMetadataCheckpointChain } from "./metadata-checkpoint.js";
import {
  activationPolicyForState,
  effectiveStateForMetadataCheckpoint,
} from "./recovery.js";
import { loadUpdaterState, type LoadedUpdaterState } from "./state.js";

export interface InstalledEngineInspection {
  readonly state: LoadedUpdaterState;
  readonly chain: ActivationChain;
  readonly active: ValidatedInstalledActivation;
  readonly rollbackReady: boolean;
  readonly rootSigningKeyIds: readonly string[];
  readonly targetSigningKeyIds: readonly string[];
}

export async function inspectInstalledEngine(
  appDataDirectory: string,
  policy: ActivationSecurityPolicy,
): Promise<InstalledEngineInspection | null> {
  const state = await loadUpdaterState(appDataDirectory);
  const chain = await loadActivationChain(
    appDataDirectory,
    policy.receipt.platform,
    policy.receipt.architecture,
  );
  const checkpoints = await loadMetadataCheckpointChain(
    appDataDirectory,
    policy.receipt,
  );
  if (!state && chain.records.length === 0) return null;
  if (
    !state ||
    !chain.current ||
    state.record.currentActivationGeneration !==
      chain.current.record.generation ||
    state.record.configuredChannel !== chain.current.record.channel
  ) {
    throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
  }
  const effectiveState = effectiveStateForMetadataCheckpoint(
    state.record,
    checkpoints,
  );
  const effectivePolicy = activationPolicyForState(
    policy,
    effectiveState.record,
  );
  const active = await validateInstalledActivation(
    appDataDirectory,
    chain.current,
    effectivePolicy,
  );
  let rollbackReady = false;
  if (state.record.previousActivationGeneration !== null) {
    const previous = chain.records.find(
      (entry) =>
        entry.record.generation === state.record.previousActivationGeneration,
    );
    if (
      previous &&
      previous.record.slotName !== chain.current.record.slotName
    ) {
      try {
        await validateInstalledActivation(
          appDataDirectory,
          previous,
          effectivePolicy,
        );
        rollbackReady = true;
      } catch {
        rollbackReady = false;
      }
    }
  }
  return {
    state,
    chain,
    active,
    rollbackReady,
    rootSigningKeyIds: signatureKeyIds(active.receipt.metadata.root.json),
    targetSigningKeyIds: signatureKeyIds(active.receipt.metadata.channel.json),
  };
}

function signatureKeyIds(envelope: JsonObject): readonly string[] {
  if (!Array.isArray(envelope.signatures)) {
    throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
  }
  const keyIds = envelope.signatures.map((signature) => {
    if (
      typeof signature !== "object" ||
      signature === null ||
      Array.isArray(signature) ||
      typeof signature.keyid !== "string"
    ) {
      throw new UpdateError("GOAT_UPDATE_STATE_INVALID");
    }
    return signature.keyid;
  });
  return [...new Set(keyIds)].sort(asciiCompare);
}

function asciiCompare(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
