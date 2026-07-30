import type { TargetFile, Targets } from "@tufjs/models";
import semver from "semver";
import { OPENCODE_BASELINE_VERSION } from "../version.js";
import { UpdateError } from "./errors.js";
import type { ParsedTufMetadata, TopLevelRevocations } from "./metadata.js";
import {
  parseAuthenticatedTarget,
  type AuthenticatedTarget,
  type UpdateArchitecture,
  type UpdateChannel,
  type UpdatePlatform,
} from "./schema.js";

export interface KnownReleaseIdentity {
  readonly releaseSequence: number;
  readonly channel: UpdateChannel;
  readonly productVersion: string;
  readonly artifactSha256: string;
}

export interface ArtifactSelectionPolicy {
  readonly channel: UpdateChannel;
  readonly platform: UpdatePlatform;
  readonly architecture: UpdateArchitecture;
  readonly launcherVersion: string;
  readonly maxAuthenticatedReleaseSequence: number;
  readonly maxActivatedReleaseSequence: number;
  readonly knownReleases?: readonly KnownReleaseIdentity[];
  readonly activeRelease?: KnownReleaseIdentity;
}

export interface ArtifactSelection {
  readonly status: "update-available" | "already-current";
  readonly target: AuthenticatedTarget;
}

export interface SignedTargetsView {
  readonly roleName: "stable" | "beta" | "development";
  readonly metadataVersion: number;
  readonly targets: Readonly<Record<string, TargetFile>>;
}

export class LauncherUpdateRequiredError extends UpdateError {
  constructor(readonly minimumLauncherVersion: string) {
    super("GOAT_UPDATE_TARGET_INCOMPATIBLE");
    this.name = "LauncherUpdateRequiredError";
  }
}

export function selectAuthenticatedArtifact(
  channelMetadata: ParsedTufMetadata<Targets>,
  policy: ArtifactSelectionPolicy,
  revocations: TopLevelRevocations,
): ArtifactSelection {
  if (
    channelMetadata.roleName !== "stable" &&
    channelMetadata.roleName !== "beta" &&
    channelMetadata.roleName !== "development"
  ) {
    throw new UpdateError("GOAT_UPDATE_TARGET_NOT_FOUND");
  }
  return selectArtifactFromTargets(
    {
      roleName: channelMetadata.roleName,
      metadataVersion: channelMetadata.metadata.signed.version,
      targets: channelMetadata.metadata.signed.targets,
    },
    policy,
    revocations,
  );
}

export function selectArtifactFromTargets(
  view: SignedTargetsView,
  policy: ArtifactSelectionPolicy,
  revocations: TopLevelRevocations,
): ArtifactSelection {
  if (view.roleName !== policy.channel) {
    throw new UpdateError("GOAT_UPDATE_TARGET_NOT_FOUND");
  }
  const parsedTargets = Object.entries(view.targets).map(
    ([targetPath, target]) => {
      const parsed = parseAuthenticatedTarget(targetPath, target);
      if (
        parsed.custom.channel !== view.roleName ||
        parsed.custom.releaseSequence !== view.metadataVersion ||
        parsed.custom.productVersion !== parsed.custom.goatEngineVersion ||
        parsed.custom.openCodeBaseline !== OPENCODE_BASELINE_VERSION
      ) {
        throw new UpdateError("GOAT_UPDATE_METADATA_MISMATCH");
      }
      return parsed;
    },
  );

  const matching = parsedTargets.filter(
    (target) =>
      target.custom.channel === policy.channel &&
      target.custom.platform === policy.platform &&
      target.custom.architecture === policy.architecture,
  );
  if (matching.length === 0) {
    throw new UpdateError("GOAT_UPDATE_TARGET_NOT_FOUND");
  }
  const highestSequence = Math.max(
    ...matching.map((target) => target.custom.releaseSequence),
  );
  const latest = matching.filter(
    (target) => target.custom.releaseSequence === highestSequence,
  );
  if (latest.length !== 1) {
    throw new UpdateError("GOAT_UPDATE_TARGET_AMBIGUOUS");
  }
  const selected = latest[0]!;

  if (
    revocations.revokedArtifactSha256.includes(selected.sha256) ||
    revocations.revokedReleaseSequences.includes(
      selected.custom.releaseSequence,
    )
  ) {
    throw new UpdateError("GOAT_UPDATE_TARGET_NOT_FOUND");
  }
  if (
    !semver.gte(
      policy.launcherVersion,
      selected.custom.launcherCompatibility.minInclusive,
    )
  ) {
    throw new LauncherUpdateRequiredError(
      selected.custom.launcherCompatibility.minInclusive,
    );
  }
  if (
    !semver.lt(
      policy.launcherVersion,
      selected.custom.launcherCompatibility.maxExclusive,
    )
  ) {
    throw new UpdateError("GOAT_UPDATE_TARGET_INCOMPATIBLE");
  }

  const sequenceFloor = Math.max(
    policy.maxAuthenticatedReleaseSequence,
    policy.maxActivatedReleaseSequence,
  );
  if (selected.custom.releaseSequence < sequenceFloor) {
    throw new UpdateError("GOAT_UPDATE_DOWNGRADE_BLOCKED");
  }
  assertKnownReleaseConsistency(selected, policy.knownReleases ?? []);
  const existingSequence = (policy.knownReleases ?? []).find(
    (release) => release.releaseSequence === selected.custom.releaseSequence,
  );
  const activeMatchesSelected =
    policy.activeRelease !== undefined &&
    policy.activeRelease.releaseSequence === selected.custom.releaseSequence &&
    policy.activeRelease.channel === selected.custom.channel &&
    policy.activeRelease.productVersion === selected.custom.productVersion &&
    policy.activeRelease.artifactSha256 === selected.sha256;
  if (selected.custom.releaseSequence === sequenceFloor) {
    if (
      !existingSequence ||
      existingSequence.channel !== selected.custom.channel ||
      existingSequence.productVersion !== selected.custom.productVersion ||
      existingSequence.artifactSha256 !== selected.sha256
    ) {
      throw new UpdateError("GOAT_UPDATE_METADATA_REPLAYED");
    }
    const alreadyCurrent =
      policy.activeRelease !== undefined
        ? activeMatchesSelected
        : selected.custom.releaseSequence ===
          policy.maxActivatedReleaseSequence;
    return {
      status: alreadyCurrent ? "already-current" : "update-available",
      target: selected,
    };
  }
  return { status: "update-available", target: selected };
}

function assertKnownReleaseConsistency(
  selected: AuthenticatedTarget,
  knownReleases: readonly KnownReleaseIdentity[],
): void {
  for (const known of knownReleases) {
    if (
      known.releaseSequence === selected.custom.releaseSequence &&
      (known.channel !== selected.custom.channel ||
        known.productVersion !== selected.custom.productVersion ||
        known.artifactSha256 !== selected.sha256)
    ) {
      throw new UpdateError("GOAT_UPDATE_METADATA_REPLAYED");
    }
    if (
      known.productVersion === selected.custom.productVersion &&
      known.artifactSha256 !== selected.sha256
    ) {
      throw new UpdateError("GOAT_UPDATE_METADATA_MISMATCH");
    }
  }
}
