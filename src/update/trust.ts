import { createHash } from "node:crypto";
import type { Root, Snapshot, Targets, Timestamp } from "@tufjs/models";
import { UpdateError } from "./errors.js";
import {
  parseRootMetadata,
  parseSnapshotMetadata,
  parseTargetsMetadata,
  parseTimestampMetadata,
  topLevelRevocations,
  type ParsedTufMetadata,
  type TopLevelRevocations,
  type TufRoleName,
} from "./metadata.js";
import type { UpdateChannel } from "./schema.js";

export interface TrustedMetadataVersions {
  readonly root: number;
  readonly timestamp: number;
  readonly snapshot: number;
  readonly targets: number;
  readonly stable: number;
  readonly beta: number;
  readonly development: number;
}

export interface TrustedMetadataDigests {
  readonly root?: string;
  readonly timestamp?: string;
  readonly snapshot?: string;
  readonly targets?: string;
  readonly stable?: string;
  readonly beta?: string;
  readonly development?: string;
}

export interface TrustedMetadataState {
  readonly versions: TrustedMetadataVersions;
  readonly digests: TrustedMetadataDigests;
  readonly trustedTimeUnixMs: number;
  readonly revokedKeyIds: readonly string[];
  readonly revokedArtifactSha256: readonly string[];
  readonly revokedReleaseSequences: readonly number[];
}

export interface AuthenticatedMetadataSet {
  readonly root: ParsedTufMetadata<Root>;
  readonly timestamp: ParsedTufMetadata<Timestamp>;
  readonly snapshot: ParsedTufMetadata<Snapshot>;
  readonly targets: ParsedTufMetadata<Targets>;
  readonly channel: ParsedTufMetadata<Targets>;
  readonly revocations: TopLevelRevocations;
  readonly nextState: TrustedMetadataState;
}

export interface AuthenticateMetadataInput {
  readonly sequentialRoots?: readonly Uint8Array[];
  readonly timestamp: Uint8Array;
  readonly snapshot: Uint8Array;
  readonly targets: Uint8Array;
  readonly channel: Uint8Array;
  readonly channelName: UpdateChannel;
  readonly state: TrustedMetadataState;
  readonly now?: Date;
}

const MAX_SEQUENTIAL_ROOTS = 32;
const MAX_VERSION_ADVANCE = 1024;

export function emptyTrustedMetadataState(
  now: Date = new Date(0),
): TrustedMetadataState {
  return {
    versions: {
      root: 0,
      timestamp: 0,
      snapshot: 0,
      targets: 0,
      stable: 0,
      beta: 0,
      development: 0,
    },
    digests: {},
    trustedTimeUnixMs: now.getTime(),
    revokedKeyIds: [],
    revokedArtifactSha256: [],
    revokedReleaseSequences: [],
  };
}

export class TufTrustStore {
  private root: ParsedTufMetadata<Root>;

  constructor(
    embeddedRootBytes: Uint8Array,
    expectedEmbeddedRootSha256: string,
  ) {
    if (
      !/^[a-f0-9]{64}$/.test(expectedEmbeddedRootSha256) ||
      sha256(embeddedRootBytes) !== expectedEmbeddedRootSha256
    ) {
      throw new UpdateError("GOAT_UPDATE_SIGNATURE_INVALID");
    }
    this.root = parseRootMetadata(embeddedRootBytes);
    assertAuthorizedSignatures(
      this.root,
      rootRoleKeyIds(this.root, "root"),
      [],
    );
    verifyDelegation(this.root, "root", this.root);
  }

  authenticate(input: AuthenticateMetadataInput): AuthenticatedMetadataSet {
    return this.authenticateInternal(input, true);
  }

  /**
   * Reauthenticates a stored installation receipt. Expiration is intentionally
   * not enforced here: expiry prevents accepting an update from the network,
   * but does not by itself revoke an already authenticated installed engine.
   * Callers must still apply the current revocation policy.
   */
  authenticateInstalledReceipt(
    input: AuthenticateMetadataInput,
  ): AuthenticatedMetadataSet {
    return this.authenticateInternal(input, false);
  }

  private authenticateInternal(
    input: AuthenticateMetadataInput,
    enforceExpiration: boolean,
  ): AuthenticatedMetadataSet {
    const sequentialRoots = input.sequentialRoots ?? [];
    if (sequentialRoots.length > MAX_SEQUENTIAL_ROOTS) {
      throw new UpdateError("GOAT_UPDATE_MANIFEST_UNSUPPORTED");
    }
    this.applySequentialRoots(sequentialRoots, input.state);

    const timestamp = parseTimestampMetadata(input.timestamp);
    const snapshot = parseSnapshotMetadata(input.snapshot);
    const targets = parseTargetsMetadata(input.targets, "targets");
    const channel = parseTargetsMetadata(input.channel, input.channelName);

    const inheritedRevocations = input.state.revokedKeyIds;
    assertAuthorizedSignatures(
      timestamp,
      rootRoleKeyIds(this.root, "timestamp"),
      inheritedRevocations,
    );
    assertAuthorizedSignatures(
      snapshot,
      rootRoleKeyIds(this.root, "snapshot"),
      inheritedRevocations,
    );
    assertAuthorizedSignatures(
      targets,
      rootRoleKeyIds(this.root, "targets"),
      inheritedRevocations,
    );
    verifyDelegation(this.root, "timestamp", timestamp);
    verifyDelegation(this.root, "snapshot", snapshot);
    verifyDelegation(this.root, "targets", targets);

    const revocations = topLevelRevocations(targets);
    assertRevocationsMonotonic(input.state, revocations);
    assertAuthorizedSignatures(
      channel,
      delegatedRoleKeyIds(targets, input.channelName),
      revocations.revokedKeyIds,
    );
    verifyDelegation(targets, input.channelName, channel);

    const trustedTimeUnixMs = Math.max(
      input.now?.getTime() ?? Date.now(),
      input.state.trustedTimeUnixMs,
    );
    for (const parsed of [this.root, timestamp, snapshot, targets, channel]) {
      if (
        enforceExpiration &&
        parsed.metadata.signed.isExpired(new Date(trustedTimeUnixMs))
      ) {
        throw new UpdateError("GOAT_UPDATE_METADATA_EXPIRED");
      }
    }

    verifyMetadataBindings(
      timestamp,
      snapshot,
      targets,
      channel,
      input.channelName,
    );
    const nextVersions = {
      ...input.state.versions,
      root: this.root.metadata.signed.version,
      timestamp: timestamp.metadata.signed.version,
      snapshot: snapshot.metadata.signed.version,
      targets: targets.metadata.signed.version,
      [input.channelName]: channel.metadata.signed.version,
    };
    const nextDigests = {
      ...input.state.digests,
      root: sha256(this.root.bytes),
      timestamp: sha256(timestamp.bytes),
      snapshot: sha256(snapshot.bytes),
      targets: sha256(targets.bytes),
      [input.channelName]: sha256(channel.bytes),
    };
    assertMetadataFloors(
      input.state,
      { root: this.root, timestamp, snapshot, targets, channel },
      input.channelName,
    );

    return {
      root: this.root,
      timestamp,
      snapshot,
      targets,
      channel,
      revocations,
      nextState: {
        versions: nextVersions,
        digests: nextDigests,
        trustedTimeUnixMs,
        revokedKeyIds: unionSorted(
          input.state.revokedKeyIds,
          revocations.revokedKeyIds,
        ),
        revokedArtifactSha256: unionSorted(
          input.state.revokedArtifactSha256,
          revocations.revokedArtifactSha256,
        ),
        revokedReleaseSequences: unionSorted(
          input.state.revokedReleaseSequences,
          revocations.revokedReleaseSequences,
        ),
      },
    };
  }

  private applySequentialRoots(
    rawRoots: readonly Uint8Array[],
    state: TrustedMetadataState,
  ): void {
    for (const rawRoot of rawRoots) {
      const next = parseRootMetadata(rawRoot);
      if (
        next.metadata.signed.version !==
        this.root.metadata.signed.version + 1
      ) {
        throw new UpdateError("GOAT_UPDATE_METADATA_REPLAYED");
      }
      const oldKeys = rootRoleKeyIds(this.root, "root");
      const newKeys = rootRoleKeyIds(next, "root");
      const allowed = unionSorted(oldKeys, newKeys);
      assertAuthorizedSignatures(next, allowed, state.revokedKeyIds);
      verifyDelegation(this.root, "root", next);
      verifyDelegation(next, "root", next);
      this.root = next;
    }
    const trustedRootFloor = state.versions.root;
    if (this.root.metadata.signed.version < trustedRootFloor) {
      throw new UpdateError("GOAT_UPDATE_METADATA_REPLAYED");
    }
    if (
      this.root.metadata.signed.version === trustedRootFloor &&
      state.digests.root &&
      state.digests.root !== sha256(this.root.bytes)
    ) {
      throw new UpdateError("GOAT_UPDATE_METADATA_REPLAYED");
    }
  }
}

function assertMetadataFloors(
  state: TrustedMetadataState,
  metadata: {
    readonly root: ParsedTufMetadata<Root>;
    readonly timestamp: ParsedTufMetadata<Timestamp>;
    readonly snapshot: ParsedTufMetadata<Snapshot>;
    readonly targets: ParsedTufMetadata<Targets>;
    readonly channel: ParsedTufMetadata<Targets>;
  },
  channelName: UpdateChannel,
): void {
  const entries: readonly [
    keyof TrustedMetadataVersions,
    ParsedTufMetadata<Root | Timestamp | Snapshot | Targets>,
  ][] = [
    ["root", metadata.root],
    ["timestamp", metadata.timestamp],
    ["snapshot", metadata.snapshot],
    ["targets", metadata.targets],
    [channelName, metadata.channel],
  ];
  for (const [role, parsed] of entries) {
    const version = parsed.metadata.signed.version;
    const floor = state.versions[role];
    if (
      version < floor ||
      (floor > 0 && version - floor > MAX_VERSION_ADVANCE)
    ) {
      throw new UpdateError("GOAT_UPDATE_METADATA_REPLAYED");
    }
    const priorDigest = state.digests[role];
    if (
      version === floor &&
      priorDigest &&
      priorDigest !== sha256(parsed.bytes)
    ) {
      throw new UpdateError("GOAT_UPDATE_METADATA_REPLAYED");
    }
  }
}

function verifyMetadataBindings(
  timestamp: ParsedTufMetadata<Timestamp>,
  snapshot: ParsedTufMetadata<Snapshot>,
  targets: ParsedTufMetadata<Targets>,
  channel: ParsedTufMetadata<Targets>,
  channelName: UpdateChannel,
): void {
  const snapshotMeta = timestamp.metadata.signed.snapshotMeta;
  if (snapshotMeta.version !== snapshot.metadata.signed.version) {
    throw new UpdateError("GOAT_UPDATE_METADATA_MISMATCH");
  }
  verifyMetaFile(snapshotMeta, snapshot.bytes);

  const targetsMeta = snapshot.metadata.signed.meta["targets.json"];
  const channelMeta = snapshot.metadata.signed.meta[`${channelName}.json`];
  if (
    !targetsMeta ||
    !channelMeta ||
    targetsMeta.version !== targets.metadata.signed.version ||
    channelMeta.version !== channel.metadata.signed.version
  ) {
    throw new UpdateError("GOAT_UPDATE_METADATA_MISMATCH");
  }
  verifyMetaFile(targetsMeta, targets.bytes);
  verifyMetaFile(channelMeta, channel.bytes);
}

function verifyMetaFile(
  meta: { verify(data: Buffer): void },
  bytes: Buffer,
): void {
  try {
    meta.verify(bytes);
  } catch (error) {
    throw new UpdateError("GOAT_UPDATE_METADATA_MISMATCH", { cause: error });
  }
}

function assertAuthorizedSignatures(
  metadata: ParsedTufMetadata<Root | Timestamp | Snapshot | Targets>,
  authorizedKeyIds: readonly string[],
  revokedKeyIds: readonly string[],
): void {
  const allowed = new Set(authorizedKeyIds);
  const revoked = new Set(revokedKeyIds);
  for (const keyId of Object.keys(metadata.metadata.signatures)) {
    if (revoked.has(keyId)) {
      throw new UpdateError("GOAT_UPDATE_SIGNING_KEY_REVOKED");
    }
    if (!allowed.has(keyId)) {
      throw new UpdateError("GOAT_UPDATE_SIGNING_KEY_UNKNOWN");
    }
  }
}

function verifyDelegation(
  delegator: ParsedTufMetadata<Root | Targets>,
  roleName: string,
  delegated: ParsedTufMetadata<Root | Timestamp | Snapshot | Targets>,
): void {
  try {
    delegator.metadata.verifyDelegate(roleName, delegated.metadata);
  } catch (error) {
    throw new UpdateError("GOAT_UPDATE_SIGNATURE_INVALID", { cause: error });
  }
}

function rootRoleKeyIds(
  root: ParsedTufMetadata<Root>,
  roleName: "root" | "targets" | "snapshot" | "timestamp",
): readonly string[] {
  const role = root.metadata.signed.roles[roleName];
  if (!role) throw new UpdateError("GOAT_UPDATE_MANIFEST_INVALID");
  return [...role.keyIDs];
}

function delegatedRoleKeyIds(
  targets: ParsedTufMetadata<Targets>,
  roleName: UpdateChannel,
): readonly string[] {
  const role = targets.metadata.signed.delegations?.roles?.[roleName];
  if (!role) throw new UpdateError("GOAT_UPDATE_MANIFEST_INVALID");
  return [...role.keyIDs];
}

function assertRevocationsMonotonic(
  state: TrustedMetadataState,
  revocations: TopLevelRevocations,
): void {
  for (const [prior, next] of [
    [state.revokedKeyIds, revocations.revokedKeyIds],
    [state.revokedArtifactSha256, revocations.revokedArtifactSha256],
    [state.revokedReleaseSequences, revocations.revokedReleaseSequences],
  ] as const) {
    const nextSet = new Set<string | number>(next);
    if (prior.some((value) => !nextSet.has(value))) {
      throw new UpdateError("GOAT_UPDATE_METADATA_REPLAYED");
    }
  }
}

function unionSorted<T extends string | number>(
  left: readonly T[],
  right: readonly T[],
): T[] {
  return [...new Set([...left, ...right])].sort((a, b) =>
    a < b ? -1 : a > b ? 1 : 0,
  );
}

function sha256(value: Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

export function metadataRoleDigest(
  metadata: ParsedTufMetadata<Root | Timestamp | Snapshot | Targets>,
): { readonly role: TufRoleName; readonly sha256: string } {
  return { role: metadata.roleName, sha256: sha256(metadata.bytes) };
}
