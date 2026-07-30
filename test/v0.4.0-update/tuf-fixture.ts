/**
 * TEST-ONLY TUF signing material.
 *
 * Private keys are generated ephemerally for hostile updater tests. This
 * module is excluded from the npm package and cannot supply a production root.
 */
import {
  createHash,
  generateKeyPairSync,
  sign,
  type KeyObject,
} from "node:crypto";
import { canonicalize } from "@tufjs/canonical-json";
import {
  expectedArchivePaths,
  expectedTargetPath,
  type GoatUpdateTargetCustom,
  type SignedContentEntry,
  type UpdateArchitecture,
  type UpdateChannel,
  type UpdatePlatform,
} from "../../src/update/schema.js";

export interface TestTufKey {
  readonly keyId: string;
  readonly privateKey: KeyObject;
  readonly publicKeyHex: string;
  readonly json: {
    readonly keytype: "ed25519";
    readonly scheme: "ed25519";
    readonly keyval: { readonly public: string };
  };
}

export interface TestTufKeySet {
  readonly root: readonly [TestTufKey, TestTufKey, TestTufKey];
  readonly targets: readonly [TestTufKey, TestTufKey, TestTufKey];
  readonly snapshot: readonly [TestTufKey];
  readonly timestamp: readonly [TestTufKey];
  readonly stable: readonly [TestTufKey, TestTufKey, TestTufKey];
  readonly beta: readonly [TestTufKey, TestTufKey, TestTufKey];
  readonly development: readonly [TestTufKey, TestTufKey, TestTufKey];
}

export interface TestTufFixture {
  readonly keys: TestTufKeySet;
  readonly root: Buffer;
  readonly rootSha256: string;
  readonly timestamp: Buffer;
  readonly snapshot: Buffer;
  readonly targets: Buffer;
  readonly channels: Readonly<Record<UpdateChannel, Buffer>>;
  readonly targetPaths: Readonly<Record<UpdateChannel, string>>;
}

export interface TestTufFixtureOptions {
  readonly keys?: TestTufKeySet;
  readonly metadataVersion?: number;
  readonly expires?: string;
  readonly revokedKeyIds?: readonly string[];
  readonly revokedArtifactSha256?: readonly string[];
  readonly revokedReleaseSequences?: readonly number[];
  readonly platform?: UpdatePlatform;
  readonly architecture?: UpdateArchitecture;
  readonly artifactLength?: number;
  readonly artifactSha256?: string;
  readonly contents?: readonly SignedContentEntry[];
  readonly codeSigningIdentityId?: string;
}

const SPEC_VERSION = "1.0.31";
const DEFAULT_EXPIRY = "2035-01-01T00:00:00Z";

export function createTestTufKeySet(): TestTufKeySet {
  return {
    root: triple(),
    targets: triple(),
    snapshot: [createTestTufKey()],
    timestamp: [createTestTufKey()],
    stable: triple(),
    beta: triple(),
    development: triple(),
  };
}

export function createTestTufFixture(
  options: TestTufFixtureOptions = {},
): TestTufFixture {
  const keys = options.keys ?? createTestTufKeySet();
  const metadataVersion = options.metadataVersion ?? 1;
  const expires = options.expires ?? DEFAULT_EXPIRY;
  const rootSigned = {
    _type: "root",
    spec_version: SPEC_VERSION,
    version: 1,
    expires,
    consistent_snapshot: true,
    keys: keyMap([
      ...keys.root,
      ...keys.targets,
      ...keys.snapshot,
      ...keys.timestamp,
    ]),
    roles: {
      root: role(keys.root, 2),
      snapshot: role(keys.snapshot, 1),
      targets: role(keys.targets, 2),
      timestamp: role(keys.timestamp, 1),
    },
  };
  const root = signEnvelope(rootSigned, keys.root.slice(0, 2));

  const channelSigned = Object.fromEntries(
    (["stable", "beta", "development"] as const).map((channel) => {
      const custom = targetCustom(channel, metadataVersion, options);
      const targetPath = expectedTargetPath(custom);
      return [
        channel,
        {
          targetPath,
          signed: {
            _type: "targets",
            spec_version: SPEC_VERSION,
            version: metadataVersion,
            expires,
            targets: {
              [targetPath]: {
                length: options.artifactLength ?? 1_024,
                hashes: {
                  sha256: options.artifactSha256 ?? artifactHash(channel),
                },
                custom,
              },
            },
          },
        },
      ];
    }),
  ) as unknown as Record<
    UpdateChannel,
    { readonly targetPath: string; readonly signed: Record<string, unknown> }
  >;

  const channels = {
    stable: signEnvelope(channelSigned.stable.signed, keys.stable.slice(0, 2)),
    beta: signEnvelope(channelSigned.beta.signed, keys.beta.slice(0, 2)),
    development: signEnvelope(
      channelSigned.development.signed,
      keys.development.slice(0, 2),
    ),
  };

  const targetsSigned = {
    _type: "targets",
    spec_version: SPEC_VERSION,
    version: metadataVersion,
    expires,
    targets: {},
    delegations: {
      keys: keyMap([...keys.stable, ...keys.beta, ...keys.development]),
      roles: (["stable", "beta", "development"] as const).map((channel) => ({
        name: channel,
        keyids: keys[channel].map((key) => key.keyId).sort(compareStrings),
        threshold: 2,
        terminating: true,
        paths: [`goat-engine/${channel}/*`],
      })),
    },
    custom: {
      goatRevocationSchema: 1,
      revokedKeyIds: [...(options.revokedKeyIds ?? [])].sort(compareStrings),
      revokedArtifactSha256: [...(options.revokedArtifactSha256 ?? [])].sort(
        compareStrings,
      ),
      revokedReleaseSequences: [
        ...(options.revokedReleaseSequences ?? []),
      ].sort((left, right) => left - right),
    },
  };
  const targets = signEnvelope(targetsSigned, keys.targets.slice(0, 2));

  const snapshotSigned = {
    _type: "snapshot",
    spec_version: SPEC_VERSION,
    version: metadataVersion,
    expires,
    meta: {
      "beta.json": metaFile(channels.beta, metadataVersion),
      "development.json": metaFile(channels.development, metadataVersion),
      "stable.json": metaFile(channels.stable, metadataVersion),
      "targets.json": metaFile(targets, metadataVersion),
    },
  };
  const snapshot = signEnvelope(snapshotSigned, keys.snapshot);
  const timestamp = signEnvelope(
    {
      _type: "timestamp",
      spec_version: SPEC_VERSION,
      version: metadataVersion,
      expires,
      meta: { "snapshot.json": metaFile(snapshot, metadataVersion) },
    },
    keys.timestamp,
  );

  return {
    keys,
    root,
    rootSha256: sha256(root),
    timestamp,
    snapshot,
    targets,
    channels,
    targetPaths: {
      stable: channelSigned.stable.targetPath,
      beta: channelSigned.beta.targetPath,
      development: channelSigned.development.targetPath,
    },
  };
}

export function createTestTufKey(): TestTufKey {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const jwk = publicKey.export({ format: "jwk" });
  if (typeof jwk.x !== "string") throw new Error("test key export failed");
  const publicKeyHex = Buffer.from(jwk.x, "base64url").toString("hex");
  const json = {
    keytype: "ed25519" as const,
    scheme: "ed25519" as const,
    keyval: { public: publicKeyHex },
  };
  return {
    keyId: sha256(Buffer.from(canonicalize(json), "utf8")),
    privateKey,
    publicKeyHex,
    json,
  };
}

export function signEnvelope(
  signed: Record<string, unknown>,
  signers: readonly TestTufKey[],
): Buffer {
  const signedBytes = Buffer.from(canonicalize(signed), "utf8");
  const signatures = signers
    .map((key) => ({
      keyid: key.keyId,
      sig: sign(null, signedBytes, key.privateKey).toString("hex"),
    }))
    .sort((left, right) => compareStrings(left.keyid, right.keyid));
  return Buffer.from(canonicalize({ signatures, signed }), "utf8");
}

export function parseFixtureEnvelope(bytes: Uint8Array): {
  signatures: { keyid: string; sig: string }[];
  signed: Record<string, unknown>;
} {
  return JSON.parse(Buffer.from(bytes).toString("utf8")) as {
    signatures: { keyid: string; sig: string }[];
    signed: Record<string, unknown>;
  };
}

function targetCustom(
  channel: UpdateChannel,
  releaseSequence: number,
  options: TestTufFixtureOptions,
): GoatUpdateTargetCustom {
  const productVersion =
    channel === "stable"
      ? "0.4.0"
      : channel === "beta"
        ? `0.4.0-beta.${releaseSequence}`
        : `0.4.0-dev.${releaseSequence}`;
  const platform = options.platform ?? "win32";
  const architecture = options.architecture ?? "x64";
  const contents =
    options.contents ??
    expectedArchivePaths(platform).map((entryPath) => ({
      path: entryPath,
      type: "regular-file" as const,
      length: 16,
      sha256: sha256(Buffer.from(`${channel}:${entryPath}`, "utf8")),
      mode: (entryPath.startsWith("bin/") ? 493 : 420) as 493 | 420,
    }));
  return {
    goatUpdateSchema: 1,
    product: "GOAT",
    component: "goat-engine",
    productVersion,
    goatEngineVersion: productVersion,
    openCodeBaseline: "1.17.11",
    releaseSequence,
    channel,
    platform,
    architecture,
    cpuFeatures: [],
    artifactFormat: "goat-engine-zip-v1",
    launcherCompatibility: {
      minInclusive: "0.4.0",
      maxExclusive: "0.5.0",
    },
    engineProtocolCompatibility: {
      launchContract: "0.0.6",
      privacyActivation: "GOATIPC2",
      authenticatedFrame: "GOATIPC1",
    },
    innerManifestSchema: 2,
    codeSigning: {
      scheme:
        platform === "win32" ? "authenticode-sha256" : "apple-developer-id",
      identityId: options.codeSigningIdentityId ?? `test-only-${platform}`,
    },
    contents,
  };
}

function triple(): [TestTufKey, TestTufKey, TestTufKey] {
  return [createTestTufKey(), createTestTufKey(), createTestTufKey()];
}

function keyMap(
  keys: readonly TestTufKey[],
): Record<string, TestTufKey["json"]> {
  return Object.fromEntries(
    [...keys]
      .sort((left, right) => compareStrings(left.keyId, right.keyId))
      .map((key) => [key.keyId, key.json]),
  );
}

function role(keys: readonly TestTufKey[], threshold: number) {
  return {
    keyids: keys.map((key) => key.keyId).sort(compareStrings),
    threshold,
  };
}

function metaFile(bytes: Buffer, version: number) {
  return {
    version,
    length: bytes.byteLength,
    hashes: { sha256: sha256(bytes) },
  };
}

function artifactHash(channel: UpdateChannel): string {
  return sha256(Buffer.from(`test-only-${channel}-artifact`, "utf8"));
}

function sha256(value: Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function compareStrings(left: string, right: string): number {
  return left.localeCompare(right);
}
