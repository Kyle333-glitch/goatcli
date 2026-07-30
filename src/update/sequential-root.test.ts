import assert from "node:assert/strict";
import { createHash, sign } from "node:crypto";
import test from "node:test";
import { canonicalize } from "@tufjs/canonical-json";
import {
  createTestTufKey,
  createTestTufKeySet,
  type TestTufKey,
  type TestTufKeySet,
} from "../../test/v0.4.0-update/tuf-fixture.js";
import { UpdateError } from "./errors.js";
import { MockManifestServer } from "../../test/v0.4.0-update/mock-manifest-server.js";
import { fetchUpdateMetadata } from "./metadata-client.js";
import { FixedOriginTransport } from "./network.js";
import { emptyTrustedMetadataState, TufTrustStore } from "./trust.js";

const NOW = new Date("2030-01-01T00:00:00Z");

interface SequentialRootFixture {
  readonly embeddedRoot: Buffer;
  readonly sequentialRoots: Buffer[];
  readonly timestamp: Buffer;
  readonly snapshot: Buffer;
  readonly targets: Buffer;
  readonly channel: Buffer;
  readonly finalRootKeys: readonly TestTufKey[];
}

function signRoot(
  signed: Record<string, unknown>,
  signers: readonly TestTufKey[],
): Buffer {
  const signedBytes = Buffer.from(canonicalize(signed), "utf8");
  const signatures = [...signers]
    .map((key) => ({
      keyid: key.keyId,
      sig: sign(null, signedBytes, key.privateKey).toString("hex"),
    }))
    .sort((left, right) => left.keyid.localeCompare(right.keyid));
  return Buffer.from(canonicalize({ signatures, signed }), "utf8");
}

function makeRoot(
  version: number,
  keys: TestTufKeySet,
  rootKeys: readonly TestTufKey[],
  options: { threshold?: number } = {},
): { readonly root: Buffer; readonly rootKeys: readonly TestTufKey[] } {
  const threshold = options.threshold ?? 2;
  const allKeys = [
    ...rootKeys,
    ...keys.targets,
    ...keys.snapshot,
    ...keys.timestamp,
    ...keys.stable,
    ...keys.beta,
    ...keys.development,
  ];
  const signed = {
    _type: "root",
    spec_version: "1.0.31",
    version,
    expires: "2035-01-01T00:00:00Z",
    consistent_snapshot: true,
    keys: Object.fromEntries(
      [...allKeys]
        .sort((a, b) => a.keyId.localeCompare(b.keyId))
        .map((key) => [key.keyId, key.json]),
    ),
    roles: {
      root: { keyids: rootKeys.map((k) => k.keyId).sort(), threshold },
      snapshot: {
        keyids: keys.snapshot.map((k) => k.keyId).sort(),
        threshold: 1,
      },
      targets: { keyids: keys.targets.map((k) => k.keyId).sort(), threshold },
      timestamp: {
        keyids: keys.timestamp.map((k) => k.keyId).sort(),
        threshold: 1,
      },
    },
  };
  return { root: signRoot(signed, rootKeys.slice(0, threshold)), rootKeys };
}

function makeChannelTargets(
  keys: TestTufKeySet,
  version: number,
  channel: "stable" | "beta" | "development",
): Buffer {
  const targetPath = `goat-engine/${channel}/0.4.0/win32-x64/goat-engine.zip`;
  const signed = {
    _type: "targets",
    spec_version: "1.0.31",
    version,
    expires: "2035-01-01T00:00:00Z",
    targets: {
      [targetPath]: {
        length: 1024,
        hashes: { sha256: "a".repeat(64) },
        custom: {
          goatUpdateSchema: 1,
          product: "GOAT",
          component: "goat-engine",
          productVersion: "0.4.0",
          goatEngineVersion: "0.4.0",
          openCodeBaseline: "1.17.11",
          releaseSequence: 1,
          channel,
          platform: "win32",
          architecture: "x64",
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
            scheme: "authenticode-sha256",
            identityId: "test-only-win32",
          },
          contents: [],
        },
      },
    },
  };
  return signRoot(signed, keys[channel].slice(0, 2));
}

function makeTargets(keys: TestTufKeySet, version: number): Buffer {
  const signed = {
    _type: "targets",
    spec_version: "1.0.31",
    version,
    expires: "2035-01-01T00:00:00Z",
    targets: {},
    delegations: {
      keys: Object.fromEntries(
        [...keys.stable, ...keys.beta, ...keys.development]
          .sort((a, b) => a.keyId.localeCompare(b.keyId))
          .map((key) => [key.keyId, key.json]),
      ),
      roles: (["stable", "beta", "development"] as const).map((channel) => ({
        name: channel,
        keyids: keys[channel].map((key) => key.keyId).sort(),
        threshold: 2,
        terminating: true,
        paths: [`goat-engine/${channel}/*`],
      })),
    },
    custom: {
      goatRevocationSchema: 1,
      revokedKeyIds: [],
      revokedArtifactSha256: [],
      revokedReleaseSequences: [],
    },
  };
  return signRoot(signed, keys.targets.slice(0, 2));
}

function makeSnapshot(
  keys: TestTufKeySet,
  version: number,
  targets: Buffer,
  channel: Buffer,
): Buffer {
  const metaFile = (bytes: Buffer) => ({
    version,
    length: bytes.byteLength,
    hashes: { sha256: sha256(bytes) },
  });
  const signed = {
    _type: "snapshot",
    spec_version: "1.0.31",
    version,
    expires: "2035-01-01T00:00:00Z",
    meta: {
      "beta.json": metaFile(channel),
      "development.json": metaFile(channel),
      "stable.json": metaFile(channel),
      "targets.json": metaFile(targets),
    },
  };
  return signRoot(signed, keys.snapshot.slice(0, 1));
}

function makeTimestamp(
  keys: TestTufKeySet,
  version: number,
  snapshot: Buffer,
): Buffer {
  const signed = {
    _type: "timestamp",
    spec_version: "1.0.31",
    version,
    expires: "2035-01-01T00:00:00Z",
    meta: {
      "snapshot.json": {
        version,
        length: snapshot.byteLength,
        hashes: { sha256: sha256(snapshot) },
      },
    },
  };
  return signRoot(signed, keys.timestamp.slice(0, 1));
}

function buildRotatedFixture(
  rotations: number,
  signWith: (
    rootKeys: readonly TestTufKey[],
    nextKeys: readonly TestTufKey[],
  ) => readonly TestTufKey[],
  options: { skipVersion?: number } = {},
): SequentialRootFixture {
  const keys = createTestTufKeySet();
  const { root: embeddedRoot } = makeRoot(1, keys, keys.root);
  const sequentialRoots: Buffer[] = [];
  let currentKeys: readonly TestTufKey[] = keys.root;
  for (let version = 2; version <= rotations + 1; version += 1) {
    const nextKeys: TestTufKey[] = [
      createTestTufKey(),
      createTestTufKey(),
      createTestTufKey(),
    ];
    const effectiveVersion =
      options.skipVersion === version ? version + 1 : version;
    const { root } = makeRoot(effectiveVersion, keys, nextKeys, {
      threshold: 2,
    });
    const signers = signWith(currentKeys, nextKeys);
    const parsed = JSON.parse(root.toString("utf8")) as {
      signed: Record<string, unknown>;
      signatures: unknown[];
    };
    sequentialRoots.push(signRoot(parsed.signed, signers));
    currentKeys = nextKeys;
  }
  const targets = makeTargets(keys, 1);
  const channelTargets = makeChannelTargets(keys, 1, "stable");
  const snapshot = makeSnapshot(keys, 1, targets, channelTargets);
  const timestamp = makeTimestamp(keys, 1, snapshot);
  return {
    embeddedRoot,
    sequentialRoots,
    timestamp,
    snapshot,
    targets,
    channel: channelTargets,
    finalRootKeys: currentKeys,
  };
}

function sha256(value: Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

test("valid sequential root rotation authenticates through the production trust store", () => {
  const fixture = buildRotatedFixture(1, (oldKeys, newKeys) => [
    ...oldKeys.slice(0, 2),
    ...newKeys.slice(0, 2),
  ]);
  const store = new TufTrustStore(
    fixture.embeddedRoot,
    sha256(fixture.embeddedRoot),
  );
  const result = store.authenticate({
    sequentialRoots: fixture.sequentialRoots,
    timestamp: fixture.timestamp,
    snapshot: fixture.snapshot,
    targets: fixture.targets,
    channel: fixture.channel,
    channelName: "stable",
    state: emptyTrustedMetadataState(),
    now: NOW,
  });
  assert.equal(result.root.metadata.signed.version, 2);
  assert.equal(result.nextState.versions.root, 2);
});

test("skipped sequential root version is rejected", () => {
  const fixture = buildRotatedFixture(
    2,
    (oldKeys, newKeys) => [...oldKeys.slice(0, 2), ...newKeys.slice(0, 2)],
    { skipVersion: 2 },
  );
  const store = new TufTrustStore(
    fixture.embeddedRoot,
    sha256(fixture.embeddedRoot),
  );
  assert.throws(
    () =>
      store.authenticate({
        sequentialRoots: fixture.sequentialRoots,
        timestamp: fixture.timestamp,
        snapshot: fixture.snapshot,
        targets: fixture.targets,
        channel: fixture.channel,
        channelName: "stable",
        state: emptyTrustedMetadataState(),
        now: NOW,
      }),
    isUpdateError("GOAT_UPDATE_METADATA_REPLAYED"),
  );
});

test("old-threshold-only signatures on the new root are rejected", () => {
  const fixture = buildRotatedFixture(1, (oldKeys) => oldKeys.slice(0, 2));
  const store = new TufTrustStore(
    fixture.embeddedRoot,
    sha256(fixture.embeddedRoot),
  );
  assert.throws(
    () =>
      store.authenticate({
        sequentialRoots: fixture.sequentialRoots,
        timestamp: fixture.timestamp,
        snapshot: fixture.snapshot,
        targets: fixture.targets,
        channel: fixture.channel,
        channelName: "stable",
        state: emptyTrustedMetadataState(),
        now: NOW,
      }),
    isUpdateError("GOAT_UPDATE_SIGNATURE_INVALID"),
  );
});

test("new-threshold-only signatures on the new root are rejected", () => {
  const fixture = buildRotatedFixture(1, (_oldKeys, newKeys) =>
    newKeys.slice(0, 2),
  );
  const store = new TufTrustStore(
    fixture.embeddedRoot,
    sha256(fixture.embeddedRoot),
  );
  assert.throws(
    () =>
      store.authenticate({
        sequentialRoots: fixture.sequentialRoots,
        timestamp: fixture.timestamp,
        snapshot: fixture.snapshot,
        targets: fixture.targets,
        channel: fixture.channel,
        channelName: "stable",
        state: emptyTrustedMetadataState(),
        now: NOW,
      }),
    isUpdateError("GOAT_UPDATE_SIGNATURE_INVALID"),
  );
});

test("dual-threshold success cross-signs the new root with old and new keys", () => {
  const fixture = buildRotatedFixture(1, (oldKeys, newKeys) => [
    ...oldKeys.slice(0, 2),
    ...newKeys.slice(0, 2),
  ]);
  const store = new TufTrustStore(
    fixture.embeddedRoot,
    sha256(fixture.embeddedRoot),
  );
  const result = store.authenticate({
    sequentialRoots: fixture.sequentialRoots,
    timestamp: fixture.timestamp,
    snapshot: fixture.snapshot,
    targets: fixture.targets,
    channel: fixture.channel,
    channelName: "stable",
    state: emptyTrustedMetadataState(),
    now: NOW,
  });
  assert.equal(result.root.metadata.signed.version, 2);
});

test("revoked rotation key is rejected", () => {
  const fixture = buildRotatedFixture(1, (oldKeys, newKeys) => [
    ...oldKeys.slice(0, 2),
    ...newKeys.slice(0, 2),
  ]);
  const state = emptyTrustedMetadataState();
  const revokedKeyId = fixture.finalRootKeys[0]!.keyId;
  const store = new TufTrustStore(
    fixture.embeddedRoot,
    sha256(fixture.embeddedRoot),
  );
  assert.throws(
    () =>
      store.authenticate({
        sequentialRoots: fixture.sequentialRoots,
        timestamp: fixture.timestamp,
        snapshot: fixture.snapshot,
        targets: fixture.targets,
        channel: fixture.channel,
        channelName: "stable",
        state: { ...state, revokedKeyIds: [revokedKeyId] },
        now: NOW,
      }),
    isUpdateError("GOAT_UPDATE_SIGNING_KEY_REVOKED"),
  );
});

test("unknown rotation key is rejected", () => {
  const fixture = buildRotatedFixture(1, (oldKeys, newKeys) => {
    const unknown = createTestTufKey();
    return [...oldKeys.slice(0, 2), unknown];
  });
  const store = new TufTrustStore(
    fixture.embeddedRoot,
    sha256(fixture.embeddedRoot),
  );
  assert.throws(
    () =>
      store.authenticate({
        sequentialRoots: fixture.sequentialRoots,
        timestamp: fixture.timestamp,
        snapshot: fixture.snapshot,
        targets: fixture.targets,
        channel: fixture.channel,
        channelName: "stable",
        state: emptyTrustedMetadataState(),
        now: NOW,
      }),
    isUpdateError("GOAT_UPDATE_SIGNING_KEY_UNKNOWN"),
  );
});

test("root-count limit bounds sequential root discovery", async (context) => {
  const keys = createTestTufKeySet();
  const { root: embeddedRoot } = makeRoot(1, keys, keys.root);
  const sequentialRoots: Buffer[] = [];
  let currentKeys: readonly TestTufKey[] = keys.root;
  for (let version = 2; version <= 34; version += 1) {
    const nextKeys: TestTufKey[] = [
      createTestTufKey(),
      createTestTufKey(),
      createTestTufKey(),
    ];
    const { root } = makeRoot(version, keys, nextKeys);
    const parsed = JSON.parse(root.toString("utf8")) as {
      signed: Record<string, unknown>;
      signatures: unknown[];
    };
    sequentialRoots.push(
      signRoot(parsed.signed, [
        ...currentKeys.slice(0, 2),
        ...nextKeys.slice(0, 2),
      ]),
    );
    currentKeys = nextKeys;
  }
  const server = new MockManifestServer();
  for (let index = 0; index < sequentialRoots.length; index += 1) {
    server.bytes(`/metadata/${index + 2}.root.json`, sequentialRoots[index]!);
  }
  const targets = makeTargets(keys, 1);
  const channelTargets = makeChannelTargets(keys, 1, "stable");
  const snapshot = makeSnapshot(keys, 1, targets, channelTargets);
  server.bytes("/metadata/timestamp.json", makeTimestamp(keys, 1, snapshot));
  server.bytes("/metadata/snapshot.json", snapshot);
  server.bytes("/metadata/targets.json", targets);
  server.bytes("/metadata/stable.json", channelTargets);
  await server.listen();
  context.after(() => server.close());

  await assert.rejects(
    fetchUpdateMetadata(
      new FixedOriginTransport({
        origin: server.origin,
        launcherVersion: "0.4.0",
        channel: "stable",
        platform: "win32",
        architecture: "x64",
        agent: server.agent,
      }),
      embeddedRoot,
      "stable",
      { waitBeforeRetry: async () => undefined },
    ),
    isUpdateError("GOAT_UPDATE_MANIFEST_UNSUPPORTED"),
  );
});

test("oversized sequential root is rejected by the per-root byte limit", () => {
  // The 2 MB total sequential-root guard is unreachable with the current
  // schema (max 32 keys * ~8 KB per valid root < 2 MB). The per-root 256 KB
  // object limit is still enforced by the production metadata parser before
  // any signature or delegation check, so this exercises the byte limit
  // through the real sequential-root authentication path.
  const fixture = buildRotatedFixture(1, (oldKeys, newKeys) => [
    ...oldKeys.slice(0, 2),
    ...newKeys.slice(0, 2),
  ]);
  const oversizedRoot = makeOversizedRoot(2);
  const store = new TufTrustStore(
    fixture.embeddedRoot,
    sha256(fixture.embeddedRoot),
  );
  assert.throws(
    () =>
      store.authenticate({
        sequentialRoots: [oversizedRoot],
        timestamp: fixture.timestamp,
        snapshot: fixture.snapshot,
        targets: fixture.targets,
        channel: fixture.channel,
        channelName: "stable",
        state: emptyTrustedMetadataState(),
        now: NOW,
      }),
    isUpdateError("GOAT_UPDATE_MANIFEST_TOO_LARGE"),
  );
});

function makeOversizedRoot(version: number): Buffer {
  const keys = createTestTufKeySet();
  const manyKeys: TestTufKey[] = [];
  for (let index = 0; index < 2000; index += 1) {
    manyKeys.push(createTestTufKey());
  }
  const { root } = makeRoot(version, keys, manyKeys, { threshold: 2 });
  assert.ok(
    root.byteLength > 256 * 1024,
    "oversized root must exceed the 256 KB per-object limit",
  );
  return root;
}

test("non-canonical sequential root with a tampered signed object is rejected", () => {
  const fixture = buildRotatedFixture(1, (oldKeys, newKeys) => [
    ...oldKeys.slice(0, 2),
    ...newKeys.slice(0, 2),
  ]);
  const original = fixture.sequentialRoots[0]!.toString("utf8");
  const mangled = original.replace('"_type":"root"', '"_type":"root","z":1');
  const roots: Buffer[] = [Buffer.from(mangled, "utf8")];
  const store = new TufTrustStore(
    fixture.embeddedRoot,
    sha256(fixture.embeddedRoot),
  );
  assert.throws(
    () =>
      store.authenticate({
        sequentialRoots: roots,
        timestamp: fixture.timestamp,
        snapshot: fixture.snapshot,
        targets: fixture.targets,
        channel: fixture.channel,
        channelName: "stable",
        state: emptyTrustedMetadataState(),
        now: NOW,
      }),
    isUpdateError("GOAT_UPDATE_MANIFEST_INVALID"),
  );
});

test("malformed sequential root that is not JSON is rejected", () => {
  const fixture = buildRotatedFixture(1, (oldKeys, newKeys) => [
    ...oldKeys.slice(0, 2),
    ...newKeys.slice(0, 2),
  ]);
  const roots: Buffer[] = [Buffer.from("not valid json", "utf8")];
  const store = new TufTrustStore(
    fixture.embeddedRoot,
    sha256(fixture.embeddedRoot),
  );
  assert.throws(
    () =>
      store.authenticate({
        sequentialRoots: roots,
        timestamp: fixture.timestamp,
        snapshot: fixture.snapshot,
        targets: fixture.targets,
        channel: fixture.channel,
        channelName: "stable",
        state: emptyTrustedMetadataState(),
        now: NOW,
      }),
    isUpdateError("GOAT_UPDATE_MANIFEST_INVALID"),
  );
});

function isUpdateError(code: UpdateError["code"]): (error: unknown) => boolean {
  return (error) => error instanceof UpdateError && error.code === code;
}
