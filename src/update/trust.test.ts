import assert from "node:assert/strict";
import { sign } from "node:crypto";
import test from "node:test";
import { canonicalize } from "@tufjs/canonical-json";
import {
  createTestTufFixture,
  createTestTufKey,
  parseFixtureEnvelope,
  signEnvelope,
} from "../../test/v0.4.0-update/tuf-fixture.js";
import { UpdateError } from "./errors.js";
import {
  emptyTrustedMetadataState,
  TufTrustStore,
  type TrustedMetadataState,
} from "./trust.js";

const NOW = new Date("2030-01-01T00:00:00Z");

test("real TUF thresholds authenticate one consistent channel metadata set", () => {
  const fixture = createTestTufFixture();
  const result = authenticate(fixture);
  assert.equal(result.nextState.versions.root, 1);
  assert.equal(result.nextState.versions.timestamp, 1);
  assert.equal(result.nextState.versions.stable, 1);
  assert.deepEqual(result.nextState.revokedKeyIds, []);
});

test("modifiedCanonicalManifestFailsSignature", () => {
  const fixture = createTestTufFixture();
  const envelope = parseFixtureEnvelope(fixture.channels.stable);
  const targets = envelope.signed.targets as Record<
    string,
    { custom: Record<string, unknown> }
  >;
  targets[fixture.targetPaths.stable]!.custom.productVersion = "0.4.1";
  const modified = Buffer.from(canonicalize(envelope), "utf8");

  assert.throws(
    () => authenticate(fixture, { channel: modified }),
    isUpdateError("GOAT_UPDATE_SIGNATURE_INVALID"),
  );
});

test("unknownSigningKeyIsRejected even when authorized signatures are present", () => {
  const fixture = createTestTufFixture();
  const envelope = parseFixtureEnvelope(fixture.channels.stable);
  const unknown = createTestTufKey();
  const unknownSignature = sign(
    null,
    Buffer.from(canonicalize(envelope.signed), "utf8"),
    unknown.privateKey,
  ).toString("hex");
  envelope.signatures.push({ keyid: unknown.keyId, sig: unknownSignature });
  envelope.signatures.sort((left, right) =>
    left.keyid.localeCompare(right.keyid),
  );
  const withUnknown = Buffer.from(canonicalize(envelope), "utf8");

  assert.throws(
    () => authenticate(fixture, { channel: withUnknown }),
    isUpdateError("GOAT_UPDATE_SIGNING_KEY_UNKNOWN"),
  );
});

test("revokedSigningKeyIsRejected", () => {
  const base = createTestTufFixture();
  const revoked = createTestTufFixture({
    keys: base.keys,
    revokedKeyIds: [base.keys.stable[0].keyId],
  });
  assert.throws(
    () => authenticate(revoked),
    isUpdateError("GOAT_UPDATE_SIGNING_KEY_REVOKED"),
  );
});

test("invalid threshold signature is rejected", () => {
  const fixture = createTestTufFixture();
  const envelope = parseFixtureEnvelope(fixture.channels.stable);
  envelope.signatures[0]!.sig = "0".repeat(128);
  const invalid = Buffer.from(canonicalize(envelope), "utf8");
  assert.throws(
    () => authenticate(fixture, { channel: invalid }),
    isUpdateError("GOAT_UPDATE_SIGNATURE_INVALID"),
  );
});

test("expiredOrReplayedMetadataIsRejected", () => {
  const expired = createTestTufFixture({
    expires: "2029-12-31T23:59:59Z",
  });
  assert.throws(
    () => authenticate(expired),
    isUpdateError("GOAT_UPDATE_METADATA_EXPIRED"),
  );

  const higher = createTestTufFixture({ metadataVersion: 2 });
  const store = new TufTrustStore(higher.root, higher.rootSha256);
  const accepted = authenticateWithStore(
    store,
    higher,
    emptyTrustedMetadataState(),
  );
  const lower = createTestTufFixture({ keys: higher.keys, metadataVersion: 1 });
  assert.throws(
    () => authenticateWithStore(store, lower, accepted.nextState),
    isUpdateError("GOAT_UPDATE_METADATA_REPLAYED"),
  );
});

test("snapshot mix-and-match is rejected even when every file is signed", () => {
  const first = createTestTufFixture({ metadataVersion: 1 });
  const second = createTestTufFixture({ keys: first.keys, metadataVersion: 2 });
  assert.throws(
    () => authenticate(second, { timestamp: first.timestamp }),
    isUpdateError("GOAT_UPDATE_METADATA_MISMATCH"),
  );
});

test("revocation lists cannot be rolled back", () => {
  const base = createTestTufFixture({ metadataVersion: 1 });
  const revokedHash = "f".repeat(64);
  const withRevocation = createTestTufFixture({
    keys: base.keys,
    metadataVersion: 2,
    revokedArtifactSha256: [revokedHash],
  });
  const store = new TufTrustStore(base.root, base.rootSha256);
  const accepted = authenticateWithStore(
    store,
    withRevocation,
    emptyTrustedMetadataState(),
  );
  const removed = createTestTufFixture({
    keys: base.keys,
    metadataVersion: 3,
  });
  assert.throws(
    () => authenticateWithStore(store, removed, accepted.nextState),
    isUpdateError("GOAT_UPDATE_METADATA_REPLAYED"),
  );
});

test("same-version metadata bytes cannot be replaced", () => {
  const fixture = createTestTufFixture();
  const store = new TufTrustStore(fixture.root, fixture.rootSha256);
  const accepted = authenticateWithStore(
    store,
    fixture,
    emptyTrustedMetadataState(),
  );
  const replacement = createTestTufFixture({
    keys: fixture.keys,
    metadataVersion: 1,
    revokedArtifactSha256: ["e".repeat(64)],
  });
  assert.throws(
    () => authenticateWithStore(store, replacement, accepted.nextState),
    isUpdateError("GOAT_UPDATE_METADATA_REPLAYED"),
  );
});

function authenticate(
  fixture: ReturnType<typeof createTestTufFixture>,
  overrides: {
    readonly timestamp?: Buffer;
    readonly snapshot?: Buffer;
    readonly targets?: Buffer;
    readonly channel?: Buffer;
    readonly state?: TrustedMetadataState;
  } = {},
) {
  const store = new TufTrustStore(fixture.root, fixture.rootSha256);
  return authenticateWithStore(
    store,
    fixture,
    overrides.state ?? emptyTrustedMetadataState(),
    overrides,
  );
}

function authenticateWithStore(
  store: TufTrustStore,
  fixture: ReturnType<typeof createTestTufFixture>,
  state: TrustedMetadataState,
  overrides: {
    readonly timestamp?: Buffer;
    readonly snapshot?: Buffer;
    readonly targets?: Buffer;
    readonly channel?: Buffer;
  } = {},
) {
  return store.authenticate({
    timestamp: overrides.timestamp ?? fixture.timestamp,
    snapshot: overrides.snapshot ?? fixture.snapshot,
    targets: overrides.targets ?? fixture.targets,
    channel: overrides.channel ?? fixture.channels.stable,
    channelName: "stable",
    state,
    now: NOW,
  });
}

function isUpdateError(code: UpdateError["code"]): (error: unknown) => boolean {
  return (error) => error instanceof UpdateError && error.code === code;
}
