import assert from "node:assert/strict";
import test from "node:test";
import { TargetFile } from "@tufjs/models";
import { createTestTufFixture } from "../../test/v0.4.0-update/tuf-fixture.js";
import type { JsonObject } from "./canonical-json.js";
import { UpdateError } from "./errors.js";
import { topLevelRevocations } from "./metadata.js";
import {
  selectArtifactFromTargets,
  selectAuthenticatedArtifact,
  type ArtifactSelectionPolicy,
} from "./selection.js";
import { emptyTrustedMetadataState, TufTrustStore } from "./trust.js";

test("one exact authenticated tuple is selected", () => {
  const authenticated = authenticatedFixture();
  const selected = selectAuthenticatedArtifact(
    authenticated.channel,
    basePolicy(),
    authenticated.revocations,
  );
  assert.equal(selected.status, "update-available");
  assert.equal(selected.target.custom.platform, "win32");
  assert.equal(selected.target.custom.architecture, "x64");
});

test("wrongPlatformTargetIsRejected", () => {
  const authenticated = authenticatedFixture();
  assert.throws(
    () =>
      selectAuthenticatedArtifact(
        authenticated.channel,
        { ...basePolicy(), platform: "darwin" },
        authenticated.revocations,
      ),
    isUpdateError("GOAT_UPDATE_TARGET_NOT_FOUND"),
  );
});

test("wrongArchitectureTargetIsRejected", () => {
  const authenticated = authenticatedFixture();
  assert.throws(
    () =>
      selectAuthenticatedArtifact(
        authenticated.channel,
        { ...basePolicy(), architecture: "arm64" },
        authenticated.revocations,
      ),
    isUpdateError("GOAT_UPDATE_TARGET_NOT_FOUND"),
  );
});

test("wrongChannelTargetIsRejected", () => {
  const authenticated = authenticatedFixture();
  assert.throws(
    () =>
      selectAuthenticatedArtifact(
        authenticated.channel,
        { ...basePolicy(), channel: "beta" },
        authenticated.revocations,
      ),
    isUpdateError("GOAT_UPDATE_TARGET_NOT_FOUND"),
  );
});

test("incompatible launcher is rejected before download", () => {
  const authenticated = authenticatedFixture();
  assert.throws(
    () =>
      selectAuthenticatedArtifact(
        authenticated.channel,
        { ...basePolicy(), launcherVersion: "0.3.2" },
        authenticated.revocations,
      ),
    isUpdateError("GOAT_UPDATE_TARGET_INCOMPATIBLE"),
  );
});

test("previouslyValidLowerSequenceIsRejected", () => {
  const authenticated = authenticatedFixture();
  assert.throws(
    () =>
      selectAuthenticatedArtifact(
        authenticated.channel,
        {
          ...basePolicy(),
          maxAuthenticatedReleaseSequence: 2,
          maxActivatedReleaseSequence: 2,
        },
        authenticated.revocations,
      ),
    isUpdateError("GOAT_UPDATE_DOWNGRADE_BLOCKED"),
  );
});

test("same sequence is current only when its complete identity is known", () => {
  const authenticated = authenticatedFixture();
  const parsed = selectAuthenticatedArtifact(
    authenticated.channel,
    basePolicy(),
    authenticated.revocations,
  ).target;
  const policy = {
    ...basePolicy(),
    maxAuthenticatedReleaseSequence: parsed.custom.releaseSequence,
    maxActivatedReleaseSequence: parsed.custom.releaseSequence,
    knownReleases: [
      {
        releaseSequence: parsed.custom.releaseSequence,
        channel: parsed.custom.channel,
        productVersion: parsed.custom.productVersion,
        artifactSha256: parsed.sha256,
      },
    ],
  } satisfies ArtifactSelectionPolicy;
  assert.equal(
    selectAuthenticatedArtifact(
      authenticated.channel,
      policy,
      authenticated.revocations,
    ).status,
    "already-current",
  );
});

test("an authenticated release resumes when activation was interrupted", () => {
  const authenticated = authenticatedFixture();
  const parsed = selectAuthenticatedArtifact(
    authenticated.channel,
    basePolicy(),
    authenticated.revocations,
  ).target;
  const policy = {
    ...basePolicy(),
    maxAuthenticatedReleaseSequence: parsed.custom.releaseSequence,
    maxActivatedReleaseSequence: 0,
    knownReleases: [
      {
        releaseSequence: parsed.custom.releaseSequence,
        channel: parsed.custom.channel,
        productVersion: parsed.custom.productVersion,
        artifactSha256: parsed.sha256,
      },
    ],
  } satisfies ArtifactSelectionPolicy;
  assert.equal(
    selectAuthenticatedArtifact(
      authenticated.channel,
      policy,
      authenticated.revocations,
    ).status,
    "update-available",
  );
});

test("ambiguous matching targets and changed same-version bytes are rejected", () => {
  const authenticated = authenticatedFixture();
  const firstPath = Object.keys(
    authenticated.channel.metadata.signed.targets,
  )[0]!;
  const first = authenticated.channel.metadata.signed.targets[firstPath]!;
  const custom = first.custom as JsonObject;
  const secondCustom = {
    ...custom,
    productVersion: "0.4.1",
    goatEngineVersion: "0.4.1",
  } as JsonObject;
  const secondPath = `goat-engine/stable/0.4.1/win32-x64/goat-engine.zip`;
  const second = new TargetFile({
    path: secondPath,
    length: first.length,
    hashes: { sha256: "c".repeat(64) },
    unrecognizedFields: { custom: secondCustom },
  });
  assert.throws(
    () =>
      selectArtifactFromTargets(
        {
          roleName: "stable",
          metadataVersion: 1,
          targets: { [firstPath]: first, [secondPath]: second },
        },
        basePolicy(),
        authenticated.revocations,
      ),
    isUpdateError("GOAT_UPDATE_TARGET_AMBIGUOUS"),
  );

  const parsed = selectAuthenticatedArtifact(
    authenticated.channel,
    basePolicy(),
    authenticated.revocations,
  ).target;
  assert.throws(
    () =>
      selectAuthenticatedArtifact(
        authenticated.channel,
        {
          ...basePolicy(),
          knownReleases: [
            {
              releaseSequence: 99,
              channel: "stable",
              productVersion: parsed.custom.productVersion,
              artifactSha256: "d".repeat(64),
            },
          ],
        },
        authenticated.revocations,
      ),
    isUpdateError("GOAT_UPDATE_METADATA_MISMATCH"),
  );
});

function authenticatedFixture() {
  const fixture = createTestTufFixture();
  const store = new TufTrustStore(fixture.root, fixture.rootSha256);
  return store.authenticate({
    timestamp: fixture.timestamp,
    snapshot: fixture.snapshot,
    targets: fixture.targets,
    channel: fixture.channels.stable,
    channelName: "stable",
    state: emptyTrustedMetadataState(),
    now: new Date("2030-01-01T00:00:00Z"),
  });
}

function basePolicy(): ArtifactSelectionPolicy {
  return {
    channel: "stable",
    platform: "win32",
    architecture: "x64",
    launcherVersion: "0.4.0",
    maxAuthenticatedReleaseSequence: 0,
    maxActivatedReleaseSequence: 0,
  };
}

function isUpdateError(code: UpdateError["code"]): (error: unknown) => boolean {
  return (error) => error instanceof UpdateError && error.code === code;
}
