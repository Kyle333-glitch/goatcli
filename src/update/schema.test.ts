import assert from "node:assert/strict";
import test from "node:test";
import { TargetFile } from "@tufjs/models";
import {
  expectedArchivePaths,
  expectedTargetPath,
  parseAuthenticatedTarget,
  parseTargetCustom,
  type GoatUpdateTargetCustom,
  type SignedContentEntry,
  type UpdatePlatform,
} from "./schema.js";
import { UpdateError } from "./errors.js";
import type { JsonObject } from "./canonical-json.js";

test("strict target schema binds version, channel, platform, and architecture", () => {
  const custom = validCustom();
  const targetPath = expectedTargetPath(custom);
  const parsed = parseAuthenticatedTarget(
    targetPath,
    new TargetFile({
      path: targetPath,
      length: 123,
      hashes: { sha256: "a".repeat(64) },
      unrecognizedFields: {
        custom: custom as unknown as JsonObject,
      },
    }),
  );
  assert.equal(parsed.targetPath, targetPath);
  assert.equal(parsed.custom.releaseSequence, 42);
  assert.equal(parsed.custom.architecture, "x64");
});

test("unsupportedManifestSchemaIsRejected", () => {
  assert.throws(
    () => parseTargetCustom({ ...validCustom(), goatUpdateSchema: 2 }),
    isInvalidManifest,
  );
});

test("wrong channel version forms and unknown fields are rejected", () => {
  for (const invalid of [
    { ...validCustom(), productVersion: "0.4.0-beta.1" },
    { ...validCustom(), channel: "beta", productVersion: "0.4.0" },
    {
      ...validCustom(),
      channel: "development",
      productVersion: "0.4.0-dev.x",
    },
    { ...validCustom(), productVersion: "0.4.0+rebuilt" },
    { ...validCustom(), untrustedUrl: "https://attacker.invalid/file.zip" },
  ]) {
    assert.throws(() => parseTargetCustom(invalid), isInvalidManifest);
  }
});

test("target path, hash set, and exact signed archive allowlist are enforced", () => {
  const custom = validCustom();
  const targetPath = expectedTargetPath(custom);
  assert.throws(
    () =>
      parseAuthenticatedTarget(
        `${targetPath}.other`,
        new TargetFile({
          path: `${targetPath}.other`,
          length: 123,
          hashes: { sha256: "a".repeat(64) },
          unrecognizedFields: {
            custom: custom as unknown as JsonObject,
          },
        }),
      ),
    isInvalidManifest,
  );
  assert.throws(
    () =>
      parseTargetCustom({
        ...custom,
        contents: custom.contents.slice(1),
      }),
    isInvalidManifest,
  );
  assert.throws(
    () =>
      parseAuthenticatedTarget(
        targetPath,
        new TargetFile({
          path: targetPath,
          length: 123,
          hashes: { sha256: "a".repeat(64), sha512: "b".repeat(128) },
          unrecognizedFields: {
            custom: custom as unknown as JsonObject,
          },
        }),
      ),
    isInvalidManifest,
  );
});

function validCustom(
  platform: UpdatePlatform = "win32",
): GoatUpdateTargetCustom {
  const contents: SignedContentEntry[] = expectedArchivePaths(platform).map(
    (entryPath) => ({
      path: entryPath,
      type: "regular-file",
      length: 10,
      sha256: "b".repeat(64),
      mode: entryPath.startsWith("bin/") ? 493 : 420,
    }),
  );
  return {
    goatUpdateSchema: 1,
    product: "GOAT",
    component: "goat-engine",
    productVersion: "0.4.0",
    goatEngineVersion: "0.4.0",
    openCodeBaseline: "1.17.11",
    releaseSequence: 42,
    channel: "stable",
    platform,
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
    codeSigning:
      platform === "win32"
        ? { scheme: "authenticode-sha256", identityId: "test-windows" }
        : { scheme: "apple-developer-id", identityId: "test-apple" },
    contents,
  };
}

function isInvalidManifest(error: unknown): boolean {
  return (
    error instanceof UpdateError &&
    error.code === "GOAT_UPDATE_MANIFEST_INVALID"
  );
}
