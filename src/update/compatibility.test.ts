import assert from "node:assert/strict";
import {
  createHash,
  generateKeyPairSync,
  sign,
  type KeyObject,
} from "node:crypto";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { canonicalJsonBytes, type JsonValue } from "./canonical-json.js";
import {
  canonicalEngineManifestV2Payload,
  parseEngineManifestV2,
  validateCandidateCompatibility,
  type CandidateCompatibilityPolicy,
  type SignedEngineManifestV2,
} from "./compatibility.js";
import { UpdateError } from "./errors.js";
import {
  expectedArchivePaths,
  type AuthenticatedTarget,
  type SignedContentEntry,
  type UpdateArchitecture,
  type UpdatePlatform,
} from "./schema.js";
import type { StagedArchive } from "./archive.js";

const signer = generateKeyPairSync("ed25519");
const publicKeyBytes = signer.publicKey.export({ format: "der", type: "spki" });
const keyId = sha256(publicKeyBytes);
const releasePolicyDigest = "9".repeat(64);

test("signed schema-2 engine manifest binds every outer compatibility field", async (context) => {
  const fixture = await compatibilityFixture(context);
  const compatible = await validateCandidateCompatibility(
    fixture.staged,
    fixture.policy,
  );
  assert.equal(compatible.manifest.releaseSequence, 17);
  assert.equal(compatible.manifestSha256, sha256(fixture.manifestBytes));
  assert.equal(
    compatible.executablePath,
    path.join(fixture.root, "bin", executableName(fixture.platform)),
  );
});

test("modified signed inner manifest is rejected", async (context) => {
  const fixture = await compatibilityFixture(context);
  const modified = {
    ...fixture.manifest,
    productVersion: "0.4.1",
  };
  await writeFile(
    path.join(fixture.root, "goat-engine.json"),
    canonicalJsonBytes(modified as unknown as JsonValue),
  );
  await assert.rejects(
    validateCandidateCompatibility(fixture.staged, fixture.policy),
    isUpdateError("GOAT_UPDATE_SIGNATURE_INVALID"),
  );
});

test("unknown and revoked inner-manifest signing keys are rejected", async (context) => {
  const fixture = await compatibilityFixture(context);
  await assert.rejects(
    validateCandidateCompatibility(fixture.staged, {
      ...fixture.policy,
      engineManifestKeyIds: [],
    }),
    isUpdateError("GOAT_UPDATE_SIGNING_KEY_UNKNOWN"),
  );
  await assert.rejects(
    validateCandidateCompatibility(fixture.staged, {
      ...fixture.policy,
      revokedKeyIds: [keyId],
    }),
    isUpdateError("GOAT_UPDATE_SIGNING_KEY_REVOKED"),
  );
});

test("outer and inner version, tuple, channel, protocol, hash, and identity mismatch are rejected", async (context) => {
  const mutations: readonly [
    string,
    (manifest: SignedEngineManifestV2) => SignedEngineManifestV2,
  ][] = [
    ["product", (manifest) => ({ ...manifest, productVersion: "0.4.1" })],
    ["engine", (manifest) => ({ ...manifest, goatEngineVersion: "0.4.1" })],
    ["baseline", (manifest) => ({ ...manifest, openCodeBaseline: "1.17.12" })],
    ["sequence", (manifest) => ({ ...manifest, releaseSequence: 18 })],
    ["channel", (manifest) => ({ ...manifest, channel: "development" })],
    [
      "platform",
      (manifest) => ({
        ...manifest,
        platform: manifest.platform === "win32" ? "darwin" : "win32",
      }),
    ],
    [
      "architecture",
      (manifest) => ({
        ...manifest,
        architecture: manifest.architecture === "x64" ? "arm64" : "x64",
      }),
    ],
    [
      "executable",
      (manifest) => ({
        ...manifest,
        executablePath: manifest.executablePath.endsWith(".exe")
          ? "bin/goat-engine"
          : "bin/goat-engine.exe",
      }),
    ],
    [
      "checksum",
      (manifest) => ({
        ...manifest,
        checksum: { ...manifest.checksum, value: "8".repeat(64) },
      }),
    ],
    [
      "launcher range",
      (manifest) => ({
        ...manifest,
        launcherCompatibility: {
          minInclusive: "0.4.1",
          maxExclusive: "0.5.0",
        },
      }),
    ],
    [
      "protocol",
      (manifest) => ({
        ...manifest,
        protocols: { ...manifest.protocols, launchContract: "0.0.7" },
      }),
    ],
    [
      "identity",
      (manifest) => ({
        ...manifest,
        codeSigningIdentityId: "test-only-other",
      }),
    ],
  ];
  for (const [name, mutate] of mutations) {
    await context.test(name, async (subtest) => {
      const fixture = await compatibilityFixture(subtest, mutate);
      await assert.rejects(
        validateCandidateCompatibility(fixture.staged, fixture.policy),
        isUpdateError("GOAT_UPDATE_COMPATIBILITY_FAILED"),
      );
    });
  }
});

test("unsupported, duplicate, and noncanonical inner manifests are rejected before trust", () => {
  const manifest = signedManifest(baseManifest(), signer.privateKey);
  const canonical = canonicalJsonBytes(manifest as unknown as JsonValue);
  const duplicate = Buffer.from(
    canonical
      .toString("utf8")
      .replace('{"architecture":', '{"architecture":"x64","architecture":'),
  );
  assert.throws(
    () => parseEngineManifestV2(duplicate),
    isUpdateError("GOAT_UPDATE_COMPATIBILITY_FAILED"),
  );
  assert.throws(
    () => parseEngineManifestV2(Buffer.from(JSON.stringify(manifest))),
    isUpdateError("GOAT_UPDATE_COMPATIBILITY_FAILED"),
  );
  const legacy = canonicalJsonBytes({ manifestVersion: 1 } as JsonValue);
  assert.throws(
    () => parseEngineManifestV2(legacy),
    isUpdateError("GOAT_UPDATE_COMPATIBILITY_FAILED"),
  );
});

async function compatibilityFixture(
  context: test.TestContext,
  mutate?: (manifest: SignedEngineManifestV2) => SignedEngineManifestV2,
) {
  const root = await mkdtemp(path.join(os.tmpdir(), "goat-compat-test-"));
  context.after(() => rm(root, { recursive: true, force: true }));
  const platform = runtimePlatform();
  const architecture = runtimeArchitecture();
  const executableBytes = Buffer.from("TEST-ONLY fixture engine");
  await mkdir(path.join(root, "bin"), { recursive: true });
  await writeFile(
    path.join(root, "bin", executableName(platform)),
    executableBytes,
  );

  const unsigned = baseManifest({ platform, architecture, executableBytes });
  const initial = signedManifest(unsigned, signer.privateKey);
  const manifest = mutate
    ? signedManifest(stripSignature(mutate(initial)), signer.privateKey)
    : initial;
  const manifestBytes = canonicalJsonBytes(manifest as unknown as JsonValue);
  await writeFile(path.join(root, "goat-engine.json"), manifestBytes);
  const target = targetForManifest(
    platform,
    architecture,
    executableBytes,
    manifestBytes,
  );
  const staged: StagedArchive = {
    root,
    target,
    treeSha256: "7".repeat(64),
  };
  const policy: CandidateCompatibilityPolicy = {
    launcherVersion: "0.4.0",
    releasePolicyDigest,
    engineManifestKeyIds: [keyId],
    revokedKeyIds: [],
    platform,
    architecture,
  };
  return { root, platform, manifest, manifestBytes, staged, policy };
}

function baseManifest(
  options: {
    platform?: UpdatePlatform;
    architecture?: UpdateArchitecture;
    executableBytes?: Buffer;
  } = {},
): Omit<SignedEngineManifestV2, "signature"> {
  const platform = options.platform ?? runtimePlatform();
  const architecture = options.architecture ?? runtimeArchitecture();
  const executableBytes =
    options.executableBytes ?? Buffer.from("TEST-ONLY fixture engine");
  return {
    manifestVersion: 2,
    releasePolicyDigest,
    product: "GOAT",
    productVersion: "0.4.0",
    goatEngineVersion: "0.4.0",
    openCodeBaseline: "1.17.11",
    releaseSequence: 17,
    channel: "stable",
    platform,
    architecture,
    executablePath: `bin/${executableName(platform)}`,
    checksum: { algorithm: "sha256", value: sha256(executableBytes) },
    launcherCompatibility: {
      minInclusive: "0.4.0",
      maxExclusive: "0.5.0",
    },
    protocols: {
      launchContract: "0.0.6",
      privacyActivation: "GOATIPC2",
      authenticatedFrame: "GOATIPC1",
    },
    codeSigningIdentityId: `test-only-${platform}`,
  };
}

function signedManifest(
  payload: Omit<SignedEngineManifestV2, "signature">,
  privateKey: KeyObject,
): SignedEngineManifestV2 {
  const placeholder: SignedEngineManifestV2 = {
    ...payload,
    signature: {
      status: "signed",
      algorithm: "ed25519",
      keyId,
      publicKey: publicKeyBytes.toString("base64url"),
      value: "A",
    },
  };
  return {
    ...placeholder,
    signature: {
      ...placeholder.signature,
      value: sign(
        null,
        canonicalEngineManifestV2Payload(placeholder),
        privateKey,
      ).toString("base64url"),
    },
  };
}

function stripSignature(
  manifest: SignedEngineManifestV2,
): Omit<SignedEngineManifestV2, "signature"> {
  const { signature: _signature, ...payload } = manifest;
  return payload;
}

function targetForManifest(
  platform: UpdatePlatform,
  architecture: UpdateArchitecture,
  executableBytes: Buffer,
  manifestBytes: Buffer,
): AuthenticatedTarget {
  const contents: SignedContentEntry[] = expectedArchivePaths(platform).map(
    (entryPath) => {
      const bytes = entryPath.startsWith("bin/")
        ? executableBytes
        : entryPath === "goat-engine.json"
          ? manifestBytes
          : Buffer.from(`TEST-ONLY ${entryPath}`);
      return {
        path: entryPath,
        type: "regular-file",
        length: bytes.length,
        sha256: sha256(bytes),
        mode: entryPath.startsWith("bin/") ? 493 : 420,
      };
    },
  );
  return {
    targetPath: `goat-engine/stable/0.4.0/${platform}-${architecture}/goat-engine.zip`,
    length: 123,
    sha256: "6".repeat(64),
    custom: {
      goatUpdateSchema: 1,
      product: "GOAT",
      component: "goat-engine",
      productVersion: "0.4.0",
      goatEngineVersion: "0.4.0",
      openCodeBaseline: "1.17.11",
      releaseSequence: 17,
      channel: "stable",
      platform,
      architecture,
      cpuFeatures: [],
      artifactFormat: "goat-engine-zip-v1",
      launcherCompatibility: { minInclusive: "0.4.0", maxExclusive: "0.5.0" },
      engineProtocolCompatibility: {
        launchContract: "0.0.6",
        privacyActivation: "GOATIPC2",
        authenticatedFrame: "GOATIPC1",
      },
      innerManifestSchema: 2,
      codeSigning: {
        scheme:
          platform === "win32" ? "authenticode-sha256" : "apple-developer-id",
        identityId: `test-only-${platform}`,
      },
      contents,
    },
  };
}

function executableName(platform: UpdatePlatform): string {
  return platform === "win32" ? "goat-engine.exe" : "goat-engine";
}

function runtimePlatform(): UpdatePlatform {
  return process.platform === "darwin" ? "darwin" : "win32";
}

function runtimeArchitecture(): UpdateArchitecture {
  return process.arch === "arm64" ? "arm64" : "x64";
}

function sha256(value: Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function isUpdateError(code: UpdateError["code"]): (error: unknown) => boolean {
  return (error) => error instanceof UpdateError && error.code === code;
}
