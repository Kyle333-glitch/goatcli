/**
 * TEST-ONLY complete authenticated update bundle.
 *
 * All signing keys are generated ephemerally. The fixture is excluded from the
 * npm package and its identity IDs are rejected by a production policy.
 */
import {
  createHash,
  generateKeyPairSync,
  sign,
  type KeyObject,
} from "node:crypto";
import { mkdtemp, realpath, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import type test from "node:test";
import type { JsonValue } from "../../src/update/canonical-json.js";
import { canonicalJsonBytes } from "../../src/update/canonical-json.js";
import {
  canonicalEngineManifestV2Payload,
  type CandidateCompatibilityPolicy,
  type SignedEngineManifestV2,
} from "../../src/update/compatibility.js";
import type {
  ApprovedCodeSigningIdentity,
  VerificationCommandRunner,
} from "../../src/update/code-signing.js";
import type { HealthCommandRunner } from "../../src/update/health.js";
import type { ActivationSecurityPolicy } from "../../src/update/activation.js";
import {
  expectedArchivePaths,
  type SignedContentEntry,
  type UpdateArchitecture,
  type UpdateChannel,
  type UpdatePlatform,
} from "../../src/update/schema.js";
import {
  extractVerifiedArchive,
  type StagedArchive,
} from "../../src/update/archive.js";
import {
  createExclusiveTemporaryFile,
  createUpdateTransactionPaths,
  cleanupUpdateTransaction,
  type UpdateTransactionPaths,
} from "../../src/update/temporary.js";
import type { HeldVerifiedArtifact } from "../../src/update/download.js";
import { disposeHeldArtifact } from "../../src/update/download.js";
import {
  persistTargetReceipt,
  type PersistedTargetReceipt,
  type ReceiptVerificationPolicy,
} from "../../src/update/receipt.js";
import { buildTestZip } from "./zip-fixture.js";
import {
  createTestTufFixture,
  createTestTufKeySet,
  type TestTufFixture,
  type TestTufKeySet,
} from "./tuf-fixture.js";

export interface TestBundleTrust {
  readonly tufKeys: TestTufKeySet;
  readonly manifestSigner: {
    readonly keyId: string;
    readonly publicKeyBytes: Buffer;
    readonly privateKey: KeyObject;
  };
  readonly releasePolicyDigest: string;
}

export interface TestUpdateBundle {
  readonly appData: string;
  readonly platform: UpdatePlatform;
  readonly architecture: UpdateArchitecture;
  readonly channel: UpdateChannel;
  readonly productVersion: string;
  readonly releaseSequence: number;
  readonly archive: Buffer;
  readonly tuf: TestTufFixture;
  readonly receipt: PersistedTargetReceipt;
  readonly receiptPolicy: ReceiptVerificationPolicy;
  readonly compatibilityPolicy: CandidateCompatibilityPolicy;
  readonly approvedCodeSigningIdentities: readonly ApprovedCodeSigningIdentity[];
  readonly runSigningCommand: VerificationCommandRunner;
  readonly runHealthCommand: HealthCommandRunner;
  readonly activationPolicy: ActivationSecurityPolicy;
  readonly transaction: UpdateTransactionPaths;
  readonly artifact: HeldVerifiedArtifact;
  readonly staged: StagedArchive;
  readonly engineManifest: SignedEngineManifestV2;
  readonly fileBytes: ReadonlyMap<string, Buffer>;
}

export interface TestUpdateBundleOptions {
  readonly appData?: string;
  readonly platform?: UpdatePlatform;
  readonly architecture?: UpdateArchitecture;
  readonly channel?: UpdateChannel;
  readonly releaseSequence?: number;
  readonly productVersion?: string;
  readonly executableBytes?: Buffer;
  readonly healthSucceeds?: boolean;
  readonly signingSucceeds?: boolean;
  readonly trust?: TestBundleTrust;
}

export function createTestBundleTrust(): TestBundleTrust {
  return {
    tufKeys: createTestTufKeySet(),
    manifestSigner: createManifestSigner(),
    releasePolicyDigest: "9".repeat(64),
  };
}

export async function createTestUpdateBundle(
  context: test.TestContext,
  options: TestUpdateBundleOptions = {},
): Promise<TestUpdateBundle> {
  const appData =
    options.appData ??
    (await mkdtemp(
      path.join(await realpath(os.tmpdir()), "goat-update-bundle-test-"),
    ));
  if (!options.appData) {
    context.after(() => rm(appData, { recursive: true, force: true }));
  }
  const platform = options.platform ?? runtimePlatform();
  const architecture = options.architecture ?? runtimeArchitecture();
  const channel = options.channel ?? "stable";
  const releaseSequence = options.releaseSequence ?? 1;
  const productVersion =
    options.productVersion ?? channelVersion(channel, releaseSequence);
  const executableBytes =
    options.executableBytes ??
    Buffer.from(`TEST-ONLY engine ${channel} ${releaseSequence}`, "utf8");
  const trust = options.trust ?? createTestBundleTrust();
  const releasePolicyDigest = trust.releasePolicyDigest;
  const manifestSigner = trust.manifestSigner;
  const codeSigningIdentityId = `test-only-${platform}`;

  const unsigned: Omit<SignedEngineManifestV2, "signature"> = {
    manifestVersion: 2,
    releasePolicyDigest,
    product: "GOAT",
    productVersion,
    goatEngineVersion: productVersion,
    openCodeBaseline: "1.17.11",
    releaseSequence,
    channel,
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
    codeSigningIdentityId,
  };
  const engineManifest = signManifest(unsigned, manifestSigner);
  const manifestBytes = canonicalJsonBytes(
    engineManifest as unknown as JsonValue,
  );
  const fileBytes = new Map<string, Buffer>([
    [`bin/${executableName(platform)}`, executableBytes],
    ["goat-engine.json", manifestBytes],
    ["package.json", Buffer.from(canonicalPackage(productVersion), "utf8")],
    ["LICENSE", Buffer.from("TEST-ONLY MIT fixture\n", "utf8")],
    ["NOTICE", Buffer.from("TEST-ONLY fixture notice\n", "utf8")],
    [
      "THIRD_PARTY_NOTICES.txt",
      Buffer.from("TEST-ONLY fixture third-party notices\n", "utf8"),
    ],
    ["sbom.spdx.json", Buffer.from(canonicalSbom(productVersion), "utf8")],
  ]);
  const contents: SignedContentEntry[] = expectedArchivePaths(platform).map(
    (entryPath) => {
      const bytes = fileBytes.get(entryPath)!;
      return {
        path: entryPath,
        type: "regular-file",
        length: bytes.byteLength,
        sha256: sha256(bytes),
        mode: entryPath.startsWith("bin/") ? 493 : 420,
      };
    },
  );
  const archive = buildTestZip(
    contents.map((content, index) => ({
      name: content.path,
      data: fileBytes.get(content.path)!,
      method: index === 0 ? 8 : 0,
    })),
  );
  const tuf = createTestTufFixture({
    metadataVersion: releaseSequence,
    keys: trust.tufKeys,
    platform,
    architecture,
    contents,
    artifactLength: archive.byteLength,
    artifactSha256: sha256(archive),
    codeSigningIdentityId,
  });
  const receiptPolicy: ReceiptVerificationPolicy = {
    embeddedRootBytes: tuf.root,
    embeddedRootSha256: tuf.rootSha256,
    launcherVersion: "0.4.0",
    platform,
    architecture,
  };
  const receipt = await persistTargetReceipt(
    appData,
    {
      embeddedRootSha256: tuf.rootSha256,
      sequentialRoots: [],
      timestamp: tuf.timestamp,
      snapshot: tuf.snapshot,
      targets: tuf.targets,
      channel: tuf.channels[channel],
      channelName: channel,
      targetPath: tuf.targetPaths[channel],
      authenticatedAtUnixMs: Date.parse("2030-01-01T00:00:00Z"),
    },
    receiptPolicy,
  );
  const compatibilityPolicy: CandidateCompatibilityPolicy = {
    launcherVersion: "0.4.0",
    releasePolicyDigest,
    engineManifestKeyIds: [manifestSigner.keyId],
    revokedKeyIds: [],
    platform,
    architecture,
  };
  const approvedCodeSigningIdentities = approvedIdentities(platform);
  const runSigningCommand = signingRunner(
    platform,
    options.signingSucceeds ?? true,
  );
  const runHealthCommand = healthRunner(
    productVersion,
    options.healthSucceeds ?? true,
  );
  const activationPolicy: ActivationSecurityPolicy = {
    receipt: receiptPolicy,
    compatibility: compatibilityPolicy,
    approvedCodeSigningIdentities,
    runSigningCommand,
    runHealthCommand,
  };

  const transaction = await createUpdateTransactionPaths(appData);
  const temporary = await createExclusiveTemporaryFile(transaction);
  await temporary.handle.writeFile(archive);
  await temporary.handle.sync();
  const artifactStats = await temporary.handle.stat();
  const artifact: HeldVerifiedArtifact = {
    path: temporary.path,
    handle: temporary.handle,
    length: archive.byteLength,
    sha256: sha256(archive),
    device: artifactStats.dev,
    inode: artifactStats.ino,
  };
  const staged = await extractVerifiedArchive(
    artifact,
    receipt.target,
    transaction,
  );
  context.after(async () => {
    await disposeHeldArtifact(artifact);
    await cleanupUpdateTransaction(transaction).catch(() => undefined);
  });
  return {
    appData,
    platform,
    architecture,
    channel,
    productVersion,
    releaseSequence,
    archive,
    tuf,
    receipt,
    receiptPolicy,
    compatibilityPolicy,
    approvedCodeSigningIdentities,
    runSigningCommand,
    runHealthCommand,
    activationPolicy,
    transaction,
    artifact,
    staged,
    engineManifest,
    fileBytes,
  };
}

function createManifestSigner(): {
  readonly keyId: string;
  readonly publicKeyBytes: Buffer;
  readonly privateKey: KeyObject;
} {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const publicKeyBytes = publicKey.export({ format: "der", type: "spki" });
  return { keyId: sha256(publicKeyBytes), publicKeyBytes, privateKey };
}

function signManifest(
  unsigned: Omit<SignedEngineManifestV2, "signature">,
  signer: ReturnType<typeof createManifestSigner>,
): SignedEngineManifestV2 {
  const placeholder: SignedEngineManifestV2 = {
    ...unsigned,
    signature: {
      status: "signed",
      algorithm: "ed25519",
      keyId: signer.keyId,
      publicKey: signer.publicKeyBytes.toString("base64url"),
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
        signer.privateKey,
      ).toString("base64url"),
    },
  };
}

function approvedIdentities(
  platform: UpdatePlatform,
): readonly ApprovedCodeSigningIdentity[] {
  return platform === "win32"
    ? [
        {
          scheme: "authenticode-sha256",
          identityId: "test-only-win32",
          certificateSha256: "a".repeat(64),
        },
      ]
    : [
        {
          scheme: "apple-developer-id",
          identityId: "test-only-darwin",
          teamIdentifier: "TEST123456",
          authority: "Developer ID Application: GOAT Test (TEST123456)",
        },
      ];
}

function signingRunner(
  platform: UpdatePlatform,
  succeeds: boolean,
): VerificationCommandRunner {
  return (command, args) => {
    if (!succeeds) return { status: 1, stdout: "", stderr: "rejected" };
    if (platform === "win32") {
      return {
        status: 0,
        stdout: JSON.stringify({
          status: "Valid",
          certificateSha256: "a".repeat(64),
        }),
        stderr: "",
      };
    }
    if (command === "/usr/bin/codesign" && args[0] === "--display") {
      return {
        status: 0,
        stdout: "",
        stderr: [
          "Authority=Developer ID Application: GOAT Test (TEST123456)",
          "Authority=Developer ID Certification Authority",
          "TeamIdentifier=TEST123456",
        ].join("\n"),
      };
    }
    return { status: 0, stdout: "", stderr: "" };
  };
}

function healthRunner(
  expectedVersion: string,
  succeeds: boolean,
): HealthCommandRunner {
  return () =>
    succeeds
      ? { status: 0, stdout: `${expectedVersion}\n`, stderr: "" }
      : { status: 2, stdout: "", stderr: "failed" };
}

function channelVersion(channel: UpdateChannel, sequence: number): string {
  return channel === "stable"
    ? "0.4.0"
    : channel === "beta"
      ? `0.4.0-beta.${sequence}`
      : `0.4.0-dev.${sequence}`;
}

function canonicalPackage(version: string): string {
  return `${JSON.stringify({ name: "@goat/engine-test-only", version })}\n`;
}

function canonicalSbom(version: string): string {
  return `${JSON.stringify({ SPDXID: "SPDXRef-DOCUMENT", name: "GOAT TEST-ONLY", version })}\n`;
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
