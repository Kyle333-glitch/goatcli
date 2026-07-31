import { createHash } from "node:crypto";
import {
  compiledUpdateReleasePolicy,
  type CompiledCodeSigningIdentity,
} from "../privacy/release-policy.js";
import { GOAT_RELEASE_POLICY_SOURCE_SHA256 } from "../privacy/release-policy.generated.js";
import {
  AUTHENTICATED_FRAME_PROTOCOL,
  ENGINE_CONTRACT_VERSION,
  OPENCODE_BASELINE_VERSION,
  PRIVACY_ACTIVATION_PROTOCOL,
} from "../version.js";
import type { ApprovedCodeSigningIdentity } from "./code-signing.js";
import { UpdateError } from "./errors.js";
import type { UpdateArchitecture, UpdatePlatform } from "./schema.js";
import {
  GOAT_TUF_ROOT_BASE64,
  GOAT_TUF_ROOT_SHA256,
} from "./trusted-root.generated.js";
import type { VerifiedUpdatePolicy } from "./updater.js";

export interface CompiledUpdatePolicyOptions {
  readonly launcherVersion: string;
  readonly platform: UpdatePlatform;
  readonly architecture: UpdateArchitecture;
}

export function compiledVerifiedUpdatePolicy(
  options: CompiledUpdatePolicyOptions,
): VerifiedUpdatePolicy | null {
  const release = compiledUpdateReleasePolicy();
  const allAbsent =
    !release.enabled &&
    release.metadataOrigin === null &&
    release.artifactOrigin === null &&
    release.embeddedTufRootSha256 === null &&
    release.engineManifestKeyIds.length === 0 &&
    release.codeSigningIdentities.length === 0 &&
    GOAT_TUF_ROOT_BASE64 === null &&
    GOAT_TUF_ROOT_SHA256 === null;
  if (allAbsent) return null;
  if (
    !release.enabled ||
    release.metadataOrigin === null ||
    release.artifactOrigin === null ||
    release.embeddedTufRootSha256 === null ||
    GOAT_TUF_ROOT_BASE64 === null ||
    GOAT_TUF_ROOT_SHA256 === null ||
    release.embeddedTufRootSha256 !== GOAT_TUF_ROOT_SHA256 ||
    release.engineManifestKeyIds.length === 0
  ) {
    throw new UpdateError("GOAT_UPDATE_DISABLED");
  }
  const rootBytes = strictBase64(GOAT_TUF_ROOT_BASE64);
  if (sha256(rootBytes) !== GOAT_TUF_ROOT_SHA256) {
    throw new UpdateError("GOAT_UPDATE_DISABLED");
  }
  const approvedCodeSigningIdentities = identitiesForPlatform(
    release.codeSigningIdentities,
    options.platform,
  );
  if (approvedCodeSigningIdentities.length === 0) {
    throw new UpdateError("GOAT_UPDATE_DISABLED");
  }
  return {
    launcherVersion: options.launcherVersion,
    platform: options.platform,
    architecture: options.architecture,
    metadataOrigin: release.metadataOrigin,
    artifactOrigin: release.artifactOrigin,
    embeddedRootBytes: rootBytes,
    embeddedRootSha256: GOAT_TUF_ROOT_SHA256,
    activation: {
      receipt: {
        embeddedRootBytes: rootBytes,
        embeddedRootSha256: GOAT_TUF_ROOT_SHA256,
        launcherVersion: options.launcherVersion,
        platform: options.platform,
        architecture: options.architecture,
      },
      compatibility: {
        launcherVersion: options.launcherVersion,
        releasePolicyDigest: GOAT_RELEASE_POLICY_SOURCE_SHA256,
        engineManifestKeyIds: [...release.engineManifestKeyIds],
        revokedKeyIds: [],
        platform: options.platform,
        architecture: options.architecture,
      },
      approvedCodeSigningIdentities,
    },
  };
}

function identitiesForPlatform(
  identities: readonly CompiledCodeSigningIdentity[],
  platform: UpdatePlatform,
): readonly ApprovedCodeSigningIdentity[] {
  return identities.filter(
    (identity) =>
      (platform === "win32" && identity.scheme === "authenticode-sha256") ||
      (platform === "darwin" && identity.scheme === "apple-developer-id"),
  );
}

function strictBase64(value: string): Buffer {
  if (
    value.length === 0 ||
    value.length > 2 * 1024 * 1024 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(
      value,
    )
  ) {
    throw new UpdateError("GOAT_UPDATE_DISABLED");
  }
  const decoded = Buffer.from(value, "base64");
  if (decoded.toString("base64") !== value) {
    throw new UpdateError("GOAT_UPDATE_DISABLED");
  }
  return decoded;
}

function sha256(value: Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

export const COMPILED_UPDATE_COMPATIBILITY = {
  openCodeBaseline: OPENCODE_BASELINE_VERSION,
  engineLaunchContract: ENGINE_CONTRACT_VERSION,
  privacyActivationProtocol: PRIVACY_ACTIVATION_PROTOCOL,
  authenticatedFrameProtocol: AUTHENTICATED_FRAME_PROTOCOL,
} as const;
