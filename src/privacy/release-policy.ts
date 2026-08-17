import type { EngineManifestTrustPolicy } from "../engine/contract.js";
import {
  GOAT_RELEASE_POLICY,
  GOAT_RELEASE_POLICY_SOURCE_SHA256,
} from "./release-policy.generated.js";
import { GOAT_RELEASE_POLICY_SIGNATURE } from "./release-policy-signature.generated.js";
import {
  verifyEmbeddedReleasePolicy,
  type EmbeddedReleasePolicySignature,
} from "./release-policy-verifier.js";

export type ReleasePolicyFeature = keyof typeof GOAT_RELEASE_POLICY.features;

export type ApprovedProviderPolicy = {
  readonly providerId: string;
  readonly modelId: string;
  readonly publicAlias:
    | "goat/muse-spark-1.2-contributor"
    | "goat/deepseek-v4-flash-0731"
    | "goat/gpt-5.6-luna"
    | "goat/auto"
    | "goat/fast"
    | "goat/balanced"
    | "goat/hard"
    | "goat/vision";
  readonly executionMode: "direct" | "hosted";
  readonly privacyApprovalId: string;
  readonly zdrApprovalId: string;
};

export type CompiledCodeSigningIdentity =
  | {
      readonly scheme: "authenticode-sha256";
      readonly identityId: string;
      readonly certificateSha256: string;
    }
  | {
      readonly scheme: "apple-developer-id";
      readonly identityId: string;
      readonly teamIdentifier: string;
      readonly authority: string;
    };

export interface CompiledUpdateReleasePolicy {
  readonly enabled: boolean;
  readonly metadataOrigin: string | null;
  readonly artifactOrigin: string | null;
  readonly embeddedTufRootSha256: string | null;
  readonly engineManifestKeyIds: readonly string[];
  readonly codeSigningIdentities: readonly CompiledCodeSigningIdentity[];
}

type ReleasePolicySnapshot = {
  readonly schemaVersion: number;
  readonly releaseVersion: string;
  readonly channel:
    "development" | "internal" | "release-candidate" | "production";
  readonly policyRevision: number;
  readonly controlPlaneOrigin: string | null;
  readonly features: Readonly<Record<ReleasePolicyFeature, boolean>>;
  readonly providers: readonly ApprovedProviderPolicy[];
  readonly sponsorAllowedOrigins: readonly string[];
  readonly distribution: {
    readonly approvedOrigins: readonly string[];
    readonly updateMetadataOrigin: string | null;
    readonly updateArtifactOrigin: string | null;
    readonly embeddedTufRootSha256: string | null;
    readonly allowUnsignedDevelopment: boolean;
    readonly engineManifestKeyIds: readonly string[];
    readonly codeSigningIdentities: readonly CompiledCodeSigningIdentity[];
    readonly codeSigningCertificateFingerprints: readonly string[];
  };
  readonly compatibility: {
    readonly engineManifestVersion: 1;
    readonly updateEngineManifestVersion: 2;
    readonly launcherVersion: string;
    readonly engineVersion: string;
    readonly openCodeBaseline: string;
    readonly engineLaunchContract: string;
    readonly privacyActivationProtocol: string;
    readonly authenticatedFrameProtocol: string;
  };
};

const policy: ReleasePolicySnapshot = GOAT_RELEASE_POLICY;
const signature: EmbeddedReleasePolicySignature = GOAT_RELEASE_POLICY_SIGNATURE;

export class ReleasePolicyError extends Error {
  constructor(
    readonly code:
      | "release_policy_invalid"
      | "production_release_blocked"
      | "feature_unavailable",
  ) {
    super(MESSAGES[code]);
    this.name = "ReleasePolicyError";
  }
}

export function compiledControlPlaneOrigin(): string | undefined {
  return policy.controlPlaneOrigin ?? undefined;
}

export function engineManifestTrustPolicy(): EngineManifestTrustPolicy {
  return {
    manifestVersion: policy.compatibility.engineManifestVersion,
    releasePolicyDigest: GOAT_RELEASE_POLICY_SOURCE_SHA256,
    allowUnsignedDevelopment: policy.distribution.allowUnsignedDevelopment,
    engineManifestKeyIds: [...policy.distribution.engineManifestKeyIds],
  };
}

export function releasePolicyAllows(feature: ReleasePolicyFeature): boolean {
  return policy.features[feature] === true;
}

export function compiledUpdateReleasePolicy(): CompiledUpdateReleasePolicy {
  return {
    enabled:
      releasePolicyAllows("updates") &&
      releasePolicyAllows("artifactDownloads"),
    metadataOrigin: policy.distribution.updateMetadataOrigin,
    artifactOrigin: policy.distribution.updateArtifactOrigin,
    embeddedTufRootSha256: policy.distribution.embeddedTufRootSha256,
    engineManifestKeyIds: [...policy.distribution.engineManifestKeyIds],
    codeSigningIdentities: [...policy.distribution.codeSigningIdentities],
  };
}

export function approvedEngineEnvironmentKeys(): readonly string[] {
  return findApprovedEngineEnvironmentKeys(
    policy.providers,
    releasePolicyAllows("directInference"),
  );
}

export function findApprovedEngineEnvironmentKeys(
  providers: readonly ApprovedProviderPolicy[],
  directInferenceAllowed: boolean,
): readonly string[] {
  if (!directInferenceAllowed) return [];

  const keys = new Set<string>();
  const pairs = new Set<string>();
  for (const provider of providers) {
    if (!isValidApprovedProvider(provider)) return [];
    const pair = `${provider.providerId}\u0000${provider.modelId}`;
    if (pairs.has(pair)) return [];
    pairs.add(pair);
    if (provider.executionMode !== "direct") continue;
    for (const key of DIRECT_PROVIDER_ENVIRONMENT_KEYS[provider.providerId] ??
      []) {
      keys.add(key);
    }
  }
  return [...keys].sort((a, b) => a.localeCompare(b));
}

export function requireReleasePolicyFeature(
  feature: ReleasePolicyFeature,
): void {
  if (!releasePolicyAllows(feature)) {
    throw new ReleasePolicyError("feature_unavailable");
  }
}

export function assertEmbeddedLauncherReleasePolicy(): void {
  assertLauncherReleasePolicy({
    production: policy.channel === "production",
  });
}

export function assertLauncherReleasePolicy(input: {
  readonly production: boolean;
}): void {
  let cryptographicallySigned = false;
  try {
    cryptographicallySigned = verifyEmbeddedReleasePolicy({
      policy,
      sourceSha256: GOAT_RELEASE_POLICY_SOURCE_SHA256,
      signature,
    }).signed;
  } catch {
    throw new ReleasePolicyError("release_policy_invalid");
  }
  if (
    policy.schemaVersion !== 1 ||
    policy.releaseVersion !== "0.4.0" ||
    policy.policyRevision < 1 ||
    policy.compatibility.engineManifestVersion !== 1 ||
    policy.compatibility.updateEngineManifestVersion !== 2 ||
    policy.compatibility.launcherVersion !== "0.4.0" ||
    policy.compatibility.engineVersion !== "0.4.0" ||
    policy.compatibility.openCodeBaseline !== "1.17.11" ||
    policy.compatibility.engineLaunchContract !== "0.0.6" ||
    policy.compatibility.privacyActivationProtocol !== "GOATIPC2" ||
    policy.compatibility.authenticatedFrameProtocol !== "GOATIPC1" ||
    !/^[a-f0-9]{64}$/.test(GOAT_RELEASE_POLICY_SOURCE_SHA256) ||
    policy.distribution.engineManifestKeyIds.some(
      (keyId) => !/^[a-f0-9]{64}$/.test(keyId),
    )
  ) {
    throw new ReleasePolicyError("release_policy_invalid");
  }

  if (input.production) {
    const updatesEnabled =
      releasePolicyAllows("updates") &&
      releasePolicyAllows("artifactDownloads");
    if (
      policy.channel !== "production" ||
      !cryptographicallySigned ||
      !signature.keyId ||
      policy.controlPlaneOrigin === null ||
      policy.distribution.allowUnsignedDevelopment ||
      policy.distribution.engineManifestKeyIds.length === 0 ||
      policy.distribution.codeSigningCertificateFingerprints.length === 0 ||
      !isLaunchPolicyComplete() ||
      (updatesEnabled &&
        (policy.distribution.updateMetadataOrigin === null ||
          policy.distribution.updateArtifactOrigin === null ||
          policy.distribution.embeddedTufRootSha256 === null ||
          policy.distribution.codeSigningIdentities.length === 0))
    ) {
      throw new ReleasePolicyError("production_release_blocked");
    }
    return;
  }

  if (
    policy.channel === "production" ||
    signature.status !== "unsigned-internal" ||
    policy.controlPlaneOrigin !== null ||
    Object.values(policy.features).some(Boolean) ||
    policy.providers.length !== 0 ||
    policy.sponsorAllowedOrigins.length !== 0 ||
    policy.distribution.approvedOrigins.length !== 0 ||
    policy.distribution.updateMetadataOrigin !== null ||
    policy.distribution.updateArtifactOrigin !== null ||
    policy.distribution.embeddedTufRootSha256 !== null ||
    policy.distribution.engineManifestKeyIds.length !== 0 ||
    policy.distribution.codeSigningCertificateFingerprints.length !== 0 ||
    policy.distribution.codeSigningIdentities.length !== 0 ||
    !policy.distribution.allowUnsignedDevelopment
  ) {
    throw new ReleasePolicyError("release_policy_invalid");
  }
}

const LAUNCH_MODEL_ALIASES = new Set([
  "goat/muse-spark-1.2-contributor",
  "goat/deepseek-v4-flash-0731",
  "goat/gpt-5.6-luna",
]);

function isLaunchPolicyComplete(): boolean {
  return (
    releasePolicyAllows("authentication") &&
    releasePolicyAllows("hostedInference") &&
    releasePolicyAllows("modelCatalog") &&
    releasePolicyAllows("unifiedQuota") &&
    !releasePolicyAllows("directInference") &&
    !releasePolicyAllows("ads") &&
    !releasePolicyAllows("autoMode") &&
    !releasePolicyAllows("paidBilling") &&
    releasePolicyAllows("updates") ===
      releasePolicyAllows("artifactDownloads") &&
    policy.providers.length > 0 &&
    policy.providers.every(
      (provider) =>
        isValidApprovedProvider(provider) &&
        provider.executionMode === "hosted" &&
        LAUNCH_MODEL_ALIASES.has(provider.publicAlias),
    )
  );
}

const DIRECT_PROVIDER_ENVIRONMENT_KEYS: Readonly<
  Record<string, readonly string[]>
> = {
  ovhcloud: ["OVHCLOUD_API_KEY"],
};

// Historical aliases remain valid only for compatibility-policy fixtures and
// retained records. The control plane owns launch model selection.
const PUBLIC_MODEL_ALIASES = new Set([
  "goat/muse-spark-1.2-contributor",
  "goat/deepseek-v4-flash-0731",
  "goat/gpt-5.6-luna",
  "goat/auto",
  "goat/fast",
  "goat/balanced",
  "goat/hard",
  "goat/vision",
]);

function isValidApprovedProvider(provider: ApprovedProviderPolicy): boolean {
  return (
    provider.providerId.length > 0 &&
    provider.providerId === provider.providerId.trim() &&
    provider.modelId.length > 0 &&
    provider.modelId === provider.modelId.trim() &&
    PUBLIC_MODEL_ALIASES.has(provider.publicAlias) &&
    (provider.executionMode === "direct" ||
      provider.executionMode === "hosted") &&
    provider.privacyApprovalId.length > 0 &&
    provider.privacyApprovalId === provider.privacyApprovalId.trim() &&
    provider.zdrApprovalId.length > 0 &&
    provider.zdrApprovalId === provider.zdrApprovalId.trim()
  );
}

const MESSAGES = {
  release_policy_invalid: "The GOAT release policy is invalid.",
  production_release_blocked:
    "The GOAT production release policy is incomplete or unsigned.",
  feature_unavailable:
    "This GOAT feature is unavailable in the approved release policy.",
} as const;
