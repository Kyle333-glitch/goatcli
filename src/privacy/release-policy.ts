import type { EngineManifestTrustPolicy } from "../engine/contract.js";
import {
  GOAT_RELEASE_POLICY,
  GOAT_RELEASE_POLICY_SOURCE_SHA256,
} from "./release-policy.generated.js";
import { GOAT_RELEASE_POLICY_SIGNATURE } from "./release-policy-signature.generated.js";

export type ReleasePolicyFeature = keyof typeof GOAT_RELEASE_POLICY.features;

export type ApprovedProviderPolicy = {
  readonly providerId: string;
  readonly modelId: string;
  readonly publicAlias:
    "goat/auto" | "goat/fast" | "goat/balanced" | "goat/hard" | "goat/vision";
  readonly executionMode: "direct" | "hosted";
  readonly privacyApprovalId: string;
  readonly zdrApprovalId: string;
};

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
    readonly allowUnsignedDevelopment: boolean;
    readonly engineManifestKeyIds: readonly string[];
    readonly codeSigningCertificateFingerprints: readonly string[];
  };
  readonly compatibility: {
    readonly engineManifestVersion: 1;
  };
};

type ReleasePolicySignatureSnapshot = {
  readonly status: "unsigned-internal" | "signed";
  readonly keyId: string | null;
};

const policy: ReleasePolicySnapshot = GOAT_RELEASE_POLICY;
const signature: ReleasePolicySignatureSnapshot = GOAT_RELEASE_POLICY_SIGNATURE;

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
  return [...keys].sort();
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
  if (
    policy.schemaVersion !== 1 ||
    policy.releaseVersion !== "0.3.2" ||
    policy.policyRevision < 1 ||
    policy.compatibility.engineManifestVersion !== 1 ||
    !/^[a-f0-9]{64}$/.test(GOAT_RELEASE_POLICY_SOURCE_SHA256) ||
    policy.distribution.engineManifestKeyIds.some(
      (keyId) => !/^[a-f0-9]{64}$/.test(keyId),
    )
  ) {
    throw new ReleasePolicyError("release_policy_invalid");
  }

  if (input.production) {
    if (
      policy.channel !== "production" ||
      signature.status !== "signed" ||
      !signature.keyId ||
      policy.controlPlaneOrigin === null ||
      policy.distribution.allowUnsignedDevelopment ||
      policy.distribution.engineManifestKeyIds.length === 0 ||
      policy.distribution.codeSigningCertificateFingerprints.length === 0
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
    policy.distribution.engineManifestKeyIds.length !== 0 ||
    policy.distribution.codeSigningCertificateFingerprints.length !== 0 ||
    !policy.distribution.allowUnsignedDevelopment
  ) {
    throw new ReleasePolicyError("release_policy_invalid");
  }
}

const DIRECT_PROVIDER_ENVIRONMENT_KEYS: Readonly<
  Record<string, readonly string[]>
> = {
  ovhcloud: ["OVHCLOUD_API_KEY"],
};

const PUBLIC_MODEL_ALIASES = new Set([
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
