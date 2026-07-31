// Generated from goat-release-policy/releases/v0.4.0/production-policy.json.
// Do not edit approval-dependent values in this repository.

export const GOAT_RELEASE_POLICY_SOURCE_SHA256 = "e0ca134f594731fd608dc235a846b538c7a58f1f860f7706f1e529a4544f605d"

export const GOAT_RELEASE_POLICY = {
  "schemaVersion": 1,
  "releaseVersion": "0.4.0",
  "channel": "internal",
  "policyRevision": 1,
  "controlPlaneOrigin": null,
  "features": {
    "optionalTelemetry": false,
    "remoteDiagnostics": false,
    "hostedInference": false,
    "directInference": false,
    "sponsors": false,
    "updates": false,
    "artifactDownloads": false,
    "externalIntegrations": false
  },
  "providers": [],
  "sponsorAllowedOrigins": [],
  "retention": {
    "approved": false,
    "policyVersion": 0,
    "billingDays": null,
    "telemetryDays": 30,
    "diagnosticsDays": 7,
    "sponsorDays": 30,
    "operationalLogDays": 7,
    "telemetryBackupExpiryDays": 35,
    "diagnosticsBackupExpiryDays": 14
  },
  "distribution": {
    "approvedOrigins": [],
    "updateMetadataOrigin": null,
    "updateArtifactOrigin": null,
    "embeddedTufRootSha256": null,
    "allowUnsignedDevelopment": true,
    "engineManifestKeyIds": [],
    "codeSigningIdentities": [],
    "codeSigningCertificateFingerprints": []
  },
  "compatibility": {
    "launcherVersion": "0.4.0",
    "engineVersion": "0.4.0",
    "launcherIpcVersions": [
      1,
      2
    ],
    "engineManifestVersion": 1,
    "updateEngineManifestVersion": 2,
    "openCodeBaseline": "1.17.11",
    "engineLaunchContract": "0.0.6",
    "privacyActivationProtocol": "GOATIPC2",
    "authenticatedFrameProtocol": "GOATIPC1"
  }
} as const

