// Generated from goat-release-policy/releases/v0.3.2/production-policy.json.
// Do not edit approval-dependent values in this repository.

export const GOAT_RELEASE_POLICY_SOURCE_SHA256 = "9cbd3eb4c172cef8f39b922157e0757ccfeb6388e3a92c0d858c8161481a882f"

export const GOAT_RELEASE_POLICY = {
  "schemaVersion": 1,
  "releaseVersion": "0.3.2",
  "channel": "internal",
  "policyRevision": 2,
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
    "engineManifestKeyIds": [],
    "codeSigningCertificateFingerprints": [],
    "allowUnsignedDevelopment": true
  },
  "compatibility": {
    "launcherVersion": "0.3.2",
    "engineVersion": "0.3.2",
    "launcherIpcVersions": [
      1,
      2
    ],
    "engineManifestVersion": 1
  }
} as const

