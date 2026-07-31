import type { Writable } from "node:stream";
import {
  AUTHENTICATED_FRAME_PROTOCOL,
  ENGINE_CONTRACT_VERSION,
  GOAT_PRODUCT_VERSION,
  OPENCODE_BASELINE_VERSION,
  PRIVACY_ACTIVATION_PROTOCOL,
} from "../version.js";
import { inspectInstalledEngine } from "../update/installed.js";
import type { VerifiedUpdatePolicy } from "../update/updater.js";

export interface VersionCommandOptions {
  readonly launcherVersion: string;
  readonly platform: string;
  readonly architecture: string;
  readonly appDataDirectory: string;
  readonly policy: VerifiedUpdatePolicy | null;
  readonly stdout: Pick<Writable, "write">;
}

export async function runVersionCommand(
  options: VersionCommandOptions,
): Promise<void> {
  const base = [
    `GOAT product: ${GOAT_PRODUCT_VERSION}`,
    `goatcli launcher: ${options.launcherVersion}`,
    `OpenCode baseline: ${OPENCODE_BASELINE_VERSION}`,
    `Engine launch contract: ${ENGINE_CONTRACT_VERSION}`,
    `Privacy protocols: ${PRIVACY_ACTIVATION_PROTOCOL} / ${AUTHENTICATED_FRAME_PROTOCOL}`,
    `Platform: ${options.platform}`,
    `Architecture: ${options.architecture}`,
  ];
  if (!options.policy) {
    options.stdout.write(
      [
        ...base,
        "GOAT engine: unavailable",
        "Configured channel: unavailable",
        "Release sequence: unavailable",
        "Active target: unavailable",
        "Active manifest: unavailable",
        "TUF root: unavailable",
        "Signing keys: unavailable",
        "Integrity: unavailable",
        "Rollback: unavailable",
        "Verified updates: disabled (approved production policy is absent)",
      ].join("\n") + "\n",
    );
    return;
  }

  const installed = await inspectInstalledEngine(
    options.appDataDirectory,
    options.policy.activation,
  );
  if (!installed) {
    options.stdout.write(
      [
        ...base,
        "GOAT engine: not installed",
        "Configured channel: stable",
        "Release sequence: none",
        "Active target: none",
        "Active manifest: none",
        `TUF root: ${options.policy.embeddedRootSha256}`,
        "Signing keys: none",
        "Integrity: no active installation",
        "Rollback: not applicable",
        "Verified updates: enabled",
      ].join("\n") + "\n",
    );
    return;
  }

  const active = installed.active;
  const record = active.activation.record;
  options.stdout.write(
    [
      ...base,
      `GOAT engine: ${record.goatEngineVersion}`,
      `Configured channel: ${installed.state.record.configuredChannel}`,
      `Release sequence: ${record.releaseSequence}`,
      `Active target: ${active.receipt.target.targetPath} (${record.artifactSha256})`,
      `Active manifest: ${record.manifestSha256}`,
      `TUF root: ${options.policy.embeddedRootSha256}`,
      `Signing keys: root=${installed.rootSigningKeyIds.join(",")}; target=${installed.targetSigningKeyIds.join(",")}; manifest=${active.candidate.manifest.signature.keyId}`,
      "Integrity: verified",
      `Rollback: ${installed.rollbackReady ? "ready" : "unavailable"}`,
      "Verified updates: enabled",
    ].join("\n") + "\n",
  );
}
