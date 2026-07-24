import assert from "node:assert/strict";
import test from "node:test";
import {
  assertEmbeddedLauncherReleasePolicy,
  approvedEngineEnvironmentKeys,
  assertLauncherReleasePolicy,
  findApprovedEngineEnvironmentKeys,
  type ApprovedProviderPolicy,
  compiledControlPlaneOrigin,
  releasePolicyAllows,
  ReleasePolicyError,
} from "./release-policy.js";

test("embedded launcher policy is a fail-closed internal release candidate", () => {
  assert.doesNotThrow(() => assertEmbeddedLauncherReleasePolicy());
  assert.equal(compiledControlPlaneOrigin(), undefined);
  assert.equal(releasePolicyAllows("optionalTelemetry"), false);
  assert.equal(releasePolicyAllows("hostedInference"), false);
  assert.equal(releasePolicyAllows("sponsors"), false);
});

test("only an exact approved direct provider enables its known credential key", () => {
  const direct = {
    providerId: "ovhcloud",
    modelId: "gpt-oss-20b",
    publicAlias: "goat/fast",
    executionMode: "direct",
    privacyApprovalId: "privacy-approval",
    zdrApprovalId: "zdr-approval",
  } satisfies ApprovedProviderPolicy;

  assert.deepEqual(approvedEngineEnvironmentKeys(), []);
  assert.deepEqual(findApprovedEngineEnvironmentKeys([direct], false), []);
  assert.deepEqual(findApprovedEngineEnvironmentKeys([direct], true), [
    "OVHCLOUD_API_KEY",
  ]);
  assert.deepEqual(
    findApprovedEngineEnvironmentKeys(
      [{ ...direct, executionMode: "hosted" }],
      true,
    ),
    [],
  );
  assert.deepEqual(
    findApprovedEngineEnvironmentKeys(
      [{ ...direct, providerId: "unknown-provider" }],
      true,
    ),
    [],
  );
  assert.deepEqual(
    findApprovedEngineEnvironmentKeys(
      [{ ...direct, privacyApprovalId: " " }],
      true,
    ),
    [],
  );
  assert.deepEqual(
    findApprovedEngineEnvironmentKeys([direct, direct], true),
    [],
  );
});

test("embedded launcher policy cannot authorize a production build", () => {
  assert.throws(
    () => assertLauncherReleasePolicy({ production: true }),
    (error: unknown) =>
      error instanceof ReleasePolicyError &&
      error.code === "production_release_blocked",
  );
});
