import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

const root = process.cwd();
const engine = path.resolve(root, "..", "goat-engine", "packages", "opencode");
const controlPlane = path.resolve(root, "..", "goat-control-plane");
const releasePolicy = path.resolve(root, "..", "goat-release-policy");
const canaryHarness = path.resolve(
  controlPlane,
  "tests",
  "cross-repository-v032.test.mjs",
);
for (const directory of [engine, controlPlane, releasePolicy]) {
  if (!fs.existsSync(directory))
    throw new Error("Required adjacent GOAT repository is unavailable.");
}
if (!fs.existsSync(canaryHarness))
  throw new Error("Required GOAT v0.3.2 canary harness is unavailable.");

runNode(releasePolicy, "scripts/verify.mjs");
runNode(releasePolicy, "scripts/verify-generated.mjs");

const bun = process.platform === "win32" ? "bun.exe" : "bun";
run(engine, [
  "test",
  "--timeout",
  "30000",
  "test/privacy",
  "test/cli/privacy-command.test.ts",
  "test/cli/privacy.test.ts",
  "test/cli/privacy-default-adapter.test.ts",
]);
run(controlPlane, [
  "test",
  "tests/auth.test.ts",
  "tests/usage-routes.test.ts",
  "tests/privacy-contract.test.ts",
  "tests/privacy-routes.test.ts",
  "tests/privacy-store.test.ts",
]);
run(controlPlane, ["test", "--timeout", "30000", canaryHarness], {
  GOAT_CROSS_REPOSITORY_CANARY: "1",
});
if (process.env.GOAT_TEST_DATABASE_URL) {
  run(controlPlane, [
    "test",
    "tests/auth-postgres.integration.test.ts",
    "tests/privacy-postgres.integration.test.ts",
  ]);
} else {
  console.log(
    "PostgreSQL integration tests skipped: GOAT_TEST_DATABASE_URL is unset.",
  );
}
run(controlPlane, ["run", "privacy:check"]);
run(controlPlane, ["run", "typecheck"]);
run(controlPlane, ["run", "build"]);
console.log("Cross-repository privacy verification passed.");

function runNode(cwd, script) {
  const result = spawnSync(process.execPath, [script], {
    cwd,
    env: process.env,
    stdio: "inherit",
    windowsHide: true,
  });
  if (result.error || result.status !== 0) {
    throw new Error("A release-policy verification command failed.");
  }
}

function run(cwd, args, additionalEnv = {}) {
  const result = spawnSync(bun, args, {
    cwd,
    env: { ...process.env, ...additionalEnv },
    stdio: "inherit",
    windowsHide: true,
  });
  if (result.error || result.status !== 0) {
    throw new Error("A cross-repository verification command failed.");
  }
}

