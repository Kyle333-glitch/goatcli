import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

const root = process.cwd();
const engine = resolveRequiredRoot(
  "GOAT_ENGINE_ROOT",
  path.resolve(root, "..", "goat-engine", "packages", "opencode"),
  "goat-engine/packages/opencode",
);
const controlPlane = resolveRequiredRoot(
  "GOAT_CONTROL_PLANE_ROOT",
  path.resolve(root, "..", "goat-control-plane"),
  "goat-control-plane",
);

assertPackageScript(
  engine,
  "opencode",
  "test:v0.4.1-platform",
  "bun test test/cli/run/run-ovh-integration.test.ts test/cli/run/run-process.test.ts test/privacy/hosted-inference-client.test.ts test/sponsor/sponsor.test.ts test/privacy/privacy-fixes-regression.test.ts test/skill/discovery-security.test.ts",
);
assertPackageScript(
  controlPlane,
  "goat-control-plane",
  "test:v0.4.1-mocked",
  "bun test tests/auth.test.ts tests/inference-routes.test.ts tests/sponsor-routes.test.ts tests/quota.test.ts tests/gateway-litellm.loopback.integration.test.ts",
);

const environment = safeEnvironment();
const bun = process.platform === "win32" ? "bun.exe" : "bun";
const engineResult = run(
  bun,
  engine,
  "engine",
  ["run", "test:v0.4.1-platform"],
  environment,
);
if (!engineResult.ok) {
  process.exitCode = engineResult.status;
} else {
  const controlPlaneResult = run(
    bun,
    controlPlane,
    "control-plane",
    ["run", "test:v0.4.1-mocked"],
    environment,
  );
  if (!controlPlaneResult.ok) process.exitCode = controlPlaneResult.status;
  else console.log("GOAT v0.4.1 mocked cross-repository coverage passed.");
}

function resolveRequiredRoot(variable, fallback, label) {
  const candidate = process.env[variable] ?? fallback;
  if (!fs.existsSync(path.join(candidate, "package.json"))) {
    throw new Error(`Required ${label} repository is unavailable.`);
  }
  return path.resolve(candidate);
}

function assertPackageScript(
  directory,
  packageName,
  scriptName,
  expectedCommand,
) {
  const packageJson = JSON.parse(
    fs.readFileSync(path.join(directory, "package.json"), "utf8"),
  );
  if (packageJson.name !== packageName) {
    throw new Error(`Unexpected ${packageName} package.`);
  }
  if (packageJson.scripts?.[scriptName] !== expectedCommand) {
    throw new Error(
      `Required ${scriptName} script is unavailable or changed in ${packageName}.`,
    );
  }
}

function safeEnvironment() {
  const allowed = new Set([
    "CI",
    "GITHUB_ACTIONS",
    "NODE_ENV",
    "BUN_INSTALL",
    "GITHUB_WORKFLOW",
    "GITHUB_RUN_ID",
    "GITHUB_RUN_ATTEMPT",
    "HOME",
    "HOMEDRIVE",
    "HOMEPATH",
    "LOCALAPPDATA",
    "APPDATA",
    "COMSPEC",
    "PATH",
    "PATHEXT",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "TMPDIR",
    "USERPROFILE",
    "WINDIR",
    "LANG",
    "LC_ALL",
    "SHELL",
    "TZ",
    "TERM",
    "NO_COLOR",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_CACHE_HOME",
  ]);
  const normalizedAllowed = new Set(
    [...allowed].map((key) =>
      process.platform === "win32" ? key.toUpperCase() : key,
    ),
  );
  const result = {};
  for (const [key, value] of Object.entries(process.env)) {
    const normalized = process.platform === "win32" ? key.toUpperCase() : key;
    if (!normalizedAllowed.has(normalized)) continue;
    result[normalized] = value;
  }
  return result;
}

function run(command, cwd, label, args, env) {
  const result = spawnSync(command, args, {
    cwd,
    env,
    stdio: "inherit",
    windowsHide: true,
  });
  if (result.error) {
    console.error(`Failed to start ${label} coverage.`);
    return { ok: false, status: 1 };
  }
  if (result.status !== 0) {
    console.error(
      `${label} coverage failed with status ${String(result.status ?? 1)}.`,
    );
    return { ok: false, status: result.status ?? 1 };
  }
  return { ok: true, status: 0 };
}
