import fs from "node:fs";
import path from "node:path";
import ts from "typescript";

const root = process.cwd();
const failures = [];
const productionFiles = walk(path.join(root, "src")).filter(
  (file) =>
    file.endsWith(".ts") &&
    !file.endsWith(".test.ts") &&
    !file.endsWith(".spec.ts"),
);
const networkModules = new Set([
  "node:http",
  "node:https",
  "node:http2",
  "node:net",
  "node:tls",
  "node:dgram",
  "node:dns",
]);
const bannedModulePattern =
  /(?:analytics|telemetry|sentry|bugsnag|datadog|newrelic|rollbar|honeycomb|opentelemetry)/i;
const processArgAllowlist = new Set(["src/cli.ts", "src/commands/doctor.ts"]);
const processEnvAllowlist = new Set([
  "src/cli.ts",
  "src/auth/browser.ts",
  "src/auth/client.ts",
  "src/platform.ts",
  "src/utils/system.ts",
]);

for (const filename of productionFiles) {
  const relative = slash(path.relative(root, filename));
  const text = fs.readFileSync(filename, "utf8");
  const source = ts.createSourceFile(
    filename,
    text,
    ts.ScriptTarget.Latest,
    true,
    ts.ScriptKind.TS,
  );

  const visit = (node) => {
    if (
      ts.isImportDeclaration(node) &&
      ts.isStringLiteral(node.moduleSpecifier)
    ) {
      const moduleName = node.moduleSpecifier.text;
      if (networkModules.has(moduleName) && relative !== "src/auth/client.ts") {
        failures.push(
          `${relative}: only src/auth/client.ts may import network primitives (${moduleName})`,
        );
      }
      if (bannedModulePattern.test(moduleName)) {
        failures.push(
          `${relative}: telemetry or error-reporting dependency is forbidden (${moduleName})`,
        );
      }
    }
    if (
      ts.isCallExpression(node) &&
      ts.isIdentifier(node.expression) &&
      node.expression.text === "fetch"
    ) {
      failures.push(`${relative}: direct fetch calls are forbidden`);
    }
    if (
      ts.isPropertyAccessExpression(node) &&
      ts.isIdentifier(node.expression)
    ) {
      if (
        node.expression.text === "process" &&
        node.name.text === "argv" &&
        !processArgAllowlist.has(relative)
      ) {
        failures.push(
          `${relative}: direct process.argv access is not approved`,
        );
      }
      if (
        node.expression.text === "process" &&
        node.name.text === "env" &&
        !processEnvAllowlist.has(relative)
      ) {
        failures.push(`${relative}: direct process.env access is not approved`);
      }
      if (
        node.expression.text === "child" &&
        (node.name.text === "stdout" || node.name.text === "stderr")
      ) {
        failures.push(`${relative}: child output collection is forbidden`);
      }
    }
    if (
      (ts.isIdentifier(node) || ts.isStringLiteral(node)) &&
      node.text === "metadata"
    ) {
      failures.push(`${relative}: generic metadata bags are forbidden`);
    }
    ts.forEachChild(node, visit);
  };
  visit(source);

  if (
    relative !== "src/engine/launch.ts" &&
    /['"](?:GOAT_CONTROL_PLANE_URL|GOAT_ENGINE_PATH|GOAT_DEV_ENGINE_PATH|GOATCLI_DEV)['"]/.test(
      text,
    )
  ) {
    failures.push(
      `${relative}: launcher routing environment keys may only be stripped in src/engine/launch.ts`,
    );
  }
  if (
    relative !== "src/commands/doctor.ts" &&
    /write\([^\n]*(?:error\.message|String\(error\))/.test(text)
  ) {
    failures.push(
      `${relative}: raw exception output is forbidden outside local doctor diagnostics`,
    );
  }
}

const packageJson = JSON.parse(
  fs.readFileSync(path.join(root, "package.json"), "utf8"),
);
for (const name of Object.keys({
  ...packageJson.dependencies,
  ...packageJson.devDependencies,
})) {
  if (bannedModulePattern.test(name))
    failures.push(`package.json: forbidden dependency ${name}`);
}

const client = read("src/auth/client.ts");
const releasePolicy = read("src/privacy/release-policy.generated.ts");
requireText(
  client,
  "compiledControlPlaneOrigin as compiledReleasePolicyOrigin",
  "auth client must use the generated release policy",
);
if (!/['"]?controlPlaneOrigin['"]?\s*:\s*null\s*,/.test(releasePolicy)) {
  failures.push("the internal launcher policy must ship without a production origin");
}
if (client.includes("APPROVED_PRODUCTION_ORIGIN"))
  failures.push("src/auth/client.ts: duplicated production origin is forbidden");
const approvedRoutePaths = [
  "/v1/auth/device/sessions",
  "/v1/auth/device/token",
  "/v1/auth/device/cancel",
  "/v1/auth/tokens/refresh",
  "/v1/auth/tokens/revoke",
  "/v1/usage/summary",
];
const declaredRoutePaths = [
  ...client.matchAll(/^\s+\w+: "(\/v1\/[^"]+)",$/gm),
].map((match) => match[1]);
if (JSON.stringify(declaredRoutePaths) !== JSON.stringify(approvedRoutePaths)) {
  failures.push(
    `auth client routes must be exactly the six approved operations (found ${declaredRoutePaths.join(", ")})`,
  );
}
for (const field of [...approvedRoutePaths, "GOAT-auth/1", "GOAT-usage/1"])
  requireText(client, field, `missing fixed auth boundary ${field}`);

const ipc = read("src/privacy/launcher-ipc.ts");
for (const forbidden of [
  "diagnostic_checks",
  "os_session_id",
  "standalone",
  "desktop",
]) {
  if (ipc.includes(forbidden))
    failures.push(
      `src/privacy/launcher-ipc.ts: forbidden launcher IPC field ${forbidden}`,
    );
}
requireText(
  ipc,
  'readonly installation_channel: "npm";',
  "IPC installation channel must be npm-only",
);

const launch = read("src/engine/launch.ts");
requireText(
  launch,
  '["inherit", "inherit", "inherit", "pipe", "pipe"]',
  "privacy IPC must preserve inherited child stdio 0-2",
);
if (/\.stdout|\.stderr/.test(launch))
  failures.push("src/engine/launch.ts: launcher must not read child output");

if (failures.length) {
  for (const failure of failures)
    console.error(`privacy architecture: ${failure}`);
  process.exitCode = 1;
} else {
  console.log(
    `Privacy architecture check passed (${productionFiles.length} production files).`,
  );
}

function read(relative) {
  return fs.readFileSync(path.join(root, relative), "utf8");
}

function requireText(source, expected, failure) {
  if (!source.includes(expected)) failures.push(failure);
}

function walk(directory) {
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const target = path.join(directory, entry.name);
    return entry.isDirectory() ? walk(target) : [target];
  });
}

function slash(value) {
  return value.replaceAll("\\", "/");
}
