import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import test from "node:test";

const execFileAsync = promisify(execFile);
const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
);

test("privacy architecture gate passes on the current source tree", async () => {
  // Fixture-level check: the gate exists and passes on the current tree. It
  // verifies forbidden imports, direct fetch calls, process argv/env access,
  // child output collection, generic metadata bags, fixed auth/update/IPC
  // boundaries, and the absent production trust material. This does NOT prove
  // that release CI enforces the gate; Sol owns that integration.
  const { stdout } = await execFileAsync(
    process.execPath,
    ["scripts/check-privacy-architecture.mjs"],
    { cwd: repoRoot, encoding: "utf8" },
  );
  assert.match(stdout, /Privacy architecture check passed/);
});

test("privacy architecture gate is wired into the npm test surface", () => {
  const packageJson = JSON.parse(
    readFileSync(path.join(repoRoot, "package.json"), "utf8"),
  ) as { scripts?: Record<string, string> };
  const scripts = Object.values(packageJson.scripts ?? {}).join("\n");
  assert.match(scripts, /privacy:check|check-privacy-architecture/);
});
