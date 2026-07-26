import { test } from "node:test";
import assert from "node:assert";
import {
  getShell,
  checkDirectoryWritable,
  checkPathLengthProblems,
} from "./system.js";

test("getShell returns standard shell path or executable", () => {
  const shell = getShell();
  assert.strictEqual(typeof shell, "string");
  assert.ok(shell.length > 0);
});

test("checkDirectoryWritable reports correctly for current working dir", () => {
  const cwd = process.cwd();
  const status = checkDirectoryWritable(cwd);
  assert.strictEqual(status.path, cwd);
  assert.strictEqual(status.exists, true);
  assert.strictEqual(status.writable, true);
});

test("checkPathLengthProblems identifies long Windows paths through injected platform", () => {
  const normalPath = "C:\\short\\path";
  const longPath = `C:\\${"a".repeat(300)}`;

  const windowsResults = checkPathLengthProblems(
    [
      { name: "Normal", path: normalPath },
      { name: "Long", path: longPath },
    ],
    { platform: "win32" },
  );
  const macResults = checkPathLengthProblems(
    [{ name: "Long", path: longPath }],
    { platform: "darwin" },
  );

  assert.strictEqual(
    windowsResults.find((r) => r.name === "Normal")?.hasProblem,
    false,
  );
  assert.strictEqual(
    windowsResults.find((r) => r.name === "Long")?.hasProblem,
    true,
  );
  assert.strictEqual(macResults[0]?.hasProblem, false);
});
