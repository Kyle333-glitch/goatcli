import { test } from "node:test";
import assert from "node:assert";
import {
  getAppDataDir,
  getCacheDir,
  getConfigDir,
  getEnginePath,
} from "./paths.js";

test("getAppDataDir returns a path string", () => {
  const dir = getAppDataDir();
  assert.strictEqual(typeof dir, "string");
  assert.ok(dir.length > 0);
});

test("getConfigDir returns a path string", () => {
  const dir = getConfigDir();
  assert.strictEqual(typeof dir, "string");
  assert.ok(dir.length > 0);
});

test("getCacheDir returns a path string", () => {
  const dir = getCacheDir();
  assert.strictEqual(typeof dir, "string");
  assert.ok(dir.length > 0);
});

test("getEnginePath returns resolution object", () => {
  const res = getEnginePath();
  assert.ok("path" in res);
  assert.ok("source" in res);
});
