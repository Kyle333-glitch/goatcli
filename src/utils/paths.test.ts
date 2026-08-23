import { test } from "node:test";
import assert from "node:assert";
import {
  getAppDataDir,
  getCacheDir,
  getConfigDir,
  getEnginePath,
  getNpmEnginePath,
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

test("resolves an injected stable npm engine package", () => {
  const result = getNpmEnginePath({
    platform: "win32",
    architecture: "x64",
    appDataDir: "C:\\missing-goat-app-data",
    npmEnginePackageResolver: () => ({
      packageName: "goat-engine-windows-x64",
      packageRoot: "C:\\npm\\goat-engine-windows-x64",
      executablePath: "C:\\npm\\goat-engine-windows-x64\\bin\\goat-engine.exe",
      manifestPath: "C:\\npm\\goat-engine-windows-x64\\goat-engine.json",
    }),
  });

  assert.ok(result);
  assert.equal(result.source, "npm-package");
  assert.equal(
    result.path,
    "C:\\npm\\goat-engine-windows-x64\\bin\\goat-engine.exe",
  );
  assert.equal(
    result.manifestPath,
    "C:\\npm\\goat-engine-windows-x64\\goat-engine.json",
  );
});

test("does not select npm engines for non-stable channels", () => {
  const resolver = () => {
    throw new Error("npm resolver must not run for non-stable channels");
  };

  assert.equal(
    getNpmEnginePath({
      platform: "win32",
      architecture: "x64",
      releaseChannel: "beta",
      npmEnginePackageResolver: resolver,
    }),
    null,
  );
  assert.equal(
    getNpmEnginePath({
      platform: "win32",
      architecture: "x64",
      releaseChannel: "development",
      npmEnginePackageResolver: resolver,
    }),
    null,
  );
});
