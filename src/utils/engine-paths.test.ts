import { test } from "node:test";
import assert from "node:assert/strict";
import { getEnginePath, getEngineExecutableName } from "./paths.js";

test("getEnginePath resolves deterministic Windows install path with spaces and .exe", () => {
  const appDataDir = "C:\\Users\\Test User\\AppData\\Local\\goat";
  const result = getEnginePath({
    platform: "win32",
    architecture: "x64",
    appDataDir,
    env: {},
  });

  assert.equal(result.error, null);
  assert.equal(result.source, "local-install");
  assert.equal(result.releaseChannel, "stable");
  assert.equal(
    result.path,
    "C:\\Users\\Test User\\AppData\\Local\\goat\\engines\\stable\\win32-x64\\bin\\goat-engine.exe",
  );
  assert.equal(
    result.manifestPath,
    "C:\\Users\\Test User\\AppData\\Local\\goat\\engines\\stable\\win32-x64\\goat-engine.json",
  );
});

test("getEnginePath resolves deterministic macOS POSIX path with spaces and Unicode", () => {
  const appDataDir = "/Users/Test User/Library/Application Support/goat-測試";
  const result = getEnginePath({
    platform: "darwin",
    architecture: "arm64",
    appDataDir,
    env: {},
  });

  assert.equal(result.error, null);
  assert.equal(result.source, "local-install");
  assert.equal(
    result.path,
    "/Users/Test User/Library/Application Support/goat-測試/engines/stable/darwin-arm64/bin/goat-engine",
  );
  assert.equal(
    result.manifestPath,
    "/Users/Test User/Library/Application Support/goat-測試/engines/stable/darwin-arm64/goat-engine.json",
  );
});

test("getEnginePath ignores all production environment override keys", () => {
  const appDataDir = "C:\\Users\\Test User\\AppData\\Local\\goat";
  const result = getEnginePath({
    platform: "win32",
    architecture: "x64",
    appDataDir,
    env: {
      GOATCLI_DEV: "1",
      GOAT_DEV_ENGINE_PATH: "C:\\PATH_SECRET_3HT6\\goat-engine.exe",
      GOAT_ENGINE_PATH: "C:\\PATH_SECRET_3HT6\\legacy.exe",
    },
  });

  assert.equal(result.error, null);
  assert.equal(result.source, "local-install");
  assert.equal(result.developmentOverride, false);
  assert.equal(result.releaseChannel, "stable");
  assert.equal(result.path?.includes("PATH_SECRET_3HT6"), false);
  assert.ok(result.manifestPath);
});

test("environment overrides cannot bypass the supported-platform boundary", () => {
  const result = getEnginePath({
    platform: "linux",
    architecture: "x64",
    env: {
      GOATCLI_DEV: "1",
      GOAT_DEV_ENGINE_PATH: "/tmp/PATH_SECRET_3HT6",
      GOAT_ENGINE_PATH: "/tmp/PATH_SECRET_3HT6",
    },
  });

  assert.equal(result.source, "none");
  assert.equal(result.path, null);
  assert.equal(result.error?.code, "GOAT_UNSUPPORTED_PLATFORM");
});

test("getEnginePath reports unsupported platforms explicitly", () => {
  const result = getEnginePath({
    platform: "linux",
    architecture: "x64",
    env: {},
  });

  assert.equal(result.source, "none");
  assert.equal(result.error?.code, "GOAT_UNSUPPORTED_PLATFORM");
});

test("getEngineExecutableName uses goat-engine executable names", () => {
  assert.equal(getEngineExecutableName("win32"), "goat-engine.exe");
  assert.equal(getEngineExecutableName("darwin"), "goat-engine");
});
