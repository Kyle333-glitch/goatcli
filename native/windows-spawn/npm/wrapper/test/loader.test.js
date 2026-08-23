"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");

const {
  WINDOWS_PRIVACY_SPAWN_ABI_VERSION,
  loadWindowsBinding,
} = require("../loader.js");

function fixtureRequire(overrides = {}) {
  const packageName = "goatcli-windows-spawn-win32-x64-msvc";
  const manifest = {
    name: packageName,
    version: "0.4.0",
    goatNativeAbi: 1,
    os: ["win32"],
    cpu: ["x64"],
    ...overrides.manifest,
  };
  const binding = {
    WINDOWS_PRIVACY_SPAWN_ABI_VERSION: 1,
    spawnWindowsPrivacyProcess() {},
    ...overrides.binding,
  };
  return (specifier) =>
    specifier.endsWith("/package.json") ? manifest : binding;
}

test("exports ABI version one and selects the x64 package", () => {
  const binding = loadWindowsBinding({
    platform: "win32",
    arch: "x64",
    expectedVersion: "0.4.0",
    requireModule: fixtureRequire(),
  });
  assert.equal(WINDOWS_PRIVACY_SPAWN_ABI_VERSION, 1);
  assert.equal(typeof binding.spawnWindowsPrivacyProcess, "function");
});

test("fails closed for unsupported platforms and architectures", () => {
  for (const runtime of [
    { platform: "darwin", arch: "x64" },
    { platform: "win32", arch: "ia32" },
  ]) {
    assert.throws(
      () => loadWindowsBinding({ ...runtime, requireModule: fixtureRequire() }),
      { code: "GOAT_WINDOWS_PRIVACY_SPAWN_UNAVAILABLE" },
    );
  }
});

test("fails closed for package-version, metadata, and native-ABI mismatches", () => {
  const cases = [
    { manifest: { name: "not-the-selected-package" } },
    { manifest: { version: "0.4.1" } },
    { manifest: { goatNativeAbi: 2 } },
    { manifest: { os: ["win32", "darwin"] } },
    { manifest: { cpu: ["arm64"] } },
    { manifest: { cpu: ["x64", "arm64"] } },
    { binding: { WINDOWS_PRIVACY_SPAWN_ABI_VERSION: 2 } },
    { binding: { spawnWindowsPrivacyProcess: undefined } },
  ];
  for (const overrides of cases) {
    assert.throws(
      () =>
        loadWindowsBinding({
          platform: "win32",
          arch: "x64",
          expectedVersion: "0.4.0",
          requireModule: fixtureRequire(overrides),
        }),
      { code: "GOAT_WINDOWS_PRIVACY_SPAWN_UNAVAILABLE" },
    );
  }
});
