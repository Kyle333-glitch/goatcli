"use strict";

const WINDOWS_PRIVACY_SPAWN_ABI_VERSION = 1;
const EXPECTED_VERSION = require("./package.json").version;

function unavailable() {
  const error = new Error("Native Windows privacy spawn is unavailable.");
  error.code = "GOAT_WINDOWS_PRIVACY_SPAWN_UNAVAILABLE";
  return error;
}

function packageFor(platform, arch) {
  if (platform !== "win32") {
    throw unavailable();
  }
  if (arch === "x64") {
    return "goatcli-windows-spawn-win32-x64-msvc";
  }
  if (arch === "arm64") {
    return "goatcli-windows-spawn-win32-arm64-msvc";
  }
  throw unavailable();
}

function loadWindowsBinding(runtime = {}) {
  const platform = runtime.platform ?? process.platform;
  const arch = runtime.arch ?? process.arch;
  const requireModule = runtime.requireModule ?? require;
  const expectedVersion = runtime.expectedVersion ?? EXPECTED_VERSION;
  const packageName = packageFor(platform, arch);

  let manifest;
  let binding;
  try {
    manifest = requireModule(`${packageName}/package.json`);
    binding = requireModule(packageName);
  } catch {
    throw unavailable();
  }

  if (
    manifest?.name !== packageName ||
    manifest?.version !== expectedVersion ||
    manifest?.goatNativeAbi !== WINDOWS_PRIVACY_SPAWN_ABI_VERSION ||
    !Array.isArray(manifest?.os) ||
    manifest.os.length !== 1 ||
    manifest.os[0] !== "win32" ||
    !Array.isArray(manifest?.cpu) ||
    manifest.cpu.length !== 1 ||
    manifest.cpu[0] !== arch ||
    binding?.WINDOWS_PRIVACY_SPAWN_ABI_VERSION !==
      WINDOWS_PRIVACY_SPAWN_ABI_VERSION ||
    typeof binding?.spawnWindowsPrivacyProcess !== "function"
  ) {
    throw unavailable();
  }

  return binding;
}

module.exports = {
  WINDOWS_PRIVACY_SPAWN_ABI_VERSION,
  loadWindowsBinding,
};
