"use strict";

const {
  WINDOWS_PRIVACY_SPAWN_ABI_VERSION,
  loadWindowsBinding,
} = require("./loader.js");

const binding = loadWindowsBinding();

function spawnWindowsPrivacyProcess(request, onExit) {
  return binding.spawnWindowsPrivacyProcess(request, onExit);
}

module.exports = {
  WINDOWS_PRIVACY_SPAWN_ABI_VERSION,
  spawnWindowsPrivacyProcess,
};
