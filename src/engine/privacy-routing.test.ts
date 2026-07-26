import assert from "node:assert/strict";
import { test } from "node:test";
import { createEngineEnvironment, getPrivacyIpcMode } from "./launch.js";

test("privacy IPC routing is exact and preserves opaque diagnostic identifiers", () => {
  assert.equal(
    getPrivacyIpcMode(["privacy", "diagnostics", "preview"]),
    "preview",
  );
  assert.equal(
    getPrivacyIpcMode(["privacy", "diagnostics", "submit"]),
    "authenticated",
  );
  assert.equal(
    getPrivacyIpcMode(["privacy", "telemetry", "delete-remote"]),
    "authenticated",
  );
  assert.equal(
    getPrivacyIpcMode(["privacy", "diagnostics", "delete", "PATH_SECRET_3HT6"]),
    "authenticated",
  );

  for (const args of [
    ["privacy"],
    ["privacy", "status"],
    ["privacy", "telemetry", "on"],
    ["privacy", "telemetry", "off"],
    ["privacy", "telemetry", "reset"],
    ["privacy", "diagnostics", "preview", "extra"],
    ["privacy", "diagnostics", "delete"],
    ["privacy", "diagnostics", "delete", ""],
    ["run", "PROMPT_SECRET_7QX9"],
  ]) {
    assert.equal(getPrivacyIpcMode(args), "lazy");
  }
});

test("engine environment forwards only minimal platform and approved provider keys", () => {
  const source = {
    Path: "C:\\Windows\\System32",
    PATH: "C:\\approved-path",
    TEMP: "C:\\approved-temp",
    PROVIDER_TOKEN: "ENV_SECRET_9DK1",
    OVHCLOUD_API_KEY: "TOKEN_SECRET_8MVP",
    SHELL_SETTING: "SOURCE_CODE_SECRET_4JK2",
    GOAT_CONTROL_PLANE_URL: "https://PATH_SECRET_3HT6.invalid",
    GOAT_ENGINE_PATH: "PATH_SECRET_3HT6",
    GOAT_DEV_ENGINE_PATH: "PATH_SECRET_3HT6",
    GOATCLI_DEV: "1",
  };
  const result = createEngineEnvironment(source, "win32");

  assert.deepEqual(result, {
    PATH: "C:\\approved-path",
    TEMP: "C:\\approved-temp",
  });
  assert.equal(source.GOAT_ENGINE_PATH, "PATH_SECRET_3HT6");

  assert.deepEqual(
    createEngineEnvironment(
      {
        PATH: "/usr/bin",
        HOME: "/Users/goat",
        SSH_AUTH_SOCK: "/tmp/ENV_SECRET_9DK1",
        ENV_SECRET_9DK1: "TOKEN_SECRET_8MVP",
      },
      "darwin",
    ),
    { PATH: "/usr/bin", HOME: "/Users/goat" },
  );
});
