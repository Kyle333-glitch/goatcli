import assert from "node:assert/strict";
import test from "node:test";
import { compiledVerifiedUpdatePolicy } from "./policy.js";

test("missing production origins and root keep verified updates fail-closed", () => {
  assert.equal(
    compiledVerifiedUpdatePolicy({
      launcherVersion: "0.4.0",
      platform: "win32",
      architecture: "x64",
    }),
    null,
  );
});
