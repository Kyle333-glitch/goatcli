import assert from "node:assert/strict";
import test from "node:test";
import { UpdateError } from "../update/errors.js";
import { parseRequestedChannel } from "./update.js";

test("update accepts only an optional exact channel selection", () => {
  assert.equal(parseRequestedChannel([]), undefined);
  assert.equal(parseRequestedChannel(["--channel", "stable"]), "stable");
  assert.equal(parseRequestedChannel(["--channel", "beta"]), "beta");
  assert.equal(
    parseRequestedChannel(["--channel", "development"]),
    "development",
  );
  for (const args of [
    ["stable"],
    ["--channel"],
    ["--channel", "dev"],
    ["--channel", "stable", "extra"],
    ["--url", "https://attacker.invalid"],
    ["--version", "0.3.2"],
    ["--downgrade"],
  ]) {
    assert.throws(
      () => parseRequestedChannel(args),
      (error: unknown) =>
        error instanceof UpdateError &&
        error.code === "GOAT_UPDATE_INVALID_ARGUMENT",
    );
  }
});
