import assert from "node:assert/strict";
import { test } from "node:test";
import {
  getEnginePackageName,
  resolveNpmEnginePackage,
} from "./npm-package.js";

test("maps each supported platform tuple to its engine package", () => {
  assert.equal(getEnginePackageName("win32", "x64"), "goat-engine-windows-x64");
  assert.equal(
    getEnginePackageName("win32", "arm64"),
    "goat-engine-windows-arm64",
  );
  assert.equal(getEnginePackageName("darwin", "x64"), "goat-engine-darwin-x64");
  assert.equal(
    getEnginePackageName("darwin", "arm64"),
    "goat-engine-darwin-arm64",
  );
});

test("does not resolve an engine package that is not installed", () => {
  assert.equal(resolveNpmEnginePackage("win32", "x64"), null);
});
