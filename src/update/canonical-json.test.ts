import assert from "node:assert/strict";
import test from "node:test";
import { canonicalize } from "@tufjs/canonical-json";
import { parseCanonicalJson } from "./canonical-json.js";
import { UpdateError } from "./errors.js";

test("canonical metadata is decoded with one unambiguous interpretation", () => {
  const source = {
    signatures: [{ keyid: "a", sig: "00" }],
    signed: { _type: "targets", spec_version: "1.0.31", version: 1 },
  };
  const bytes = Buffer.from(canonicalize(source), "utf8");
  assert.deepEqual(parseCanonicalJson(bytes), source);
});

test("duplicateOrNonCanonicalFieldsAreRejected", () => {
  for (const raw of [
    '{"signed":{"version":1,"version":2}}',
    '{"signed": {"version":1}}',
    '{"signed":{"version":1.0}}',
    '{"signed":{"version":1}}trailing',
  ]) {
    assert.throws(
      () => parseCanonicalJson(Buffer.from(raw, "utf8")),
      isUpdateError("GOAT_UPDATE_MANIFEST_INVALID"),
    );
  }
});

test("malformed UTF-8, BOMs, and oversized metadata are rejected", () => {
  assert.throws(
    () => parseCanonicalJson(Buffer.from([0xc3, 0x28])),
    isUpdateError("GOAT_UPDATE_MANIFEST_INVALID"),
  );
  assert.throws(
    () =>
      parseCanonicalJson(
        Buffer.concat([
          Buffer.from([0xef, 0xbb, 0xbf]),
          Buffer.from("{}", "utf8"),
        ]),
      ),
    isUpdateError("GOAT_UPDATE_MANIFEST_INVALID"),
  );
  assert.throws(
    () => parseCanonicalJson(Buffer.from("{}"), { maxBytes: 1 }),
    isUpdateError("GOAT_UPDATE_MANIFEST_TOO_LARGE"),
  );
});

function isUpdateError(code: UpdateError["code"]): (error: unknown) => boolean {
  return (error) => error instanceof UpdateError && error.code === code;
}
