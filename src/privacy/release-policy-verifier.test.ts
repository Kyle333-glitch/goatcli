import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";
import {
  verifyEmbeddedReleasePolicy,
  type EmbeddedReleasePolicySignature,
} from "./release-policy-verifier.js";

function signedFixture(policy: unknown) {
  const source = Buffer.from(`${JSON.stringify(policy)}\n`, "utf8");
  const keys = generateKeyPairSync("ed25519");
  const publicKey = keys.publicKey.export({ format: "der", type: "spki" });
  const signature = sign(null, source, keys.privateKey);
  return {
    source,
    input: {
      policy,
      sourceSha256: createHash("sha256").update(source).digest("hex"),
      signature: {
        algorithm: "ed25519",
        status: "signed",
        keyId: createHash("sha256").update(publicKey).digest("hex"),
        signature: signature.toString("base64url"),
        policySourceBase64: source.toString("base64"),
        trustedPublicKeySpkiBase64Url: publicKey.toString("base64url"),
      } satisfies EmbeddedReleasePolicySignature,
    },
  };
}

test("verifies the exact embedded policy bytes against a pinned Ed25519 key", () => {
  const fixture = signedFixture({
    releaseVersion: "test",
    features: { hostedInference: true },
  });
  assert.deepEqual(verifyEmbeddedReleasePolicy(fixture.input), {
    signed: true,
  });
});

test("rejects policy tampering even when generated fields remain structurally valid", () => {
  const fixture = signedFixture({
    releaseVersion: "test",
    features: { hostedInference: true },
  });
  assert.throws(
    () =>
      verifyEmbeddedReleasePolicy({
        ...fixture.input,
        policy: {
          releaseVersion: "test",
          features: { hostedInference: false },
        },
      }),
    /does not match/,
  );
});

test("rejects a wrong key and a tampered detached signature", () => {
  const fixture = signedFixture({ releaseVersion: "test" });
  const other = signedFixture({ releaseVersion: "test" });
  assert.throws(
    () =>
      verifyEmbeddedReleasePolicy({
        ...fixture.input,
        signature: {
          ...fixture.input.signature,
          trustedPublicKeySpkiBase64Url:
            other.input.signature.trustedPublicKeySpkiBase64Url,
        },
      }),
    /key ID/,
  );
  const detached = Buffer.from(fixture.input.signature.signature!, "base64url");
  detached[0] ^= 1;
  assert.throws(
    () =>
      verifyEmbeddedReleasePolicy({
        ...fixture.input,
        signature: {
          ...fixture.input.signature,
          signature: detached.toString("base64url"),
        },
      }),
    /signature is invalid/,
  );
});
