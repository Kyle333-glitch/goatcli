import { createHash, createPublicKey, verify } from "node:crypto";

export type EmbeddedReleasePolicySignature = {
  readonly algorithm: "ed25519";
  readonly status: "unsigned-internal" | "signed";
  readonly keyId: string | null;
  readonly signature: string | null;
  readonly policySourceBase64: string;
  readonly trustedPublicKeySpkiBase64Url: string | null;
};

export function verifyEmbeddedReleasePolicy(input: {
  readonly policy: unknown;
  readonly sourceSha256: string;
  readonly signature: EmbeddedReleasePolicySignature;
}): { readonly signed: boolean } {
  const source = decodeBase64(
    input.signature.policySourceBase64,
    "release policy source",
  );
  const digest = createHash("sha256").update(source).digest("hex");
  if (digest !== input.sourceSha256)
    throw new Error("release policy digest mismatch");

  let parsed: unknown;
  try {
    parsed = JSON.parse(source.toString("utf8"));
  } catch {
    throw new Error("release policy source is not valid JSON");
  }
  if (JSON.stringify(parsed) !== JSON.stringify(input.policy)) {
    throw new Error(
      "generated release policy does not match its signed source",
    );
  }

  if (input.signature.algorithm !== "ed25519") {
    throw new Error("release policy signature algorithm is invalid");
  }
  if (input.signature.status === "unsigned-internal") {
    if (
      input.signature.keyId !== null ||
      input.signature.signature !== null ||
      input.signature.trustedPublicKeySpkiBase64Url !== null
    ) {
      throw new Error("unsigned release policy contains signing material");
    }
    return { signed: false };
  }

  const keyId = input.signature.keyId;
  const encodedKey = input.signature.trustedPublicKeySpkiBase64Url;
  const encodedSignature = input.signature.signature;
  if (
    !keyId ||
    !encodedKey ||
    !encodedSignature ||
    !/^[a-f0-9]{64}$/.test(keyId)
  ) {
    throw new Error(
      "signed release policy is missing trusted signing material",
    );
  }
  const key = decodeBase64Url(encodedKey, "release policy public key");
  if (createHash("sha256").update(key).digest("hex") !== keyId) {
    throw new Error(
      "release policy key ID does not match the trusted public key",
    );
  }
  const detached = decodeBase64Url(
    encodedSignature,
    "release policy signature",
  );
  if (detached.byteLength !== 64)
    throw new Error("release policy signature length is invalid");

  let publicKey;
  try {
    publicKey = createPublicKey({ key, format: "der", type: "spki" });
  } catch {
    throw new Error("release policy public key is invalid");
  }
  if (!verify(null, source, publicKey, detached)) {
    throw new Error("release policy signature is invalid");
  }
  return { signed: true };
}

function decodeBase64(value: string, label: string): Buffer {
  if (
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(
      value,
    )
  ) {
    throw new Error(`${label} is not canonical base64`);
  }
  const decoded = Buffer.from(value, "base64");
  if (decoded.toString("base64") !== value)
    throw new Error(`${label} is not canonical base64`);
  return decoded;
}

function decodeBase64Url(value: string, label: string): Buffer {
  if (!/^[A-Za-z0-9_-]+$/.test(value))
    throw new Error(`${label} is not canonical base64url`);
  const decoded = Buffer.from(value, "base64url");
  if (decoded.toString("base64url") !== value)
    throw new Error(`${label} is not canonical base64url`);
  return decoded;
}
