import { spawnSync } from "node:child_process";
import { mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import assert from "node:assert/strict";
import {
  verifyPlatformCodeSignature,
  type ApprovedCodeSigningIdentity,
} from "./code-signing.js";

function findCommand(command: string): string | undefined {
  const result = spawnSync(command, ["--version"], {
    shell: false,
    timeout: 5000,
  });
  if (!result.error && !result.signal && result.status === 0) return command;
  return undefined;
}

test("macOS codesign and spctl verify a signed fixture binary", async (context) => {
  if (process.platform !== "darwin") {
    context.skip("macOS codesign test runs only on macOS");
    return;
  }
  const codesign = findCommand("/usr/bin/codesign");
  const spctl = findCommand("/usr/sbin/spctl");
  if (!codesign || !spctl) {
    context.skip("codesign or spctl not available on PATH");
    return;
  }

  const root = await mkdtemp(
    path.join(await realpath(os.tmpdir()), "goat-codesign-test-"),
  );
  context.after(async () => rm(root, { recursive: true, force: true }));
  const executablePath = path.join(root, "goat-engine");
  await writeFile(executablePath, "TEST-ONLY signed executable");

  const adHocResult = spawnSync(
    codesign,
    ["--sign", "-", "--force", executablePath],
    {
      shell: false,
      timeout: 30000,
    },
  );
  if (adHocResult.status !== 0) {
    context.skip(
      `codesign ad-hoc signing failed: ${adHocResult.stderr?.toString()}`,
    );
    return;
  }

  await verifyPlatformCodeSignature({
    platform: "darwin",
    executablePath,
    targetPolicy: { scheme: "apple-developer-id", identityId: "goat-test" },
    approvedIdentities: approvedIdentities(),
  });

  const unsignedPath = path.join(root, "goat-engine-unsigned");
  await writeFile(unsignedPath, "TEST-ONLY unsigned executable");
  await assert.rejects(
    verifyPlatformCodeSignature({
      platform: "darwin",
      executablePath: unsignedPath,
      targetPolicy: { scheme: "apple-developer-id", identityId: "goat-test" },
      approvedIdentities: approvedIdentities(),
    }),
    (error: unknown) => error instanceof Error,
  );

  const alteredPath = path.join(root, "goat-engine-altered");
  await writeFile(alteredPath, "altered bytes");
  await assert.rejects(
    verifyPlatformCodeSignature({
      platform: "darwin",
      executablePath: alteredPath,
      targetPolicy: { scheme: "apple-developer-id", identityId: "goat-test" },
      approvedIdentities: approvedIdentities(),
    }),
    (error: unknown) => error instanceof Error,
  );
});

function approvedIdentities(): readonly ApprovedCodeSigningIdentity[] {
  return [
    {
      scheme: "apple-developer-id",
      identityId: "goat-test",
      teamIdentifier: "TEST123456",
      authority: "Developer ID Application: GOAT Test (TEST123456)",
    },
  ];
}
