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

test("Windows Authenticode verification with a test-only self-signed certificate", async (context) => {
  if (process.platform !== "win32") {
    context.skip("Authenticode test runs only on Windows");
    return;
  }
  const signtool = findSigntool();
  if (!signtool) {
    context.skip("signtool.exe not available on PATH");
    return;
  }
  const ps = findPowerShell();
  if (!ps) {
    context.skip("PowerShell not available to create test certificate");
    return;
  }

  const root = await mkdtemp(
    path.join(await realpath(os.tmpdir()), "goat-authenticode-test-"),
  );
  context.after(async () => rm(root, { recursive: true, force: true }));
  const executablePath = path.join(root, "goat-engine.exe");
  await writeFile(executablePath, "TEST-ONLY signed executable");

  const certResult = spawnSync(
    ps,
    [
      "-NoProfile",
      "-Command",
      `$cert = New-SelfSignedCertificate -Type Custom -Subject "CN=GOAT Test" -KeyUsage DigitalSignature -FriendlyName "GOAT Test" -CertStoreLocation Cert:\\CurrentUser\\My; Write-Output $cert.Thumbprint; Write-Output $cert.GetCertHashString('SHA256')`,
    ],
    { encoding: "utf8", shell: false, windowsHide: true, timeout: 30000 },
  );
  if (certResult.status !== 0 || !certResult.stdout?.trim()) {
    context.skip("could not create test self-signed certificate");
    return;
  }
  const certLines = certResult.stdout.trim().split(/\r?\n/).filter(Boolean);
  const thumbprint = certLines[0]!;
  const certificateSha256 = certLines[1]!.toLowerCase();

  const signResult = spawnSync(
    signtool,
    [
      "sign",
      "/sha1",
      thumbprint,
      "/fd",
      "sha256",
      "/tr",
      "http://timestamp.digicert.com",
      "/td",
      "sha256",
      executablePath,
    ],
    { encoding: "utf8", shell: false, windowsHide: true, timeout: 30000 },
  );
  if (signResult.status !== 0) {
    context.skip(`signtool sign failed: ${signResult.stderr}`);
    return;
  }

  await verifyPlatformCodeSignature({
    platform: "win32",
    executablePath,
    targetPolicy: { scheme: "authenticode-sha256", identityId: "goat-test" },
    approvedIdentities: approvedIdentities(certificateSha256),
  });

  await assert.rejects(
    verifyPlatformCodeSignature({
      platform: "win32",
      executablePath,
      targetPolicy: { scheme: "authenticode-sha256", identityId: "goat-test" },
      approvedIdentities: approvedIdentities("b".repeat(64)),
    }),
    (error: unknown) => error instanceof Error,
  );

  const alteredPath = path.join(root, "goat-engine-altered.exe");
  await writeFile(alteredPath, "altered bytes");
  await assert.rejects(
    verifyPlatformCodeSignature({
      platform: "win32",
      executablePath: alteredPath,
      targetPolicy: { scheme: "authenticode-sha256", identityId: "goat-test" },
      approvedIdentities: approvedIdentities(certificateSha256),
    }),
    (error: unknown) => error instanceof Error,
  );
});

function findSigntool(): string | undefined {
  const candidates = ["signtool.exe"];
  for (const command of candidates) {
    const result = spawnSync(command, ["/?"], {
      shell: false,
      windowsHide: true,
      timeout: 5000,
      encoding: "utf8",
    });
    if (
      !result.error &&
      !result.signal &&
      (result.status === 0 || result.status === 1)
    )
      return command;
  }
  return undefined;
}

function findPowerShell(): string | undefined {
  const candidates = [
    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "powershell.exe",
  ];
  for (const command of candidates) {
    const result = spawnSync(command, ["-Command", "exit"], {
      shell: false,
      windowsHide: true,
      timeout: 5000,
    });
    if (!result.error && !result.signal && result.status === 0) return command;
  }
  return undefined;
}

function approvedIdentities(
  thumbprint: string,
): readonly ApprovedCodeSigningIdentity[] {
  return [
    {
      scheme: "authenticode-sha256",
      identityId: "goat-test",
      certificateSha256: thumbprint.toLowerCase(),
    },
  ];
}
