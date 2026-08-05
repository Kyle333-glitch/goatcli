import assert from "node:assert/strict";
import { mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  verifyPlatformCodeSignature,
  type VerificationCommandRunner,
} from "./code-signing.js";
import { UpdateError } from "./errors.js";

const WINDOWS_CERTIFICATE = "a".repeat(64);

test("Windows Authenticode uses fixed no-profile PowerShell and exact SHA-256 identity", async (context) => {
  const executablePath = await fixtureExecutable(context);
  const calls: { command: string; args: readonly string[] }[] = [];
  const run: VerificationCommandRunner = (command, args, options) => {
    calls.push({ command, args });
    assert.equal(options.timeoutMs, 15_000);
    assert.equal(options.maxBufferBytes, 16 * 1024);
    return {
      status: 0,
      stdout: JSON.stringify({
        status: "Valid",
        certificateSha256: WINDOWS_CERTIFICATE.toUpperCase(),
      }),
      stderr: "",
    };
  };
  await verifyPlatformCodeSignature({
    platform: "win32",
    executablePath,
    targetPolicy: {
      scheme: "authenticode-sha256",
      identityId: "windows-production-1",
    },
    approvedIdentities: [
      {
        scheme: "authenticode-sha256",
        identityId: "windows-production-1",
        certificateSha256: WINDOWS_CERTIFICATE,
      },
    ],
    windowsSystemRoot: "C:\\Windows",
    runCommand: run,
  });
  assert.equal(calls.length, 1);
  assert.equal(
    calls[0]!.command,
    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  );
  assert.deepEqual(calls[0]!.args.slice(0, 6), [
    "-NoLogo",
    "-NoProfile",
    "-NonInteractive",
    "-ExecutionPolicy",
    "RemoteSigned",
    "-Command",
  ]);
  assert.equal(calls[0]!.args.at(-1), executablePath);
  assert.equal(
    calls[0]!.args.some((arg) => arg.includes(WINDOWS_CERTIFICATE)),
    false,
  );
});

test("invalid Authenticode status, fingerprint, output shape, or tool failure is rejected", async (context) => {
  const executablePath = await fixtureExecutable(context);
  const results = [
    {
      status: 0,
      stdout: '{"status":"NotSigned","certificateSha256":""}',
      stderr: "",
    },
    {
      status: 0,
      stdout: JSON.stringify({
        status: "Valid",
        certificateSha256: "b".repeat(64),
      }),
      stderr: "",
    },
    {
      status: 0,
      stdout: JSON.stringify({
        status: "Valid",
        certificateSha256: WINDOWS_CERTIFICATE,
        unexpected: true,
      }),
      stderr: "",
    },
    { status: 1, stdout: "", stderr: "failed" },
  ];
  for (const [index, result] of results.entries()) {
    await context.test(String(index), async () => {
      await assert.rejects(
        verifyPlatformCodeSignature({
          platform: "win32",
          executablePath,
          targetPolicy: {
            scheme: "authenticode-sha256",
            identityId: "windows-production-1",
          },
          approvedIdentities: [
            {
              scheme: "authenticode-sha256",
              identityId: "windows-production-1",
              certificateSha256: WINDOWS_CERTIFICATE,
            },
          ],
          runCommand: () => result,
        }),
        isUpdateError("GOAT_UPDATE_CODE_SIGNATURE_INVALID"),
      );
    });
  }
});

test("macOS requires strict codesign identity plus Gatekeeper assessment", async (context) => {
  const executablePath = await fixtureExecutable(context);
  const commands: string[] = [];
  const run: VerificationCommandRunner = (command, args) => {
    commands.push(`${command} ${args.slice(0, -1).join(" ")}`);
    if (command === "/usr/bin/codesign" && args[0] === "--display") {
      return {
        status: 0,
        stdout: "",
        stderr: [
          "Executable=/fixture/goat-engine",
          "Identifier=dev.goat.engine",
          "Authority=Developer ID Application: GOAT Test (ABC123DEFG)",
          "Authority=Developer ID Certification Authority",
          "TeamIdentifier=ABC123DEFG",
          "Runtime Version=15.0.0",
        ].join("\n"),
      };
    }
    return { status: 0, stdout: "", stderr: "accepted" };
  };
  await verifyPlatformCodeSignature({
    platform: "darwin",
    executablePath,
    targetPolicy: {
      scheme: "apple-developer-id",
      identityId: "apple-production-1",
    },
    approvedIdentities: [
      {
        scheme: "apple-developer-id",
        identityId: "apple-production-1",
        teamIdentifier: "ABC123DEFG",
        authority: "Developer ID Application: GOAT Test (ABC123DEFG)",
      },
    ],
    runCommand: run,
  });
  assert.deepEqual(commands, [
    "/usr/bin/codesign --verify --strict --verbose=2",
    "/usr/bin/codesign --display --verbose=4",
    "/usr/sbin/spctl --assess --type execute --verbose=4",
  ]);
});

test("macOS wrong Team ID, authority, or Gatekeeper failure is rejected", async (context) => {
  const executablePath = await fixtureExecutable(context);
  for (const mode of ["team", "authority", "spctl"] as const) {
    await context.test(mode, async () => {
      const run: VerificationCommandRunner = (command, args) => {
        if (command === "/usr/bin/codesign" && args[0] === "--display") {
          return {
            status: 0,
            stdout: "",
            stderr: [
              `Authority=${mode === "authority" ? "Developer ID Application: Attacker (ZZZ999ZZZZ)" : "Developer ID Application: GOAT Test (ABC123DEFG)"}`,
              `TeamIdentifier=${mode === "team" ? "ZZZ999ZZZZ" : "ABC123DEFG"}`,
            ].join("\n"),
          };
        }
        if (command === "/usr/sbin/spctl" && mode === "spctl") {
          return { status: 3, stdout: "", stderr: "rejected" };
        }
        return { status: 0, stdout: "", stderr: "" };
      };
      await assert.rejects(
        verifyPlatformCodeSignature({
          platform: "darwin",
          executablePath,
          targetPolicy: {
            scheme: "apple-developer-id",
            identityId: "apple-production-1",
          },
          approvedIdentities: [
            {
              scheme: "apple-developer-id",
              identityId: "apple-production-1",
              teamIdentifier: "ABC123DEFG",
              authority: "Developer ID Application: GOAT Test (ABC123DEFG)",
            },
          ],
          runCommand: run,
        }),
        isUpdateError("GOAT_UPDATE_CODE_SIGNATURE_INVALID"),
      );
    });
  }
});

test("unknown, duplicate, or mismatched signing identity is rejected before tools run", async (context) => {
  const executablePath = await fixtureExecutable(context);
  let called = false;
  await assert.rejects(
    verifyPlatformCodeSignature({
      platform: "win32",
      executablePath,
      targetPolicy: {
        scheme: "authenticode-sha256",
        identityId: "missing",
      },
      approvedIdentities: [],
      runCommand: () => {
        called = true;
        return { status: 0, stdout: "", stderr: "" };
      },
    }),
    isUpdateError("GOAT_UPDATE_CODE_SIGNATURE_INVALID"),
  );
  assert.equal(called, false);
});

test("symlinked executable is rejected before signature tools", async (context) => {
  const executablePath = await fixtureExecutable(context);
  const linkPath = `${executablePath}-link`;
  try {
    await symlink(executablePath, linkPath, "file");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EPERM") {
      context.skip("native symlink creation is unavailable");
      return;
    }
    throw error;
  }
  await assert.rejects(
    verifyPlatformCodeSignature({
      platform: "win32",
      executablePath: linkPath,
      targetPolicy: {
        scheme: "authenticode-sha256",
        identityId: "windows-production-1",
      },
      approvedIdentities: [
        {
          scheme: "authenticode-sha256",
          identityId: "windows-production-1",
          certificateSha256: WINDOWS_CERTIFICATE,
        },
      ],
      runCommand: () => ({ status: 0, stdout: "", stderr: "" }),
    }),
    isUpdateError("GOAT_UPDATE_CODE_SIGNATURE_INVALID"),
  );
});

async function fixtureExecutable(context: test.TestContext): Promise<string> {
  const root = await mkdtemp(path.join(os.tmpdir(), "goat-signing-test-"));
  context.after(() => rm(root, { recursive: true, force: true }));
  const executablePath = path.join(root, "goat-engine.exe");
  await writeFile(executablePath, "TEST-ONLY executable");
  return executablePath;
}

function isUpdateError(code: UpdateError["code"]): (error: unknown) => boolean {
  return (error) => error instanceof UpdateError && error.code === code;
}
