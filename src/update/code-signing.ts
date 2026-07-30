import path from "node:path";
import { lstat, realpath } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { UpdateError } from "./errors.js";
import type { CodeSigningPolicy, UpdatePlatform } from "./schema.js";

export type ApprovedCodeSigningIdentity =
  | {
      readonly scheme: "authenticode-sha256";
      readonly identityId: string;
      readonly certificateSha256: string;
    }
  | {
      readonly scheme: "apple-developer-id";
      readonly identityId: string;
      readonly teamIdentifier: string;
      readonly authority: string;
    };

export interface VerificationCommandResult {
  readonly status: number | null;
  readonly signal?: NodeJS.Signals | null;
  readonly stdout: string;
  readonly stderr: string;
  readonly error?: Error;
}

export type VerificationCommandRunner = (
  command: string,
  args: readonly string[],
  options: {
    readonly timeoutMs: number;
    readonly maxBufferBytes: number;
    readonly environment: NodeJS.ProcessEnv;
  },
) => VerificationCommandResult;

export interface VerifyCodeSignatureOptions {
  readonly platform: UpdatePlatform;
  readonly executablePath: string;
  readonly targetPolicy: CodeSigningPolicy;
  readonly approvedIdentities: readonly ApprovedCodeSigningIdentity[];
  readonly runCommand?: VerificationCommandRunner;
  readonly windowsSystemRoot?: string;
}

const MAX_TOOL_OUTPUT_BYTES = 16 * 1024;
const TOOL_TIMEOUT_MS = 15_000;
const POWERSHELL_SIGNATURE_SCRIPT = [
  "$ErrorActionPreference='Stop'",
  "$signature=Get-AuthenticodeSignature -LiteralPath $args[0]",
  "$fingerprint=''",
  "if($null -ne $signature.SignerCertificate){$fingerprint=$signature.SignerCertificate.GetCertHashString('SHA256')}",
  "[pscustomobject]@{status=[string]$signature.Status;certificateSha256=[string]$fingerprint}|ConvertTo-Json -Compress",
].join(";");

export async function verifyPlatformCodeSignature(
  options: VerifyCodeSignatureOptions,
): Promise<void> {
  await assertRegularExecutable(options.executablePath);
  const approved = selectApprovedIdentity(
    options.targetPolicy,
    options.approvedIdentities,
  );
  if (options.platform === "win32") {
    if (
      options.targetPolicy.scheme !== "authenticode-sha256" ||
      approved.scheme !== "authenticode-sha256"
    ) {
      throw invalidSignature();
    }
    verifyWindowsAuthenticode(options, approved);
    return;
  }
  if (
    options.targetPolicy.scheme !== "apple-developer-id" ||
    approved.scheme !== "apple-developer-id"
  ) {
    throw invalidSignature();
  }
  verifyMacDeveloperId(options, approved);
}

function verifyWindowsAuthenticode(
  options: VerifyCodeSignatureOptions,
  approved: Extract<
    ApprovedCodeSigningIdentity,
    { scheme: "authenticode-sha256" }
  >,
): void {
  const powershell = powershellPath(options.windowsSystemRoot);
  const result = run(options, powershell, [
    "-NoLogo",
    "-NoProfile",
    "-NonInteractive",
    "-ExecutionPolicy",
    "RemoteSigned",
    "-Command",
    POWERSHELL_SIGNATURE_SCRIPT,
    options.executablePath,
  ]);
  if (
    result.status !== 0 ||
    result.signal ||
    result.error ||
    Buffer.byteLength(result.stdout, "utf8") > MAX_TOOL_OUTPUT_BYTES ||
    Buffer.byteLength(result.stderr, "utf8") > MAX_TOOL_OUTPUT_BYTES
  ) {
    throw invalidSignature();
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(result.stdout);
  } catch (error) {
    throw new UpdateError("GOAT_UPDATE_CODE_SIGNATURE_INVALID", {
      cause: error,
    });
  }
  if (
    !isRecord(parsed) ||
    !hasExactKeys(parsed, ["certificateSha256", "status"]) ||
    parsed.status !== "Valid" ||
    typeof parsed.certificateSha256 !== "string" ||
    parsed.certificateSha256.toLowerCase() !== approved.certificateSha256
  ) {
    throw invalidSignature();
  }
}

function verifyMacDeveloperId(
  options: VerifyCodeSignatureOptions,
  approved: Extract<
    ApprovedCodeSigningIdentity,
    { scheme: "apple-developer-id" }
  >,
): void {
  const verify = run(options, "/usr/bin/codesign", [
    "--verify",
    "--strict",
    "--verbose=2",
    options.executablePath,
  ]);
  if (failed(verify)) throw invalidSignature();

  const display = run(options, "/usr/bin/codesign", [
    "--display",
    "--verbose=4",
    options.executablePath,
  ]);
  if (failed(display)) throw invalidSignature();
  const lines = display.stderr.split(/\r?\n/);
  const teamIdentifiers = lines
    .filter((line) => line.startsWith("TeamIdentifier="))
    .map((line) => line.slice("TeamIdentifier=".length));
  const authorities = lines
    .filter((line) => line.startsWith("Authority="))
    .map((line) => line.slice("Authority=".length));
  if (
    teamIdentifiers.length !== 1 ||
    teamIdentifiers[0] !== approved.teamIdentifier ||
    authorities.length < 1 ||
    authorities[0] !== approved.authority
  ) {
    throw invalidSignature();
  }

  const assessment = run(options, "/usr/sbin/spctl", [
    "--assess",
    "--type",
    "execute",
    "--verbose=4",
    options.executablePath,
  ]);
  if (failed(assessment)) throw invalidSignature();
}

function selectApprovedIdentity(
  target: CodeSigningPolicy,
  approved: readonly ApprovedCodeSigningIdentity[],
): ApprovedCodeSigningIdentity {
  const matches = approved.filter(
    (identity) =>
      identity.scheme === target.scheme &&
      identity.identityId === target.identityId,
  );
  if (matches.length !== 1) throw invalidSignature();
  const selected = matches[0]!;
  if (
    selected.scheme === "authenticode-sha256" &&
    !/^[a-f0-9]{64}$/.test(selected.certificateSha256)
  ) {
    throw invalidSignature();
  }
  if (
    selected.scheme === "apple-developer-id" &&
    (!/^[A-Z0-9]{10}$/.test(selected.teamIdentifier) ||
      selected.authority.length === 0 ||
      selected.authority.length > 256 ||
      /[\r\n\0]/.test(selected.authority))
  ) {
    throw invalidSignature();
  }
  return selected;
}

function run(
  options: VerifyCodeSignatureOptions,
  command: string,
  args: readonly string[],
): VerificationCommandResult {
  const runner = options.runCommand ?? defaultRunner;
  return runner(command, args, {
    timeoutMs: TOOL_TIMEOUT_MS,
    maxBufferBytes: MAX_TOOL_OUTPUT_BYTES,
    environment: minimalToolEnvironment(options.platform),
  });
}

function defaultRunner(
  command: string,
  args: readonly string[],
  options: {
    readonly timeoutMs: number;
    readonly maxBufferBytes: number;
    readonly environment: NodeJS.ProcessEnv;
  },
): VerificationCommandResult {
  const result = spawnSync(command, [...args], {
    shell: false,
    windowsHide: true,
    encoding: "utf8",
    timeout: options.timeoutMs,
    maxBuffer: options.maxBufferBytes,
    env: options.environment,
  });
  return {
    status: result.status,
    signal: result.signal,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
    error: result.error,
  };
}

function minimalToolEnvironment(platform: UpdatePlatform): NodeJS.ProcessEnv {
  if (platform === "win32") {
    return {
      SystemRoot: process.env.SystemRoot ?? "C:\\Windows",
      TEMP: process.env.TEMP,
      TMP: process.env.TMP,
    };
  }
  return {
    HOME: "/var/empty",
    LANG: "C",
    LC_ALL: "C",
    PATH: "/usr/bin:/bin:/usr/sbin:/sbin",
    TMPDIR: "/tmp",
  };
}

function powershellPath(systemRoot: string | undefined): string {
  const root = systemRoot ?? process.env.SystemRoot ?? "C:\\Windows";
  // Validate the pre-resolve value is absolute so relative input cannot be
  // turned into an absolute path by resolve. Reject UNC paths and any value
  // containing control characters.
  if (
    !path.win32.isAbsolute(root) ||
    root.startsWith("\\\\") ||
    /[\r\n\0]/.test(root) ||
    root.length > 128
  ) {
    throw invalidSignature();
  }
  const normalized = path.win32.normalize(root);
  return path.win32.join(
    normalized,
    "System32",
    "WindowsPowerShell",
    "v1.0",
    "powershell.exe",
  );
}

async function assertRegularExecutable(executablePath: string): Promise<void> {
  if (!path.isAbsolute(executablePath)) throw invalidSignature();
  try {
    const stats = await lstat(executablePath);
    const canonical = await realpath(executablePath);
    if (
      !stats.isFile() ||
      stats.isSymbolicLink() ||
      stats.nlink !== 1 ||
      path.resolve(canonical) !== path.resolve(executablePath)
    ) {
      throw invalidSignature();
    }
  } catch (error) {
    if (error instanceof UpdateError) throw error;
    throw new UpdateError("GOAT_UPDATE_CODE_SIGNATURE_INVALID", {
      cause: error,
    });
  }
}

function failed(result: VerificationCommandResult): boolean {
  return (
    result.status !== 0 ||
    Boolean(result.signal) ||
    Boolean(result.error) ||
    Buffer.byteLength(result.stdout, "utf8") > MAX_TOOL_OUTPUT_BYTES ||
    Buffer.byteLength(result.stderr, "utf8") > MAX_TOOL_OUTPUT_BYTES
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasExactKeys(
  value: Record<string, unknown>,
  keys: readonly string[],
): boolean {
  const actual = Object.keys(value);
  return actual.length === keys.length && keys.every((key) => key in value);
}

function invalidSignature(): UpdateError {
  return new UpdateError("GOAT_UPDATE_CODE_SIGNATURE_INVALID");
}
