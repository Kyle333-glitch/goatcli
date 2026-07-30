import { randomBytes } from "node:crypto";
import path from "node:path";
import { lstat, readdir, realpath, rename, rm, stat } from "node:fs/promises";
import {
  appendUpdateActivationRecord,
  expectedSlotName,
  loadActivationChain,
  slotRoot,
  type ActivationChain,
  type LoadedActivationRecord,
} from "./activation-record.js";
import {
  finalizeStagedPermissions,
  verifyStagedArchive,
  type StagedArchive,
} from "./archive.js";
import {
  verifyPlatformCodeSignature,
  type ApprovedCodeSigningIdentity,
  type VerificationCommandRunner,
} from "./code-signing.js";
import {
  validateCandidateCompatibility,
  validateCandidateCompatibilityBytes,
  type CandidateCompatibilityPolicy,
  type CompatibleCandidate,
} from "./compatibility.js";
import { ensurePrivateDirectory, syncDirectory } from "./durable.js";
import { UpdateError } from "./errors.js";
import { runEngineHealthCheck, type HealthCommandRunner } from "./health.js";
import {
  loadTargetReceipt,
  type PersistedTargetReceipt,
  type ReceiptVerificationPolicy,
} from "./receipt.js";
import {
  assertHeldVerifiedSlotBound,
  disposeHeldVerifiedSlot,
  openHeldVerifiedSlot,
  type HeldVerifiedSlot,
} from "./slot-seal.js";
import { assertNoLinkOrReparsePath } from "./temporary.js";

export interface ActivationSecurityPolicy {
  readonly receipt: ReceiptVerificationPolicy;
  readonly compatibility: CandidateCompatibilityPolicy;
  readonly approvedCodeSigningIdentities: readonly ApprovedCodeSigningIdentity[];
  readonly runSigningCommand?: VerificationCommandRunner;
  readonly runHealthCommand?: HealthCommandRunner;
}

export interface ActivateCandidateInput {
  readonly appDataDirectory: string;
  readonly staged: StagedArchive;
  readonly receiptSha256: string;
  readonly policy: ActivationSecurityPolicy;
  readonly committedAtUnixMs?: number;
  readonly observer?: ActivationTransactionObserver;
  readonly transactionId?: string;
}

export interface ActivationTransactionObserver {
  preparedRollback?(): void | Promise<void>;
  preparedActivation?(slotName: string): void | Promise<void>;
  provisionalSlotPlaced?(slotName: string): void | Promise<void>;
  provisionalSlotValidated?(
    slotName: string,
    slotSealSha256: string,
  ): void | Promise<void>;
  activationCommitted?(
    activation: LoadedActivationRecord,
  ): void | Promise<void>;
}

export interface ActivatedInstallation {
  readonly activation: LoadedActivationRecord;
  readonly receipt: PersistedTargetReceipt;
  readonly candidate: CompatibleCandidate;
  readonly slotRoot: string;
  readonly priorChain: ActivationChain;
}

export interface ValidatedInstalledActivation {
  readonly activation: LoadedActivationRecord;
  readonly receipt: PersistedTargetReceipt;
  readonly candidate: CompatibleCandidate;
  readonly slotRoot: string;
}

export async function activateCandidate(
  input: ActivateCandidateInput,
): Promise<ActivatedInstallation> {
  const appData = path.resolve(input.appDataDirectory);
  assertCandidatePolicyBinding(input.staged, input.policy);
  const receipt = await loadTargetReceipt(
    appData,
    input.receiptSha256,
    input.policy.receipt,
  );
  assertReceiptMatchesCandidate(receipt, input.staged);
  const priorChain = await loadActivationChain(
    appData,
    input.staged.target.custom.platform,
    input.staged.target.custom.architecture,
  );
  if (priorChain.current) {
    try {
      await validateInstalledActivation(
        appData,
        priorChain.current,
        input.policy,
      );
    } catch (error) {
      throwError("GOAT_UPDATE_ROLLBACK_INVALID", error);
    }
  }
  await input.observer?.preparedRollback?.();

  await verifyStagedArchive(input.staged.root, input.staged.target, false);
  await validateCandidateCompatibility(
    input.staged,
    input.policy.compatibility,
  );
  const finalized = await finalizeStagedPermissions(input.staged);
  const releaseDirectory = await ensureReleaseDirectory(appData, finalized);
  const slotName = expectedSlotName({
    releaseSequence: finalized.target.custom.releaseSequence,
    goatEngineVersion: finalized.target.custom.goatEngineVersion,
    artifactSha256: finalized.target.sha256,
  });
  const transactionId = normalizeTransactionId(input.transactionId);
  const provisionalRoot = path.join(
    releaseDirectory,
    `.pending-${transactionId}-${slotName}`,
  );
  const destination = path.join(releaseDirectory, slotName);

  // J10 is durable before any slot mutation, so recovery can name both paths.
  await input.observer?.preparedActivation?.(slotName);
  await assertAbsent(provisionalRoot);
  await assertAbsent(destination);
  await assertSameVolume(finalized.root, releaseDirectory);
  await assertNoLinkOrReparsePath(appData, finalized.root);
  await assertNoLinkOrReparsePath(appData, releaseDirectory);
  await renameAndSync(finalized.root, provisionalRoot, releaseDirectory);
  // Node's Windows handles do not permit a directory rename while its files
  // are open. Move to the unique final pathname before opening the handles;
  // J10 still names both paths if either durable rename is interrupted.
  await renameAndSync(provisionalRoot, destination, releaseDirectory);
  await input.observer?.provisionalSlotPlaced?.(slotName);

  const placed: StagedArchive = {
    root: destination,
    target: finalized.target,
    treeSha256: finalized.treeSha256,
  };
  let held: HeldVerifiedSlot | undefined;
  let activationResult: ActivatedInstallation | undefined;
  let primaryFailure: unknown;
  try {
    held = await openHeldVerifiedSlot(destination, finalized.target);
    if (held.treeSha256 !== finalized.treeSha256) {
      throwError("GOAT_UPDATE_ACTIVATION_FAILED");
    }
    const compatible = validateCandidateCompatibilityBytes(
      placed,
      held.manifestBytes,
      input.policy.compatibility,
    );
    if (compatible.manifestSha256 !== held.manifestSha256) {
      throwError("GOAT_UPDATE_ACTIVATION_FAILED");
    }

    await assertHeldVerifiedSlotBound(held, destination);
    const activatedExecutablePath = boundExecutablePath(held);
    await verifyPlatformCodeSignature({
      platform: finalized.target.custom.platform,
      executablePath: activatedExecutablePath,
      targetPolicy: finalized.target.custom.codeSigning,
      approvedIdentities: input.policy.approvedCodeSigningIdentities,
      runCommand: input.policy.runSigningCommand,
    });
    await assertHeldVerifiedSlotBound(held, destination);
    await runEngineHealthCheck({
      executablePath: activatedExecutablePath,
      expectedVersion: compatible.manifest.goatEngineVersion,
      platform: finalized.target.custom.platform,
      runCommand: input.policy.runHealthCommand,
    });
    await assertHeldVerifiedSlotBound(held, destination);

    // J12 binds the journal to the held objects before activation commitment.
    await input.observer?.provisionalSlotValidated?.(
      slotName,
      held.slotSealSha256,
    );
    await assertHeldVerifiedSlotBound(held, destination);

    const committedCandidate = rebaseCandidate(compatible, destination);
    const activation = await appendUpdateActivationRecord(
      appData,
      {
        channel: finalized.target.custom.channel,
        platform: finalized.target.custom.platform,
        architecture: finalized.target.custom.architecture,
        releaseSequence: finalized.target.custom.releaseSequence,
        productVersion: finalized.target.custom.productVersion,
        goatEngineVersion: finalized.target.custom.goatEngineVersion,
        artifactSha256: finalized.target.sha256,
        slotName,
        slotSealSha256: held.slotSealSha256,
        treeSha256: held.treeSha256,
        receiptSha256: receipt.receiptSha256,
        manifestSha256: compatible.manifestSha256,
      },
      input.committedAtUnixMs,
    );
    await assertHeldVerifiedSlotBound(held, destination);
    await input.observer?.activationCommitted?.(activation);
    await assertHeldVerifiedSlotBound(held, destination);
    activationResult = {
      activation,
      receipt,
      candidate: committedCandidate,
      slotRoot: destination,
      priorChain,
    };
  } catch (error) {
    primaryFailure = error;
  }

  let disposalFailure: unknown;
  if (held) {
    try {
      await disposeHeldVerifiedSlot(held);
    } catch (error) {
      disposalFailure = error;
    }
  }

  if (primaryFailure !== undefined) throw primaryFailure;
  if (disposalFailure !== undefined) {
    throw new UpdateError("GOAT_UPDATE_ACTIVATION_FAILED", {
      cause: disposalFailure,
    });
  }
  return activationResult!;
}

export async function validateInstalledActivation(
  appDataDirectory: string,
  activation: LoadedActivationRecord,
  policy: ActivationSecurityPolicy,
): Promise<ValidatedInstalledActivation> {
  const record = activation.record;
  if (
    record.platform !== policy.receipt.platform ||
    record.architecture !== policy.receipt.architecture ||
    record.platform !== policy.compatibility.platform ||
    record.architecture !== policy.compatibility.architecture
  ) {
    throwError("GOAT_UPDATE_ROLLBACK_INVALID");
  }
  const receipt = await loadTargetReceipt(
    appDataDirectory,
    record.receiptSha256,
    policy.receipt,
  );
  const target = receipt.target;
  if (
    target.custom.channel !== record.channel ||
    target.custom.releaseSequence !== record.releaseSequence ||
    target.custom.productVersion !== record.productVersion ||
    target.custom.goatEngineVersion !== record.goatEngineVersion ||
    target.sha256 !== record.artifactSha256
  ) {
    throwError("GOAT_UPDATE_ROLLBACK_INVALID");
  }
  const root = slotRoot(appDataDirectory, record);
  await assertNoLinkOrReparsePath(path.resolve(appDataDirectory), root);
  const staged: StagedArchive = {
    root,
    target,
    treeSha256: record.treeSha256,
  };
  let held: HeldVerifiedSlot | undefined;
  let validationResult: ValidatedInstalledActivation | undefined;
  let primaryFailure: unknown;
  try {
    held = await openHeldVerifiedSlot(root, target);
    if (
      held.treeSha256 !== record.treeSha256 ||
      held.slotSealSha256 !== record.slotSealSha256
    ) {
      throwError("GOAT_UPDATE_ROLLBACK_INVALID");
    }
    const candidate = validateCandidateCompatibilityBytes(
      staged,
      held.manifestBytes,
      policy.compatibility,
    );
    if (
      candidate.manifestSha256 !== record.manifestSha256 ||
      candidate.manifestSha256 !== held.manifestSha256
    ) {
      throwError("GOAT_UPDATE_ROLLBACK_INVALID");
    }
    await assertHeldVerifiedSlotBound(held, root);
    await verifyPlatformCodeSignature({
      platform: record.platform,
      executablePath: boundExecutablePath(held),
      targetPolicy: target.custom.codeSigning,
      approvedIdentities: policy.approvedCodeSigningIdentities,
      runCommand: policy.runSigningCommand,
    });
    await assertHeldVerifiedSlotBound(held, root);
    validationResult = { activation, receipt, candidate, slotRoot: root };
  } catch (error) {
    primaryFailure = error;
  }

  let disposalFailure: unknown;
  if (held) {
    try {
      await disposeHeldVerifiedSlot(held);
    } catch (error) {
      disposalFailure = error;
    }
  }

  if (primaryFailure !== undefined) throw primaryFailure;
  if (disposalFailure !== undefined) {
    throw new UpdateError("GOAT_UPDATE_ROLLBACK_INVALID", {
      cause: disposalFailure,
    });
  }
  return validationResult!;
}

export async function cleanupSupersededSlots(
  appDataDirectory: string,
  chain: ActivationChain,
  platform: "win32" | "darwin",
  architecture: "x64" | "arm64",
): Promise<readonly string[]> {
  const keep = new Set<string>();
  for (const entry of [...chain.records].reverse()) {
    const root = slotRoot(appDataDirectory, entry.record);
    keep.add(path.resolve(root));
    if (keep.size === 2) break;
  }
  const deferred: string[] = [];
  for (const channel of ["stable", "beta", "development"] as const) {
    const releases = path.join(
      path.resolve(appDataDirectory),
      "engines",
      channel,
      `${platform}-${architecture}`,
      "releases",
    );
    let entries;
    try {
      entries = await readdir(releases, { withFileTypes: true });
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") continue;
      throwError("GOAT_UPDATE_ACTIVATION_FAILED", error);
    }
    for (const entry of entries) {
      const candidate = path.resolve(releases, entry.name);
      if (
        !entry.isDirectory() ||
        entry.isSymbolicLink() ||
        !/^\d+-[0-9A-Za-z.-]+-[a-f0-9]{12}$/.test(entry.name)
      ) {
        throwError("GOAT_UPDATE_RECOVERY_REQUIRED");
      }
      if (keep.has(candidate)) continue;
      try {
        await rm(candidate, { recursive: true, force: true, maxRetries: 1 });
      } catch {
        deferred.push(candidate);
      }
    }
  }
  return deferred.sort(asciiCompare);
}

function assertCandidatePolicyBinding(
  staged: StagedArchive,
  policy: ActivationSecurityPolicy,
): void {
  const custom = staged.target.custom;
  if (
    custom.platform !== policy.receipt.platform ||
    custom.architecture !== policy.receipt.architecture ||
    custom.platform !== policy.compatibility.platform ||
    custom.architecture !== policy.compatibility.architecture ||
    policy.receipt.embeddedRootSha256.length !== 64 ||
    policy.compatibility.releasePolicyDigest.length !== 64
  ) {
    throwError("GOAT_UPDATE_COMPATIBILITY_FAILED");
  }
}

function assertReceiptMatchesCandidate(
  receipt: PersistedTargetReceipt,
  staged: StagedArchive,
): void {
  if (
    receipt.target.targetPath !== staged.target.targetPath ||
    receipt.target.length !== staged.target.length ||
    receipt.target.sha256 !== staged.target.sha256 ||
    receipt.target.custom.releaseSequence !==
      staged.target.custom.releaseSequence
  ) {
    throwError("GOAT_UPDATE_METADATA_MISMATCH");
  }
}
function normalizeTransactionId(transactionId: string | undefined): string {
  const normalized = transactionId ?? randomBytes(16).toString("hex");
  if (!/^[a-f0-9]{32}$/.test(normalized)) {
    throwError("GOAT_UPDATE_ACTIVATION_FAILED");
  }
  return normalized;
}

function rebaseCandidate(
  candidate: CompatibleCandidate,
  destination: string,
): CompatibleCandidate {
  return {
    ...candidate,
    staged: {
      ...candidate.staged,
      root: destination,
    },
    executablePath: path.join(
      destination,
      ...candidate.manifest.executablePath.split("/"),
    ),
  };
}

async function renameAndSync(
  source: string,
  destination: string,
  directory: string,
): Promise<void> {
  try {
    await rename(source, destination);
    await syncDirectory(directory, "GOAT_UPDATE_ACTIVATION_FAILED");
  } catch (error) {
    if (error instanceof UpdateError) throw error;
    throwError("GOAT_UPDATE_ACTIVATION_FAILED", error);
  }
}

async function ensureReleaseDirectory(
  appDataDirectory: string,
  staged: StagedArchive,
): Promise<string> {
  const custom = staged.target.custom;
  const tuple = path.join(
    appDataDirectory,
    "engines",
    custom.channel,
    `${custom.platform}-${custom.architecture}`,
  );
  const releases = await ensurePrivateDirectory(
    path.join(tuple, "releases"),
    "GOAT_UPDATE_ACTIVATION_FAILED",
  );
  await ensurePrivateDirectory(
    path.join(tuple, "activations"),
    "GOAT_UPDATE_ACTIVATION_FAILED",
  );
  return releases;
}

async function assertAbsent(target: string): Promise<void> {
  try {
    await lstat(target);
    throwError("GOAT_UPDATE_ACTIVATION_FAILED");
  } catch (error) {
    if (error instanceof UpdateError) throw error;
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
      throwError("GOAT_UPDATE_ACTIVATION_FAILED", error);
    }
  }
}

async function assertSameVolume(
  source: string,
  destinationParent: string,
): Promise<void> {
  try {
    const [sourceStats, destinationStats, sourceCanonical] = await Promise.all([
      lstat(source),
      lstat(destinationParent),
      realpath(source),
    ]);
    const canonicalStats = await lstat(sourceCanonical);
    if (
      !sourceStats.isDirectory() ||
      sourceStats.isSymbolicLink() ||
      !destinationStats.isDirectory() ||
      destinationStats.isSymbolicLink() ||
      sourceStats.dev !== destinationStats.dev ||
      sourceStats.dev !== canonicalStats.dev ||
      sourceStats.ino !== canonicalStats.ino
    ) {
      throwError("GOAT_UPDATE_ACTIVATION_FAILED");
    }
  } catch (error) {
    if (error instanceof UpdateError) throw error;
    throwError("GOAT_UPDATE_ACTIVATION_FAILED", error);
  }
}

function asciiCompare(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function executableEntryPath(held: HeldVerifiedSlot): string {
  return path.join(
    held.originalRoot,
    held.target.custom.platform === "win32"
      ? "bin/goat-engine.exe"
      : "bin/goat-engine",
  );
}

/**
 * Return a path that is bound to the already-verified executable file.
 *
 * On Linux we pass the file descriptor through /proc/${process.pid}/fd so that external
 * verification/health tools operate on the exact kernel object that was
 * validated by the held slot, even if the slot path is swapped between
 * verification and use. On macOS and Windows we keep the regular path: macOS
 * tools such as `codesign` do not reliably accept /dev/fd paths, and on
 * Windows an open handle already prevents replacement of the binary. In all
 * cases the surrounding code calls `assertHeldVerifiedSlotBound` before and
 * after each external command.
 */
function boundExecutablePath(held: HeldVerifiedSlot): string {
  if (process.platform !== "linux") {
    return executableEntryPath(held);
  }

  const expectedRelativePath =
    held.target.custom.platform === "win32"
      ? "bin/goat-engine.exe"
      : "bin/goat-engine";
  const entry = held.entries.find(
    (candidate) => candidate.relativePath === expectedRelativePath,
  );
  if (!entry) {
    throwError("GOAT_UPDATE_ACTIVATION_FAILED");
  }
  const fd = entry.handle.fd;
  if (typeof fd !== "number" || fd < 0) {
    throwError("GOAT_UPDATE_ACTIVATION_FAILED");
  }

  // Use the launcher process's own fd table so external tools (which run as
  // child processes) resolve the path to the file we have opened, not to an
  // fd in their own table.
  return `/proc/${process.pid}/fd/${fd}`;
}

function throwError(code: string, cause?: unknown): never {
  if (cause === undefined) {
    throw new UpdateError(code as any);
  }
  throw new UpdateError(code as any, { cause });
}
