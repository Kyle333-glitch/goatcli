import assert from "node:assert/strict";
import {
  lstat,
  mkdir,
  readFile,
  readdir,
  rename,
  writeFile,
} from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import {
  createTestBundleTrust,
  createTestUpdateBundle,
} from "../../test/v0.4.0-update/update-bundle-fixture.js";
import { loadActivationChain, slotRoot } from "./activation-record.js";
import {
  activateCandidate,
  cleanupSupersededSlots,
  validateInstalledActivation,
} from "./activation.js";
import { verifyStagedArchive } from "./archive.js";
import { UpdateError } from "./errors.js";
import { recoverInstallation } from "./recovery.js";

test("verified candidate moves to a unique immutable slot before activation record commit", async (context) => {
  const bundle = await createTestUpdateBundle(context);
  const transitions: string[] = [];
  const activated = await activateCandidate({
    appDataDirectory: bundle.appData,
    staged: bundle.staged,
    receiptSha256: bundle.receipt.receiptSha256,
    policy: bundle.activationPolicy,
    committedAtUnixMs: 100,
    observer: {
      preparedRollback: () => {
        transitions.push("prepare-rollback");
      },
      preparedActivation: () => {
        transitions.push("prepare-activation");
      },
      provisionalSlotPlaced: () => {
        transitions.push("place-provisional-slot");
      },
      provisionalSlotValidated: () => {
        transitions.push("validate-provisional-slot");
      },
      activationCommitted: () => {
        transitions.push("commit-activation");
      },
    },
  });
  assert.deepEqual(transitions, [
    "prepare-rollback",
    "prepare-activation",
    "place-provisional-slot",
    "validate-provisional-slot",
    "commit-activation",
  ]);
  assert.equal(activated.activation.record.generation, 1);
  assert.equal(activated.activation.record.releaseSequence, 1);
  assert.equal(activated.activation.record.channel, "stable");
  assert.equal(activated.activation.record.reason, "update");
  assert.equal(
    activated.slotRoot,
    slotRoot(bundle.appData, activated.activation.record),
  );
  assert.equal(
    await verifyStagedArchive(activated.slotRoot, bundle.receipt.target, true),
    activated.activation.record.treeSha256,
  );
  const validated = await validateInstalledActivation(
    bundle.appData,
    activated.activation,
    bundle.activationPolicy,
  );
  assert.equal(validated.activation.sha256, activated.activation.sha256);
  await assert.rejects(lstat(bundle.staged.root), { code: "ENOENT" });
});

test("health failure leaves old installation complete and candidate unselected", async (context) => {
  const trust = createTestBundleTrust();
  const first = await createTestUpdateBundle(context, {
    trust,
    channel: "stable",
    releaseSequence: 1,
  });
  const active = await activateCandidate({
    appDataDirectory: first.appData,
    staged: first.staged,
    receiptSha256: first.receipt.receiptSha256,
    policy: first.activationPolicy,
  });
  const beforeBytes = await readFile(active.candidate.executablePath);

  const second = await createTestUpdateBundle(context, {
    appData: first.appData,
    trust,
    channel: "beta",
    releaseSequence: 2,
    healthSucceeds: false,
  });
  await assert.rejects(
    activateCandidate({
      appDataDirectory: second.appData,
      staged: second.staged,
      receiptSha256: second.receipt.receiptSha256,
      policy: second.activationPolicy,
    }),
    isUpdateError("GOAT_UPDATE_HEALTH_CHECK_FAILED"),
  );
  const chain = await loadActivationChain(
    first.appData,
    first.platform,
    first.architecture,
  );
  assert.equal(chain.records.length, 1);
  assert.equal(chain.current?.sha256, active.activation.sha256);
  assert.deepEqual(
    await readFile(active.candidate.executablePath),
    beforeBytes,
  );
  await validateInstalledActivation(
    first.appData,
    active.activation,
    first.activationPolicy,
  );
  const betaReleases = path.join(
    first.appData,
    "engines",
    "beta",
    `${first.platform}-${first.architecture}`,
    "releases",
  );
  assert.equal((await readdir(betaReleases)).length, 1);
});

test("code-signing failure never commits or executes candidate health check", async (context) => {
  const bundle = await createTestUpdateBundle(context, {
    signingSucceeds: false,
  });
  let healthRan = false;
  await assert.rejects(
    activateCandidate({
      appDataDirectory: bundle.appData,
      staged: bundle.staged,
      receiptSha256: bundle.receipt.receiptSha256,
      policy: {
        ...bundle.activationPolicy,
        runHealthCommand: () => {
          healthRan = true;
          return {
            status: 0,
            stdout: `${bundle.productVersion}\n`,
            stderr: "",
          };
        },
      },
    }),
    isUpdateError("GOAT_UPDATE_CODE_SIGNATURE_INVALID"),
  );
  assert.equal(healthRan, false);
  assert.equal(
    (
      await loadActivationChain(
        bundle.appData,
        bundle.platform,
        bundle.architecture,
      )
    ).current,
    null,
  );
});

test("post-validation provisional-slot substitution cannot create an activation for unverified bytes", async (context) => {
  const trust = createTestBundleTrust();
  const first = await createTestUpdateBundle(context, {
    trust,
    releaseSequence: 1,
  });
  const firstActivated = await activateCandidate({
    appDataDirectory: first.appData,
    staged: first.staged,
    receiptSha256: first.receipt.receiptSha256,
    policy: first.activationPolicy,
  });
  const firstExecutableBytes = await readFile(
    firstActivated.candidate.executablePath,
  );

  const second = await createTestUpdateBundle(context, {
    appData: first.appData,
    trust,
    channel: "beta",
    releaseSequence: 2,
  });
  const executableRelativePath =
    second.platform === "win32" ? "bin/goat-engine.exe" : "bin/goat-engine";
  const maliciousBytes = Buffer.from(
    second.fileBytes.get(executableRelativePath)!,
  );
  maliciousBytes[0] ^= 0xff;
  let substitutionAttempted = false;
  let candidateRoot = "";

  class SubstitutionBlocked extends Error {
    constructor(cause: unknown) {
      super("The filesystem blocked both replacement attempts", { cause });
    }
  }

  await assert.rejects(
    activateCandidate({
      appDataDirectory: second.appData,
      staged: second.staged,
      receiptSha256: second.receipt.receiptSha256,
      policy: second.activationPolicy,
      transactionId: "9".repeat(32),
      observer: {
        provisionalSlotValidated: async (slotName) => {
          substitutionAttempted = true;
          candidateRoot = path.join(
            second.appData,
            "engines",
            second.channel,
            `${second.platform}-${second.architecture}`,
            "releases",
            slotName,
          );
          const executable = path.join(
            candidateRoot,
            ...executableRelativePath.split("/"),
          );
          try {
            await rename(executable, `${executable}.verified-object`);
            await writeFile(executable, maliciousBytes, { flag: "wx" });
          } catch (replacementError) {
            try {
              // Windows commonly denies the pathname rename while the verified
              // handle is open. An in-place same-length mutation must also be
              // detected by the final descriptor hash and metadata checks.
              await writeFile(executable, maliciousBytes);
            } catch (mutationError) {
              throw new SubstitutionBlocked(
                new AggregateError([replacementError, mutationError]),
              );
            }
          }
        },
      },
    }),
    (error) =>
      error instanceof SubstitutionBlocked ||
      (error instanceof UpdateError &&
        error.code === "GOAT_UPDATE_ARCHIVE_CONTENT_MISMATCH"),
  );

  assert.equal(substitutionAttempted, true);
  const chain = await loadActivationChain(
    first.appData,
    first.platform,
    first.architecture,
  );
  assert.equal(chain.records.length, 1);
  assert.equal(chain.current?.sha256, firstActivated.activation.sha256);
  assert.equal(
    chain.records.some(
      (activation) =>
        activation.record.artifactSha256 === second.receipt.target.sha256,
    ),
    false,
  );
  const stillActive = await validateInstalledActivation(
    first.appData,
    firstActivated.activation,
    first.activationPolicy,
  );
  assert.deepEqual(
    await readFile(stillActive.candidate.executablePath),
    firstExecutableBytes,
  );

  await recoverInstallation({
    appDataDirectory: first.appData,
    policy: second.activationPolicy,
  });
  assert.ok(candidateRoot);
  await assert.rejects(lstat(candidateRoot), { code: "ENOENT" });
});

test("existing destination cannot be reused as a candidate slot", async (context) => {
  const bundle = await createTestUpdateBundle(context);
  const slotName = `${bundle.releaseSequence}-${bundle.productVersion}-${bundle.receipt.target.sha256.slice(0, 12)}`;
  const destination = path.join(
    bundle.appData,
    "engines",
    bundle.channel,
    `${bundle.platform}-${bundle.architecture}`,
    "releases",
    slotName,
  );
  await mkdir(destination, { recursive: true });
  await writeFile(path.join(destination, "attacker"), "do not reuse");
  await assert.rejects(
    activateCandidate({
      appDataDirectory: bundle.appData,
      staged: bundle.staged,
      receiptSha256: bundle.receipt.receiptSha256,
      policy: bundle.activationPolicy,
    }),
    isUpdateError("GOAT_UPDATE_ACTIVATION_FAILED"),
  );
  assert.equal(
    (
      await loadActivationChain(
        bundle.appData,
        bundle.platform,
        bundle.architecture,
      )
    ).current,
    null,
  );
  assert.equal(
    await readFile(path.join(destination, "attacker"), "utf8"),
    "do not reuse",
  );
});

test("corrupted current installation is refused as rollback before candidate placement", async (context) => {
  const trust = createTestBundleTrust();
  const first = await createTestUpdateBundle(context, { trust });
  const active = await activateCandidate({
    appDataDirectory: first.appData,
    staged: first.staged,
    receiptSha256: first.receipt.receiptSha256,
    policy: first.activationPolicy,
  });
  await writeFile(active.candidate.executablePath, "corrupted current engine");
  const second = await createTestUpdateBundle(context, {
    appData: first.appData,
    trust,
    channel: "beta",
    releaseSequence: 2,
  });
  await assert.rejects(
    activateCandidate({
      appDataDirectory: second.appData,
      staged: second.staged,
      receiptSha256: second.receipt.receiptSha256,
      policy: second.activationPolicy,
    }),
    isUpdateError("GOAT_UPDATE_ROLLBACK_INVALID"),
  );
  const chain = await loadActivationChain(
    first.appData,
    first.platform,
    first.architecture,
  );
  assert.equal(chain.records.length, 1);
  assert.ok(await lstat(second.staged.root));
});

test("cleanup retains current plus one known-good prior slot", async (context) => {
  const trust = createTestBundleTrust();
  const first = await createTestUpdateBundle(context, { trust });
  await activateCandidate({
    appDataDirectory: first.appData,
    staged: first.staged,
    receiptSha256: first.receipt.receiptSha256,
    policy: first.activationPolicy,
  });
  const second = await createTestUpdateBundle(context, {
    appData: first.appData,
    trust,
    channel: "beta",
    releaseSequence: 2,
  });
  await activateCandidate({
    appDataDirectory: second.appData,
    staged: second.staged,
    receiptSha256: second.receipt.receiptSha256,
    policy: second.activationPolicy,
  });
  const third = await createTestUpdateBundle(context, {
    appData: first.appData,
    trust,
    channel: "development",
    releaseSequence: 3,
  });
  await activateCandidate({
    appDataDirectory: third.appData,
    staged: third.staged,
    receiptSha256: third.receipt.receiptSha256,
    policy: third.activationPolicy,
  });
  const chain = await loadActivationChain(
    first.appData,
    first.platform,
    first.architecture,
  );
  assert.equal(chain.records.length, 3);
  assert.deepEqual(
    await cleanupSupersededSlots(
      first.appData,
      chain,
      first.platform,
      first.architecture,
    ),
    [],
  );
  await assert.rejects(
    lstat(slotRoot(first.appData, chain.records[0]!.record)),
    {
      code: "ENOENT",
    },
  );
  assert.ok(await lstat(slotRoot(first.appData, chain.records[1]!.record)));
  assert.ok(await lstat(slotRoot(first.appData, chain.records[2]!.record)));
});

function isUpdateError(code: UpdateError["code"]): (error: unknown) => boolean {
  return (error) => error instanceof UpdateError && error.code === code;
}
