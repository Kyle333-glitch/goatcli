import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  createTestBundleTrust,
  createTestUpdateBundle,
  type TestUpdateBundle,
} from "../../test/v0.4.0-update/update-bundle-fixture.js";
import { loadActivationChain } from "./activation-record.js";
import { activateCandidate } from "./activation.js";
import { UpdateError } from "./errors.js";
import { performAutomaticRollback } from "./rollback.js";
import {
  appendUpdaterState,
  initialUpdaterState,
  initializeUpdaterState,
  stateAfterActivation,
  stateAfterAuthentication,
  type LoadedUpdaterState,
} from "./state.js";

test("known-good rollback selects complete prior slot without lowering sequence floors", async (context) => {
  const fixture = await twoInstalledReleases(context);
  const result = await performAutomaticRollback({
    appDataDirectory: fixture.appData,
    state: fixture.state,
    policy: fixture.second.activationPolicy,
    committedAtUnixMs: 300,
  });
  assert.equal(result.activation.record.reason, "automatic-rollback");
  assert.equal(result.activation.record.releaseSequence, 1);
  assert.equal(result.state.record.configuredChannel, "stable");
  assert.equal(result.state.record.maxAuthenticatedReleaseSequence, 2);
  assert.equal(result.state.record.maxActivatedReleaseSequence, 2);
  assert.equal(result.state.record.currentActivationGeneration, 3);
  assert.equal(result.state.record.previousActivationGeneration, 2);
  const chain = await loadActivationChain(
    fixture.appData,
    fixture.first.platform,
    fixture.first.architecture,
  );
  assert.equal(chain.current?.record.releaseSequence, 1);
  assert.equal(chain.current?.record.rollbackSourceGeneration, 1);
});

test("corrupted rollback slot is never activated", async (context) => {
  const fixture = await twoInstalledReleases(context);
  const chainBefore = await loadActivationChain(
    fixture.appData,
    fixture.first.platform,
    fixture.first.architecture,
  );
  const firstExecutable = path.join(
    resultSlotRoot(fixture.appData, chainBefore.records[0]!.record),
    "bin",
    fixture.first.platform === "win32" ? "goat-engine.exe" : "goat-engine",
  );
  await writeFile(firstExecutable, "corrupted rollback material");
  await assert.rejects(
    performAutomaticRollback({
      appDataDirectory: fixture.appData,
      state: fixture.state,
      policy: fixture.second.activationPolicy,
    }),
    isUpdateError("GOAT_UPDATE_ROLLBACK_INVALID"),
  );
  const chainAfter = await loadActivationChain(
    fixture.appData,
    fixture.first.platform,
    fixture.first.architecture,
  );
  assert.equal(chainAfter.records.length, 2);
  assert.equal(chainAfter.current?.record.releaseSequence, 2);
});

test("revoked rollback artifact is refused even when its files are intact", async (context) => {
  const fixture = await twoInstalledReleases(context);
  const firstHash = (
    await loadActivationChain(
      fixture.appData,
      fixture.first.platform,
      fixture.first.architecture,
    )
  ).records[0]!.record.artifactSha256;
  await assert.rejects(
    performAutomaticRollback({
      appDataDirectory: fixture.appData,
      state: fixture.state,
      policy: {
        ...fixture.second.activationPolicy,
        receipt: {
          ...fixture.second.receiptPolicy,
          currentRevocations: {
            goatRevocationSchema: 1,
            revokedKeyIds: [],
            revokedArtifactSha256: [firstHash],
            revokedReleaseSequences: [],
          },
        },
      },
    }),
    isUpdateError("GOAT_UPDATE_ROLLBACK_INVALID"),
  );
});

test("fresh installation without a prior slot refuses automatic rollback", async (context) => {
  const appData = await temporaryAppData(context);
  let state = await initializeUpdaterState(appData, initialUpdaterState());
  const trust = createTestBundleTrust();
  const bundle = await createTestUpdateBundle(context, { appData, trust });
  state = await commitBundle(bundle, state);
  await assert.rejects(
    performAutomaticRollback({
      appDataDirectory: appData,
      state,
      policy: bundle.activationPolicy,
    }),
    isUpdateError("GOAT_UPDATE_ROLLBACK_INVALID"),
  );
});

async function twoInstalledReleases(context: test.TestContext) {
  const appData = await temporaryAppData(context);
  let state = await initializeUpdaterState(appData, initialUpdaterState());
  const trust = createTestBundleTrust();
  const first = await createTestUpdateBundle(context, {
    appData,
    trust,
    channel: "stable",
    releaseSequence: 1,
  });
  state = await commitBundle(first, state);
  const second = await createTestUpdateBundle(context, {
    appData,
    trust,
    channel: "beta",
    releaseSequence: 2,
  });
  state = await commitBundle(second, state);
  return { appData, state, first, second };
}

async function commitBundle(
  bundle: TestUpdateBundle,
  state: LoadedUpdaterState,
): Promise<LoadedUpdaterState> {
  const authenticated = await appendUpdaterState(
    bundle.appData,
    state,
    stateAfterAuthentication(state.record, {
      release: bundle.receipt.release,
      receiptSha256: bundle.receipt.receiptSha256,
    }),
  );
  const activated = await activateCandidate({
    appDataDirectory: bundle.appData,
    staged: bundle.staged,
    receiptSha256: bundle.receipt.receiptSha256,
    policy: bundle.activationPolicy,
  });
  return appendUpdaterState(
    bundle.appData,
    authenticated,
    stateAfterActivation(authenticated.record, {
      activationGeneration: activated.activation.record.generation,
      release: bundle.receipt.release,
      receiptSha256: bundle.receipt.receiptSha256,
    }),
  );
}

function resultSlotRoot(
  appData: string,
  record: {
    readonly channel: string;
    readonly platform: string;
    readonly architecture: string;
    readonly slotName: string;
  },
): string {
  return path.join(
    appData,
    "engines",
    record.channel,
    `${record.platform}-${record.architecture}`,
    "releases",
    record.slotName,
  );
}

async function temporaryAppData(context: test.TestContext): Promise<string> {
  const root = await mkdtemp(path.join(os.tmpdir(), "goat-rollback-test-"));
  context.after(() => rm(root, { recursive: true, force: true }));
  return root;
}

function isUpdateError(code: UpdateError["code"]): (error: unknown) => boolean {
  return (error) => error instanceof UpdateError && error.code === code;
}
