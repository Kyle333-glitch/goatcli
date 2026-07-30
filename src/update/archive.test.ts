import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  buildEntryLocalBytes,
  buildTestZip,
  type TestZipEntry,
  type TestZipOptions,
} from "../../test/v0.4.0-update/zip-fixture.js";
import {
  extractVerifiedArchive,
  finalizeStagedPermissions,
  verifyStagedArchive,
} from "./archive.js";
import { disposeHeldArtifact, type HeldVerifiedArtifact } from "./download.js";
import { UpdateError } from "./errors.js";
import {
  expectedArchivePaths,
  type AuthenticatedTarget,
  type SignedContentEntry,
  type UpdatePlatform,
} from "./schema.js";
import {
  cleanupUpdateTransaction,
  createExclusiveTemporaryFile,
  createUpdateTransactionPaths,
} from "./temporary.js";

test("authenticated ZIP is preflighted completely before allowlisted extraction", async (context) => {
  const fixture = await archiveFixture(context, validEntries());
  const staged = await extractVerifiedArchive(
    fixture.artifact,
    fixture.target,
    fixture.transaction,
  );
  assert.match(staged.treeSha256, /^[a-f0-9]{64}$/);
  for (const content of fixture.target.custom.contents) {
    const file = path.join(staged.root, ...content.path.split("/"));
    assert.equal((await stat(file)).mode & 0o111, 0);
  }
  const finalized = await finalizeStagedPermissions(staged);
  assert.equal(
    await verifyStagedArchive(finalized.root, finalized.target, true),
    finalized.treeSha256,
  );
});

test("parentTraversalEntryIsRejectedBeforeExtraction", async (context) => {
  await assertPathRejected(context, "../outside-engine");
});

test("absoluteAndWindowsPathFormsAreRejectedBeforeExtraction", async (context) => {
  for (const hostile of [
    "/absolute/engine",
    "C:/absolute/engine.exe",
    "C:relative-engine.exe",
    "\\\\server\\share\\engine.exe",
    "bin\\engine.exe",
    "bin/../../engine.exe",
    "NUL",
    "bin/con.txt",
    "bin/trailing.",
    "bin/com0",
    "bin/COM10.txt",
    "bin/clock$",
    "bin/conin$",
    "bin/conout$",
  ]) {
    await context.test(hostile, async (subtest) => {
      await assertPathRejected(subtest, hostile);
    });
  }
});

test("escapingSymlinkIsRejected", async (context) => {
  const entries = validEntries();
  entries[0] = { ...entries[0]!, unixMode: 0o120777 };
  const fixture = await archiveFixture(context, entries);
  await assertArchiveRejected(fixture, "GOAT_UPDATE_ARCHIVE_ENTRY_UNSAFE");
});

test("escapingHardLinkIsRejected", async (context) => {
  const entries = validEntries();
  entries[0] = {
    ...entries[0]!,
    centralExtra: Buffer.from([0x0d, 0x00, 0x00, 0x00]),
    localExtra: Buffer.from([0x0d, 0x00, 0x00, 0x00]),
  };
  const fixture = await archiveFixture(context, entries);
  await assertArchiveRejected(fixture, "GOAT_UPDATE_ARCHIVE_ENTRY_UNSAFE");
});

test("specialOrUnexpectedEntryTypesAreRejected", async (context) => {
  for (const unixMode of [0o020666, 0o010666, 0o140666]) {
    await context.test(unixMode.toString(8), async (subtest) => {
      const entries = validEntries();
      entries[0] = { ...entries[0]!, unixMode };
      const fixture = await archiveFixture(subtest, entries);
      await assertArchiveRejected(fixture, "GOAT_UPDATE_ARCHIVE_ENTRY_UNSAFE");
    });
  }
});

test("duplicateNormalizedPathsAreRejected", async (context) => {
  const entries = validEntries();
  entries[1] = { ...entries[1]!, name: entries[0]!.name.toLowerCase() };
  const fixture = await archiveFixture(context, entries);
  await assertArchiveRejected(fixture, "GOAT_UPDATE_ARCHIVE_PATH_UNSAFE");
});

test("archiveResourceLimitViolationIsRejectedSafely", async (context) => {
  const tooMany = Array.from({ length: 33 }, (_, index) => ({
    name: `file-${index}.txt`,
    data: Buffer.from("x"),
  }));
  const countFixture = await archiveFixture(context, tooMany);
  await assertArchiveRejected(countFixture, "GOAT_UPDATE_ARCHIVE_LIMIT");

  const largeEntries = validEntries();
  largeEntries[0] = { ...largeEntries[0]!, data: Buffer.alloc(64) };
  const sizeFixture = await archiveFixture(context, largeEntries);
  await assert.rejects(
    extractVerifiedArchive(
      sizeFixture.artifact,
      sizeFixture.target,
      sizeFixture.transaction,
      {
        maxEntries: 32,
        maxSingleExpandedBytes: 32,
        maxTotalExpandedBytes: 256,
        maxCompressionRatio: 100,
      },
    ),
    isArchiveLimitOrUnsafe,
  );
  assert.deepEqual(await readdir(sizeFixture.transaction.stagingRoot), []);

  const bombEntries = validEntries();
  bombEntries[0] = {
    ...bombEntries[0]!,
    data: Buffer.alloc(32 * 1024),
    method: 8,
  };
  const ratioFixture = await archiveFixture(context, bombEntries);
  await assertArchiveRejected(ratioFixture, "GOAT_UPDATE_ARCHIVE_ENTRY_UNSAFE");
});

test("total expanded bytes are bounded independently of per-entry limits", async (context) => {
  const entries = Array.from({ length: 5 }, (_, index) => ({
    name: `file-${index}.txt`,
    data: Buffer.alloc(100),
  }));
  const fixture = await archiveFixture(context, entries, undefined, {
    maxEntries: 8,
    maxSingleExpandedBytes: 128,
    maxTotalExpandedBytes: 499,
    maxCompressionRatio: 100,
  });
  await assertArchiveRejected(fixture, "GOAT_UPDATE_ARCHIVE_LIMIT");
});

test("entry count guard is discriminated from signed-manifest mismatch", async (context) => {
  const entries = Array.from({ length: 6 }, (_, index) => ({
    name: `file-${index}.txt`,
    data: Buffer.from("x"),
  }));
  const fixture = await archiveFixture(context, entries, undefined, {
    maxEntries: 4,
    maxSingleExpandedBytes: 16,
    maxTotalExpandedBytes: 256,
    maxCompressionRatio: 100,
  });
  await assertArchiveRejected(fixture, "GOAT_UPDATE_ARCHIVE_LIMIT");
});

test("compression ratio is bounded after preflight", async (context) => {
  const entries: import("../../test/v0.4.0-update/zip-fixture.js").TestZipEntry[] =
    [{ name: "sparse.bin", data: Buffer.alloc(10_000, 0x00), method: 8 }];
  const fixture = await archiveFixture(context, entries, undefined, {
    maxEntries: 8,
    maxSingleExpandedBytes: 20_000,
    maxTotalExpandedBytes: 20_000,
    maxCompressionRatio: 2,
  });
  await assert.rejects(
    extractVerifiedArchive(
      fixture.artifact,
      fixture.target,
      fixture.transaction,
      fixture.limits,
    ),
    isArchiveLimitOrUnsafe,
  );
  assert.deepEqual(await readdir(fixture.transaction.stagingRoot), []);
});

test("data descriptors, prefix/suffix data, comments, and local mismatches are rejected", async (context) => {
  const cases: readonly {
    readonly name: string;
    readonly mutate?: (entries: TestZipEntry[]) => void;
    readonly options?: TestZipOptions;
  }[] = [
    {
      name: "data-descriptor",
      mutate: (entries) => {
        entries[0] = { ...entries[0]!, flags: 0x0808 };
      },
    },
    { name: "prefix", options: { prefix: Buffer.from("hidden") } },
    { name: "suffix", options: { suffix: Buffer.from("hidden") } },
    { name: "comment", options: { comment: Buffer.from("hidden") } },
    {
      name: "local-name-mismatch",
      mutate: (entries) => {
        entries[0] = { ...entries[0]!, localName: "different.txt" };
      },
    },
  ];
  for (const hostile of cases) {
    await context.test(hostile.name, async (subtest) => {
      const entries = validEntries();
      hostile.mutate?.(entries);
      const fixture = await archiveFixture(subtest, entries, hostile.options);
      await assert.rejects(
        extractVerifiedArchive(
          fixture.artifact,
          fixture.target,
          fixture.transaction,
        ),
        (error: unknown) => error instanceof UpdateError,
      );
      assert.deepEqual(await readdir(fixture.transaction.stagingRoot), []);
    });
  }
});

test("overlappingEntryArchiveIsRejected (zip-overlap attack)", async (context) => {
  // The zip-overlap attack: entry A's data region contains a valid local
  // file header + payload for entry B. Entry B's central-directory entry
  // points its local-header offset into A's data range. A naive extractor
  // that reads entries by central-directory offset would decode two
  // different files from overlapping byte ranges. GOAT's contiguous-range
  // preflight rejects this because B's localStart falls inside A's
  // [localStart, dataEnd) range, breaking the contiguity invariant.
  const entryAName = "file-a.txt";
  const entryBName = "file-b.txt";
  const entryBData = Buffer.from("file-b-payload");
  const entryBLocal = buildEntryLocalBytes({
    name: entryBName,
    data: entryBData,
    method: 0,
  });
  const entryAData = entryBLocal;
  const entryALocalHeaderSize = 30 + Buffer.from(entryAName, "utf8").byteLength;
  const entries: TestZipEntry[] = [
    { name: entryAName, data: entryAData, method: 0 },
    {
      name: entryBName,
      data: entryBData,
      method: 0,
      localOffset: entryALocalHeaderSize,
      includeLocal: false,
    },
  ];
  const archive = buildTestZip(entries);
  const contents: SignedContentEntry[] = [
    {
      path: entryAName,
      type: "regular-file",
      length: entryAData.byteLength,
      sha256: sha256(entryAData),
      mode: 420,
    },
    {
      path: entryBName,
      type: "regular-file",
      length: entryBData.byteLength,
      sha256: sha256(entryBData),
      mode: 420,
    },
  ];
  const target: AuthenticatedTarget = {
    targetPath: "goat-engine/stable/0.4.0/win32-x64/goat-engine.zip",
    length: archive.byteLength,
    sha256: sha256(archive),
    custom: {
      goatUpdateSchema: 1,
      product: "GOAT",
      component: "goat-engine",
      productVersion: "0.4.0",
      goatEngineVersion: "0.4.0",
      openCodeBaseline: "1.17.11",
      releaseSequence: 1,
      channel: "stable",
      platform: "win32",
      architecture: "x64",
      cpuFeatures: [],
      artifactFormat: "goat-engine-zip-v1",
      launcherCompatibility: {
        minInclusive: "0.4.0",
        maxExclusive: "0.5.0",
      },
      engineProtocolCompatibility: {
        launchContract: "0.0.6",
        privacyActivation: "GOATIPC2",
        authenticatedFrame: "GOATIPC1",
      },
      innerManifestSchema: 2,
      codeSigning: {
        scheme: "authenticode-sha256",
        identityId: "test-only-windows",
      },
      contents,
    },
  };
  const appData = await mkdtemp(
    path.join(await realpath(os.tmpdir()), "goat-overlap-test-"),
  );
  const transaction = await createUpdateTransactionPaths(appData);
  const temporary = await createExclusiveTemporaryFile(transaction);
  await temporary.handle.writeFile(archive);
  await temporary.handle.sync();
  const stats = await temporary.handle.stat();
  const artifact: HeldVerifiedArtifact = {
    path: temporary.path,
    handle: temporary.handle,
    length: archive.byteLength,
    sha256: sha256(archive),
    device: stats.dev,
    inode: stats.ino,
  };
  context.after(async () => {
    await disposeHeldArtifact(artifact);
    await cleanupUpdateTransaction(transaction).catch(() => undefined);
    await rm(appData, { recursive: true, force: true });
  });
  await assert.rejects(
    extractVerifiedArchive(artifact, target, transaction),
    isUpdateError("GOAT_UPDATE_ARCHIVE_INVALID"),
  );
  assert.deepEqual(await readdir(transaction.stagingRoot), []);
});

test("junctionOrReparseEscapeIsRejected where native links are available", async (context) => {
  const fixture = await archiveFixture(context, validEntries());
  const outside = await mkdtemp(
    path.join(await realpath(os.tmpdir()), "goat-outside-test-"),
  );
  context.after(() => rm(outside, { recursive: true, force: true }));
  const sentinel = path.join(outside, "sentinel.txt");
  await writeFile(sentinel, "unchanged");
  try {
    await symlink(
      outside,
      path.join(fixture.transaction.stagingRoot, "bin"),
      process.platform === "win32" ? "junction" : "dir",
    );
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EPERM") {
      context.skip("native junction/symlink creation is not permitted");
      return;
    }
    throw error;
  }
  await assert.rejects(
    extractVerifiedArchive(
      fixture.artifact,
      fixture.target,
      fixture.transaction,
    ),
    isUpdateError("GOAT_UPDATE_TEMPORARY_FILE_UNSAFE"),
  );
  assert.equal(await readFile(sentinel, "utf8"), "unchanged");
});

async function assertPathRejected(
  context: test.TestContext,
  hostilePath: string,
): Promise<void> {
  const entries = validEntries();
  entries[0] = { ...entries[0]!, name: hostilePath };
  const fixture = await archiveFixture(context, entries);
  await assertArchiveRejected(fixture, "GOAT_UPDATE_ARCHIVE_PATH_UNSAFE");
}

async function assertArchiveRejected(
  fixture: Awaited<ReturnType<typeof archiveFixture>>,
  code: UpdateError["code"],
): Promise<void> {
  await assert.rejects(
    extractVerifiedArchive(
      fixture.artifact,
      fixture.target,
      fixture.transaction,
      fixture.limits,
    ),
    isUpdateError(code),
  );
  assert.deepEqual(await readdir(fixture.transaction.stagingRoot), []);
}

async function archiveFixture(
  context: test.TestContext,
  entries: readonly TestZipEntry[],
  options: TestZipOptions = {},
  limits?: import("./archive.js").ArchiveResourceLimits,
) {
  const archive = buildTestZip(entries, options);
  const appData = await mkdtemp(
    path.join(await realpath(os.tmpdir()), "goat-archive-test-"),
  );
  const transaction = await createUpdateTransactionPaths(appData);
  const temporary = await createExclusiveTemporaryFile(transaction);
  await temporary.handle.writeFile(archive);
  await temporary.handle.sync();
  const stats = await temporary.handle.stat();
  const artifact: HeldVerifiedArtifact = {
    path: temporary.path,
    handle: temporary.handle,
    length: archive.length,
    sha256: sha256(archive),
    device: stats.dev,
    inode: stats.ino,
  };
  const target = targetForArchive(archive, entries);
  context.after(async () => {
    await disposeHeldArtifact(artifact);
    await cleanupUpdateTransaction(transaction).catch(() => undefined);
    await rm(appData, { recursive: true, force: true });
  });
  return { artifact, target, transaction, limits };
}

function validEntries(): TestZipEntry[] {
  return expectedArchivePaths(runtimePlatform()).map((entryPath, index) => ({
    name: entryPath,
    data: Buffer.from(`fixture-${index}-${entryPath}`, "utf8"),
    method: index === 0 ? 8 : 0,
  }));
}

function targetForArchive(
  archive: Buffer,
  archiveEntries: readonly TestZipEntry[],
): AuthenticatedTarget {
  const platform = runtimePlatform();
  const dataByPath = new Map(
    archiveEntries.map((entry) => [entry.name, Buffer.from(entry.data)]),
  );
  const contents: SignedContentEntry[] = archiveEntries.map((entry) => {
    const data =
      dataByPath.get(entry.name) ?? Buffer.from(`missing-${entry.name}`);
    return {
      path: entry.name,
      type: "regular-file",
      length: data.length,
      sha256: sha256(data),
      mode: entry.name.startsWith("bin/") ? 493 : 420,
    };
  });
  const architecture = process.arch === "arm64" ? "arm64" : "x64";
  const targetPath = `goat-engine/stable/0.4.0/${platform}-${architecture}/goat-engine.zip`;
  return {
    targetPath,
    length: archive.length,
    sha256: sha256(archive),
    custom: {
      goatUpdateSchema: 1,
      product: "GOAT",
      component: "goat-engine",
      productVersion: "0.4.0",
      goatEngineVersion: "0.4.0",
      openCodeBaseline: "1.17.11",
      releaseSequence: 1,
      channel: "stable",
      platform,
      architecture,
      cpuFeatures: [],
      artifactFormat: "goat-engine-zip-v1",
      launcherCompatibility: {
        minInclusive: "0.4.0",
        maxExclusive: "0.5.0",
      },
      engineProtocolCompatibility: {
        launchContract: "0.0.6",
        privacyActivation: "GOATIPC2",
        authenticatedFrame: "GOATIPC1",
      },
      innerManifestSchema: 2,
      codeSigning:
        platform === "win32"
          ? {
              scheme: "authenticode-sha256",
              identityId: "test-only-windows",
            }
          : {
              scheme: "apple-developer-id",
              identityId: "test-only-apple",
            },
      contents,
    },
  };
}

function runtimePlatform(): UpdatePlatform {
  return process.platform === "darwin" ? "darwin" : "win32";
}

function sha256(value: Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function isArchiveLimitOrUnsafe(error: unknown): boolean {
  return (
    error instanceof UpdateError &&
    (error.code === "GOAT_UPDATE_ARCHIVE_LIMIT" ||
      error.code === "GOAT_UPDATE_ARCHIVE_ENTRY_UNSAFE")
  );
}

function isUpdateError(code: UpdateError["code"]): (error: unknown) => boolean {
  return (error) => error instanceof UpdateError && error.code === code;
}
