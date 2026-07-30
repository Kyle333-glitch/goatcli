import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { spawn, type ChildProcess } from "node:child_process";
import { once } from "node:events";
import { chmod, mkdtemp, mkdir, open, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import { pathToFileURL } from "node:url";
import { UpdateError } from "./errors.js";
import {
  acquireUpdateLock,
  inspectUpdateLock,
  type UpdateLock,
} from "./lock.js";

test("concurrent updaters allow exactly one owner", async (context) => {
  const appData = await temporaryAppData(context);
  const attempts = await Promise.allSettled([
    acquireUpdateLock(appData, { recoverStaleTransaction: async () => {} }),
    acquireUpdateLock(appData, { recoverStaleTransaction: async () => {} }),
  ]);
  const winner = onlyWinner(attempts);
  assert.equal(
    attempts.filter((result) => result.status === "rejected").length,
    1,
  );
  assert.ok(
    attempts.some(
      (result) =>
        result.status === "rejected" &&
        isUpdateError("GOAT_UPDATE_BUSY")(result.reason),
    ),
  );
  await winner.release();
  assert.equal(await inspectUpdateLock(appData), null);
});

test("stale recovery runs only while the replacement lock is owned", async (context) => {
  const appData = await temporaryAppData(context);
  const stalePid = 1001;
  await seedStaleOwner(appData, stalePid, 10);
  const calls: number[] = [];
  const replacement = await acquireUpdateLock(appData, {
    pid: 1002,
    now: () => 20,
    isProcessAlive: (pid) => pid !== stalePid,
    recoverStaleTransaction: async () => {
      const visibleOwner = await inspectUpdateLock(appData);
      calls.push(visibleOwner!.pid);
      assert.equal(visibleOwner?.pid, 1002);
    },
  });
  assert.deepEqual(calls, [1002]);
  await replacement.release();
});

test("simultaneous stale contenders allow exactly one mutating recovery", async (context) => {
  const appData = await temporaryAppData(context);
  const stalePid = 4001;
  await seedStaleOwner(appData, stalePid, 10);

  let releaseRecovery!: () => void;
  const recoveryGate = new Promise<void>((resolve) => {
    releaseRecovery = resolve;
  });
  let reportRecoveryStarted!: () => void;
  const recoveryStarted = new Promise<void>((resolve) => {
    reportRecoveryStarted = resolve;
  });
  const recoveryOwners: number[] = [];
  let recoveryMutations = 0;
  const recover = async (): Promise<void> => {
    const visibleOwner = await inspectUpdateLock(appData);
    assert.ok(visibleOwner);
    recoveryOwners.push(visibleOwner.pid);
    recoveryMutations += 1;
    reportRecoveryStarted();
    await recoveryGate;
  };

  const attemptsPromise = Promise.allSettled([
    acquireUpdateLock(appData, {
      pid: 4002,
      isProcessAlive: (pid) => pid !== stalePid,
      recoverStaleTransaction: recover,
    }),
    acquireUpdateLock(appData, {
      pid: 4003,
      isProcessAlive: (pid) => pid !== stalePid,
      recoverStaleTransaction: recover,
    }),
  ]);
  await recoveryStarted;
  assert.equal(recoveryMutations, 1);
  releaseRecovery();
  const attempts = await attemptsPromise;
  const winner = onlyWinner(attempts);
  const losers = attempts.filter(
    (result): result is PromiseRejectedResult => result.status === "rejected",
  );
  assert.equal(losers.length, 1);
  assert.ok(isUpdateError("GOAT_UPDATE_BUSY")(losers[0]!.reason));
  assert.deepEqual(recoveryOwners, [winner.owner.pid]);
  assert.equal((await inspectUpdateLock(appData))?.pid, winner.owner.pid);
  await winner.release();
  assert.equal(await inspectUpdateLock(appData), null);
});

test("failed owned recovery releases authority for a safe retry", async (context) => {
  const appData = await temporaryAppData(context);
  const stalePid = 2001;
  await seedStaleOwner(appData, stalePid, 10);
  await assert.rejects(
    acquireUpdateLock(appData, {
      pid: 2002,
      isProcessAlive: (pid) => pid !== stalePid,
      recoverStaleTransaction: async () => {
        throw new UpdateError("GOAT_UPDATE_RECOVERY_REQUIRED");
      },
    }),
    isUpdateError("GOAT_UPDATE_RECOVERY_REQUIRED"),
  );
  assert.equal(await inspectUpdateLock(appData), null);
  let retried = 0;
  const retry = await acquireUpdateLock(appData, {
    pid: 2003,
    recoverStaleTransaction: async () => {
      retried += 1;
      assert.equal((await inspectUpdateLock(appData))?.pid, 2003);
    },
  });
  assert.equal(retried, 1);
  await retry.release();
});

test("release creates reusable available authority and every owner recovers", async (context) => {
  const appData = await temporaryAppData(context);
  const recovered: number[] = [];
  const first = await acquireUpdateLock(appData, {
    pid: 3001,
    recoverStaleTransaction: async () => {
      recovered.push(3001);
    },
  });
  await first.release();
  const second = await acquireUpdateLock(appData, {
    pid: 3002,
    recoverStaleTransaction: async () => {
      recovered.push(3002);
    },
  });
  assert.deepEqual(recovered, [3001, 3002]);
  await second.release();
  await second.release();
  assert.equal(await inspectUpdateLock(appData), null);
});

test("delayed stale claimant cannot overwrite a newer live authority", async (context) => {
  const appData = await temporaryAppData(context);
  const stalePid = 5001;
  await seedStaleOwner(appData, stalePid, 10);
  let releaseClaimant!: () => void;
  const claimantGate = new Promise<void>((resolve) => {
    releaseClaimant = resolve;
  });
  let reportClaimantPaused!: () => void;
  const claimantPaused = new Promise<void>((resolve) => {
    reportClaimantPaused = resolve;
  });
  let loserRecoveryCalls = 0;
  const delayed = acquireUpdateLock(appData, {
    pid: 5002,
    isProcessAlive: (pid) => pid !== stalePid,
    beforeOwnershipClaim: async () => {
      reportClaimantPaused();
      await claimantGate;
    },
    recoverStaleTransaction: async () => {
      loserRecoveryCalls += 1;
    },
  });
  await claimantPaused;

  let winnerRecoveryCalls = 0;
  const winner = await acquireUpdateLock(appData, {
    pid: 5003,
    isProcessAlive: (pid) => pid !== stalePid,
    recoverStaleTransaction: async () => {
      winnerRecoveryCalls += 1;
    },
  });
  releaseClaimant();
  await assert.rejects(delayed, isUpdateError("GOAT_UPDATE_BUSY"));
  assert.equal(loserRecoveryCalls, 0);
  assert.equal(winnerRecoveryCalls, 1);
  assert.equal((await inspectUpdateLock(appData))?.pid, 5003);
  await winner.release();
});

test("a live owner is not displaced", async (context) => {
  const appData = await temporaryAppData(context);
  const held = await acquireUpdateLock(appData, {
    pid: 6001,
    now: () => 1,
    recoverStaleTransaction: async () => {},
  });
  let recovered = false;
  await assert.rejects(
    acquireUpdateLock(appData, {
      pid: 6002,
      now: () => 999_999,
      isProcessAlive: () => false,
      recoverStaleTransaction: async () => {
        recovered = true;
      },
    }),
    isUpdateError("GOAT_UPDATE_BUSY"),
  );
  assert.equal(recovered, false);
  await held.release();
});

test("a child crash releases SQLite ownership for one replacement recovery", async (context) => {
  const appData = await temporaryAppData(context);
  const moduleUrl = pathToFileURL(path.resolve("src/update/lock.ts")).href;
  const script = `
    const { acquireUpdateLock } = await import(process.argv[2]);
    const held = await acquireUpdateLock(process.argv[1], {
      recoverStaleTransaction: async () => {},
    });
    process.stdout.write(JSON.stringify(held.owner) + "\\n");
    await new Promise(() => {});
  `;
  const child = spawn(
    process.execPath,
    [
      "--import",
      "tsx",
      "--input-type=module",
      "--eval",
      script,
      appData,
      moduleUrl,
    ],
    { stdio: ["ignore", "pipe", "pipe"], windowsHide: true },
  );
  context.after(() => stopChild(child));
  const owner = JSON.parse(await firstOutputLine(child)) as {
    readonly pid: number;
  };
  assert.equal(owner.pid, child.pid);
  child.kill();
  await once(child, "exit");

  let recoveryCalls = 0;
  const replacement = await acquireUpdateLock(appData, {
    recoverStaleTransaction: async () => {
      recoveryCalls += 1;
    },
  });
  assert.equal(recoveryCalls, 1);
  await replacement.release();
});

test("a zero-length initialization crash is recoverable", async (context) => {
  const appData = await temporaryAppData(context);
  const updates = path.join(appData, "updates");
  await mkdir(updates, { recursive: true, mode: 0o700 });
  const handle = await open(path.join(updates, "update.lock"), "wx", 0o600);
  await handle.close();
  let recovered = 0;
  const lock = await acquireUpdateLock(appData, {
    recoverStaleTransaction: async () => {
      recovered += 1;
    },
  });
  assert.equal(recovered, 1);
  await lock.release();
});

test("malformed or unexpected SQLite state fails before recovery", async (context) => {
  for (const scenario of [
    "directory",
    "garbage",
    "wrong-schema",
    "extra-schema",
  ] as const) {
    await context.test(scenario, async (subtest) => {
      const appData = await temporaryAppData(subtest);
      const updates = path.join(appData, "updates");
      await mkdir(updates, { recursive: true, mode: 0o700 });
      const lockPath = path.join(updates, "update.lock");
      if (scenario === "directory") {
        await mkdir(lockPath);
      } else if (scenario === "garbage") {
        await writeFile(lockPath, "not-a-sqlite-database", { mode: 0o600 });
      } else if (scenario === "wrong-schema") {
        const database = new DatabaseSync(lockPath);
        database.exec("CREATE TABLE wrong (value INTEGER) STRICT");
        database.close();
      } else {
        const initialized = await acquireUpdateLock(appData, {
          recoverStaleTransaction: async () => {},
        });
        await initialized.release();
        const database = new DatabaseSync(lockPath);
        database.exec("CREATE TABLE unexpected (value INTEGER) STRICT");
        database.close();
      }
      if (process.platform !== "win32" && scenario !== "directory") {
        await chmod(lockPath, 0o600);
      }
      let recovered = false;
      await assert.rejects(
        acquireUpdateLock(appData, {
          recoverStaleTransaction: async () => {
            recovered = true;
          },
        }),
        isUpdateError("GOAT_UPDATE_LOCK_INVALID"),
      );
      assert.equal(recovered, false);
      await assert.rejects(
        inspectUpdateLock(appData),
        isUpdateError("GOAT_UPDATE_LOCK_INVALID"),
      );
    });
  }
});

async function seedStaleOwner(
  appData: string,
  pid: number,
  startedAtUnixMs: number,
): Promise<void> {
  const initialized = await acquireUpdateLock(appData, {
    recoverStaleTransaction: async () => {},
  });
  const lockPath = initialized.path;
  await initialized.release();
  const token = randomBytes(16).toString("hex");
  const database = new DatabaseSync(lockPath);
  database.exec("PRAGMA synchronous = FULL; BEGIN IMMEDIATE");
  const result = database
    .prepare(
      `UPDATE update_lock
       SET authority_token = ?, owner_token = ?, pid = ?, started_at_unix_ms = ?
       WHERE singleton = 1 AND owner_token IS NULL`,
    )
    .run(token, token, pid, startedAtUnixMs);
  assert.equal(Number(result.changes), 1);
  database.exec("COMMIT");
  database.close();
}

function onlyWinner(
  results: readonly PromiseSettledResult<UpdateLock>[],
): UpdateLock {
  const winners = results.filter(
    (result): result is PromiseFulfilledResult<UpdateLock> =>
      result.status === "fulfilled",
  );
  assert.equal(winners.length, 1);
  return winners[0]!.value;
}

async function firstOutputLine(child: ChildProcess): Promise<string> {
  if (!child.stdout) throw new Error("missing child stdout");
  let output = "";
  return new Promise<string>((resolve, reject) => {
    child.stdout!.setEncoding("utf8");
    child.stdout!.on("data", (chunk: string) => {
      output += chunk;
      const newline = output.indexOf("\n");
      if (newline >= 0) resolve(output.slice(0, newline));
    });
    child.once("error", reject);
    child.once("exit", (code) => {
      if (!output.includes("\n"))
        reject(new Error(`lock child exited ${code}`));
    });
  });
}

async function stopChild(child: ChildProcess): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return;
  child.kill();
  await once(child, "exit").catch(() => undefined);
}

async function temporaryAppData(context: test.TestContext): Promise<string> {
  const root = await mkdtemp(path.join(os.tmpdir(), "goat-lock-test-"));
  context.after(() => rm(root, { recursive: true, force: true }));
  return root;
}

function isUpdateError(code: UpdateError["code"]): (error: unknown) => boolean {
  return (error) => error instanceof UpdateError && error.code === code;
}
