import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { UpdateError } from "./errors.js";
import { runEngineHealthCheck, type HealthCommandRunner } from "./health.js";

test("health check executes only absolute candidate with version argument and empty cwd", async (context) => {
  const executablePath = await fixtureExecutable(context);
  let observed = false;
  const run: HealthCommandRunner = (command, args, options) => {
    observed = true;
    assert.equal(command, executablePath);
    assert.deepEqual(args, ["--version"]);
    assert.equal(options.shell, false);
    assert.equal(options.timeoutMs, 10_000);
    assert.equal(options.maxBufferBytes, 8 * 1024);
    assert.match(path.basename(options.cwd), /^goat-health-/);
    assert.equal(options.environment.GOAT_ACCESS_TOKEN, undefined);
    assert.equal(options.environment.GITHUB_TOKEN, undefined);
    assert.equal(options.environment.HOME, undefined);
    return { status: 0, stdout: "0.4.0\n", stderr: "" };
  };
  await runEngineHealthCheck({
    executablePath,
    expectedVersion: "0.4.0",
    platform: "win32",
    runCommand: run,
  });
  assert.equal(observed, true);
});

test("macOS health environment is fixed and credential-free", async (context) => {
  const executablePath = await fixtureExecutable(context);
  await runEngineHealthCheck({
    executablePath,
    expectedVersion: "0.4.0",
    platform: "darwin",
    runCommand: (_command, _args, options) => {
      assert.deepEqual(options.environment, {
        HOME: "/var/empty",
        LANG: "C",
        LC_ALL: "C",
        PATH: "/usr/bin:/bin",
        TMPDIR: "/tmp",
      });
      return { status: 0, stdout: "0.4.0", stderr: "" };
    },
  });
});

test("wrong output, extra lines, stderr, failure, timeout, and oversized output reject candidate", async (context) => {
  const executablePath = await fixtureExecutable(context);
  const results = [
    { status: 0, stdout: "0.4.1\n", stderr: "" },
    { status: 0, stdout: "0.4.0\nextra\n", stderr: "" },
    { status: 0, stdout: "0.4.0\n", stderr: "warning" },
    { status: 3, stdout: "0.4.0\n", stderr: "" },
    {
      status: null,
      signal: "SIGTERM" as NodeJS.Signals,
      stdout: "",
      stderr: "",
      error: Object.assign(new Error("timed out"), { code: "ETIMEDOUT" }),
    },
    { status: 0, stdout: "x".repeat(8 * 1024 + 1), stderr: "" },
  ];
  for (const [index, result] of results.entries()) {
    await context.test(String(index), async () => {
      await assert.rejects(
        runEngineHealthCheck({
          executablePath,
          expectedVersion: "0.4.0",
          platform: "win32",
          runCommand: () => result,
        }),
        isUpdateError("GOAT_UPDATE_HEALTH_CHECK_FAILED"),
      );
    });
  }
});

test("relative, missing, and linked executables are rejected before execution", async (context) => {
  const executablePath = await fixtureExecutable(context);
  let called = false;
  const runner: HealthCommandRunner = () => {
    called = true;
    return { status: 0, stdout: "0.4.0\n", stderr: "" };
  };
  for (const hostile of ["relative-engine", `${executablePath}-missing`]) {
    await assert.rejects(
      runEngineHealthCheck({
        executablePath: hostile,
        expectedVersion: "0.4.0",
        platform: "win32",
        runCommand: runner,
      }),
      isUpdateError("GOAT_UPDATE_HEALTH_CHECK_FAILED"),
    );
  }
  assert.equal(called, false);
});

test("invalid expected version cannot weaken output matching", async (context) => {
  const executablePath = await fixtureExecutable(context);
  await assert.rejects(
    runEngineHealthCheck({
      executablePath,
      expectedVersion: "0.4.0\nattacker",
      platform: "win32",
      runCommand: () => ({
        status: 0,
        stdout: "0.4.0\nattacker",
        stderr: "",
      }),
    }),
    isUpdateError("GOAT_UPDATE_HEALTH_CHECK_FAILED"),
  );
});

async function fixtureExecutable(context: test.TestContext): Promise<string> {
  const root = await mkdtemp(path.join(os.tmpdir(), "goat-health-fixture-"));
  context.after(() => rm(root, { recursive: true, force: true }));
  const executablePath = path.join(root, "goat-engine.exe");
  await writeFile(executablePath, "TEST-ONLY executable");
  return executablePath;
}

function isUpdateError(code: UpdateError["code"]): (error: unknown) => boolean {
  return (error) => error instanceof UpdateError && error.code === code;
}
