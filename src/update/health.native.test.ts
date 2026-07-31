import { spawnSync } from "node:child_process";
import { mkdtemp, realpath, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { runEngineHealthCheck } from "./health.js";

const SOURCE = fileURLToPath(
  new URL(
    "../../test/v0.4.0-update/fixtures/fixture-engine.c",
    import.meta.url,
  ),
);

interface Compiler {
  readonly command: string;
  readonly args: (output: string, source: string) => readonly string[];
}

const COMPILERS: Compiler[] = [
  {
    command: "cc",
    args: (output, source) => [source, "-o", output],
  },
  {
    command: "gcc",
    args: (output, source) => [source, "-o", output],
  },
  {
    command: "clang",
    args: (output, source) => [source, "-o", output],
  },
  {
    command: "cl",
    args: (output, source) => [source, `/Fe:${output}`],
  },
];

function findCompiler(): Compiler | undefined {
  for (const compiler of COMPILERS) {
    // MSVC's cl.exe treats --version as a source filename and exits with 2.
    // Detect it by invoking it without arguments, which also prints usage.
    if (compiler.command === "cl") {
      const result = spawnSync(compiler.command, [], {
        shell: false,
        windowsHide: true,
        timeout: 5000,
        killSignal: "SIGKILL",
      });
      if (!result.error && !result.signal) return compiler;
      continue;
    }
    const result = spawnSync(compiler.command, ["--version"], {
      shell: false,
      windowsHide: true,
      timeout: 5000,
      killSignal: "SIGKILL",
    });
    if (result.error) continue;
    if (result.signal) continue;
    if (result.status === 0) return compiler;
  }
  return undefined;
}

function expectedFixtureVersion(): string {
  return "0.4.0";
}

function compileFixture(compiler: Compiler, outputDirectory: string): string {
  const binaryName =
    process.platform === "win32" ? "fixture-engine.exe" : "fixture-engine";
  const outputPath = path.join(outputDirectory, binaryName);
  const result = spawnSync(
    compiler.command,
    [...compiler.args(outputPath, SOURCE)],
    {
      shell: false,
      windowsHide: true,
      encoding: "utf8",
      timeout: 30000,
      killSignal: "SIGKILL",
    },
  );
  if (result.status !== 0) {
    throw new Error(
      `fixture engine compilation failed: ${result.stderr ?? result.error?.message ?? compiler.command}`,
    );
  }
  return outputPath;
}

test("native fixture engine passes the launcher health check", async (context) => {
  if (process.platform !== "win32" && process.platform !== "darwin") {
    context.skip(
      "native health test runs only on supported platforms (win32 or darwin)",
    );
    return;
  }

  const compiler = findCompiler();
  if (!compiler) {
    context.skip("no C compiler available for native fixture engine");
    return;
  }

  const root = await mkdtemp(
    path.join(await realpath(os.tmpdir()), "goat-native-health-"),
  );
  context.after(async () => {
    try {
      await rm(root, { recursive: true, force: true });
    } catch (error) {
      // On Windows the fixture executable may still be held briefly by the
      // kernel after spawnSync returns; the directory is under the OS temp
      // path, so leaving it is harmless for a test-only artifact.
      if ((error as NodeJS.ErrnoException).code !== "EPERM") throw error;
    }
  });

  const executablePath = compileFixture(compiler, root);

  await runEngineHealthCheck({
    executablePath,
    expectedVersion: expectedFixtureVersion(),
    platform: process.platform === "win32" ? "win32" : "darwin",
  });
});
