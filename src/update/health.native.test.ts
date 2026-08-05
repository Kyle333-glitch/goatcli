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

// Prefer the compiler explicitly installed and verified by CI on Windows.
// Some Windows ARM images expose a `cc` shim that can resolve to an
// incompatible or emulated toolchain, while `gcc` is the reproducible MinGW
// compiler used by the workflow.
const COMPILERS: Compiler[] = [
  {
    command: "gcc",
    args: (output, source) => [source, "-o", output],
  },
  {
    command: "cc",
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
      // Windows ARM may run the x64 MinGW compiler under emulation; allow
      // that test-only compilation enough time without weakening health's
      // ten-second candidate execution bound.
      timeout: 120000,
      killSignal: "SIGKILL",
    },
  );
  if (result.error || result.signal || result.status !== 0) {
    const detail =
      result.stderr?.trim() ||
      result.error?.message ||
      (result.signal
        ? `terminated by ${result.signal}`
        : `exit status ${result.status}`);
    throw new Error(`fixture engine compilation failed: ${detail}`);
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
      if (
        process.platform !== "win32" ||
        (error as NodeJS.ErrnoException).code !== "EPERM"
      ) {
        throw error;
      }
    }
  });

  const executablePath = compileFixture(compiler, root);

  await runEngineHealthCheck({
    executablePath,
    expectedVersion: expectedFixtureVersion(),
    platform: process.platform === "win32" ? "win32" : "darwin",
  });
});
