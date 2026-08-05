import path from "node:path";
import { fileURLToPath } from "node:url";
import { EngineContractError } from "../../src/engine/contract.js";
import { launchValidatedEngine } from "../../src/engine/launch.js";

const fixturePath = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "process-tree-fixture.ts",
);
const mode = process.argv[2] ?? "normal";

report({ event: "ready", role: "launcher", pid: process.pid, mode });
if (mode === "termination-command-failure") {
  process.stdin.setEncoding("utf8");
  process.stdin.once("data", (value) => {
    process.stdin.destroy();
    if (String(value) === "TRIGGER\n") process.emit("SIGTERM");
  });
}

try {
  const result = await launchValidatedEngine(
    {
      executablePath:
        mode === "spawn-failure"
          ? path.join(path.dirname(fixturePath), "missing-engine.exe")
          : process.execPath,
      platform: currentPlatform(),
    },
    ["--import", "tsx", fixturePath, "engine"],
    {
      cwd: process.cwd(),
      processTerminator:
        mode === "termination-command-failure"
          ? (command, args) => {
              report({ event: "termination-command", command, args });
              return { status: 1 };
            }
          : undefined,
      privacyIpc:
        mode === "ipc-failure"
          ? {
              mode: "eager",
              engineIntegrity: "verified",
              credentialStore: "available",
              credential: new TextEncoder().encode("A".repeat(43)),
              credentialExpiresAtUnixMs: Date.now() + 60_000,
              launcherPid: process.pid,
            }
          : undefined,
    },
  );
  report({ event: "result", role: "launcher", ...result });
  process.exitCode = result.exitCode;
} catch (error) {
  report({
    event: "error",
    role: "launcher",
    code:
      error instanceof EngineContractError
        ? error.code
        : "GOAT_NATIVE_FIXTURE_FAILED",
  });
  process.exitCode = 70;
}

function currentPlatform(): "win32" | "darwin" {
  if (process.platform !== "win32" && process.platform !== "darwin") {
    throw new Error("unsupported fixture platform");
  }
  return process.platform;
}

function report(value: Record<string, unknown>): void {
  process.stdout.write(
    JSON.stringify({ goatProcessFixture: 1, ...value }) + "\n",
  );
}
