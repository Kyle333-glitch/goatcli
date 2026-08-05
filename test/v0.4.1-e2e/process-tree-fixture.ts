import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const fixturePath = fileURLToPath(import.meta.url);
const role = process.argv[2];

if (role === "engine" || role === "child") {
  const nextRole = role === "engine" ? "child" : "grandchild";
  const child = spawn(
    process.execPath,
    ["--import", "tsx", fixturePath, nextRole],
    {
      shell: false,
      stdio: ["ignore", "inherit", "inherit"],
      windowsHide: true,
    },
  );
  child.once("error", () => process.exit(71));
  report({
    event: "ready",
    role,
    pid: process.pid,
    childPid: child.pid ?? null,
  });
  keepAlive();
} else if (role === "grandchild") {
  report({ event: "ready", role, pid: process.pid });
  keepAlive();
} else if (role === "sentinel") {
  process.stdin.resume();
  process.stdin.once("end", () => process.exit(0));
  process.stdin.once("close", () => process.exit(0));
  report({ event: "ready", role, pid: process.pid });
  keepAlive();
} else {
  process.exitCode = 64;
}

function report(value: Record<string, unknown>): void {
  process.stdout.write(
    JSON.stringify({ goatProcessFixture: 1, ...value }) + "\n",
  );
}

function keepAlive(): void {
  setInterval(() => undefined, 1_000);
}
