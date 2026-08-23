import { acceptLauncherSession } from "../../../goat-engine/packages/opencode/src/privacy/launcher-ipc.ts";
import { inheritedLauncherIpcTransport } from "../../../goat-engine/packages/opencode/src/privacy/node-launcher-ipc.ts";

const transport = inheritedLauncherIpcTransport();
try {
  const session = await acceptLauncherSession({
    ...transport,
    expectedLauncherPid: process.ppid,
    expectedEnginePid: process.pid,
    expectedOsSessionId: undefined,
  });
  session.dispose();
} catch (error) {
  const code =
    error && typeof error === "object" && typeof error.code === "string"
      ? error.code
      : "LAUNCHER_IPC_MESSAGE_INVALID";
  process.stderr.write(`Engine privacy IPC fixture failed: ${code}\n`);
  process.exitCode = 1;
}
