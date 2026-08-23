import { copyFile, mkdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const nativeRoot = path.dirname(fileURLToPath(import.meta.url));
const outputDirectory = path.join(nativeRoot, "target", "test-hooks");
const source = path.join(outputDirectory, "goatcli-windows-spawn.node");
const destination = path.join(
  outputDirectory,
  "goatcli-windows-spawn-test.node",
);

await mkdir(outputDirectory, { recursive: true });
await copyFile(source, destination);
