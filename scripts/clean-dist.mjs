import { realpath } from "node:fs/promises";
import { basename, dirname, resolve } from "node:path";
import { rm } from "node:fs/promises";

const workspace = await realpath(process.cwd());
const dist = resolve(workspace, "dist");
if (dirname(dist) !== workspace || basename(dist) !== "dist") {
  throw new Error("Refusing to clean an unverified output directory.");
}
await rm(dist, { force: true, recursive: true });
