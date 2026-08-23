import fs from "node:fs";
import path from "node:path";

if (process.argv.length !== 4) {
  throw new Error(
    "Usage: bun scripts/build-windows-privacy-fixture.mjs <entrypoint> <outfile>",
  );
}

const entrypoint = path.resolve(process.argv[2]);
const outfile = path.resolve(process.argv[3]);
if (!fs.statSync(entrypoint).isFile()) {
  throw new Error("The Windows privacy fixture entrypoint is unavailable.");
}

fs.mkdirSync(path.dirname(outfile), { recursive: true });
const result = await Bun.build({
  entrypoints: [entrypoint],
  target: "bun",
  format: "esm",
  compile: {
    outfile,
    autoloadBunfig: false,
    autoloadDotenv: false,
    autoloadTsconfig: false,
    autoloadPackageJson: false,
    windows: { hideConsole: true },
  },
});

if (!result.success) {
  for (const log of result.logs) console.error(log);
  throw new Error("The Windows privacy fixture could not be compiled.");
}
if (!fs.statSync(outfile).isFile()) {
  throw new Error("The Windows privacy fixture binary was not produced.");
}
