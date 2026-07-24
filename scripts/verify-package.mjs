import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

const root = process.cwd();
const pkg = JSON.parse(
  fs.readFileSync(path.join(root, "package.json"), "utf8"),
);
const failures = [];

if (pkg.name !== "goatcli") failures.push("package name must be goatcli");
if (pkg.version !== "0.3.2") failures.push("package version must be 0.3.2");
if (pkg.private === true)
  failures.push("public launcher package must not be private");
if (pkg.license !== "MIT") failures.push("public launcher license must be MIT");
if (pkg.engines?.node !== ">=24.16.0")
  failures.push("Node runtime floor must be >=24.16.0");
if (pkg.bin?.goat !== "./dist/index.js")
  failures.push("installed command must be goat");

const requiredFiles = ["README.md", "PRIVACY.md", "LICENSE", "NOTICE"];
for (const file of requiredFiles) {
  if (!fs.existsSync(path.join(root, file)))
    failures.push(`missing package document ${file}`);
}

const notice = fs.existsSync(path.join(root, "NOTICE"))
  ? fs.readFileSync(path.join(root, "NOTICE"), "utf8")
  : "";
if (!notice.includes("not covered by this MIT license")) {
  failures.push(
    "NOTICE must exclude private engine, control plane, and distributed binaries",
  );
}

const npmCli = process.env.npm_execpath;
if (!npmCli) failures.push("npm executable path is unavailable");
const packed = npmCli
  ? spawnSync(
      process.execPath,
      [npmCli, "pack", "--dry-run", "--json", "--ignore-scripts"],
      {
        cwd: root,
        encoding: "utf8",
        windowsHide: true,
      },
    )
  : { status: null, stdout: "" };
if (packed.status !== 0) {
  failures.push("npm pack --dry-run failed");
} else {
  let result;
  try {
    result = JSON.parse(packed.stdout)[0];
  } catch {
    failures.push("npm pack returned invalid JSON");
  }
  if (result) {
    const paths = result.files.map((file) => file.path.replaceAll("\\", "/"));
    const allowed = (file) =>
      file === "package.json" ||
      requiredFiles.includes(file) ||
      file.startsWith("dist/");
    for (const file of paths)
      if (!allowed(file)) failures.push(`unexpected packed file ${file}`);
    for (const file of requiredFiles)
      if (!paths.includes(file))
        failures.push(`packed payload missing ${file}`);
    if (!paths.includes("dist/index.js"))
      failures.push("packed payload missing dist/index.js");
    if (
      paths.some((file) =>
        /(?:^|\/)(?:src|test|scripts|\.github)(?:\/|$)/.test(file),
      )
    ) {
      failures.push(
        "packed payload contains development source or automation files",
      );
    }
    if (
      paths.some((file) =>
        /(?:\.test\.|\.spec\.|goat-engine(?:\.exe)?$)/.test(file),
      )
    ) {
      failures.push("packed payload contains tests or a private engine binary");
    }
  }
}

if (failures.length) {
  failures.forEach((failure) =>
    console.error(`package verification: ${failure}`),
  );
  process.exitCode = 1;
} else {
  console.log("Package verification passed.");
}
