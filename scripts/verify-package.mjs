import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

const root = process.cwd();
const pkg = JSON.parse(
  fs.readFileSync(path.join(root, "package.json"), "utf8"),
);
const failures = [];

if (pkg.name !== "goatcli") failures.push("package name must be goatcli");
if (pkg.version !== "0.4.0") failures.push("package version must be 0.4.0");
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

    scanPackedFiles(result.files, failures);
  }
}

function scanPackedFiles(fileEntries, failures) {
  const secretPatterns = [
    /BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY/i,
    /BEGIN\s+EC\s+PRIVATE\s+KEY/i,
    /BEGIN\s+DSA\s+PRIVATE\s+KEY/i,
    /BEGIN\s+OPENSSH\s+PRIVATE\s+KEY/i,
    /BEGIN\s+PGP\s+PRIVATE\s+KEY/i,
    /BEGIN\s+ENCRYPTED\s+PRIVATE\s+KEY/i,
    /BEGIN\s+CERTIFICATE/i,
    /\bapi[_-]?key\s*[:=]\s*["']?[A-Za-z0-9_\-/+=]{8,}["']?/i,
    /\bapi[_-]?secret\s*[:=]\s*["']?[A-Za-z0-9_\-/+=]{8,}["']?/i,
    /\bpassword\s*[:=]\s*["'][^"']{8,}["']/i,
    /\btoken\s*[:=]\s*["'][A-Za-z0-9_\-/+=]{16,}["']/i,
    /AKIA[0-9A-Z]{16}/,
    /gh[opsr]_[a-zA-Z0-9]{36}/,
  ];
  const blockedExtensions = new Set([
    ".pem",
    ".key",
    ".crt",
    ".cer",
    ".der",
    ".p12",
    ".pfx",
    ".node",
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".macho",
    ".zip",
    ".bin",
  ]);
  const textExtensions = new Set([".js", ".ts", ".json", ".md"]);
  for (const { path: filePath } of fileEntries) {
    const normalized = filePath.replaceAll("\\", "/");
    if (!normalized.startsWith("dist/")) continue;
    const lower = normalized.toLowerCase();
    const basename = lower.split("/").pop() ?? "";
    const ext = basename.includes(".")
      ? basename.slice(basename.lastIndexOf("."))
      : "";
    if (blockedExtensions.has(ext)) {
      failures.push(
        `packed payload contains unexpected key/certificate/binary extension: ${normalized}`,
      );
    }
    if (textExtensions.has(ext)) {
      try {
        const raw = fs.readFileSync(path.join(root, normalized));
        if (containsBinaryPayload(raw)) {
          failures.push(
            `packed file ${normalized} appears to contain non-text (native/binary) bytes`,
          );
          continue;
        }
        const contents = raw.toString("utf8");
        for (const pattern of secretPatterns) {
          if (pattern.test(contents)) {
            failures.push(
              `packed file ${normalized} may contain secret material matching ${pattern.source}`,
            );
            break;
          }
        }
      } catch {
        failures.push(
          `could not read packed file ${normalized} for secret scan`,
        );
      }
    }
  }
}

function containsBinaryPayload(raw) {
  const sample = raw.subarray(0, 8192);
  // Null bytes are a strong indicator of a native/binary file.
  if (sample.includes(0)) return true;
  // Valid UTF-8 text (including multi-byte characters) should not be flagged
  // as binary. Reject any content that cannot be decoded as valid UTF-8.
  try {
    new TextDecoder("utf8", { fatal: true }).decode(sample);
    return false;
  } catch {
    return true;
  }
}

if (failures.length) {
  failures.forEach((failure) =>
    console.error(`package verification: ${failure}`),
  );
  process.exitCode = 1;
} else {
  console.log("Package verification passed.");
  console.log(
    "Note: secret-marker scan is a best-effort preventative check, not a proof of complete secret absence.",
  );
}
