import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";

const root = process.cwd();
const pkg = JSON.parse(
  fs.readFileSync(path.join(root, "package.json"), "utf8"),
);
const failures = [];
const report = {
  schemaVersion: 1,
  evidenceType: "artifact",
  package: { name: pkg.name, version: pkg.version },
  status: "failed",
  artifact: null,
  reproducibility: null,
  dependencyGraph: null,
  scans: {
    archiveHeaders: "not-run",
    extractedBytes: "not-run",
    secretMarkers: "not-run",
    forbiddenModules: "not-run",
  },
  limitations: [
    "Secret-marker scanning is preventative evidence, not proof that every possible secret encoding is absent.",
    "A byte-identical npm archive does not prove reproducibility across different npm, Node, or operating-system versions.",
  ],
};

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
const reportPath = parseReportPath(process.argv.slice(2));
let temporaryRoot;
if (npmCli) {
  try {
    temporaryRoot = fs.mkdtempSync(
      path.join(os.tmpdir(), "goatcli-package-verification-"),
    );
    const attempts = [
      packActualArtifact(npmCli, temporaryRoot, 1),
      packActualArtifact(npmCli, temporaryRoot, 2),
    ];
    const [first, second] = attempts;
    const byteForByte = first.sha256 === second.sha256;
    if (!byteForByte) {
      failures.push("repeated npm packs were not byte-for-byte identical");
    }
    report.artifact = {
      filename: first.filename,
      bytes: first.bytes,
      sha256: first.sha256,
      sha1: first.sha1,
      sha512Integrity: first.sha512Integrity,
      fileCount: first.fileCount,
    };
    report.reproducibility = {
      attempts: attempts.length,
      byteForByte,
      sha256: attempts.map((attempt) => attempt.sha256),
      invariant:
        "two npm archives built consecutively from the same checkout, Node, npm, and operating system",
    };
    report.scans.archiveHeaders = "passed";
    report.scans.extractedBytes = "passed";
    report.scans.secretMarkers = "passed-best-effort";
    report.scans.forbiddenModules = "passed";
  } catch (error) {
    failures.push(
      `actual npm artifact verification failed: ${safeErrorMessage(error)}`,
    );
  } finally {
    if (temporaryRoot) {
      fs.rmSync(temporaryRoot, { recursive: true, force: true });
    }
  }
}

inspectProductionDependencyGraph(npmCli);

function packActualArtifact(npmCli, temporaryRoot, attempt) {
  const destination = path.join(temporaryRoot, "pack-" + attempt);
  fs.mkdirSync(destination);
  const packed = runCommand(
    process.execPath,
    [
      npmCli,
      "pack",
      "--json",
      "--ignore-scripts",
      "--pack-destination",
      destination,
    ],
    "npm pack attempt " + attempt,
  );

  let parsed;
  try {
    parsed = JSON.parse(packed);
  } catch {
    throw artifactError("npm pack returned invalid JSON");
  }
  if (!Array.isArray(parsed) || parsed.length !== 1) {
    throw artifactError("npm pack must return exactly one artifact");
  }

  const metadata = parsed[0];
  if (
    !metadata ||
    typeof metadata.filename !== "string" ||
    metadata.filename !== path.basename(metadata.filename)
  ) {
    throw artifactError("npm pack returned an unsafe artifact filename");
  }
  if (!Array.isArray(metadata.files)) {
    throw artifactError("npm pack omitted its file manifest");
  }

  const archivePath = resolveChildPath(destination, metadata.filename);
  const archiveStats = fs.lstatSync(archivePath);
  if (!archiveStats.isFile() || archiveStats.isSymbolicLink()) {
    throw artifactError("npm pack did not create a regular archive file");
  }
  const archiveBytes = fs.readFileSync(archivePath);
  const sha1 = digest("sha1", archiveBytes, "hex");
  const sha256 = digest("sha256", archiveBytes, "hex");
  const sha512Integrity = "sha512-" + digest("sha512", archiveBytes, "base64");
  if (metadata.size !== archiveBytes.length) {
    throw artifactError("npm pack size metadata does not match the archive");
  }
  if (metadata.shasum !== sha1) {
    throw artifactError("npm pack SHA-1 metadata does not match the archive");
  }
  if (metadata.integrity !== sha512Integrity) {
    throw artifactError(
      "npm pack SHA-512 integrity metadata does not match the archive",
    );
  }

  const metadataPaths = validatePackedMetadata(metadata.files);
  const archivePaths = listArchivePaths(archivePath);
  const expectedArchivePaths = metadataPaths
    .map((filePath) => "package/" + filePath)
    .sort();
  assertSamePaths(
    archivePaths,
    expectedArchivePaths,
    "archive headers and npm file metadata differ",
  );
  assertRegularArchiveHeaders(archivePath, archivePaths.length);

  const extractionRoot = path.join(destination, "extracted");
  fs.mkdirSync(extractionRoot);
  runCommand(
    "tar",
    ["-xzf", path.basename(archivePath), "-C", extractionRoot],
    "artifact extraction",
    { cwd: path.dirname(archivePath) },
  );
  const packageRoot = resolveChildPath(extractionRoot, "package");
  const extractedPaths = walkRegularFiles(packageRoot);
  assertSamePaths(
    extractedPaths,
    metadataPaths,
    "extracted files and npm file metadata differ",
  );

  const scanFailures = [];
  scanPackedFiles(metadata.files, packageRoot, scanFailures);
  if (scanFailures.length > 0) {
    throw artifactError(scanFailures[0]);
  }
  validatePackedPackageJson(packageRoot);

  return {
    filename: metadata.filename,
    bytes: archiveBytes.length,
    sha1,
    sha256,
    sha512Integrity,
    fileCount: metadataPaths.length,
  };
}

function validatePackedMetadata(fileEntries) {
  const paths = [];
  const seen = new Set();
  const allowed = (filePath) =>
    filePath === "package.json" ||
    requiredFiles.includes(filePath) ||
    filePath.startsWith("dist/");

  for (const entry of fileEntries) {
    if (
      !entry ||
      typeof entry.path !== "string" ||
      !Number.isSafeInteger(entry.size) ||
      entry.size < 0
    ) {
      throw artifactError("npm pack returned invalid file metadata");
    }
    const normalized = entry.path.replaceAll("\\", "/");
    if (!isSafeRelativePath(normalized) || seen.has(normalized)) {
      throw artifactError("npm pack returned an unsafe or duplicate file path");
    }
    seen.add(normalized);
    paths.push(normalized);
    if (!allowed(normalized)) {
      throw artifactError("unexpected packed file " + normalized);
    }
  }

  for (const file of requiredFiles) {
    if (!seen.has(file)) {
      throw artifactError("packed payload missing " + file);
    }
  }
  if (!seen.has("dist/index.js")) {
    throw artifactError("packed payload missing dist/index.js");
  }
  if (
    paths.some((filePath) =>
      /(?:^|\/)(?:src|test|scripts|\.github)(?:\/|$)/.test(filePath),
    )
  ) {
    throw artifactError(
      "packed payload contains development source or automation files",
    );
  }
  if (
    paths.some((filePath) =>
      /(?:\.test\.|\.spec\.|goat-engine(?:\.exe)?$)/.test(filePath),
    )
  ) {
    throw artifactError("packed payload contains tests or a private engine");
  }
  return paths.sort();
}

function listArchivePaths(archivePath) {
  const listing = runCommand(
    "tar",
    ["-tf", path.basename(archivePath)],
    "archive listing",
    { cwd: path.dirname(archivePath) },
  );
  return listing
    .split(/\r?\n/)
    .filter(Boolean)
    .map((entry) => {
      if (
        entry.includes("\0") ||
        entry.includes("\\") ||
        !entry.startsWith("package/") ||
        path.posix.normalize(entry) !== entry
      ) {
        throw artifactError("archive contains an unsafe path");
      }
      return entry;
    })
    .sort();
}

function assertRegularArchiveHeaders(archivePath, expectedCount) {
  const verbose = runCommand(
    "tar",
    ["-tvf", path.basename(archivePath)],
    "verbose archive listing",
    { cwd: path.dirname(archivePath) },
  );
  const headers = verbose.split(/\r?\n/).filter(Boolean);
  if (headers.length !== expectedCount) {
    throw artifactError(
      "archive header count does not match its file manifest",
    );
  }
  if (headers.some((header) => !header.startsWith("-"))) {
    throw artifactError(
      "archive contains a link, directory, or non-regular entry",
    );
  }
}

function walkRegularFiles(packageRoot) {
  const rootStats = fs.lstatSync(packageRoot);
  if (!rootStats.isDirectory() || rootStats.isSymbolicLink()) {
    throw artifactError("extracted package root is not a regular directory");
  }
  const files = [];
  const visit = (directory, relativeDirectory) => {
    for (const name of fs.readdirSync(directory)) {
      const relativePath = relativeDirectory
        ? relativeDirectory + "/" + name
        : name;
      if (!isSafeRelativePath(relativePath)) {
        throw artifactError("extracted package contains an unsafe path");
      }
      const absolutePath = resolveChildPath(packageRoot, relativePath);
      const stats = fs.lstatSync(absolutePath);
      if (stats.isSymbolicLink()) {
        throw artifactError("extracted package contains a symbolic link");
      }
      if (stats.isDirectory()) {
        visit(absolutePath, relativePath);
      } else if (stats.isFile()) {
        files.push(relativePath);
      } else {
        throw artifactError("extracted package contains a non-regular file");
      }
    }
  };
  visit(packageRoot, "");
  return files.sort();
}

function validatePackedPackageJson(packageRoot) {
  const packedPackagePath = resolveChildPath(packageRoot, "package.json");
  let packedPackage;
  try {
    packedPackage = JSON.parse(fs.readFileSync(packedPackagePath, "utf8"));
  } catch {
    throw artifactError("packed package.json is invalid");
  }
  if (
    packedPackage.name !== pkg.name ||
    packedPackage.version !== pkg.version ||
    packedPackage.bin?.goat !== pkg.bin.goat
  ) {
    throw artifactError(
      "packed package metadata differs from the release input",
    );
  }
  const expectedDependencies = Object.keys(pkg.dependencies ?? {}).sort();
  const packedDependencies = Object.keys(
    packedPackage.dependencies ?? {},
  ).sort();
  assertSamePaths(
    packedDependencies,
    expectedDependencies,
    "packed runtime dependency declarations differ from package.json",
  );
  for (const script of ["preinstall", "install", "postinstall"]) {
    if (packedPackage.scripts?.[script]) {
      throw artifactError(
        "packed package contains an unexpected install lifecycle script",
      );
    }
  }
}

function inspectProductionDependencyGraph(npmCli) {
  if (!npmCli) return;
  try {
    const output = runCommand(
      process.execPath,
      [npmCli, "ls", "--omit=dev", "--all", "--json"],
      "production dependency graph",
    );
    const graph = JSON.parse(output);
    const expectedTopLevel = Object.keys(pkg.dependencies ?? {}).sort();
    const actualTopLevel = Object.keys(graph.dependencies ?? {}).sort();
    assertSamePaths(
      actualTopLevel,
      expectedTopLevel,
      "installed production dependency roots differ from package.json",
    );

    const packages = flattenDependencyGraph(graph.dependencies ?? {});
    const forbidden = packages.filter(({ name }) =>
      /^(?:@opentelemetry\/|@sentry\/|posthog(?:-|$)|newrelic$|@datadog\/|@segment\/analytics|mixpanel$|amplitude(?:-|$))/i.test(
        name,
      ),
    );
    if (forbidden.length > 0) {
      throw artifactError(
        "production dependency graph contains a forbidden telemetry package",
      );
    }

    const devOnlyRoots = new Set(
      Object.keys(pkg.devDependencies ?? {}).filter(
        (name) => !(name in (pkg.dependencies ?? {})),
      ),
    );
    if (actualTopLevel.some((name) => devOnlyRoots.has(name))) {
      throw artifactError(
        "development-only dependency leaked into the production dependency roots",
      );
    }
    report.dependencyGraph = {
      source: "npm ls --omit=dev --all --json",
      topLevel: actualTopLevel,
      packageCount: packages.length,
      packages: packages.map(
        ({ name, version }) => name + "@" + (version ?? "unknown"),
      ),
      forbiddenTelemetryPackages: [],
    };
  } catch (error) {
    failures.push(
      "production dependency graph verification failed: " +
        safeErrorMessage(error),
    );
  }
}

function flattenDependencyGraph(dependencies) {
  const found = new Map();
  const visit = (items) => {
    for (const [name, value] of Object.entries(items ?? {})) {
      const version =
        value && typeof value === "object" && typeof value.version === "string"
          ? value.version
          : undefined;
      const key = name + "\0" + (version ?? "");
      if (found.has(key)) continue;
      found.set(key, { name, version });
      if (value && typeof value === "object") {
        visit(value.dependencies);
      }
    }
  };
  visit(dependencies);
  return [...found.values()].sort((left, right) =>
    left.name === right.name
      ? (left.version ?? "").localeCompare(right.version ?? "")
      : left.name.localeCompare(right.name),
  );
}

function runCommand(command, args, label, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd ?? root,
    encoding: "utf8",
    windowsHide: true,
    shell: false,
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.error || result.status !== 0) {
    const details = result.error?.message ?? result.stderr?.trim();
    throw artifactError(
      details ? `${label} failed: ${details}` : `${label} failed`,
    );
  }
  return result.stdout;
}

function assertSamePaths(actual, expected, message) {
  if (
    actual.length !== expected.length ||
    actual.some((value, index) => value !== expected[index])
  ) {
    throw artifactError(message);
  }
}

function isSafeRelativePath(value) {
  return (
    value.length > 0 &&
    !value.includes("\0") &&
    !value.includes("\\") &&
    !path.posix.isAbsolute(value) &&
    path.posix.normalize(value) === value &&
    value !== "." &&
    !value.startsWith("../")
  );
}

function resolveChildPath(parent, child) {
  const parentResolved = path.resolve(parent);
  const resolved = path.resolve(parentResolved, child);
  const boundary = parentResolved.endsWith(path.sep)
    ? parentResolved
    : parentResolved + path.sep;
  if (!resolved.startsWith(boundary) || resolved === parentResolved) {
    throw artifactError("path resolves outside the expected artifact root");
  }
  return resolved;
}

function digest(algorithm, value, encoding) {
  return createHash(algorithm).update(value).digest(encoding);
}

function artifactError(message) {
  const error = new Error(message);
  error.name = "ArtifactVerificationError";
  return error;
}

function safeErrorMessage(error) {
  return error instanceof Error && error.name === "ArtifactVerificationError"
    ? error.message
    : "unexpected verifier failure";
}

function parseReportPath(args) {
  if (args.length === 0) return undefined;
  if (args.length !== 2 || args[0] !== "--report" || !args[1]) {
    failures.push("usage: verify-package.mjs [--report <path>]");
    return undefined;
  }
  return path.resolve(args[1]);
}

function scanPackedFiles(fileEntries, packageRoot, failures) {
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
  const forbiddenArtifactPatterns = [
    /@opentelemetry\//i,
    /@sentry\//i,
    /(?:^|["'])posthog(?:-node|-js)?(?:["'\/])/im,
    /@datadog\//i,
    /@segment\/analytics/i,
    /(?:^|["'])newrelic(?:["'\/])/im,
    /OTEL_EXPORTER_[A-Z_]+/,
    /(?:ingest\.)?sentry\.io\/api\//i,
    /(?:app|us\.i)\.posthog\.com/i,
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
  const textExtensions = new Set([
    ".js",
    ".ts",
    ".json",
    ".md",
    ".yml",
    ".yaml",
    ".txt",
    ".html",
    ".css",
    ".svg",
    ".xml",
    ".csv",
  ]);
  for (const { path: filePath, size } of fileEntries) {
    const normalized = filePath.replaceAll("\\", "/");
    const resolved = resolvePackedPath(packageRoot, normalized);
    if (!resolved) {
      failures.push(
        `packed path ${normalized} resolves outside the package root or is not a regular file`,
      );
      continue;
    }
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

    let raw;
    try {
      raw = fs.readFileSync(resolved);
    } catch {
      failures.push(`could not read packed file ${normalized}`);
      continue;
    }
    if (raw.length !== size) {
      failures.push(
        `packed file ${normalized} does not match npm file-size metadata`,
      );
    }
    if (!textExtensions.has(ext)) continue;
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
    if (normalized.startsWith("dist/")) {
      for (const pattern of forbiddenArtifactPatterns) {
        if (pattern.test(contents)) {
          failures.push(
            `packed runtime file ${normalized} contains forbidden telemetry or remote-sink material matching ${pattern.source}`,
          );
          break;
        }
      }
    }
  }
}

function resolvePackedPath(packageRoot, normalized) {
  const fullPath = path.join(packageRoot, normalized);
  const resolved = path.resolve(fullPath);
  const rootResolved = path.resolve(packageRoot);
  const boundary = rootResolved.endsWith(path.sep)
    ? rootResolved
    : `${rootResolved}${path.sep}`;
  if (!resolved.startsWith(boundary) || resolved === rootResolved) {
    return null;
  }
  let stats;
  try {
    stats = fs.lstatSync(resolved);
  } catch {
    return null;
  }
  if (!stats.isFile() || stats.isSymbolicLink()) {
    return null;
  }
  return resolved;
}

function containsBinaryPayload(raw) {
  // Null bytes are a strong indicator of a native/binary file.
  if (raw.includes(0)) return true;
  // Valid UTF-8 text (including multi-byte characters) should not be flagged
  // as binary. Reject any content that cannot be decoded as valid UTF-8.
  try {
    new TextDecoder("utf8", { fatal: true }).decode(raw);
    return false;
  } catch {
    return true;
  }
}

report.status = failures.length === 0 ? "passed" : "failed";
report.failureCount = failures.length;
report.failures = [...failures];
let serializedReport = JSON.stringify(report, null, 2) + "\n";
if (reportPath) {
  try {
    fs.writeFileSync(reportPath, serializedReport, {
      encoding: "utf8",
      flag: "wx",
    });
  } catch {
    failures.push("could not create the requested machine-readable report");
    report.status = "failed";
    report.failureCount = failures.length;
    report.failures = [...failures];
    serializedReport = JSON.stringify(report, null, 2) + "\n";
  }
}
process.stdout.write(serializedReport);
if (failures.length > 0) {
  for (const failure of failures) {
    console.error(`package verification: ${failure}`);
  }
  process.exitCode = 1;
}
