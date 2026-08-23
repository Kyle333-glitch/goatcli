import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";

const root = process.cwd();
const pkg = JSON.parse(
  fs.readFileSync(path.join(root, "package.json"), "utf8"),
);
const windowsSpawnAbiVersion = 1;
const windowsSpawnWorkspacePattern = "native/windows-spawn/npm/*";
const enginePackages = [
  {
    name: "goat-engine-windows-x64",
    os: "win32",
    cpu: "x64",
  },
  {
    name: "goat-engine-windows-arm64",
    os: "win32",
    cpu: "arm64",
  },
  {
    name: "goat-engine-darwin-x64",
    os: "darwin",
    cpu: "x64",
  },
  {
    name: "goat-engine-darwin-arm64",
    os: "darwin",
    cpu: "arm64",
  },
];
const windowsSpawnPackages = [
  {
    name: "goatcli-windows-spawn",
    directory: "native/windows-spawn/npm/wrapper",
    kind: "wrapper",
  },
  {
    name: "goatcli-windows-spawn-win32-x64-msvc",
    directory: "native/windows-spawn/npm/win32-x64-msvc",
    kind: "platform",
    cpu: "x64",
    peMachine: 0x8664,
  },
  {
    name: "goatcli-windows-spawn-win32-arm64-msvc",
    directory: "native/windows-spawn/npm/win32-arm64-msvc",
    kind: "platform",
    cpu: "arm64",
    peMachine: 0xaa64,
  },
];
const failures = [];
const report = {
  schemaVersion: 1,
  evidenceType: "artifact",
  package: { name: pkg.name, version: pkg.version },
  status: "failed",
  artifact: null,
  reproducibility: null,
  dependencyGraph: null,
  nativePackages: [],
  enginePackages: {
    status: "not-checked",
    pendingPublication: [],
  },
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
if (!isValidReleaseVersion(pkg.version))
  failures.push(
    "package version must be a valid semver (MAJOR.MINOR.PATCH with optional prerelease/build)",
  );
if (pkg.private === true)
  failures.push("public launcher package must not be private");
if (pkg.license !== "MIT") failures.push("public launcher license must be MIT");
if (
  pkg.publishConfig?.access !== "public" ||
  pkg.publishConfig?.provenance !== true ||
  (pkg.publishConfig?.registry !== undefined &&
    pkg.publishConfig.registry !== "https://registry.npmjs.org/")
) {
  failures.push("launcher must publish publicly to npm with provenance");
}
if (pkg.engines?.node !== ">=22.18.0")
  failures.push("Node runtime floor must be >=22.18.0");
if (pkg.bin?.goat !== "./dist/index.js")
  failures.push("installed command must be goat");
if (
  !Array.isArray(pkg.workspaces) ||
  pkg.workspaces.length !== 1 ||
  pkg.workspaces[0] !== windowsSpawnWorkspacePattern
) {
  failures.push(
    `npm workspaces must contain only ${windowsSpawnWorkspacePattern}`,
  );
}
if (
  JSON.stringify(pkg.napi) !==
  JSON.stringify({ binaryName: "goatcli-windows-spawn" })
) {
  failures.push("N-API binary name must be goatcli-windows-spawn");
}
const optionalDependencyNames = Object.keys(
  pkg.optionalDependencies ?? {},
).sort();
const expectedOptionalDependencyNames = [
  ...enginePackages.map((definition) => definition.name),
  "goatcli-windows-spawn",
].sort();
if (
  optionalDependencyNames.length !== expectedOptionalDependencyNames.length ||
  optionalDependencyNames.some(
    (name, index) => name !== expectedOptionalDependencyNames[index],
  ) ||
  optionalDependencyNames.some(
    (name) => typeof pkg.optionalDependencies?.[name] !== "string",
  )
) {
  failures.push(
    "the launcher must declare all four platform engine packages and the Windows privacy package as optional dependencies",
  );
}
const enginePackageVersion = pkg.optionalDependencies?.[enginePackages[0].name];
for (const definition of enginePackages) {
  if (
    typeof enginePackageVersion !== "string" ||
    pkg.optionalDependencies?.[definition.name] !== enginePackageVersion
  ) {
    failures.push(
      `${definition.name} must use the same exact engine version as the other platform packages`,
    );
  }
}
if (pkg.optionalDependencies?.["goatcli-windows-spawn"] !== pkg.version) {
  failures.push(
    "goatcli-windows-spawn must exactly match the launcher version",
  );
}
assertNoInstallLifecycle(pkg, "root package", failures);
validateEngineLockEntries({
  requirePublishedIntegrity:
    process.env.GITHUB_REF?.startsWith("refs/tags/") === true ||
    process.env.GOAT_REQUIRE_PUBLISHED_ENGINE_INTEGRITY === "1",
});

const requiredFiles = ["README.md", "PRIVACY.md", "LICENSE", "NOTICE"];
for (const file of requiredFiles) {
  if (!fs.existsSync(path.join(root, file)))
    failures.push(`missing package document ${file}`);
}

const notice = fs.existsSync(path.join(root, "NOTICE"))
  ? fs.readFileSync(path.join(root, "NOTICE"), "utf8")
  : "";
const launcherLicense = fs.existsSync(path.join(root, "LICENSE"))
  ? fs
      .readFileSync(path.join(root, "LICENSE"), "utf8")
      .replaceAll("\r\n", "\n")
      .trimEnd()
  : "";
if (!notice.includes("not covered by this MIT license")) {
  failures.push(
    "NOTICE must exclude private engine, control plane, and distributed binaries",
  );
}

validateWindowsSpawnWorkspaceManifests();

const npmCli = process.env.npm_execpath;
if (!npmCli) failures.push("npm executable path is unavailable");
const verifierOptions = parseOptions(process.argv.slice(2));
const reportPath = verifierOptions.reportPath;
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

if (npmCli && verifierOptions.nativePackages) {
  try {
    const nativeTemporaryRoot = fs.mkdtempSync(
      path.join(os.tmpdir(), "goatcli-native-package-verification-"),
    );
    try {
      const selectedDefinitions = windowsSpawnPackages.filter(
        (definition) =>
          definition.kind === "wrapper" ||
          verifierOptions.nativePackageNames.length === 0 ||
          verifierOptions.nativePackageNames.includes(definition.name),
      );
      report.nativePackages = selectedDefinitions.map((definition) => {
        const attempts = [1, 2].map((attempt) =>
          packAndValidateNativePackage(
            npmCli,
            nativeTemporaryRoot,
            definition,
            attempt,
          ),
        );
        if (attempts[0].sha256 !== attempts[1].sha256) {
          throw artifactError(
            `${definition.name} repeated npm packs were not byte-for-byte identical`,
          );
        }
        return {
          ...attempts[0],
          reproducible: true,
          attemptSha256: attempts.map((attempt) => attempt.sha256),
        };
      });
    } finally {
      fs.rmSync(nativeTemporaryRoot, { recursive: true, force: true });
    }
  } catch (error) {
    failures.push(
      `native npm artifact verification failed: ${safeErrorMessage(error)}`,
    );
  }
}

inspectProductionDependencyGraph(npmCli);

function validateEngineLockEntries({ requirePublishedIntegrity }) {
  const lockPath = path.join(root, "package-lock.json");
  let lock;
  try {
    lock = JSON.parse(fs.readFileSync(lockPath, "utf8"));
  } catch {
    failures.push("package-lock.json is missing or invalid");
    return;
  }
  for (const definition of enginePackages) {
    const entry = lock.packages?.[`node_modules/${definition.name}`];
    if (!entry || typeof entry !== "object") {
      failures.push(`${definition.name} is missing from package-lock.json`);
      continue;
    }
    if (
      entry.resolved !==
      `https://registry.npmjs.org/${definition.name}/-/${definition.name}-${enginePackageVersion}.tgz`
    ) {
      failures.push(
        `${definition.name} lockfile URL is not the npm registry tarball`,
      );
    }
    const hasPublishedIntegrity =
      typeof entry.integrity === "string" &&
      /^sha512-[A-Za-z0-9+/]+={0,2}$/.test(entry.integrity);
    if (!hasPublishedIntegrity) {
      report.enginePackages.pendingPublication.push(definition.name);
      if (requirePublishedIntegrity) {
        failures.push(
          `${definition.name} lockfile entry must contain SHA-512 integrity`,
        );
      }
    }
    if (
      entry.optional !== true ||
      JSON.stringify(entry.os) !== JSON.stringify([definition.os]) ||
      JSON.stringify(entry.cpu) !== JSON.stringify([definition.cpu])
    ) {
      failures.push(`${definition.name} lockfile platform metadata is invalid`);
    }
  }
  report.enginePackages.status =
    report.enginePackages.pendingPublication.length === 0
      ? "verified"
      : requirePublishedIntegrity
        ? "failed"
        : "pending-publication";
}

function validateWindowsSpawnWorkspaceManifests() {
  const definitionsByName = new Map(
    windowsSpawnPackages.map((definition) => [definition.name, definition]),
  );
  for (const definition of windowsSpawnPackages) {
    const manifestPath = path.join(root, definition.directory, "package.json");
    let manifest;
    try {
      manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    } catch {
      failures.push(`missing or invalid workspace manifest ${manifestPath}`);
      continue;
    }

    if (manifest.name !== definition.name) {
      failures.push(`${definition.directory} has an unexpected package name`);
    }
    if (manifest.version !== pkg.version) {
      failures.push(
        `${definition.name} must exactly match the launcher version`,
      );
    }
    if (manifest.license !== "MIT") {
      failures.push(`${definition.name} must use the MIT license`);
    }
    if (manifest.private === true) {
      failures.push(`${definition.name} must be publishable`);
    }
    if (
      manifest.publishConfig?.access !== "public" ||
      manifest.publishConfig?.provenance !== true ||
      (manifest.publishConfig?.registry !== undefined &&
        manifest.publishConfig.registry !== "https://registry.npmjs.org/")
    ) {
      failures.push(
        `${definition.name} must publish publicly to npm with provenance`,
      );
    }
    if (manifest.engines?.node !== pkg.engines?.node) {
      failures.push(
        `${definition.name} must use the launcher Node runtime floor`,
      );
    }
    assertNoInstallLifecycle(manifest, definition.name, failures);

    for (const requiredFile of ["README.md", "LICENSE", "NOTICE"]) {
      try {
        const stats = fs.lstatSync(
          path.join(root, definition.directory, requiredFile),
        );
        if (!stats.isFile() || stats.isSymbolicLink() || stats.size === 0) {
          failures.push(
            `${definition.name} ${requiredFile} must be a non-empty regular file`,
          );
        }
      } catch {
        failures.push(`${definition.name} ${requiredFile} is missing`);
      }
    }
    try {
      const nativeLicense = fs
        .readFileSync(path.join(root, definition.directory, "LICENSE"), "utf8")
        .replaceAll("\r\n", "\n")
        .trimEnd();
      if (nativeLicense !== launcherLicense) {
        failures.push(
          `${definition.name} LICENSE must match the public launcher MIT license`,
        );
      }
    } catch {
      // The missing LICENSE failure above is sufficient and path-free.
    }

    try {
      const nativeNotice = fs.readFileSync(
        path.join(root, definition.directory, "NOTICE"),
        "utf8",
      );
      if (
        !nativeNotice.includes("napi-rs") ||
        !nativeNotice.includes("windows-sys")
      ) {
        failures.push(
          `${definition.name} NOTICE must identify its native third-party components`,
        );
      }
    } catch {
      // The missing NOTICE failure above is sufficient and path-free.
    }

    const dependencies = Object.keys(manifest.dependencies ?? {});
    if (dependencies.length > 0) {
      failures.push(`${definition.name} must not have runtime dependencies`);
    }

    if (definition.kind === "wrapper") {
      if (
        JSON.stringify(manifest.os) !== JSON.stringify(["win32"]) ||
        "cpu" in manifest ||
        "libc" in manifest
      ) {
        failures.push(
          `${definition.name} must target Windows without constraining CPU or libc`,
        );
      }
      const expectedPlatformNames = windowsSpawnPackages
        .filter((candidate) => candidate.kind === "platform")
        .map((candidate) => candidate.name)
        .sort();
      const actualPlatformNames = Object.keys(
        manifest.optionalDependencies ?? {},
      ).sort();
      if (
        actualPlatformNames.length !== expectedPlatformNames.length ||
        actualPlatformNames.some(
          (name, index) => name !== expectedPlatformNames[index],
        )
      ) {
        failures.push(
          `${definition.name} must declare only the two platform packages as optional dependencies`,
        );
      }
      for (const name of expectedPlatformNames) {
        if (manifest.optionalDependencies?.[name] !== pkg.version) {
          failures.push(
            `${definition.name} dependency ${name} must exactly match the launcher version`,
          );
        }
      }
      if (manifest.goatNativeAbi !== windowsSpawnAbiVersion) {
        failures.push(
          `${definition.name} must declare goatNativeAbi ${windowsSpawnAbiVersion}`,
        );
      }
      if (manifest.main !== "index.js" || manifest.types !== "index.d.ts") {
        failures.push(
          `${definition.name} must expose only its checked-in JavaScript loader and types`,
        );
      }
      try {
        const wrapperSource = ["index.js", "loader.js"]
          .map((file) =>
            fs.readFileSync(
              path.join(root, definition.directory, file),
              "utf8",
            ),
          )
          .join("\n");
        if (
          !wrapperSource.includes("WINDOWS_PRIVACY_SPAWN_ABI_VERSION") ||
          !new RegExp(
            `WINDOWS_PRIVACY_SPAWN_ABI_VERSION\\s*=\\s*${windowsSpawnAbiVersion}(?:\\D|$)`,
          ).test(wrapperSource)
        ) {
          failures.push(
            `${definition.name} must export native ABI version ${windowsSpawnAbiVersion}`,
          );
        }
      } catch {
        failures.push(`${definition.name} JavaScript loader is missing`);
      }
    } else {
      if (
        JSON.stringify(manifest.os) !== JSON.stringify(["win32"]) ||
        JSON.stringify(manifest.cpu) !== JSON.stringify([definition.cpu]) ||
        "libc" in manifest
      ) {
        failures.push(
          `${definition.name} must declare only win32/${definition.cpu} platform constraints`,
        );
      }
      if (manifest.goatNativeAbi !== windowsSpawnAbiVersion) {
        failures.push(
          `${definition.name} must declare goatNativeAbi ${windowsSpawnAbiVersion}`,
        );
      }
      if (Object.keys(manifest.optionalDependencies ?? {}).length > 0) {
        failures.push(
          `${definition.name} must not have optional runtime dependencies`,
        );
      }
      if (
        manifest.main !==
          `goatcli-windows-spawn.win32-${definition.cpu}-msvc.node` ||
        !isSafeRelativePath(manifest.main)
      ) {
        failures.push(`${definition.name} main must be its native .node file`);
      }
    }

    const expectedFiles =
      definition.kind === "wrapper"
        ? [
            "LICENSE",
            "NOTICE",
            "README.md",
            "index.d.ts",
            "index.js",
            "loader.js",
          ]
        : [
            "LICENSE",
            "NOTICE",
            "README.md",
            `goatcli-windows-spawn.win32-${definition.cpu}-msvc.node`,
          ];
    const actualFiles = Array.isArray(manifest.files)
      ? [...manifest.files].sort()
      : [];
    if (
      actualFiles.length !== expectedFiles.length ||
      actualFiles.some((file, index) => file !== expectedFiles[index])
    ) {
      failures.push(`${definition.name} has an unexpected files allowlist`);
    }

    for (const optionalName of Object.keys(
      manifest.optionalDependencies ?? {},
    )) {
      if (!definitionsByName.has(optionalName)) {
        failures.push(
          `${definition.name} contains an unexpected optional dependency`,
        );
      }
    }
  }
}

function packAndValidateNativePackage(
  npmCli,
  temporaryRoot,
  definition,
  attempt,
) {
  const destination = path.join(
    temporaryRoot,
    `${definition.name.replaceAll("/", "-").replaceAll("@", "")}-${attempt}`,
  );
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
      "--workspace",
      definition.name,
    ],
    `npm pack ${definition.name}`,
  );
  let parsed;
  try {
    parsed = JSON.parse(packed);
  } catch {
    throw artifactError(`${definition.name} npm pack returned invalid JSON`);
  }
  if (!Array.isArray(parsed) || parsed.length !== 1) {
    throw artifactError(
      `${definition.name} npm pack must return exactly one artifact`,
    );
  }
  const metadata = parsed[0];
  if (
    !metadata ||
    typeof metadata.filename !== "string" ||
    metadata.filename !== path.basename(metadata.filename) ||
    !Array.isArray(metadata.files)
  ) {
    throw artifactError(`${definition.name} returned unsafe npm metadata`);
  }

  const archivePath = resolveChildPath(destination, metadata.filename);
  const archiveBytes = fs.readFileSync(archivePath);
  const sha1 = digest("sha1", archiveBytes, "hex");
  const sha256 = digest("sha256", archiveBytes, "hex");
  const sha512Integrity = "sha512-" + digest("sha512", archiveBytes, "base64");
  if (
    metadata.size !== archiveBytes.length ||
    metadata.shasum !== sha1 ||
    metadata.integrity !== sha512Integrity
  ) {
    throw artifactError(`${definition.name} npm integrity metadata differs`);
  }

  const metadataPaths = validateNativePackedMetadata(
    metadata.files,
    definition,
  );
  const archivePaths = listArchivePaths(archivePath);
  assertSamePaths(
    archivePaths,
    metadataPaths.map((filePath) => `package/${filePath}`).sort(),
    `${definition.name} archive headers and npm metadata differ`,
  );
  assertRegularArchiveHeaders(archivePath, archivePaths.length);

  const extractionRoot = path.join(destination, "extracted");
  fs.mkdirSync(extractionRoot);
  runCommand(
    "tar",
    ["-xzf", path.basename(archivePath), "-C", extractionRoot],
    `${definition.name} artifact extraction`,
    { cwd: destination },
  );
  const packageRoot = resolveChildPath(extractionRoot, "package");
  assertSamePaths(
    walkRegularFiles(packageRoot),
    metadataPaths,
    `${definition.name} extracted files and npm metadata differ`,
  );
  validateNativePackedPackageJson(packageRoot, definition);
  scanNativePackedFiles(metadata.files, packageRoot, definition);
  if (
    definition.kind === "platform" &&
    process.platform === "win32" &&
    process.arch === definition.cpu
  ) {
    validateLoadableNativeBinding(packageRoot, definition);
  }

  return {
    name: definition.name,
    filename: metadata.filename,
    bytes: archiveBytes.length,
    sha256,
    sha512Integrity,
    fileCount: metadataPaths.length,
  };
}

function validateNativePackedMetadata(fileEntries, definition) {
  const paths = [];
  const seen = new Set();
  for (const entry of fileEntries) {
    if (
      !entry ||
      typeof entry.path !== "string" ||
      !Number.isSafeInteger(entry.size) ||
      entry.size < 0
    ) {
      throw artifactError(`${definition.name} has invalid npm file metadata`);
    }
    const normalized = entry.path.replaceAll("\\", "/");
    if (!isSafeRelativePath(normalized) || seen.has(normalized)) {
      throw artifactError(
        `${definition.name} has an unsafe or duplicate packed path`,
      );
    }
    const allowedPaths =
      definition.kind === "wrapper"
        ? new Set([
            "package.json",
            "README.md",
            "LICENSE",
            "NOTICE",
            "index.js",
            "loader.js",
            "index.d.ts",
          ])
        : new Set([
            "package.json",
            "README.md",
            "LICENSE",
            "NOTICE",
            `goatcli-windows-spawn.win32-${definition.cpu}-msvc.node`,
          ]);
    if (!allowedPaths.has(normalized)) {
      throw artifactError(
        `${definition.name} contains unexpected packed file ${normalized}`,
      );
    }
    seen.add(normalized);
    paths.push(normalized);
  }
  for (const required of ["package.json", "README.md", "LICENSE", "NOTICE"]) {
    if (!seen.has(required)) {
      throw artifactError(`${definition.name} is missing ${required}`);
    }
  }
  if (definition.kind === "wrapper") {
    for (const required of ["index.js", "loader.js", "index.d.ts"]) {
      if (!seen.has(required)) {
        throw artifactError(`${definition.name} is missing ${required}`);
      }
    }
  }
  const nativeFiles = paths.filter((filePath) => filePath.endsWith(".node"));
  if (definition.kind === "wrapper" && nativeFiles.length !== 0) {
    throw artifactError("wrapper package must remain native-binary-free");
  }
  if (definition.kind === "platform" && nativeFiles.length !== 1) {
    throw artifactError(
      `${definition.name} must contain exactly one native binary`,
    );
  }
  const expectedCount = definition.kind === "wrapper" ? 7 : 5;
  if (paths.length !== expectedCount) {
    throw artifactError(`${definition.name} packed file allowlist differs`);
  }
  return paths.sort();
}

function validateLoadableNativeBinding(packageRoot, definition) {
  const manifest = JSON.parse(
    fs.readFileSync(resolveChildPath(packageRoot, "package.json"), "utf8"),
  );
  const binaryPath = resolveChildPath(packageRoot, manifest.main);
  const testOnlyExports = [
    "createInheritableEventForTest",
    "isHandleValidForTest",
    "isHandleInheritableForTest",
    "isFdInheritableForTest",
    "closeHandleForTest",
  ];
  // Probe in a short-lived process so Windows unloads the DLL before the
  // verifier removes the extracted package directory.
  const probeSource = `
    "use strict";
    const binding = require(process.argv[1]);
    const testOnlyExports = ${JSON.stringify(testOnlyExports)};
    process.stdout.write(JSON.stringify({
      exportNames: Object.keys(binding).sort(),
      abi: binding.WINDOWS_PRIVACY_SPAWN_ABI_VERSION,
      spawnType: typeof binding.spawnWindowsPrivacyProcess,
      processType: typeof binding.SpawnedWindowsPrivacyProcess,
      processExportNames:
        typeof binding.SpawnedWindowsPrivacyProcess === "function"
          ? Object.getOwnPropertyNames(
              binding.SpawnedWindowsPrivacyProcess.prototype,
            ).sort()
          : [],
      presentTestExports: testOnlyExports.filter((name) => name in binding),
    }));
  `;
  const probe = spawnSync(process.execPath, ["-e", probeSource, binaryPath], {
    cwd: packageRoot,
    encoding: "utf8",
    windowsHide: true,
    shell: false,
    timeout: 10_000,
    maxBuffer: 64 * 1024,
  });
  if (probe.error || probe.status !== 0) {
    throw artifactError(`${definition.name} native binary could not be loaded`);
  }
  let binding;
  try {
    binding = JSON.parse(probe.stdout);
  } catch {
    throw artifactError(`${definition.name} native load probe was invalid`);
  }
  const expectedExports = [
    "SpawnedWindowsPrivacyProcess",
    "WINDOWS_PRIVACY_SPAWN_ABI_VERSION",
    "spawnWindowsPrivacyProcess",
  ].sort();
  if (!Array.isArray(binding.exportNames)) {
    throw artifactError(`${definition.name} native export probe was invalid`);
  }
  assertSamePaths(
    binding.exportNames,
    expectedExports,
    `${definition.name} native export surface differs`,
  );
  if (
    binding.abi !== windowsSpawnAbiVersion ||
    binding.spawnType !== "function" ||
    binding.processType !== "function"
  ) {
    throw artifactError(`${definition.name} native ABI validation failed`);
  }
  const expectedProcessExports = [
    "close",
    "constructor",
    "pid",
    "takeLauncherReadFd",
    "takeLauncherWriteFd",
    "terminate",
  ].sort();
  if (!Array.isArray(binding.processExportNames)) {
    throw artifactError(
      `${definition.name} native process export probe was invalid`,
    );
  }
  assertSamePaths(
    binding.processExportNames,
    expectedProcessExports,
    `${definition.name} native process export surface differs`,
  );
  if (
    !Array.isArray(binding.presentTestExports) ||
    binding.presentTestExports.length > 0
  ) {
    throw artifactError(
      `${definition.name} contains a test-only native export`,
    );
  }
}

function validateNativePackedPackageJson(packageRoot, definition) {
  let manifest;
  try {
    manifest = JSON.parse(
      fs.readFileSync(resolveChildPath(packageRoot, "package.json"), "utf8"),
    );
  } catch {
    throw artifactError(`${definition.name} packed package.json is invalid`);
  }
  if (manifest.name !== definition.name || manifest.version !== pkg.version) {
    throw artifactError(
      `${definition.name} packed identity differs from the release input`,
    );
  }
  const sourceManifest = JSON.parse(
    fs.readFileSync(
      path.join(root, definition.directory, "package.json"),
      "utf8",
    ),
  );
  for (const field of [
    "name",
    "version",
    "main",
    "types",
    "license",
    "engines",
    "os",
    "cpu",
    "goatNativeAbi",
    "dependencies",
    "optionalDependencies",
    "publishConfig",
    "exports",
    "files",
  ]) {
    if (
      JSON.stringify(manifest[field]) !== JSON.stringify(sourceManifest[field])
    ) {
      throw artifactError(
        `${definition.name} packed ${field} metadata differs from its source manifest`,
      );
    }
  }
  if (hasInstallLifecycle(manifest)) {
    throw artifactError(
      `${definition.name} contains an unexpected install lifecycle script`,
    );
  }
}

function scanNativePackedFiles(fileEntries, packageRoot, definition) {
  for (const entry of fileEntries) {
    const normalized = entry.path.replaceAll("\\", "/");
    const resolved = resolveChildPath(packageRoot, normalized);
    const raw = fs.readFileSync(resolved);
    if (raw.length !== entry.size) {
      throw artifactError(`${definition.name} packed file size differs`);
    }
    if (normalized.endsWith(".node")) {
      validatePeMachine(raw, definition);
      const binaryText = raw.toString("latin1");
      if (
        /BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY|AKIA[0-9A-Z]{16}|gh[opsr]_[a-zA-Z0-9]{36}/.test(
          binaryText,
        )
      ) {
        throw artifactError(
          `${definition.name} native artifact may contain secret material`,
        );
      }
      if (
        /@opentelemetry\/|@sentry\/|posthog|newrelic|@datadog\//i.test(
          binaryText,
        )
      ) {
        throw artifactError(
          `${definition.name} native artifact contains forbidden telemetry material`,
        );
      }
      continue;
    }
    if (containsBinaryPayload(raw)) {
      throw artifactError(
        `${definition.name} contains unexpected binary content in ${normalized}`,
      );
    }
    const contents = raw.toString("utf8");
    if (
      /BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY|BEGIN\s+OPENSSH\s+PRIVATE\s+KEY|\b(?:api[_-]?key|password|token)\s*[:=]/i.test(
        contents,
      )
    ) {
      throw artifactError(
        `${definition.name} may contain secret material in ${normalized}`,
      );
    }
    if (
      /@opentelemetry\/|@sentry\/|posthog|newrelic|@datadog\//i.test(contents)
    ) {
      throw artifactError(
        `${definition.name} contains forbidden telemetry material`,
      );
    }
  }
}

function validatePeMachine(raw, definition) {
  if (raw.length < 0x40 || raw[0] !== 0x4d || raw[1] !== 0x5a) {
    throw artifactError(`${definition.name} native artifact is not PE/COFF`);
  }
  const peOffset = raw.readUInt32LE(0x3c);
  if (
    peOffset > raw.length - 6 ||
    raw[peOffset] !== 0x50 ||
    raw[peOffset + 1] !== 0x45 ||
    raw[peOffset + 2] !== 0 ||
    raw[peOffset + 3] !== 0
  ) {
    throw artifactError(`${definition.name} has an invalid PE header`);
  }
  if (raw.readUInt16LE(peOffset + 4) !== definition.peMachine) {
    throw artifactError(`${definition.name} PE architecture does not match`);
  }
}

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
    packedPackage.bin?.goat !== pkg.bin.goat ||
    JSON.stringify(packedPackage.napi) !== JSON.stringify(pkg.napi)
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
  for (const name of expectedDependencies) {
    if (packedPackage.dependencies?.[name] !== pkg.dependencies?.[name]) {
      throw artifactError(
        "packed runtime dependency versions differ from package.json",
      );
    }
  }
  const expectedOptionalDependencies = Object.keys(
    pkg.optionalDependencies ?? {},
  ).sort();
  const packedOptionalDependencies = Object.keys(
    packedPackage.optionalDependencies ?? {},
  ).sort();
  assertSamePaths(
    packedOptionalDependencies,
    expectedOptionalDependencies,
    "packed optional dependency declarations differ from package.json",
  );
  for (const name of expectedOptionalDependencies) {
    if (
      packedPackage.optionalDependencies?.[name] !==
      pkg.optionalDependencies?.[name]
    ) {
      throw artifactError(
        "packed optional dependency versions differ from package.json",
      );
    }
  }
  if (hasInstallLifecycle(packedPackage)) {
    throw artifactError(
      "packed package contains an unexpected install lifecycle script",
    );
  }
}

function inspectProductionDependencyGraph(npmCli) {
  if (!npmCli) return;
  try {
    const output = runCommand(
      process.execPath,
      [
        npmCli,
        "ls",
        "--offline",
        "--omit=dev",
        "--all",
        "--json",
        "--package-lock-only",
      ],
      "production dependency graph",
    );
    const graph = JSON.parse(output);
    const unexpectedProblems = Array.isArray(graph.problems)
      ? graph.problems.filter(
          (problem) =>
            typeof problem !== "string" || !problem.startsWith("extraneous:"),
        )
      : [];
    if (unexpectedProblems.length > 0) {
      throw artifactError("production dependency graph is incomplete");
    }
    const productionRoots = Object.fromEntries(
      Object.entries(graph.dependencies ?? {}).filter(
        ([, dependency]) =>
          !dependency ||
          typeof dependency !== "object" ||
          dependency.extraneous !== true,
      ),
    );
    const requiredTopLevel = Object.keys(pkg.dependencies ?? {}).sort();
    const optionalTopLevel = Object.keys(pkg.optionalDependencies ?? {}).sort();
    const workspacePackageNames = windowsSpawnPackages
      .map((definition) => definition.name)
      .sort();
    const allowedTopLevel = [
      ...new Set([
        ...requiredTopLevel,
        ...optionalTopLevel,
        ...workspacePackageNames,
      ]),
    ].sort();
    const actualTopLevel = Object.keys(productionRoots).sort();
    const missingRequired = requiredTopLevel.filter(
      (name) => !actualTopLevel.includes(name),
    );
    const unexpected = actualTopLevel.filter(
      (name) => !allowedTopLevel.includes(name),
    );
    if (missingRequired.length > 0 || unexpected.length > 0) {
      throw artifactError(
        "installed production dependency roots differ from package.json",
      );
    }

    const packages = flattenDependencyGraph(productionRoots);
    for (const definition of enginePackages) {
      const installed = packages.filter(
        (dependency) => dependency.name === definition.name,
      );
      if (
        installed.some(
          (dependency) => dependency.version !== enginePackageVersion,
        )
      ) {
        throw artifactError(
          `installed GOAT engine dependency ${definition.name} has the wrong version`,
        );
      }
    }
    if (process.platform === "win32" || process.platform === "darwin") {
      const expectedEnginePackage = enginePackages.find(
        (definition) =>
          definition.os === process.platform && definition.cpu === process.arch,
      );
      if (
        expectedEnginePackage &&
        !packages.some(
          (dependency) =>
            dependency.name === expectedEnginePackage.name &&
            dependency.version === enginePackageVersion,
        )
      ) {
        throw artifactError(
          `installed GOAT engine dependency ${expectedEnginePackage.name} is missing or has the wrong version`,
        );
      }
    }
    for (const definition of windowsSpawnPackages) {
      const installed = packages.filter(
        (dependency) => dependency.name === definition.name,
      );
      if (installed.some((dependency) => dependency.version !== pkg.version)) {
        throw artifactError(
          `installed Windows native dependency ${definition.name} has the wrong version`,
        );
      }
    }
    if (process.platform === "win32") {
      const expectedPlatformPackage =
        process.arch === "x64"
          ? "goatcli-windows-spawn-win32-x64-msvc"
          : process.arch === "arm64"
            ? "goatcli-windows-spawn-win32-arm64-msvc"
            : undefined;
      const requiredNativeNames = ["goatcli-windows-spawn"];
      if (expectedPlatformPackage) {
        requiredNativeNames.push(expectedPlatformPackage);
      }
      for (const name of requiredNativeNames) {
        if (
          !packages.some(
            (dependency) =>
              dependency.name === name && dependency.version === pkg.version,
          )
        ) {
          throw artifactError(
            `installed Windows native dependency ${name} is missing or has the wrong version`,
          );
        }
      }
    }
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
      source: "npm ls --omit=dev --all --json --package-lock-only",
      topLevel: actualTopLevel,
      omittedOptionalRoots: optionalTopLevel.filter(
        (name) => !actualTopLevel.includes(name),
      ),
      linkedWorkspaceRoots: actualTopLevel.filter(
        (name) =>
          workspacePackageNames.includes(name) &&
          !requiredTopLevel.includes(name) &&
          !optionalTopLevel.includes(name),
      ),
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
      if (value && typeof value === "object" && value.extraneous === true) {
        continue;
      }
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

function hasInstallLifecycle(manifest) {
  return ["preinstall", "install", "postinstall"].some(
    (script) => typeof manifest.scripts?.[script] === "string",
  );
}

function assertNoInstallLifecycle(manifest, label, targetFailures) {
  if (hasInstallLifecycle(manifest)) {
    targetFailures.push(`${label} must not contain install lifecycle scripts`);
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

function isValidReleaseVersion(version) {
  return (
    typeof version === "string" &&
    /^\d+\.\d+\.\d+(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/.test(
      version,
    )
  );
}

function safeErrorMessage(error) {
  return error instanceof Error && error.name === "ArtifactVerificationError"
    ? error.message
    : "unexpected verifier failure";
}

function parseOptions(args) {
  const options = {
    nativePackages: false,
    nativePackageNames: [],
    reportPath: undefined,
  };
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === "--native-packages") {
      options.nativePackages = true;
      continue;
    }
    if (argument === "--native-package" && args[index + 1]) {
      const packageName = args[index + 1];
      const definition = windowsSpawnPackages.find(
        (candidate) => candidate.name === packageName,
      );
      if (!definition || definition.kind !== "platform") {
        failures.push("--native-package must name a Windows platform package");
      } else if (!options.nativePackageNames.includes(packageName)) {
        options.nativePackageNames.push(packageName);
      }
      options.nativePackages = true;
      index += 1;
      continue;
    }
    if (argument === "--report" && args[index + 1]) {
      options.reportPath = path.resolve(args[index + 1]);
      index += 1;
      continue;
    }
    failures.push(
      "usage: verify-package.mjs [--native-packages] [--native-package <name>] [--report <path>]",
    );
    break;
  }
  return options;
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
