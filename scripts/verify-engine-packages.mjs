import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import {
  createHash,
  createPublicKey,
  verify as verifySignature,
} from "node:crypto";

const root = process.cwd();
const packageJson = JSON.parse(
  fs.readFileSync(path.join(root, "package.json"), "utf8"),
);
const policySource = fs.readFileSync(
  path.join(root, "src/privacy/release-policy.generated.ts"),
  "utf8",
);
const packageDefinitions = [
  {
    name: "goat-engine-windows-x64",
    platform: "win32",
    architecture: "x64",
    executable: "goat-engine.exe",
  },
  {
    name: "goat-engine-windows-arm64",
    platform: "win32",
    architecture: "arm64",
    executable: "goat-engine.exe",
  },
  {
    name: "goat-engine-darwin-x64",
    platform: "darwin",
    architecture: "x64",
    executable: "goat-engine",
  },
  {
    name: "goat-engine-darwin-arm64",
    platform: "darwin",
    architecture: "arm64",
    executable: "goat-engine",
  },
];
const engineVersion =
  packageJson.optionalDependencies?.[packageDefinitions[0].name];
for (const definition of packageDefinitions) {
  if (packageJson.optionalDependencies?.[definition.name] !== engineVersion) {
    throw new Error(
      `${definition.name} is not pinned to the common engine version`,
    );
  }
}
const policyDigest = policySource.match(
  /GOAT_RELEASE_POLICY_SOURCE_SHA256\s*=\s*"([a-f0-9]{64})"/,
)?.[1];
const keyIds = [
  ...(
    policySource.match(/"engineManifestKeyIds"\s*:\s*\[([\s\S]*?)\]/)?.[1] ?? ""
  ).matchAll(/"([a-f0-9]{64})"/g),
].map((match) => match[1]);

if (
  typeof engineVersion !== "string" ||
  !/^\d+\.\d+\.\d+$/.test(engineVersion)
) {
  throw new Error("launcher engine dependency version is invalid");
}
if (!policyDigest || keyIds.length === 0) {
  throw new Error(
    "launcher release policy has no approved engine-manifest signing key; refusing production engine use",
  );
}

const npmCli = process.env.npm_execpath;
if (!npmCli) throw new Error("npm executable path is unavailable");
const temporaryRoot = fs.mkdtempSync(
  path.join(os.tmpdir(), "goatcli-engine-package-verification-"),
);
try {
  for (const definition of packageDefinitions) {
    verifyPackage(npmCli, temporaryRoot, definition);
  }
} finally {
  fs.rmSync(temporaryRoot, { recursive: true, force: true });
}

function verifyPackage(npmCliPath, destinationRoot, definition) {
  const destination = path.join(destinationRoot, definition.name);
  fs.mkdirSync(destination);
  const output = run(
    process.execPath,
    [
      npmCliPath,
      "pack",
      `${definition.name}@${engineVersion}`,
      "--json",
      "--ignore-scripts",
      "--pack-destination",
      destination,
    ],
    `npm pack ${definition.name}`,
  );
  let metadata;
  try {
    const parsed = JSON.parse(output);
    if (!Array.isArray(parsed) || parsed.length !== 1) throw new Error();
    metadata = parsed[0];
  } catch {
    throw new Error(`${definition.name} returned invalid npm pack metadata`);
  }
  if (
    !metadata ||
    typeof metadata.filename !== "string" ||
    metadata.filename !== path.basename(metadata.filename)
  ) {
    throw new Error(`${definition.name} returned an unsafe npm archive name`);
  }
  const archive = path.join(destination, metadata.filename);
  const archiveStats = fs.lstatSync(archive);
  if (!archiveStats.isFile() || archiveStats.isSymbolicLink()) {
    throw new Error(`${definition.name} did not produce a regular npm archive`);
  }
  const executableRelative = `bin/${definition.executable}`;
  const expectedFiles = [
    "goat-engine.json",
    "package.json",
    executableRelative,
  ].sort((a, b) => a.localeCompare(b));
  assertSafeArchive(archive, expectedFiles, definition.name);

  const extracted = path.join(destination, "extracted");
  fs.mkdirSync(extracted);
  run(
    "tar",
    [
      "--extract",
      "--gzip",
      "--file",
      archive,
      "--directory",
      extracted,
      "--no-same-owner",
      "--no-same-permissions",
    ],
    `${definition.name} extraction`,
  );
  const packageRoot = path.join(extracted, "package");
  const actualFiles = walk(packageRoot).sort((a, b) => a.localeCompare(b));
  if (JSON.stringify(actualFiles) !== JSON.stringify(expectedFiles)) {
    throw new Error(`${definition.name} tarball contains unexpected files`);
  }

  const packageManifest = readJson(path.join(packageRoot, "package.json"));
  if (
    packageManifest.name !== definition.name ||
    packageManifest.version !== engineVersion ||
    packageManifest.license !== "MIT" ||
    packageManifest.preferUnplugged !== true ||
    JSON.stringify(packageManifest.os) !==
      JSON.stringify([definition.platform]) ||
    JSON.stringify(packageManifest.cpu) !==
      JSON.stringify([definition.architecture]) ||
    packageManifest.publishConfig?.access !== "public" ||
    packageManifest.publishConfig?.provenance !== true ||
    JSON.stringify(packageManifest.files) !==
      JSON.stringify(["bin", "goat-engine.json"]) ||
    packageManifest.scripts !== undefined ||
    Object.keys(packageManifest.dependencies ?? {}).length !== 0 ||
    Object.keys(packageManifest.optionalDependencies ?? {}).length !== 0
  ) {
    throw new Error(
      `${definition.name} package metadata is not an approved engine package`,
    );
  }

  const executableBytes = fs.readFileSync(
    path.join(packageRoot, executableRelative),
  );
  const manifest = readJson(path.join(packageRoot, "goat-engine.json"));
  if (
    manifest.manifestVersion !== 1 ||
    manifest.releasePolicyDigest !== policyDigest ||
    manifest.engineVersion !== engineVersion ||
    manifest.platform !== definition.platform ||
    manifest.architecture !== definition.architecture ||
    manifest.executablePath !== executableRelative ||
    manifest.releaseChannel !== "stable" ||
    manifest.checksum?.algorithm !== "sha256" ||
    manifest.checksum.value !== sha256(executableBytes) ||
    manifest.signature?.status !== "signed" ||
    !keyIds.includes(manifest.signature.keyId)
  ) {
    throw new Error(
      `${definition.name} manifest is not a trusted stable engine manifest`,
    );
  }
  verifyManifestSignature(manifest);
}

function verifyManifestSignature(manifest) {
  const publicKeyBytes = Buffer.from(manifest.signature.publicKey, "base64url");
  const signatureBytes = Buffer.from(manifest.signature.value, "base64url");
  if (
    publicKeyBytes.length === 0 ||
    signatureBytes.length !== 64 ||
    sha256(publicKeyBytes) !== manifest.signature.keyId
  ) {
    throw new Error("engine manifest signature encoding is invalid");
  }
  let publicKey;
  try {
    publicKey = createPublicKey({
      key: publicKeyBytes,
      format: "der",
      type: "spki",
    });
  } catch {
    throw new Error("engine manifest public key is invalid");
  }
  if (
    publicKey.asymmetricKeyType !== "ed25519" ||
    !verifySignature(
      null,
      Buffer.from(canonicalPayload(manifest), "utf8"),
      publicKey,
      signatureBytes,
    )
  ) {
    throw new Error("engine manifest signature verification failed");
  }
}

function canonicalPayload(manifest) {
  return JSON.stringify({
    manifestVersion: manifest.manifestVersion,
    releasePolicyDigest: manifest.releasePolicyDigest,
    engineVersion: manifest.engineVersion,
    platform: manifest.platform,
    architecture: manifest.architecture,
    executablePath: manifest.executablePath,
    releaseChannel: manifest.releaseChannel,
    checksum: {
      algorithm: manifest.checksum.algorithm,
      value: manifest.checksum.value,
    },
    compatibility:
      manifest.compatibility.maximumLauncherVersion === undefined
        ? {
            minimumLauncherVersion:
              manifest.compatibility.minimumLauncherVersion,
          }
        : {
            minimumLauncherVersion:
              manifest.compatibility.minimumLauncherVersion,
            maximumLauncherVersion:
              manifest.compatibility.maximumLauncherVersion,
          },
  });
}

function assertSafeArchive(archive, expectedFiles, name) {
  const entries = run(
    "tar",
    ["--list", "--gzip", "--file", archive],
    `${name} archive listing`,
  )
    .split(/\r?\n/)
    .filter(Boolean);
  const expectedEntries = expectedFiles.map((file) => `package/${file}`);
  if (
    entries.some(
      (entry) =>
        entry.includes(String.fromCharCode(0)) ||
        entry.includes("\\") ||
        !entry.startsWith("package/") ||
        path.posix.normalize(entry) !== entry,
    ) ||
    JSON.stringify([...entries].sort((a, b) => a.localeCompare(b))) !==
      JSON.stringify(expectedEntries)
  ) {
    throw new Error(`${name} archive contains unsafe or unexpected paths`);
  }

  const headers = run(
    "tar",
    ["--list", "--verbose", "--gzip", "--file", archive],
    `${name} archive header inspection`,
  )
    .split(/\r?\n/)
    .filter(Boolean);
  if (
    headers.length !== entries.length ||
    headers.some((header) => !header.startsWith("-"))
  ) {
    throw new Error(`${name} archive contains a link or non-regular entry`);
  }
}

function walk(directory, relative = "") {
  const files = [];
  for (const name of fs.readdirSync(directory)) {
    const childRelative = relative ? `${relative}/${name}` : name;
    const child = path.join(directory, name);
    const stats = fs.lstatSync(child);
    if (stats.isSymbolicLink()) {
      throw new Error("engine tarball contains a symbolic link");
    }
    if (stats.isDirectory()) files.push(...walk(child, childRelative));
    else if (stats.isFile()) {
      files.push(childRelative.replaceAll("\\", "/"));
    } else {
      throw new Error("engine tarball contains a non-regular entry");
    }
  }
  return files;
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function run(command, args, label) {
  const result = spawnSync(command, args, {
    cwd: root,
    encoding: "utf8",
    shell: false,
    windowsHide: true,
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.error || result.status !== 0) {
    throw new Error(`${label} failed`);
  }
  return result.stdout;
}
