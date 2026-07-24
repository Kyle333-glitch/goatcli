import fs from "node:fs/promises";
import {
  deletePassword,
  getPassword,
  setPassword,
} from "@napi-rs/keyring/keytar.js";
import { getConfigDir } from "../utils/paths.js";
import { getPathModule } from "../platform.js";
import type { CredentialStore, GoatCredentials } from "./types.js";

const SERVICE = "goatcli";
const ACCOUNT = "goat-auth";
const TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const ISO_TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const CREDENTIAL_KEYS = [
  "accessToken",
  "refreshToken",
  "tokenType",
  "accessTokenExpiresAt",
  "refreshTokenExpiresAt",
] as const;
const LEGACY_CREDENTIAL_MAX_BYTES = 4 * 1024;

export type CredentialStoreErrorCode =
  | "GOAT_CREDENTIAL_STORE_UNAVAILABLE"
  | "GOAT_CREDENTIALS_INVALID"
  | "GOAT_CREDENTIAL_MIGRATION_FAILED";

export class CredentialStoreError extends Error {
  constructor(readonly code: CredentialStoreErrorCode) {
    super(credentialStoreErrorMessage(code));
    this.name = "CredentialStoreError";
  }
}

export interface KeyringLike {
  getPassword(service: string, account: string): Promise<string | null>;
  setPassword(
    service: string,
    account: string,
    password: string,
  ): Promise<void>;
  deletePassword(service: string, account: string): Promise<boolean>;
}

export interface CredentialStoreOptions {
  platform?: NodeJS.Platform;
  env?: NodeJS.ProcessEnv;
  homeDir?: string;
  keyring?: KeyringLike;
}

export function createCredentialStore(
  options: CredentialStoreOptions = {},
): CredentialStore {
  const keyring = options.keyring ?? {
    getPassword,
    setPassword,
    deletePassword,
  };
  const platform = options.platform ?? process.platform;
  const pathModule = getPathModule(platform);
  const legacyPath = pathModule.join(
    getConfigDir({
      platform,
      env: options.env,
      homeDir: options.homeDir,
    }),
    "auth.json",
  );

  async function readKeyring(): Promise<GoatCredentials | null> {
    let raw: string | null;
    try {
      raw = await keyring.getPassword(SERVICE, ACCOUNT);
    } catch {
      throw new CredentialStoreError("GOAT_CREDENTIAL_STORE_UNAVAILABLE");
    }
    if (raw === null) return null;
    const parsed = parseCredentials(raw);
    if (!parsed) throw new CredentialStoreError("GOAT_CREDENTIALS_INVALID");
    return parsed;
  }

  async function migrateLegacy(): Promise<GoatCredentials | null> {
    const raw = await readLegacyFile(legacyPath);
    if (raw === null) {
      await cleanupStaleTemps(legacyPath, platform);
      return null;
    }
    const credentials = parseCredentials(raw);
    if (!credentials)
      throw new CredentialStoreError("GOAT_CREDENTIALS_INVALID");
    try {
      await keyring.setPassword(SERVICE, ACCOUNT, JSON.stringify(credentials));
      const verified = await readKeyring();
      if (!verified || !sameCredentials(credentials, verified)) {
        throw new CredentialStoreError("GOAT_CREDENTIAL_MIGRATION_FAILED");
      }
    } catch (error) {
      if (error instanceof CredentialStoreError) throw error;
      throw new CredentialStoreError("GOAT_CREDENTIAL_MIGRATION_FAILED");
    }

    await cleanupLegacy(legacyPath, platform);
    return credentials;
  }

  return {
    async get() {
      const credentials = await readKeyring();
      if (!credentials) return migrateLegacy();
      await cleanupLegacy(legacyPath, platform);
      return credentials;
    },
    async set(credentials) {
      const validated = reconstructCredentials(credentials);
      if (!validated)
        throw new CredentialStoreError("GOAT_CREDENTIALS_INVALID");
      try {
        await keyring.setPassword(SERVICE, ACCOUNT, JSON.stringify(validated));
        const verified = await readKeyring();
        if (!verified || !sameCredentials(validated, verified)) {
          throw new CredentialStoreError("GOAT_CREDENTIAL_STORE_UNAVAILABLE");
        }
      } catch (error) {
        if (error instanceof CredentialStoreError) throw error;
        throw new CredentialStoreError("GOAT_CREDENTIAL_STORE_UNAVAILABLE");
      }
      await cleanupLegacy(legacyPath, platform);
    },
    async delete() {
      // Remove plaintext first so a failed cleanup cannot be silently remigrated.
      await cleanupLegacy(legacyPath, platform);
      try {
        await keyring.deletePassword(SERVICE, ACCOUNT);
      } catch {
        throw new CredentialStoreError("GOAT_CREDENTIAL_STORE_UNAVAILABLE");
      }
    },
  };
}

export async function refreshStoredCredentials(
  client: {
    refresh(
      refreshToken: string,
    ): Promise<{ status: string; credentials?: GoatCredentials }>;
    revoke(refreshToken: string): Promise<void>;
  },
  store: CredentialStore,
): Promise<GoatCredentials | null> {
  const current = await store.get();
  if (!current) return null;
  const result = await client.refresh(current.refreshToken);
  if (result.status !== "authorized" || !result.credentials) {
    if (
      ["invalid_grant", "revoked", "replay_detected", "expired"].includes(
        result.status,
      )
    ) {
      await store.delete();
    }
    return null;
  }
  try {
    await store.set(result.credentials);
  } catch (error) {
    await discardUnstoredCredential(
      client,
      store,
      result.credentials.refreshToken,
    );
    if (error instanceof CredentialStoreError) throw error;
    throw new CredentialStoreError("GOAT_CREDENTIAL_STORE_UNAVAILABLE");
  }
  return result.credentials;
}

async function discardUnstoredCredential(
  client: { revoke(refreshToken: string): Promise<void> },
  store: CredentialStore,
  refreshToken: string,
): Promise<void> {
  try {
    await client.revoke(refreshToken);
  } catch {
    // Best effort: never surface transport details or the credential.
  }
  try {
    await store.delete();
  } catch {
    // Preserve the fixed persistence failure returned by the caller.
  }
}

export function parseCredentials(raw: string): GoatCredentials | null {
  try {
    return reconstructCredentials(JSON.parse(raw));
  } catch {
    return null;
  }
}

function reconstructCredentials(value: unknown): GoatCredentials | null {
  if (!isExactObject(value, CREDENTIAL_KEYS)) return null;
  if (
    !isToken(value.accessToken) ||
    !isToken(value.refreshToken) ||
    value.tokenType !== "Bearer"
  )
    return null;
  if (
    !isTimestamp(value.accessTokenExpiresAt) ||
    !isTimestamp(value.refreshTokenExpiresAt)
  )
    return null;
  return {
    accessToken: value.accessToken,
    refreshToken: value.refreshToken,
    tokenType: "Bearer",
    accessTokenExpiresAt: value.accessTokenExpiresAt,
    refreshTokenExpiresAt: value.refreshTokenExpiresAt,
  };
}

function isExactObject<const T extends readonly string[]>(
  value: unknown,
  keys: T,
): value is Record<T[number], unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    return false;
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return (
    actual.length === expected.length &&
    actual.every((key, index) => key === expected[index])
  );
}

function isToken(value: unknown): value is string {
  return typeof value === "string" && TOKEN_PATTERN.test(value);
}

function isTimestamp(value: unknown): value is string {
  if (typeof value !== "string" || !ISO_TIMESTAMP_PATTERN.test(value))
    return false;
  const time = Date.parse(value);
  return Number.isFinite(time) && new Date(time).toISOString() === value;
}

function sameCredentials(
  left: GoatCredentials,
  right: GoatCredentials,
): boolean {
  return CREDENTIAL_KEYS.every((key) => left[key] === right[key]);
}

async function readLegacyFile(path: string): Promise<string | null> {
  let pathStats: Awaited<ReturnType<typeof fs.lstat>>;
  try {
    pathStats = await fs.lstat(path);
  } catch (error) {
    if (isMissing(error)) return null;
    throw new CredentialStoreError("GOAT_CREDENTIAL_MIGRATION_FAILED");
  }
  if (!pathStats.isFile()) {
    throw new CredentialStoreError("GOAT_CREDENTIALS_INVALID");
  }

  let handle: Awaited<ReturnType<typeof fs.open>>;
  try {
    handle = await fs.open(path, "r");
  } catch (error) {
    if (isMissing(error)) return null;
    throw new CredentialStoreError("GOAT_CREDENTIAL_MIGRATION_FAILED");
  }

  const bytes = Buffer.alloc(LEGACY_CREDENTIAL_MAX_BYTES + 1);
  try {
    let stats;
    try {
      stats = await handle.stat();
    } catch {
      throw new CredentialStoreError("GOAT_CREDENTIAL_MIGRATION_FAILED");
    }
    if (
      !stats.isFile() ||
      stats.size < 1 ||
      stats.size > LEGACY_CREDENTIAL_MAX_BYTES
    ) {
      throw new CredentialStoreError("GOAT_CREDENTIALS_INVALID");
    }

    let offset = 0;
    while (offset < bytes.byteLength) {
      let bytesRead: number;
      try {
        ({ bytesRead } = await handle.read(
          bytes,
          offset,
          bytes.byteLength - offset,
          null,
        ));
      } catch {
        throw new CredentialStoreError("GOAT_CREDENTIAL_MIGRATION_FAILED");
      }
      if (bytesRead === 0) break;
      offset += bytesRead;
    }
    if (offset < 1 || offset > LEGACY_CREDENTIAL_MAX_BYTES) {
      throw new CredentialStoreError("GOAT_CREDENTIALS_INVALID");
    }
    try {
      return new TextDecoder("utf-8", { fatal: true }).decode(
        bytes.subarray(0, offset),
      );
    } catch {
      throw new CredentialStoreError("GOAT_CREDENTIALS_INVALID");
    }
  } finally {
    bytes.fill(0);
    try {
      await handle.close();
    } catch {
      throw new CredentialStoreError("GOAT_CREDENTIAL_MIGRATION_FAILED");
    }
  }
}

async function cleanupLegacy(
  path: string,
  platform: NodeJS.Platform,
): Promise<void> {
  try {
    await fs.rm(path, { force: true });
  } catch {
    throw new CredentialStoreError("GOAT_CREDENTIAL_MIGRATION_FAILED");
  }
  await cleanupStaleTemps(path, platform);
}

async function cleanupStaleTemps(
  path: string,
  platform: NodeJS.Platform,
): Promise<void> {
  const pathModule = getPathModule(platform);
  const directory = pathModule.dirname(path);
  const baseName = pathModule.basename(path);
  let entries: string[];
  try {
    entries = await fs.readdir(directory);
  } catch (error) {
    if (isMissing(error)) return;
    throw new CredentialStoreError("GOAT_CREDENTIAL_MIGRATION_FAILED");
  }
  for (const entry of entries) {
    if (!entry.startsWith(`${baseName}.`) || !entry.endsWith(".tmp")) continue;
    try {
      await fs.rm(pathModule.join(directory, entry), { force: true });
    } catch {
      throw new CredentialStoreError("GOAT_CREDENTIAL_MIGRATION_FAILED");
    }
  }
}

function credentialStoreErrorMessage(code: CredentialStoreErrorCode): string {
  if (code === "GOAT_CREDENTIALS_INVALID") {
    return "Stored GOAT credentials are invalid. Run `goat login` again.";
  }
  if (code === "GOAT_CREDENTIAL_MIGRATION_FAILED") {
    return "GOAT could not migrate legacy credentials. Run `goat login` again.";
  }
  return "The OS credential store is unavailable. Check it and run `goat login` again.";
}

function isMissing(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    (error as { code?: unknown }).code === "ENOENT"
  );
}
