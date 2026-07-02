import fs from 'node:fs/promises';
import os from 'node:os';
import { randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { deletePassword, getPassword, setPassword } from '@napi-rs/keyring/keytar.js';
import { getConfigDir } from '../utils/paths.js';
import { getPathModule, replaceFileAtomically } from '../platform.js';
import type { CredentialStore, GoatCredentials } from './types.js';

const SERVICE = 'goatcli';
const ACCOUNT = 'goat-auth';

export interface KeyringLike {
  getPassword(service: string, account: string): Promise<string | null>;
  setPassword(service: string, account: string, password: string): Promise<void>;
  deletePassword(service: string, account: string): Promise<boolean>;
}

export interface CredentialStoreOptions {
  platform?: NodeJS.Platform;
  env?: NodeJS.ProcessEnv;
  homeDir?: string;
  keyring?: KeyringLike;
  allowFallback?: boolean;
  hardenWindowsAcl?: (filePath: string) => boolean;
}

export function createCredentialStore(options: CredentialStoreOptions = {}): CredentialStore {
  const keyring = options.keyring ?? { getPassword, setPassword, deletePassword };
  const platform = options.platform ?? process.platform;
  const pathModule = getPathModule(platform);
  const filePath = pathModule.join(getConfigDir({ platform, env: options.env, homeDir: options.homeDir }), 'auth.json');
  const allowFallback = options.allowFallback ?? true;
  const hardenAcl = options.hardenWindowsAcl ?? hardenWindowsAcl;

  async function readFallback(): Promise<GoatCredentials | null> {
    try {
      const raw = await fs.readFile(filePath, 'utf8');
      return parseCredentials(raw);
    } catch (error) {
      if (isMissing(error)) return null;
      throw error;
    }
  }

  async function writeFallback(credentials: GoatCredentials): Promise<void> {
    const serialized = JSON.stringify(credentials);
    const dir = pathModule.dirname(filePath);
    await fs.mkdir(dir, { recursive: true, mode: platform === 'win32' ? undefined : 0o700 });
    if (platform === 'win32') {
      await writeWindowsFallback(filePath, serialized, hardenAcl, platform);
      return;
    }

    await fs.chmod(dir, 0o700);
    await replaceFileAtomically(filePath, serialized, { mode: 0o600, pathModule });
    await fs.chmod(filePath, 0o600);
  }

  return {
    async get() {
      try {
        const raw = await keyring.getPassword(SERVICE, ACCOUNT);
        if (raw) return parseCredentials(raw);
      } catch {
        if (!allowFallback) throw new Error('Unable to read GOAT credentials from the OS credential store.');
      }
      return allowFallback ? readFallback() : null;
    },
    async set(credentials) {
      const serialized = JSON.stringify(credentials);
      try {
        await keyring.setPassword(SERVICE, ACCOUNT, serialized);
        await fs.rm(filePath, { force: true });
        return;
      } catch {
        if (!allowFallback) throw new Error('Unable to write GOAT credentials to the OS credential store.');
      }
      await writeFallback(credentials);
    },
    async delete() {
      try {
        await keyring.deletePassword(SERVICE, ACCOUNT);
      } catch {
        // Continue with fallback cleanup; absence in keyring is not an auth failure.
      }
      await fs.rm(filePath, { force: true });
    },
  };
}

export async function refreshStoredCredentials(client: { refresh(refreshToken: string): Promise<{ status: string; credentials?: GoatCredentials }> }, store: CredentialStore): Promise<GoatCredentials | null> {
  const current = await store.get();
  if (!current) return null;
  const result = await client.refresh(current.refreshToken);
  if (result.status !== 'authorized' || !result.credentials) {
    if (result.status === 'invalid_grant' || result.status === 'revoked') await store.delete();
    return null;
  }
  try {
    await store.set(result.credentials);
  } catch (error) {
    // Preserve existing credentials if the write fails;
    // the old tokens are still valid until they expire.
    throw error;
  }
  return result.credentials;
}

function parseCredentials(raw: string): GoatCredentials | null {
  try {
    const parsed = JSON.parse(raw) as Partial<GoatCredentials>;
    if (
      typeof parsed.accessToken === 'string' &&
      parsed.accessToken.length >= 32 &&
      typeof parsed.refreshToken === 'string' &&
      parsed.refreshToken.length >= 32 &&
      parsed.tokenType === 'Bearer' &&
      typeof parsed.accessTokenExpiresAt === 'string' &&
      typeof parsed.refreshTokenExpiresAt === 'string' &&
      !isNaN(Date.parse(parsed.accessTokenExpiresAt)) &&
      !isNaN(Date.parse(parsed.refreshTokenExpiresAt))
    ) {
      return parsed as GoatCredentials;
    }
    return null;
  } catch {
    return null;
  }
}

async function writeWindowsFallback(filePath: string, serialized: string, hardenAcl: (filePath: string) => boolean, platform: NodeJS.Platform): Promise<void> {
  const tempPath = `${filePath}.${process.pid}.${Date.now()}.${randomUUID()}.tmp`;
  let published = false;
  try {
    await fs.writeFile(tempPath, serialized, { mode: 0o600 });
    if (!hardenAcl(tempPath)) {
      throw new Error('Unable to restrict GOAT auth fallback file ACL to the current Windows user.');
    }
    await fs.rename(tempPath, filePath);
    published = true;
  } finally {
    if (!published) {
      await fs.rm(tempPath, { force: true }).catch(() => undefined);
    }
  }
  // Clean up stale temp files from prior crashed runs.
  await cleanupStaleTempFiles(filePath, platform);
}

async function cleanupStaleTempFiles(filePath: string, platform: NodeJS.Platform): Promise<void> {
  const pathModule = getPathModule(platform);
  const dir = pathModule.dirname(filePath);
  const baseName = pathModule.basename(filePath);
  try {
    const entries = await fs.readdir(dir);
    const now = Date.now();
    const oneHour = 60 * 60 * 1000;
    for (const entry of entries) {
      if (!entry.startsWith(baseName) || !entry.endsWith('.tmp')) continue;
      const fullPath = pathModule.join(dir, entry);
      try {
        const stat = await fs.stat(fullPath);
        if (stat.isFile() && now - stat.mtimeMs > oneHour) {
          await fs.rm(fullPath, { force: true });
        }
      } catch {
        // Ignore per-file errors during best-effort cleanup.
      }
    }
  } catch {
    // Ignore directory read errors.
  }
}

function hardenWindowsAcl(filePath: string): boolean {
  try {
    const user = os.userInfo().username;
    // Validate username contains only safe characters for icacls.
    // Domain users may appear as DOMAIN\User or user@domain.tld;
    // spawnSync runs without shell:true, so \ and @ are not injection risks.
    if (!/^[a-zA-Z0-9._\- @\\]+$/.test(user)) {
      return false;
    }
    const disableInheritance = spawnSync('icacls', [filePath, '/inheritance:r'], { stdio: 'ignore', windowsHide: true });
    if (disableInheritance.status !== 0 || disableInheritance.error) return false;
    // Use /grant:r with a safe user string - no shell interpolation.
    const grant = spawnSync('icacls', [filePath, '/grant:r', `${user}:(R,W)`], { stdio: 'ignore', windowsHide: true });
    return grant.status === 0 && !grant.error;
  } catch {
    return false;
  }
}

function isMissing(error: unknown): boolean {
  return typeof error === 'object' && error !== null && 'code' in error && (error as { code?: unknown }).code === 'ENOENT';
}