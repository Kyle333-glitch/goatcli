import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { runCli } from '../src/cli.js';
import { createBrowserOpener } from '../src/auth/browser.js';
import { createAuthApiClient } from '../src/auth/client.js';
import { createCredentialStore, refreshStoredCredentials } from '../src/auth/credentials.js';
import type { AuthApiClient, CredentialStore, GoatCredentials, UsageSummaryResponse, UsageSummaryResult } from '../src/auth/types.js';

const credentials: GoatCredentials = {
  accessToken: 'access-token',
  refreshToken: 'refresh-token',
  tokenType: 'Bearer',
  accessTokenExpiresAt: new Date(Date.now() + 900_000).toISOString(),
  refreshTokenExpiresAt: new Date(Date.now() + 2_000_000).toISOString(),
};
const fixedCredentials: GoatCredentials = {
  ...credentials,
  accessTokenExpiresAt: '2026-07-05T12:15:00.000Z',
  refreshTokenExpiresAt: '2026-07-05T13:00:00.000Z',
};

const expiredAccessCredentials: GoatCredentials = {
  ...credentials,
  accessTokenExpiresAt: '2026-07-05T11:59:00.000Z',
  refreshTokenExpiresAt: '2026-07-05T13:00:00.000Z',
};

const refreshedCredentials: GoatCredentials = {
  ...credentials,
  accessToken: 'new-access-token',
  refreshToken: 'new-refresh-token',
  accessTokenExpiresAt: '2026-07-05T12:45:00.000Z',
  refreshTokenExpiresAt: '2026-07-05T14:00:00.000Z',
};

const usageSummary: UsageSummaryResponse = {
  version: 'v0.2.5',
  generatedAt: '2026-07-05T12:00:00.000Z',
  requestId: 'request-1',
  account: {
    displayName: 'User Example',
    email: 'user@example.com',
    tier: 'regular',
    status: 'active',
  },
  quota: {
    allowanceMicrousd: '100000000',
    usedMicrousd: '85000000',
    activeReservedMicrousd: '0',
    totalCommittedMicrousd: '85000000',
    remainingMicrousd: '15000000',
    lowQuota: true,
    lowQuotaThresholdPercent: 20,
  },
  window: {
    seconds: 3600,
    startedAt: '2026-07-05T11:00:00.000Z',
    nextResetAt: '2026-07-05T13:00:00.000Z',
  },
  usage: {
    regularMicrousd: '12000000',
    premiumMicrousd: '73000000',
    totalMicrousd: '85000000',
  },
  recent: [
    { label: '24h', windowSeconds: 86400, regularMicrousd: '12000000', premiumMicrousd: '73000000', totalMicrousd: '85000000' },
    { label: '7d', windowSeconds: 604800, regularMicrousd: '18000000', premiumMicrousd: '93000000', totalMicrousd: '111000000' },
  ],
};

test('goat login is launcher-owned and stores credentials without spawning engine', async () => {
  let output = '';
  const store = new MemoryCredentialStore();
  const client = new FakeAuthClient([
    { status: 'pending', intervalSeconds: 5 },
    { status: 'authorized', credentials },
  ]);

  await runCli({
    argv: ['login'],
    authClient: client,
    credentialStore: store,
    browserOpener: { open: async () => false },
    clock: { sleep: async () => {} },
    stdout: writer((chunk) => { output += chunk; }),
    spawnEngine: () => {
      throw new Error('login should not spawn engine');
    },
  });

  assert.match(output, /Open this URL in your browser: https:\/\/control\.example\.com\/auth\/device/);
  assert.match(output, /Enter code: ABCD-EFGH/);
  assert.equal((await store.get())?.refreshToken, 'refresh-token');
  assert.equal(output.includes('device-code'), false);
  assert.equal(output.includes('access-token'), false);
});

test('goat logout revokes before deleting credentials', async () => {
  const store = new MemoryCredentialStore(credentials);
  const client = new FakeAuthClient([]);

  await runCli({
    argv: ['logout'],
    env: { GOAT_CONTROL_PLANE_URL: 'https://control.example.com' },
    authClient: client,
    credentialStore: store,
    stdout: writer(() => {}),
    spawnEngine: () => {
      throw new Error('logout should not spawn engine');
    },
  });

  assert.deepEqual(client.revokedTokens, ['refresh-token']);
  assert.equal(await store.get(), null);
});

test('goat logout deletes local credentials even when server revocation fails', async () => {
  const store = new MemoryCredentialStore(credentials);
  const client = new FakeAuthClient([]);
  client.revoke = async () => {
    throw new Error('server unreachable');
  };

  let output = '';
  let stderr = '';
  let exitCode: number | undefined;
  await runCli({
    argv: ['logout'],
    env: { GOAT_CONTROL_PLANE_URL: 'https://control.example.com' },
    authClient: client,
    credentialStore: store,
    stdout: writer((chunk) => { output += chunk; }),
    stderr: writer((chunk) => { stderr += chunk; }),
    exit: (code) => { exitCode = code; },
    spawnEngine: () => {
      throw new Error('logout should not spawn engine');
    },
  });

  assert.equal(exitCode, 1);
  assert.equal(await store.get(), null);
  assert.match(stderr, /server unreachable/);
  assert.match(output, /Removed local GOAT credentials, but server session revocation failed/);
});

test('auth client treats failed token revocation as logout failure', async () => {
  const client = createAuthApiClient(new URL('https://control.example.com'), async () => new Response(
    JSON.stringify({ error: { code: 'server_error', message: 'failed' } }),
    { status: 500, headers: { 'content-type': 'application/json' } },
  ));

  await assert.rejects(() => client.revoke('refresh-token'), /Token revocation failed with HTTP 500/);
});

test('goat logout --local-only does not require control plane URL', async () => {
  const store = new MemoryCredentialStore(credentials);
  const client = new FakeAuthClient([]);

  await runCli({
    argv: ['logout', '--local-only'],
    env: {},
    authClient: client,
    credentialStore: store,
    stdout: writer(() => {}),
  });

  assert.deepEqual(client.revokedTokens, []);
  assert.equal(await store.get(), null);
});


test('goat usage is launcher-owned and renders deterministic public usage', async () => {
  let output = '';
  let stderr = '';
  const store = new MemoryCredentialStore(fixedCredentials);
  const client = new FakeAuthClient([], [{ status: 'ok', summary: usageSummary }]);

  await runCli({
    argv: ['usage'],
    env: { GOAT_CONTROL_PLANE_URL: 'https://control.example.com' },
    authClient: client,
    credentialStore: store,
    stdout: writer((chunk) => { output += chunk; }),
    stderr: writer((chunk) => { stderr += chunk; }),
    clock: { sleep: async () => {}, now: () => new Date('2026-07-05T12:00:00.000Z') },
    spawnEngine: () => {
      throw new Error('usage should not spawn engine');
    },
  });

  assert.equal(stderr, '');
  assert.match(output, /GOAT usage/);
  assert.match(output, /Account: User Example <user@example.com>/);
  assert.match(output, /Tier: Regular/);
  assert.match(output, /Quota: 15\.00 of 100\.00 quota units remaining \(15%\)/);
  assert.match(output, /Warning: GOAT quota is low\./);
  assert.match(output, /Next reset: 2026-07-05 13:00 UTC/);
  assert.match(output, /Usage this window: 12\.00 regular, 73\.00 premium, 85\.00 total/);
  assert.equal(output.includes('access-token'), false);
  assert.equal(output.includes('refresh-token'), false);
  assert.equal(output.includes('gpt-'), false);
  assert.equal(output.includes('$'), false);
});

test('goat usage --json emits structured errors for TUI consumers', async () => {
  let output = '';
  let stderr = '';
  let exitCode: number | undefined;

  await runCli({
    argv: ['usage', '--json'],
    env: { GOAT_CONTROL_PLANE_URL: 'https://control.example.com' },
    authClient: new FakeAuthClient([]),
    credentialStore: new MemoryCredentialStore(),
    stdout: writer((chunk) => { output += chunk; }),
    stderr: writer((chunk) => { stderr += chunk; }),
    exit: (code) => { exitCode = code; },
    spawnEngine: () => {
      throw new Error('usage should not spawn engine');
    },
  });

  assert.equal(exitCode, 1);
  assert.equal(stderr, '');
  const parsed = JSON.parse(output) as { ok: boolean; error: { code: string; message: string } };
  assert.equal(parsed.ok, false);
  assert.equal(parsed.error.code, 'no_credentials');
  assert.match(parsed.error.message, /goat login/);
});

test('goat usage --json sanitizes unexpected launcher errors', async () => {
  let output = '';
  let stderr = '';
  let exitCode: number | undefined;

  await runCli({
    argv: ['usage', '--json'],
    env: { GOAT_CONTROL_PLANE_URL: 'https://control.example.com' },
    authClient: new FakeAuthClient([]),
    credentialStore: {
      async get() {
        throw new Error('C:\\Users\\Test User\\AppData\\Roaming\\goat\\auth.json token-secret');
      },
      async set() {},
      async delete() {},
    },
    stdout: writer((chunk) => { output += chunk; }),
    stderr: writer((chunk) => { stderr += chunk; }),
    exit: (code) => { exitCode = code; },
    spawnEngine: () => {
      throw new Error('usage should not spawn engine');
    },
  });

  assert.equal(exitCode, 1);
  assert.equal(stderr, '');
  const parsed = JSON.parse(output) as { ok: boolean; error: { code: string; message: string } };
  assert.equal(parsed.ok, false);
  assert.equal(parsed.error.code, 'unavailable');
  assert.equal(parsed.error.message, 'Unable to load GOAT usage right now. Try again later.');
  assert.equal(output.includes('AppData'), false);
  assert.equal(output.includes('token-secret'), false);
});

test('goat usage reports offline control-plane failures without calling them rate limits', async () => {
  let stderr = '';
  let exitCode: number | undefined;
  const store = new MemoryCredentialStore(fixedCredentials);
  const client = new FakeAuthClient([], [{ status: 'network_error', message: 'fetch failed' }]);

  await runCli({
    argv: ['usage'],
    env: { GOAT_CONTROL_PLANE_URL: 'https://control.example.com' },
    authClient: client,
    credentialStore: store,
    stdout: writer(() => {}),
    stderr: writer((chunk) => { stderr += chunk; }),
    exit: (code) => { exitCode = code; },
    clock: { sleep: async () => {}, now: () => new Date('2026-07-05T12:00:00.000Z') },
    spawnEngine: () => {
      throw new Error('usage should not spawn engine');
    },
  });

  assert.equal(exitCode, 1);
  assert.match(stderr, /Unable to reach GOAT control plane/);
  assert.doesNotMatch(stderr, /rate limit/i);
});

test('goat usage refreshes expired access tokens before loading usage', async () => {
  let output = '';
  const store = new MemoryCredentialStore(expiredAccessCredentials);
  const client = new FakeAuthClient(
    [{ status: 'authorized', credentials: refreshedCredentials }],
    [{ status: 'ok', summary: usageSummary }],
  );

  await runCli({
    argv: ['usage'],
    env: { GOAT_CONTROL_PLANE_URL: 'https://control.example.com' },
    authClient: client,
    credentialStore: store,
    stdout: writer((chunk) => { output += chunk; }),
    stderr: writer(() => {}),
    clock: { sleep: async () => {}, now: () => new Date('2026-07-05T12:00:00.000Z') },
    spawnEngine: () => {
      throw new Error('usage should not spawn engine');
    },
  });

  assert.match(output, /GOAT usage/);
  assert.equal((await store.get())?.refreshToken, 'new-refresh-token');
});

test('goat usage clears local credentials when auth is expired', async () => {
  let stderr = '';
  let exitCode: number | undefined;
  const store = new MemoryCredentialStore(fixedCredentials);
  const client = new FakeAuthClient(
    [{ status: 'invalid_grant', message: 'invalid' }],
    [{ status: 'unauthorized', message: 'expired' }],
  );

  await runCli({
    argv: ['usage'],
    env: { GOAT_CONTROL_PLANE_URL: 'https://control.example.com' },
    authClient: client,
    credentialStore: store,
    stdout: writer(() => {}),
    stderr: writer((chunk) => { stderr += chunk; }),
    exit: (code) => { exitCode = code; },
    clock: { sleep: async () => {}, now: () => new Date('2026-07-05T12:00:00.000Z') },
    spawnEngine: () => {
      throw new Error('usage should not spawn engine');
    },
  });

  assert.equal(exitCode, 1);
  assert.equal(await store.get(), null);
  assert.match(stderr, /GOAT login expired/);
});
test('browser opener allowlists safe control-plane URLs', async () => {
  const calls: Array<{ command: string; args: readonly string[] }> = [];
  const opener = createBrowserOpener('win32', (command, args) => {
    calls.push({ command, args });
    return { unref() {} };
  });

  assert.equal(await opener.open('https://control.example.com/auth/device'), true);
  assert.equal(await opener.open('file:///C:/secrets'), false);
  const expectedCommand = `${process.env.SystemRoot ?? 'C:\\Windows'}\\explorer.exe`;
  assert.equal(calls[0]?.command, expectedCommand);
  assert.deepEqual(calls[0]?.args, ['https://control.example.com/auth/device']);
});

test('refreshStoredCredentials atomically replaces tokens and deletes stale local tokens on replay', async () => {
  const store = new MemoryCredentialStore(credentials);
  const rotated: GoatCredentials = { ...credentials, accessToken: 'new-access', refreshToken: 'new-refresh' };

  const refreshed = await refreshStoredCredentials({ refresh: async () => ({ status: 'authorized', credentials: rotated }) }, store);
  assert.equal(refreshed?.refreshToken, 'new-refresh');
  assert.equal((await store.get())?.refreshToken, 'new-refresh');

  const replay = await refreshStoredCredentials({ refresh: async () => ({ status: 'invalid_grant', message: 'replay' }) }, store);
  assert.equal(replay, null);
  assert.equal(await store.get(), null);
});

test('pollDeviceToken returns network_error on fetch exception instead of throwing', async () => {
  const client = createAuthApiClient(new URL('https://control.example.com'), async () => {
    throw new Error('fetch failed');
  });

  const result = await client.pollDeviceToken('test-code');
  assert.equal(result.status, 'network_error');
  assert.equal(typeof result.message, 'string');
});

test('runLogin retries on network_error and eventually succeeds', async () => {
  let output = '';
  const store = new MemoryCredentialStore();
  const client = new FakeAuthClient([
    { status: 'network_error', message: 'fetch failed' },
    { status: 'pending', intervalSeconds: 5 },
    { status: 'authorized', credentials },
  ]);

  await runCli({
    argv: ['login'],
    authClient: client,
    credentialStore: store,
    browserOpener: { open: async () => false },
    clock: { sleep: async () => {} },
    stdout: writer((chunk) => { output += chunk; }),
    spawnEngine: () => {
      throw new Error('login should not spawn engine');
    },
  });

  assert.match(output, /GOAT login complete/);
  assert.equal((await store.get())?.refreshToken, 'refresh-token');
});

test('Windows fallback does not publish credential bytes when ACL hardening fails', async () => {
  if (process.platform !== 'win32') return;
  const tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'goatcli-auth-'));
  try {
    const store = createCredentialStore({
      platform: 'win32',
      env: { APPDATA: tempRoot },
      keyring: failingKeyring(),
      hardenWindowsAcl: () => false,
    });

    await assert.rejects(() => store.set(credentials), /Unable to restrict GOAT auth fallback file ACL/);

    const configDir = path.join(tempRoot, 'goat');
    const authPath = path.join(configDir, 'auth.json');
    await assert.rejects(() => fs.stat(authPath), /ENOENT/);
    const remainingFiles = await fs.readdir(configDir).catch(() => []);
    assert.deepEqual(remainingFiles, []);
  } finally {
    await fs.rm(tempRoot, { force: true, recursive: true });
  }
});

function failingKeyring() {
  return {
    async getPassword() {
      throw new Error('keyring unavailable');
    },
    async setPassword() {
      throw new Error('keyring unavailable');
    },
    async deletePassword() {
      return false;
    },
  };
}

class FakeAuthClient implements AuthApiClient {
  readonly revokedTokens: string[] = [];

  constructor(
    private readonly pollResults: Array<Awaited<ReturnType<AuthApiClient['pollDeviceToken']>>>,
    private readonly usageResults: UsageSummaryResult[] = [],
  ) {}

  async createDeviceSession() {
    return {
      verificationUrl: 'https://control.example.com/auth/device',
      userCode: 'ABCD-EFGH',
      deviceCode: 'device-code-that-is-not-printed',
      intervalSeconds: 5,
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
      expiresInSeconds: 300,
    };
  }

  async pollDeviceToken() {
    return this.pollResults.shift() ?? { status: 'pending', intervalSeconds: 5 };
  }

  async cancelDeviceSession() {}

  async refresh() {
    return this.pollResults.shift() ?? { status: 'invalid_grant', message: 'invalid' };
  }

  async revoke(refreshToken: string) {
    this.revokedTokens.push(refreshToken);
  }

  async getUsageSummary(): Promise<UsageSummaryResult> {
    return this.usageResults.shift() ?? { status: 'network_error', message: 'No usage result configured.' };
  }
}

class MemoryCredentialStore implements CredentialStore {
  constructor(private current: GoatCredentials | null = null) {}

  async get() {
    return this.current;
  }

  async set(credentials: GoatCredentials) {
    this.current = credentials;
  }

  async delete() {
    this.current = null;
  }
}

function writer(onWrite: (chunk: string) => void): Pick<NodeJS.WriteStream, 'write'> {
  return {
    write(chunk: string | Uint8Array) {
      onWrite(chunk.toString());
      return true;
    },
  };
}
