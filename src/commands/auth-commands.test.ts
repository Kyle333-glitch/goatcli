import assert from "node:assert/strict";
import { test } from "node:test";
import { runCli } from "../cli.js";
import { runLogin } from "./login.js";
import { runLogout } from "./logout.js";
import { runUsage } from "./usage.js";
import type {
  AuthApiClient,
  CredentialStore,
  GoatCredentials,
  UsageSummaryResponse,
} from "../auth/types.js";

const CREDENTIALS: GoatCredentials = {
  accessToken: "A".repeat(43),
  refreshToken: "R".repeat(43),
  tokenType: "Bearer",
  accessTokenExpiresAt: "2026-07-17T13:00:00.000Z",
  refreshTokenExpiresAt: "2026-07-18T13:00:00.000Z",
};

const ROTATED_CREDENTIALS: GoatCredentials = {
  ...CREDENTIALS,
  accessToken: "C".repeat(43),
  refreshToken: "D".repeat(43),
  accessTokenExpiresAt: "2026-07-17T13:30:00.000Z",
  refreshTokenExpiresAt: "2026-07-18T14:00:00.000Z",
};

test("goat login stores credentials only in the injected keyring store", async () => {
  const store = new MemoryStore();
  let stdout = "";
  let stderr = "";
  let exitCode: number | undefined;
  await runCli({
    argv: ["login"],
    authClient: client({
      async createDeviceSession() {
        return {
          verificationUrl: "http://127.0.0.1:4040/auth/device",
          userCode: "ABCD-EFGH",
          deviceCode: "D".repeat(43),
          intervalSeconds: 2,
          expiresAt: new Date(Date.now() + 60_000).toISOString(),
          expiresInSeconds: 60,
        };
      },
      async pollDeviceToken() {
        return { status: "authorized", credentials: CREDENTIALS };
      },
    }),
    credentialStore: store,
    browserOpener: {
      async open() {
        return true;
      },
    },
    stdout: {
      write(value) {
        stdout += value;
        return true;
      },
    },
    stderr: {
      write(value) {
        stderr += value;
        return true;
      },
    },
    exit(code) {
      exitCode = code;
    },
  });

  assert.deepEqual(store.value, CREDENTIALS);
  assert.match(stdout, /GOAT login complete/);
  assert.equal(stderr, "");
  assert.equal(exitCode, undefined);
});

test("login storage, logout revoke, and launcher failures never print exception canaries", async () => {
  let stderr = "";
  await runCli({
    argv: ["login"],
    authClient: client({
      async createDeviceSession() {
        throw new Error("PATH_SECRET_3HT6");
      },
    }),
    credentialStore: new MemoryStore(),
    browserOpener: {
      async open() {
        return false;
      },
    },
    stdout: {
      write() {
        return true;
      },
    },
    stderr: {
      write(value) {
        stderr += value;
        return true;
      },
    },
    exit() {},
  });
  assert.equal(stderr.includes("PATH_SECRET_3HT6"), false);
  assert.match(stderr, /login is unavailable/);

  stderr = "";
  const store = new MemoryStore(CREDENTIALS);
  const result = await runLogout({
    client: client({
      async revoke() {
        throw new Error("TOKEN_SECRET_8MVP");
      },
    }),
    store,
    stdout: {
      write() {
        return true;
      },
    },
    stderr: {
      write(value) {
        stderr += value;
        return true;
      },
    },
  });
  assert.equal(result, 1);
  assert.equal(stderr.includes("TOKEN_SECRET_8MVP"), false);
  assert.equal(store.value, null);
});

test("usage human and JSON output contain no account PII fields", async () => {
  const summary = usageSummary();
  for (const json of [false, true]) {
    let stdout = "";
    let stderr = "";
    const result = await runUsage({
      client: client({
        async getUsageSummary() {
          return { status: "ok", summary };
        },
      }),
      store: new MemoryStore(CREDENTIALS),
      stdout: {
        write(value) {
          stdout += value;
          return true;
        },
      },
      stderr: {
        write(value) {
          stderr += value;
          return true;
        },
      },
      json,
      now: () => new Date("2026-07-17T12:00:00.000Z"),
    });
    assert.equal(result, 0);
    assert.equal(stderr, "");
    assert.equal(stdout.includes("displayName"), false);
    assert.equal(stdout.includes("email"), false);
    assert.equal(stdout.includes("requestId"), false);
  }
});

test("failed keyring writes revoke rotated credentials and do not use them", async () => {
  const loginRevocations: string[] = [];
  let loginError = "";
  const loginStore = new MemoryStore(null, true);
  const loginResult = await runLogin({
    client: client({
      async createDeviceSession() {
        return {
          verificationUrl: "http://127.0.0.1:4040/auth/device",
          userCode: "ABCD-EFGH",
          deviceCode: "D".repeat(43),
          intervalSeconds: 2,
          expiresAt: new Date(Date.now() + 60_000).toISOString(),
          expiresInSeconds: 600,
        };
      },
      async pollDeviceToken() {
        return { status: "authorized", credentials: ROTATED_CREDENTIALS };
      },
      async revoke(refreshToken) {
        loginRevocations.push(refreshToken);
      },
    }),
    store: loginStore,
    opener: {
      async open() {
        return true;
      },
    },
    stdout: {
      write() {
        return true;
      },
    },
    stderr: {
      write(value) {
        loginError += value;
        return true;
      },
    },
    clock: { sleep: async () => {} },
  });
  assert.equal(loginResult, 1);
  assert.deepEqual(loginRevocations, [ROTATED_CREDENTIALS.refreshToken]);
  assert.equal(loginStore.value, null);
  assert.equal(loginError.includes("PATH_SECRET_3HT6"), false);

  const usageRevocations: string[] = [];
  let usageCalls = 0;
  let usageError = "";
  const usageStore = new MemoryStore(
    { ...CREDENTIALS, accessTokenExpiresAt: "2026-07-17T11:59:00.000Z" },
    true,
  );
  const usageResult = await runUsage({
    client: client({
      async refresh() {
        return { status: "authorized", credentials: ROTATED_CREDENTIALS };
      },
      async revoke(refreshToken) {
        usageRevocations.push(refreshToken);
      },
      async getUsageSummary() {
        usageCalls += 1;
        throw new Error("TOKEN_SECRET_8MVP");
      },
    }),
    store: usageStore,
    stdout: {
      write() {
        return true;
      },
    },
    stderr: {
      write(value) {
        usageError += value;
        return true;
      },
    },
    now: () => new Date("2026-07-17T12:00:00.000Z"),
  });
  assert.equal(usageResult, 1);
  assert.equal(usageCalls, 0);
  assert.deepEqual(usageRevocations, [ROTATED_CREDENTIALS.refreshToken]);
  assert.equal(usageStore.value, null);
  assert.equal(usageError.includes("TOKEN_SECRET_8MVP"), false);
  assert.equal(usageError.includes("PATH_SECRET_3HT6"), false);
});

class MemoryStore implements CredentialStore {
  constructor(
    public value: GoatCredentials | null = null,
    private readonly failSet = false,
  ) {}
  async get() {
    return this.value;
  }
  async set(credentials: GoatCredentials) {
    if (this.failSet) throw new Error("PATH_SECRET_3HT6");
    this.value = credentials;
  }
  async delete() {
    this.value = null;
  }
}

function client(overrides: Partial<AuthApiClient> = {}): AuthApiClient {
  return {
    async createDeviceSession() {
      throw new Error("unused");
    },
    async pollDeviceToken() {
      return { status: "network_error", message: "unused" };
    },
    async cancelDeviceSession() {},
    async refresh() {
      return { status: "network_error", message: "unused" };
    },
    async revoke() {},
    async getUsageSummary() {
      return { status: "network_error", message: "unused" };
    },
    ...overrides,
  };
}

function usageSummary(): UsageSummaryResponse {
  return {
    version: "v0.3.2",
    generatedAt: "2026-07-17T12:00:00.000Z",
    account: { tier: "regular", status: "active" },
    quota: {
      allowanceMicrousd: "100000000",
      usedMicrousd: "1000",
      activeReservedMicrousd: "0",
      totalCommittedMicrousd: "1000",
      remainingMicrousd: "99999000",
      lowQuota: false,
      lowQuotaThresholdPercent: 20,
    },
    window: {
      seconds: 3600,
      startedAt: "2026-07-17T12:00:00.000Z",
      nextResetAt: "2026-07-17T13:00:00.000Z",
    },
    usage: {
      regularMicrousd: "1000",
      premiumMicrousd: "0",
      totalMicrousd: "1000",
    },
    recent: [
      {
        label: "24h",
        windowSeconds: 86400,
        regularMicrousd: "1000",
        premiumMicrousd: "0",
        totalMicrousd: "1000",
      },
      {
        label: "7d",
        windowSeconds: 604800,
        regularMicrousd: "1000",
        premiumMicrousd: "0",
        totalMicrousd: "1000",
      },
    ],
  };
}
