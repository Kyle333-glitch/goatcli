import assert from "node:assert/strict";
import { test } from "node:test";
import { runCli } from "../cli.js";
import { runLogin } from "./login.js";
import { runLogout } from "./logout.js";
import { formatUsageSummary, runUsage } from "./usage.js";
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
    clock: { sleep: async () => {} },
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
  assert.match(stdout, /Signed in successfully/);
  assert.equal(stderr, "");
  assert.equal(exitCode, undefined);
});

test("goat login enrolls a per-device attestation credential best-effort", async () => {
  const store = new MemoryStore();
  const DEVICE_SECRET = "S".repeat(43);
  const provisioned: Array<{
    accessToken: string;
    deviceId: string;
    label: string;
  }> = [];
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
      async provisionDeviceCredential(accessToken, deviceId, label) {
        provisioned.push({ accessToken, deviceId, label: label ?? "" });
        return { deviceId, deviceSecret: DEVICE_SECRET };
      },
    }),
    credentialStore: store,
    browserOpener: {
      async open() {
        return true;
      },
    },
    clock: { sleep: async () => {} },
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
    exit(code) {
      exitCode = code;
    },
  });

  assert.equal(provisioned.length, 1);
  assert.equal(provisioned[0]!.accessToken, CREDENTIALS.accessToken);
  assert.equal(provisioned[0]!.label, "goatcli");
  // The CLI generates a fresh device id per enrollment; it must round-trip
  // into the keyring together with the server-issued secret.
  assert.match(provisioned[0]!.deviceId, /^[0-9a-f-]{36}$/);
  assert.deepEqual(store.value, {
    ...CREDENTIALS,
    deviceId: provisioned[0]!.deviceId,
    deviceSecret: DEVICE_SECRET,
  });
  assert.equal(stderr, "");
  assert.equal(exitCode, undefined);
});

test("goat login succeeds when device attestation provisioning fails", async () => {
  const store = new MemoryStore();
  let provisioningCalls = 0;
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
      async provisionDeviceCredential() {
        provisioningCalls += 1;
        throw new Error("PATH_SECRET_3HT6");
      },
    }),
    credentialStore: store,
    browserOpener: {
      async open() {
        return true;
      },
    },
    clock: { sleep: async () => {} },
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
    exit(code) {
      exitCode = code;
    },
  });

  assert.equal(provisioningCalls, 1);
  assert.deepEqual(store.value, CREDENTIALS);
  assert.equal(stderr.includes("PATH_SECRET_3HT6"), false);
  assert.equal(exitCode, undefined);
});

test("goat login opens a verification URL with the user code pre-filled", async () => {
  const opened: string[] = [];
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
    credentialStore: new MemoryStore(),
    browserOpener: {
      async open(url) {
        opened.push(url);
        return true;
      },
    },
    clock: { sleep: async () => {} },
    stdout: {
      write() {
        return true;
      },
    },
    stderr: {
      write() {
        return true;
      },
    },
    exit(code) {
      exitCode = code;
    },
  });

  assert.equal(opened.length, 1);
  const url = new URL(opened[0]!);
  assert.equal(url.pathname, "/auth/device");
  assert.equal(url.searchParams.get("code"), "ABCD-EFGH");
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

test("goat login honors pending, slow-down, and network retry intervals", async () => {
  const clock = new ManualClock();
  const polls = [
    { status: "pending" as const, intervalSeconds: 1 },
    { status: "slow_down" as const, retryAfterSeconds: 5 },
    { status: "network_error" as const, message: "offline" },
    { status: "authorized" as const, credentials: CREDENTIALS },
  ];
  const store = new MemoryStore();

  const result = await runLogin({
    client: client({
      async createDeviceSession() {
        return deviceSession(clock, 60);
      },
      async pollDeviceToken() {
        return polls.shift() ?? { status: "expired", message: "expired" };
      },
    }),
    store,
    opener: {
      async open() {
        return true;
      },
    },
    stdout: sink(),
    stderr: sink(),
    clock,
  });

  assert.equal(result, 0);
  assert.deepEqual(clock.sleeps, [2_000, 2_000, 5_000, 10_000]);
  assert.deepEqual(store.value, CREDENTIALS);
});

test("goat login stops on denial without storing credentials", async () => {
  const clock = new ManualClock();
  let stderr = "";
  const store = new MemoryStore();
  const result = await runLogin({
    client: client({
      async createDeviceSession() {
        return deviceSession(clock, 60);
      },
      async pollDeviceToken() {
        return { status: "denied", message: "denied" };
      },
    }),
    store,
    opener: {
      async open() {
        return true;
      },
    },
    stdout: sink(),
    stderr: {
      write(value) {
        stderr += value;
        return true;
      },
    },
    clock,
  });

  assert.equal(result, 1);
  assert.equal(store.value, null);
  assert.match(stderr, /not authorized/);
});

test("goat login expires at the server deadline and cancels the device session", async () => {
  const clock = new ManualClock();
  let polls = 0;
  let cancellations = 0;
  const result = await runLogin({
    client: client({
      async createDeviceSession() {
        return {
          ...deviceSession(clock, 3),
          // The relative lifetime remains an independent upper bound even if
          // a malformed server timestamp is far in the future.
          expiresAt: "2030-01-01T00:00:00.000Z",
        };
      },
      async pollDeviceToken() {
        polls += 1;
        return { status: "pending" };
      },
      async cancelDeviceSession() {
        cancellations += 1;
      },
    }),
    store: new MemoryStore(),
    opener: {
      async open() {
        return true;
      },
    },
    stdout: sink(),
    stderr: sink(),
    clock,
  });

  assert.equal(result, 1);
  assert.equal(polls, 1);
  assert.equal(cancellations, 1);
  assert.deepEqual(clock.sleeps, [2_000, 1_000]);
});

test("goat login prints browser instructions when automatic opening fails", async () => {
  const clock = new ManualClock();
  let stdout = "";
  const result = await runLogin({
    client: client({
      async createDeviceSession() {
        return deviceSession(clock, 60);
      },
      async pollDeviceToken() {
        return { status: "authorized", credentials: CREDENTIALS };
      },
    }),
    store: new MemoryStore(),
    opener: {
      async open() {
        return false;
      },
    },
    stdout: {
      write(value) {
        stdout += value;
        return true;
      },
    },
    stderr: sink(),
    clock,
  });

  assert.equal(result, 0);
  assert.match(stdout, /Open this URL in your browser:/);
  assert.match(stdout, /code=ABCD-EFGH/);
});

test("goat login revokes the previous token family only after replacement is stored", async () => {
  const clock = new ManualClock();
  const events: string[] = [];
  const store = new MemoryStore(CREDENTIALS);
  const originalSet = store.set.bind(store);
  store.set = async (credentials) => {
    events.push("store");
    await originalSet(credentials);
  };
  const result = await runLogin({
    client: client({
      async createDeviceSession() {
        return deviceSession(clock, 60);
      },
      async pollDeviceToken() {
        return { status: "authorized", credentials: ROTATED_CREDENTIALS };
      },
      async revoke(refreshToken) {
        events.push(`revoke:${refreshToken}`);
      },
    }),
    store,
    opener: {
      async open() {
        return true;
      },
    },
    stdout: sink(),
    stderr: sink(),
    clock,
  });

  assert.equal(result, 0);
  assert.deepEqual(events, ["store", `revoke:${CREDENTIALS.refreshToken}`]);
  assert.deepEqual(store.value, ROTATED_CREDENTIALS);
});

test("human usage output is percentage-only", async () => {
  const output = formatUsageSummary(usageSummary());
  assert.match(output, /GOAT usage — 99% remaining/);
  assert.match(output, /Used: 0%/);
  assert.match(output, /Committed: 0%/);
  assert.equal(output.includes("microusd"), false);
  assert.equal(output.includes("Tier"), false);
  assert.equal(output.includes("reset"), false);
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
    assert.equal(stdout.includes("Microusd"), false);
    assert.equal(stdout.includes("microusd"), false);
    assert.equal(stdout.includes("regular"), false);
    assert.equal(stdout.includes("premium"), false);
  }
});

test("goat usage refresh preserves the enrolled device attestation", async () => {
  const store = new MemoryStore({
    ...CREDENTIALS,
    accessTokenExpiresAt: "2026-07-17T11:59:00.000Z",
    deviceId: "123e4567-e89b-12d3-a456-426614174000",
    deviceSecret: "D".repeat(43),
  });
  const result = await runUsage({
    client: client({
      async refresh() {
        return { status: "authorized", credentials: ROTATED_CREDENTIALS };
      },
      async getUsageSummary() {
        return { status: "ok", summary: usageSummary() };
      },
    }),
    store,
    stdout: {
      write() {
        return true;
      },
    },
    stderr: {
      write() {
        return true;
      },
    },
    now: () => new Date("2026-07-17T12:00:00.000Z"),
  });
  assert.equal(result, 0);
  assert.deepEqual(store.value, {
    ...ROTATED_CREDENTIALS,
    deviceId: "123e4567-e89b-12d3-a456-426614174000",
    deviceSecret: "D".repeat(43),
  });
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

class ManualClock {
  private current = Date.parse("2026-07-17T12:00:00.000Z");
  readonly sleeps: number[] = [];

  now() {
    return new Date(this.current);
  }

  async sleep(ms: number) {
    this.sleeps.push(ms);
    this.current += ms;
  }
}

function deviceSession(clock: ManualClock, expiresInSeconds: number) {
  return {
    verificationUrl: "http://127.0.0.1:4040/auth/device",
    userCode: "ABCD-EFGH",
    deviceCode: "D".repeat(43),
    intervalSeconds: 2,
    expiresAt: new Date(
      clock.now().getTime() + expiresInSeconds * 1000,
    ).toISOString(),
    expiresInSeconds,
  };
}

function sink() {
  return {
    write() {
      return true;
    },
  };
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
    account: { status: "active" },
    quota: {
      usedPercent: 0,
      committedPercent: 0,
      remainingPercent: 99,
      lowQuota: false,
    },
    window: {
      kind: "rolling",
      seconds: 86400,
      startedAt: "2026-07-17T12:00:00.000Z",
      nextUsageExpiresAt: "2026-07-18T12:00:00.000Z",
    },
  };
}
