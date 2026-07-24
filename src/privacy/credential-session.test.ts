import assert from "node:assert/strict";
import { test } from "node:test";
import type {
  AuthApiClient,
  CredentialStore,
  GoatCredentials,
  PollResult,
} from "../auth/types.js";
import {
  preparePrivacyCredential,
  PrivacyCredentialError,
} from "./credential-session.js";

const NOW = Date.parse("2026-07-17T12:00:00.000Z");

const current: GoatCredentials = {
  accessToken: "A".repeat(43),
  refreshToken: "B".repeat(43),
  tokenType: "Bearer",
  accessTokenExpiresAt: "2026-07-17T12:10:00.000Z",
  refreshTokenExpiresAt: "2026-07-17T13:00:00.000Z",
};

const refreshed: GoatCredentials = {
  accessToken: "C".repeat(43),
  refreshToken: "D".repeat(43),
  tokenType: "Bearer",
  accessTokenExpiresAt: "2026-07-17T12:20:00.000Z",
  refreshTokenExpiresAt: "2026-07-17T14:00:00.000Z",
};

test("uses a fresh keyring credential without a launcher network request", async () => {
  const store = new MemoryStore(current);
  let refreshCalls = 0;
  const credential = await preparePrivacyCredential({
    store,
    client: authClient(async () => {
      refreshCalls += 1;
      return { status: "network_error", message: "must not be called" };
    }),
    now: () => NOW,
  });

  assert.equal(refreshCalls, 0);
  assert.equal(
    new TextDecoder().decode(credential.accessToken),
    current.accessToken,
  );
  assert.equal(
    credential.expiresAtUnixMs,
    Date.parse(current.accessTokenExpiresAt),
  );
  credential.accessToken.fill(0);
});

test("refreshes an expiring credential through the single bounded auth client", async () => {
  const expiring = {
    ...current,
    accessTokenExpiresAt: "2026-07-17T12:00:30.000Z",
  };
  const store = new MemoryStore(expiring);
  let transmittedRefreshToken: string | undefined;
  const credential = await preparePrivacyCredential({
    store,
    client: authClient(async (refreshToken) => {
      transmittedRefreshToken = refreshToken;
      return { status: "authorized", credentials: refreshed };
    }),
    now: () => NOW,
  });

  assert.equal(transmittedRefreshToken, expiring.refreshToken);
  assert.deepEqual(store.value, refreshed);
  assert.equal(
    new TextDecoder().decode(credential.accessToken),
    refreshed.accessToken,
  );
  credential.accessToken.fill(0);
});

test("clears expired or revoked keyring credentials and requires login", async () => {
  for (const setup of [
    {
      credentials: {
        ...current,
        accessTokenExpiresAt: "2026-07-17T11:00:00.000Z",
        refreshTokenExpiresAt: "2026-07-17T11:30:00.000Z",
      },
      result: { status: "network_error", message: "unused" } as PollResult,
    },
    {
      credentials: {
        ...current,
        accessTokenExpiresAt: "2026-07-17T12:00:30.000Z",
      },
      result: { status: "revoked", message: "server detail" } as PollResult,
    },
  ]) {
    const store = new MemoryStore(setup.credentials);
    await assert.rejects(
      () =>
        preparePrivacyCredential({
          store,
          client: authClient(async () => setup.result),
          now: () => NOW,
        }),
      (error) =>
        error instanceof PrivacyCredentialError &&
        error.code === "GOAT_PRIVACY_LOGIN_REQUIRED" &&
        !error.message.includes("server detail"),
    );
    assert.equal(store.value, null);
  }
});

test("maps keyring and refresh failures to fixed path-free errors", async () => {
  const failingStore: CredentialStore = {
    async get() {
      throw new Error("PATH_SECRET_3HT6");
    },
    async set() {},
    async delete() {},
  };
  await assert.rejects(
    () =>
      preparePrivacyCredential({
        store: failingStore,
        client: authClient(async () => {
          throw new Error("TOKEN_SECRET_8MVP");
        }),
        now: () => NOW,
      }),
    (error) =>
      error instanceof PrivacyCredentialError &&
      error.code === "GOAT_PRIVACY_CREDENTIAL_UNAVAILABLE" &&
      !error.message.includes("PATH_SECRET_3HT6"),
  );

  const expiring = {
    ...current,
    accessTokenExpiresAt: "2026-07-17T12:00:30.000Z",
  };
  await assert.rejects(
    () =>
      preparePrivacyCredential({
        store: new MemoryStore(expiring),
        client: authClient(async () => {
          throw new Error("TOKEN_SECRET_8MVP");
        }),
        now: () => NOW,
      }),
    (error) =>
      error instanceof PrivacyCredentialError &&
      !error.message.includes("TOKEN_SECRET_8MVP"),
  );
});

test("revokes a rotated credential when keyring persistence fails", async () => {
  const expiring = {
    ...current,
    accessTokenExpiresAt: "2026-07-17T12:00:30.000Z",
  };
  let stored: GoatCredentials | null = expiring;
  let revoked: string | undefined;
  const store: CredentialStore = {
    async get() {
      return stored;
    },
    async set() {
      throw new Error("PATH_SECRET_3HT6");
    },
    async delete() {
      stored = null;
    },
  };
  const client = authClient(async () => ({
    status: "authorized",
    credentials: refreshed,
  }));
  client.revoke = async (refreshToken) => {
    revoked = refreshToken;
  };

  await assert.rejects(
    () => preparePrivacyCredential({ store, client, now: () => NOW }),
    (error) =>
      error instanceof PrivacyCredentialError &&
      error.code === "GOAT_PRIVACY_CREDENTIAL_UNAVAILABLE" &&
      !error.message.includes("PATH_SECRET_3HT6"),
  );
  assert.equal(revoked, refreshed.refreshToken);
  assert.equal(stored, null);
});

class MemoryStore implements CredentialStore {
  constructor(public value: GoatCredentials | null) {}

  async get(): Promise<GoatCredentials | null> {
    return this.value;
  }

  async set(credentials: GoatCredentials): Promise<void> {
    this.value = credentials;
  }

  async delete(): Promise<void> {
    this.value = null;
  }
}

function authClient(
  refresh: (refreshToken: string) => Promise<PollResult>,
): AuthApiClient {
  return {
    async createDeviceSession() {
      throw new Error("unused");
    },
    async pollDeviceToken() {
      throw new Error("unused");
    },
    async cancelDeviceSession() {},
    refresh,
    async revoke() {},
    async getUsageSummary() {
      throw new Error("unused");
    },
  };
}
