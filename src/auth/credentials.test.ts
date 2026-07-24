import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import {
  CredentialStoreError,
  createCredentialStore,
  parseCredentials,
  refreshStoredCredentials,
  type KeyringLike,
} from "./credentials.js";
import type { CredentialStore, GoatCredentials } from "./types.js";
import { getPathModule } from "../platform.js";
import { getConfigDir } from "../utils/paths.js";

const VALID: GoatCredentials = {
  accessToken: "A".repeat(43),
  refreshToken: "R".repeat(43),
  tokenType: "Bearer",
  accessTokenExpiresAt: "2026-07-17T13:00:00.000Z",
  refreshTokenExpiresAt: "2026-07-18T13:00:00.000Z",
};

const ROTATED: GoatCredentials = {
  ...VALID,
  accessToken: "C".repeat(43),
  refreshToken: "D".repeat(43),
};

test("accepts only the exact five-field credential schema and 43-byte tokens", () => {
  assert.deepEqual(parseCredentials(JSON.stringify(VALID)), VALID);
  for (const value of [
    { ...VALID, arbitrary: "ENV_SECRET_9DK1" },
    { ...VALID, accessToken: "short" },
    { ...VALID, refreshToken: `${"R".repeat(42)}=` },
    { ...VALID, tokenType: "bearer" },
    { ...VALID, accessTokenExpiresAt: "not-a-date" },
  ]) {
    assert.equal(parseCredentials(JSON.stringify(value)), null);
  }
});

test("uses only the OS keyring for active credentials and verifies writes", async () => {
  await withCredentialRoot(async (root, platform) => {
    const keyring = new MemoryKeyring();
    const store = createCredentialStore(storeOptions(root, platform, keyring));
    assert.equal(await store.get(), null);
    await store.set(VALID);
    assert.deepEqual(await store.get(), VALID);
    assert.equal(keyring.raw, JSON.stringify(VALID));
    await store.delete();
    assert.equal(await store.get(), null);
  });
});

test("migrates a strict legacy file only after keyring write and readback", async () => {
  await withCredentialRoot(async (root, platform) => {
    const keyring = new MemoryKeyring();
    const legacyPath = legacyCredentialPath(root, platform);
    await fs.mkdir(path.dirname(legacyPath), { recursive: true });
    await fs.writeFile(legacyPath, JSON.stringify(VALID), "utf8");
    await fs.writeFile(
      `${legacyPath}.SOURCE_CODE_SECRET_4JK2.tmp`,
      "stale",
      "utf8",
    );

    const store = createCredentialStore(storeOptions(root, platform, keyring));
    assert.deepEqual(await store.get(), VALID);
    assert.equal(keyring.raw, JSON.stringify(VALID));
    await assert.rejects(() => fs.stat(legacyPath), hasFsCode("ENOENT"));
    await assert.rejects(
      () => fs.stat(`${legacyPath}.SOURCE_CODE_SECRET_4JK2.tmp`),
      hasFsCode("ENOENT"),
    );
  });
});

test("never authenticates from plaintext when migration cannot be verified", async () => {
  await withCredentialRoot(async (root, platform) => {
    const legacyPath = legacyCredentialPath(root, platform);
    await fs.mkdir(path.dirname(legacyPath), { recursive: true });
    await fs.writeFile(legacyPath, JSON.stringify(VALID), "utf8");
    const keyring = new MemoryKeyring();
    keyring.failSet = true;
    const store = createCredentialStore(storeOptions(root, platform, keyring));

    await assert.rejects(
      () => store.get(),
      (error) =>
        error instanceof CredentialStoreError &&
        error.code === "GOAT_CREDENTIAL_MIGRATION_FAILED" &&
        !error.message.includes(legacyPath),
    );
    assert.equal(await fs.readFile(legacyPath, "utf8"), JSON.stringify(VALID));
    assert.equal(keyring.raw, null);
  });
});

test("rejects malformed keyring data without falling back to a legacy file", async () => {
  await withCredentialRoot(async (root, platform) => {
    const legacyPath = legacyCredentialPath(root, platform);
    await fs.mkdir(path.dirname(legacyPath), { recursive: true });
    await fs.writeFile(legacyPath, JSON.stringify(VALID), "utf8");
    const keyring = new MemoryKeyring();
    keyring.raw = JSON.stringify({ ...VALID, filename: "PATH_SECRET_3HT6" });
    const store = createCredentialStore(storeOptions(root, platform, keyring));

    await assert.rejects(
      () => store.get(),
      (error) =>
        error instanceof CredentialStoreError &&
        error.code === "GOAT_CREDENTIALS_INVALID",
    );
    assert.equal(await fs.readFile(legacyPath, "utf8"), JSON.stringify(VALID));
  });
});

test("rejects oversized legacy credential files without reading them into the keyring", async () => {
  await withCredentialRoot(async (root, platform) => {
    const legacyPath = legacyCredentialPath(root, platform);
    await fs.mkdir(path.dirname(legacyPath), { recursive: true });
    await fs.writeFile(legacyPath, "TOKEN_SECRET_8MVP".repeat(300), "utf8");
    const keyring = new MemoryKeyring();
    const store = createCredentialStore(storeOptions(root, platform, keyring));

    await assert.rejects(
      () => store.get(),
      (error) =>
        error instanceof CredentialStoreError &&
        error.code === "GOAT_CREDENTIALS_INVALID" &&
        !error.message.includes(legacyPath),
    );
    assert.equal(keyring.raw, null);
    assert.ok((await fs.stat(legacyPath)).size > 4 * 1024);
  });
});

test("rejects legacy credential symlinks instead of migrating their targets", async (context) => {
  await withCredentialRoot(async (root, platform) => {
    const legacyPath = legacyCredentialPath(root, platform);
    const targetPath = path.join(root, "TOKEN_SECRET_8MVP.json");
    await fs.mkdir(path.dirname(legacyPath), { recursive: true });
    await fs.writeFile(targetPath, JSON.stringify(VALID), "utf8");
    try {
      await fs.symlink(targetPath, legacyPath, "file");
    } catch (error) {
      if (
        typeof error === "object" &&
        error !== null &&
        "code" in error &&
        ["EPERM", "EACCES", "ENOTSUP"].includes(
          String((error as { code?: unknown }).code),
        )
      ) {
        context.skip("file symlinks are unavailable on this host");
        return;
      }
      throw error;
    }

    const keyring = new MemoryKeyring();
    const store = createCredentialStore(storeOptions(root, platform, keyring));
    await assert.rejects(
      () => store.get(),
      (error) =>
        error instanceof CredentialStoreError &&
        error.code === "GOAT_CREDENTIALS_INVALID" &&
        !error.message.includes(targetPath),
    );
    assert.equal(keyring.raw, null);
    assert.equal(await fs.readFile(targetPath, "utf8"), JSON.stringify(VALID));
  });
});

test("refresh helper revokes and clears a rotated credential when persistence fails", async () => {
  let stored: GoatCredentials | null = VALID;
  let refreshedWith: string | undefined;
  const revoked: string[] = [];
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

  await assert.rejects(
    () =>
      refreshStoredCredentials(
        {
          async refresh(refreshToken) {
            refreshedWith = refreshToken;
            return { status: "authorized", credentials: ROTATED };
          },
          async revoke(refreshToken) {
            revoked.push(refreshToken);
            throw new Error("TOKEN_SECRET_8MVP");
          },
        },
        store,
      ),
    (error) =>
      error instanceof CredentialStoreError &&
      error.code === "GOAT_CREDENTIAL_STORE_UNAVAILABLE" &&
      !error.message.includes("PATH_SECRET_3HT6") &&
      !error.message.includes("TOKEN_SECRET_8MVP"),
  );

  assert.equal(refreshedWith, VALID.refreshToken);
  assert.deepEqual(revoked, [ROTATED.refreshToken]);
  assert.equal(stored, null);
});

class MemoryKeyring implements KeyringLike {
  raw: string | null = null;
  failSet = false;

  async getPassword(): Promise<string | null> {
    return this.raw;
  }

  async setPassword(
    _service: string,
    _account: string,
    password: string,
  ): Promise<void> {
    if (this.failSet) throw new Error("PATH_SECRET_3HT6");
    this.raw = password;
  }

  async deletePassword(): Promise<boolean> {
    const existed = this.raw !== null;
    this.raw = null;
    return existed;
  }
}

async function withCredentialRoot(
  run: (root: string, platform: "win32" | "darwin") => Promise<void>,
): Promise<void> {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "goatcli-keyring-"));
  const platform = process.platform === "darwin" ? "darwin" : "win32";
  try {
    await run(root, platform);
  } finally {
    await fs.rm(root, { force: true, recursive: true });
  }
}

function storeOptions(
  root: string,
  platform: "win32" | "darwin",
  keyring: KeyringLike,
) {
  return {
    platform,
    homeDir: root,
    env: platform === "win32" ? { APPDATA: root, LOCALAPPDATA: root } : {},
    keyring,
  };
}

function legacyCredentialPath(
  root: string,
  platform: "win32" | "darwin",
): string {
  const pathModule = getPathModule(platform);
  return pathModule.join(
    getConfigDir({
      platform,
      homeDir: root,
      env: platform === "win32" ? { APPDATA: root, LOCALAPPDATA: root } : {},
    }),
    "auth.json",
  );
}

function hasFsCode(code: string): (error: unknown) => boolean {
  return (error) =>
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    (error as { code?: unknown }).code === code;
}
