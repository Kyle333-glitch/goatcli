import type {
  AuthApiClient,
  CredentialStore,
  GoatCredentials,
} from "../auth/types.js";
import type { PrivacyLaunchCredential } from "../engine/launch.js";

export type PrivacyCredentialErrorCode =
  "GOAT_PRIVACY_LOGIN_REQUIRED" | "GOAT_PRIVACY_CREDENTIAL_UNAVAILABLE";

const OPAQUE_TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;

const activeRefresh = new WeakMap<AuthApiClient, Promise<unknown>>();

export class PrivacyCredentialError extends Error {
  readonly code: PrivacyCredentialErrorCode;

  constructor(code: PrivacyCredentialErrorCode) {
    super(
      code === "GOAT_PRIVACY_LOGIN_REQUIRED"
        ? "GOAT privacy authentication is required. Run `goat login`."
        : "GOAT privacy authentication is unavailable. Try again later.",
    );
    this.name = "PrivacyCredentialError";
    this.code = code;
  }
}

export interface PreparePrivacyCredentialOptions {
  readonly client: AuthApiClient;
  readonly store: CredentialStore;
  readonly now?: () => number;
  readonly minimumLifetimeMs?: number;
}

export async function preparePrivacyCredential(
  options: PreparePrivacyCredentialOptions,
): Promise<PrivacyLaunchCredential> {
  const now = options.now?.() ?? Date.now();
  const minimumLifetimeMs = options.minimumLifetimeMs ?? 60_000;
  if (
    !Number.isSafeInteger(now) ||
    now <= 0 ||
    !Number.isSafeInteger(minimumLifetimeMs) ||
    minimumLifetimeMs < 0
  ) {
    throw new PrivacyCredentialError("GOAT_PRIVACY_CREDENTIAL_UNAVAILABLE");
  }

  let current: GoatCredentials | null;
  try {
    current = await options.store.get();
  } catch {
    throw new PrivacyCredentialError("GOAT_PRIVACY_CREDENTIAL_UNAVAILABLE");
  }
  if (!current) {
    throw new PrivacyCredentialError("GOAT_PRIVACY_LOGIN_REQUIRED");
  }

  const accessExpiry = Date.parse(current.accessTokenExpiresAt);
  if (
    Number.isSafeInteger(accessExpiry) &&
    accessExpiry > now + minimumLifetimeMs
  ) {
    return encodeCredential(current);
  }

  const refreshExpiry = Date.parse(current.refreshTokenExpiresAt);
  if (!Number.isSafeInteger(refreshExpiry) || refreshExpiry <= now) {
    await deleteInvalidCredentials(options.store);
    throw new PrivacyCredentialError("GOAT_PRIVACY_LOGIN_REQUIRED");
  }

  const refreshed = await refreshWithMutex(options.client, current.refreshToken);
  if (refreshed.status !== "authorized") {
    if (
      refreshed.status === "invalid_grant" ||
      refreshed.status === "revoked" ||
      refreshed.status === "replay_detected" ||
      refreshed.status === "expired"
    ) {
      await deleteInvalidCredentials(options.store);
      throw new PrivacyCredentialError("GOAT_PRIVACY_LOGIN_REQUIRED");
    }
    throw new PrivacyCredentialError("GOAT_PRIVACY_CREDENTIAL_UNAVAILABLE");
  }

  if (!isValidGoatCredentials(refreshed.credentials, now)) {
    await discardUnstoredCredential(
      options.client,
      options.store,
      refreshed.credentials.refreshToken,
    );
    throw new PrivacyCredentialError("GOAT_PRIVACY_CREDENTIAL_UNAVAILABLE");
  }

  try {
    await options.store.set(refreshed.credentials);
  } catch {
    await discardUnstoredCredential(
      options.client,
      options.store,
      refreshed.credentials.refreshToken,
    );
    throw new PrivacyCredentialError("GOAT_PRIVACY_CREDENTIAL_UNAVAILABLE");
  }
  return encodeCredential(refreshed.credentials);
}

async function refreshWithMutex(
  client: AuthApiClient,
  refreshToken: string,
): Promise<import("../auth/types.js").PollResult> {
  const pending = activeRefresh.get(client);
  if (pending) {
    const result = (await pending.catch(() => undefined)) as
      | import("../auth/types.js").PollResult
      | undefined;
    if (result?.status === "authorized") {
      return result;
    }
  }
  const operation = client.refresh(refreshToken).catch(() => ({
    status: "network_error" as const,
    message: "Unable to refresh GOAT privacy credential.",
  }));
  activeRefresh.set(client, operation);
  try {
    return await operation;
  } finally {
    activeRefresh.delete(client);
  }
}

function isValidGoatCredentials(
  credentials: GoatCredentials,
  now: number,
): boolean {
  if (typeof credentials.accessToken !== "string" || !OPAQUE_TOKEN_PATTERN.test(credentials.accessToken)) {
    return false;
  }
  if (typeof credentials.refreshToken !== "string" || !OPAQUE_TOKEN_PATTERN.test(credentials.refreshToken)) {
    return false;
  }
  if (credentials.tokenType !== "Bearer") {
    return false;
  }
  const accessExpiresAt = Date.parse(credentials.accessTokenExpiresAt);
  const refreshExpiresAt = Date.parse(credentials.refreshTokenExpiresAt);
  if (
    !Number.isSafeInteger(accessExpiresAt) ||
    accessExpiresAt <= now ||
    !Number.isSafeInteger(refreshExpiresAt) ||
    refreshExpiresAt <= now
  ) {
    return false;
  }
  return true;
}

async function discardUnstoredCredential(
  client: AuthApiClient,
  store: CredentialStore,
  refreshToken: string,
): Promise<void> {
  try {
    await client.revoke(refreshToken);
  } catch {
    // Best effort: never surface server details or the credential.
  }
  try {
    await store.delete();
  } catch {
    // Best effort: preserve the fixed privacy credential error.
  }
}

function encodeCredential(
  credentials: GoatCredentials,
): PrivacyLaunchCredential {
  const expiresAtUnixMs = Date.parse(credentials.accessTokenExpiresAt);
  const accessToken = new TextEncoder().encode(credentials.accessToken);
  if (
    accessToken.byteLength !== 43 ||
    !/^[A-Za-z0-9_-]{43}$/.test(credentials.accessToken) ||
    !Number.isSafeInteger(expiresAtUnixMs)
  ) {
    accessToken.fill(0);
    throw new PrivacyCredentialError("GOAT_PRIVACY_CREDENTIAL_UNAVAILABLE");
  }
  return { accessToken, expiresAtUnixMs };
}

async function deleteInvalidCredentials(store: CredentialStore): Promise<void> {
  try {
    await store.delete();
  } catch {
    throw new PrivacyCredentialError("GOAT_PRIVACY_CREDENTIAL_UNAVAILABLE");
  }
}
