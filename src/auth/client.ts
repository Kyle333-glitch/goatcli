import type { AuthApiClient, DeviceSessionResponse, GoatCredentials, PollResult, UsageSummaryResponse, UsageSummaryResult } from './types.js';

export interface FetchLike {
  (input: string | URL, init?: RequestInit): Promise<Response>;
}

export function resolveControlPlaneUrl(env: NodeJS.ProcessEnv = process.env): URL {
  const raw = env.GOAT_CONTROL_PLANE_URL?.trim();
  if (!raw) throw new Error('GOAT_CONTROL_PLANE_URL is required for goat auth commands.');
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error('GOAT_CONTROL_PLANE_URL is not a valid URL.');
  }
  if (!isAllowedControlPlaneUrl(url)) {
    throw new Error('GOAT_CONTROL_PLANE_URL must be https://, except loopback http:// for local development.');
  }
  url.pathname = url.pathname.replace(/\/+$/, '');
  return url;
}

export function isAllowedControlPlaneUrl(url: URL): boolean {
  if (url.protocol === 'https:') return true;
  if (url.protocol !== 'http:') return false;
  if (url.hostname === 'localhost' || url.hostname === '127.0.0.1') return true;
  return url.hostname === '::1';
}

export function createAuthApiClient(baseUrl: URL, fetchImpl: FetchLike = fetch): AuthApiClient {
  return {
    async createDeviceSession() {
      try {
        const res = await fetchJson(endpoint(baseUrl, '/v1/auth/device/sessions'), { method: 'POST' }, fetchImpl);
        if (!res.ok) throw new Error(`Device login failed with HTTP ${res.status}`);
        return await res.json() as DeviceSessionResponse;
      } catch (error) {
        if (error instanceof Error && error.message.startsWith('Device login failed')) throw error;
        throw new Error('A network error occurred while starting device login.');
      }
    },
    async pollDeviceToken(deviceCode) {
      try {
        const res = await fetchJson(endpoint(baseUrl, '/v1/auth/device/token'), {
          method: 'POST',
          body: JSON.stringify({ deviceCode }),
        }, fetchImpl);
        return parseTokenResponse(res);
      } catch {
        return { status: 'network_error', message: 'A network error occurred while polling for authorization.' };
      }
    },
    async cancelDeviceSession(deviceCode) {
      await fetchJson(endpoint(baseUrl, '/v1/auth/device/cancel'), {
        method: 'POST',
        body: JSON.stringify({ deviceCode }),
      }, fetchImpl);
    },
    async refresh(refreshToken) {
      try {
        const res = await fetchJson(endpoint(baseUrl, '/v1/auth/tokens/refresh'), {
          method: 'POST',
          body: JSON.stringify({ refreshToken }),
        }, fetchImpl);
        return parseTokenResponse(res);
      } catch {
        return { status: 'network_error', message: 'A network error occurred while refreshing credentials.' };
      }
    },
    async revoke(refreshToken) {
      try {
        const res = await fetchJson(endpoint(baseUrl, '/v1/auth/tokens/revoke'), {
          method: 'POST',
          body: JSON.stringify({ refreshToken }),
        }, fetchImpl);
        if (!res.ok) throw new Error(`Token revocation failed with HTTP ${res.status}`);
      } catch (error) {
        if (error instanceof Error && error.message.startsWith('Token revocation failed')) throw error;
        throw new Error('A network error occurred while revoking the server session.');
      }
    },
    async getUsageSummary(accessToken) {
      try {
        const res = await fetchJson(endpoint(baseUrl, '/v1/usage/summary'), {
          method: 'GET',
          headers: { authorization: `Bearer ${accessToken.replace(/[\r\n]/g, '')}` },
        }, fetchImpl);
        return parseUsageSummaryResponse(res);
      } catch {
        return { status: 'network_error', message: 'A network error occurred while loading GOAT usage.' };
      }
    },
  };
}

async function fetchJson(url: URL, init: RequestInit, fetchImpl: FetchLike): Promise<Response> {
  return fetchImpl(url, {
    ...init,
    headers: {
      'content-type': 'application/json',
      accept: 'application/json',
      ...init.headers,
    },
  });
}

async function parseTokenResponse(res: Response): Promise<PollResult> {
  let body: unknown = null;
  try {
    body = await res.json();
  } catch {
    body = null;
  }

  // 202 Accepted means the device authorization is still pending;
  // check this before res.ok since res.ok is true for all 2xx.
  if (res.status === 202) return { status: 'pending', intervalSeconds: intervalSeconds(body) };

  const code = errorCode(body);
  if (code === 'authorization_pending') return { status: 'pending', intervalSeconds: intervalSeconds(body) };
  if (res.status === 429 || code === 'slow_down') {
    const retryAfter = Number(res.headers.get('retry-after'));
    return { status: 'slow_down', retryAfterSeconds: Number.isFinite(retryAfter) && retryAfter > 0 ? retryAfter : 5 };
  }
  if (code === 'access_denied') return { status: 'denied', message: 'The login request was denied.' };
  if (code === 'cancelled') return { status: 'cancelled', message: 'The login request was cancelled.' };
  if (code === 'expired_token') return { status: 'expired', message: 'The login request expired.' };
  if (code === 'revoked_token') return { status: 'revoked', message: 'The refresh token was revoked.' };
  if (code === 'replay_detected') return { status: 'replay_detected', message: 'Refresh token was already used; all tokens for this session have been revoked.' };

  if (res.ok && body && typeof body === 'object') {
    const credentials = body as GoatCredentials;
    return { status: 'authorized', credentials };
  }

  if (res.ok) return { status: 'network_error', message: 'The server returned an unexpected empty response.' };

  return { status: 'invalid_grant', message: 'The login token is invalid or already used.' };
}

async function parseUsageSummaryResponse(res: Response): Promise<UsageSummaryResult> {
  let body: unknown = null;
  try {
    body = await res.json();
  } catch {
    body = null;
  }

  if (res.status === 401) return { status: 'unauthorized', message: 'Invalid or expired GOAT access token.' };
  if (res.ok) {
    if (isUsageSummaryResponse(body)) return { status: 'ok', summary: body };
    return { status: 'unexpected_response', message: 'The server returned an unexpected usage response.' };
  }
  return { status: 'server_error', message: 'GOAT usage is temporarily unavailable.' };
}

function isUsageSummaryResponse(value: unknown): value is UsageSummaryResponse {
  const body = objectValue(value);
  if (!body) return false;
  return typeof body.version === 'string' &&
    typeof body.generatedAt === 'string' &&
    isStringOrNull(body.requestId) &&
    isUsageAccount(body.account) &&
    isUsageQuota(body.quota) &&
    isUsageWindow(body.window) &&
    isUsageBreakdown(body.usage) &&
    Array.isArray(body.recent) &&
    body.recent.every(isUsageRecentTotal);
}

function isUsageAccount(value: unknown): boolean {
  const account = objectValue(value);
  return !!account &&
    isStringOrNull(account.displayName) &&
    isStringOrNull(account.email) &&
    (account.tier === 'free' || account.tier === 'regular' || account.tier === 'premium' || account.tier === 'none') &&
    (account.status === 'active' || account.status === 'no_entitlement' || account.status === 'quota_suspended' || account.status === 'quota_revoked');
}

function isUsageQuota(value: unknown): boolean {
  const quota = objectValue(value);
  return !!quota &&
    isAmountOrNull(quota.allowanceMicrousd) &&
    isAmount(quota.usedMicrousd) &&
    isAmount(quota.activeReservedMicrousd) &&
    isAmount(quota.totalCommittedMicrousd) &&
    isAmountOrNull(quota.remainingMicrousd) &&
    typeof quota.lowQuota === 'boolean' &&
    typeof quota.lowQuotaThresholdPercent === 'number';
}

function isUsageWindow(value: unknown): boolean {
  const window = objectValue(value);
  return !!window &&
    (typeof window.seconds === 'number' || window.seconds === null) &&
    isStringOrNull(window.startedAt) &&
    isStringOrNull(window.nextResetAt);
}

function isUsageBreakdown(value: unknown): boolean {
  const usage = objectValue(value);
  return !!usage &&
    isAmount(usage.regularMicrousd) &&
    isAmount(usage.premiumMicrousd) &&
    isAmount(usage.totalMicrousd);
}

function isUsageRecentTotal(value: unknown): boolean {
  const recent = objectValue(value);
  return !!recent &&
    isUsageBreakdown(recent) &&
    typeof recent.label === 'string' &&
    typeof recent.windowSeconds === 'number';
}

function endpoint(baseUrl: URL, path: string): URL {
  const url = new URL(baseUrl.toString());
  url.pathname = url.pathname.replace(/\/+$/, '') + '/' + path.replace(/^\/+/, '');
  return url;
}

function errorCode(body: unknown): string | null {
  if (!body || typeof body !== 'object') return null;
  const error = (body as { error?: unknown }).error;
  if (!error || typeof error !== 'object') return null;
  const code = (error as { code?: unknown }).code;
  return typeof code === 'string' ? code : null;
}

function intervalSeconds(body: unknown): number | undefined {
  if (!body || typeof body !== 'object') return undefined;
  const value = (body as { intervalSeconds?: unknown }).intervalSeconds;
  return typeof value === 'number' ? value : undefined;
}

function objectValue(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === 'object' ? value as Record<string, unknown> : null;
}

function isStringOrNull(value: unknown): boolean {
  return typeof value === 'string' || value === null;
}

function isAmount(value: unknown): boolean {
  return typeof value === 'string' && /^\d+$/.test(value);
}

function isAmountOrNull(value: unknown): boolean {
  return value === null || isAmount(value);
}
