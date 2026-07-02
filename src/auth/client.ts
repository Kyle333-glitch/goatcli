import type { AuthApiClient, DeviceSessionResponse, GoatCredentials, PollResult } from './types.js';

export interface FetchLike {
  (input: string | URL, init?: RequestInit): Promise<Response>;
}

export function resolveControlPlaneUrl(env: NodeJS.ProcessEnv = process.env): URL {
  const raw = env.GOAT_CONTROL_PLANE_URL?.trim();
  if (!raw) throw new Error('GOAT_CONTROL_PLANE_URL is required for goat auth commands.');
  const url = new URL(raw);
  if (!isAllowedControlPlaneUrl(url)) {
    throw new Error('GOAT_CONTROL_PLANE_URL must be https://, except loopback http:// for local development.');
  }
  url.pathname = url.pathname.replace(/\/+$/, '');
  return url;
}

export function isAllowedControlPlaneUrl(url: URL): boolean {
  if (url.protocol === 'https:') return true;
  return url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
}

export function createAuthApiClient(baseUrl: URL, fetchImpl: FetchLike = fetch): AuthApiClient {
  return {
    async createDeviceSession() {
      const res = await fetchJson(endpoint(baseUrl, '/v1/auth/device/sessions'), { method: 'POST' }, fetchImpl);
      if (!res.ok) throw new Error(`Device login failed with HTTP ${res.status}`);
      return await res.json() as DeviceSessionResponse;
    },
    async pollDeviceToken(deviceCode) {
      const res = await fetchJson(endpoint(baseUrl, '/v1/auth/device/token'), {
        method: 'POST',
        body: JSON.stringify({ deviceCode }),
      }, fetchImpl);
      return parseTokenResponse(res);
    },
    async cancelDeviceSession(deviceCode) {
      await fetchJson(endpoint(baseUrl, '/v1/auth/device/cancel'), {
        method: 'POST',
        body: JSON.stringify({ deviceCode }),
      }, fetchImpl);
    },
    async refresh(refreshToken) {
      const res = await fetchJson(endpoint(baseUrl, '/v1/auth/tokens/refresh'), {
        method: 'POST',
        body: JSON.stringify({ refreshToken }),
      }, fetchImpl);
      return parseTokenResponse(res);
    },
    async revoke(refreshToken) {
      const res = await fetchJson(endpoint(baseUrl, '/v1/auth/tokens/revoke'), {
        method: 'POST',
        body: JSON.stringify({ refreshToken }),
      }, fetchImpl);
      if (!res.ok) throw new Error(`Token revocation failed with HTTP ${res.status}`);
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

  if (res.ok) {
    const credentials = body as GoatCredentials;
    return { status: 'authorized', credentials };
  }

  const code = errorCode(body);
  if (res.status === 202 || code === 'authorization_pending') return { status: 'pending', intervalSeconds: intervalSeconds(body) };
  if (res.status === 429 || code === 'slow_down') {
    const retryAfter = Number(res.headers.get('retry-after'));
    return { status: 'slow_down', retryAfterSeconds: Number.isFinite(retryAfter) && retryAfter > 0 ? retryAfter : 5 };
  }
  if (code === 'access_denied') return { status: 'denied', message: 'The login request was denied.' };
  if (code === 'cancelled') return { status: 'cancelled', message: 'The login request was cancelled.' };
  if (code === 'expired_token') return { status: 'expired', message: 'The login request expired.' };
  if (code === 'revoked_token') return { status: 'revoked', message: 'The refresh token was revoked.' };
  if (code === 'replay_detected') return { status: 'replay_detected', message: 'Refresh token was already used; all tokens for this session have been revoked.' };
  return { status: 'invalid_grant', message: 'The login token is invalid or already used.' };
}

function endpoint(baseUrl: URL, path: string): URL {
  return new URL(path, baseUrl);
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