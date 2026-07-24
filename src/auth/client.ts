import {
  request as httpRequest,
  type IncomingMessage,
  type RequestOptions,
} from "node:http";
import { request as httpsRequest } from "node:https";
import { compiledControlPlaneOrigin as compiledReleasePolicyOrigin } from "../privacy/release-policy.js";
import type {
  AuthApiClient,
  DeviceSessionResponse,
  GoatCredentials,
  PollResult,
  UsageAccountStatus,
  UsageAmountBreakdown,
  UsageQuotaSummary,
  UsageRecentTotal,
  UsageSummaryResponse,
  UsageSummaryResult,
  UsageTier,
  UsageWindowSummary,
} from "./types.js";

const REQUEST_TIMEOUT_MS = 5_000;
const MAX_RESPONSE_BYTES = 16 * 1024;
const OPAQUE_TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const USER_CODE_PATTERN = /^[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$/;
const AMOUNT_PATTERN = /^\d{1,20}$/;
const JSON_CONTENT_TYPE_PATTERN = /^application\/json(?:\s*;|$)/i;

const AUTH_USER_AGENT = "GOAT-auth/1";
const USAGE_USER_AGENT = "GOAT-usage/1";
const DEVICE_AUTH_PATH = "/auth/device";

const ROUTES = {
  createDeviceSession: "/v1/auth/device/sessions",
  pollDeviceToken: "/v1/auth/device/token",
  cancelDeviceSession: "/v1/auth/device/cancel",
  refresh: "/v1/auth/tokens/refresh",
  revoke: "/v1/auth/tokens/revoke",
  usage: "/v1/usage/summary",
} as const;

export type ControlPlaneClientErrorCode =
  | "control_plane_unavailable"
  | "invalid_auth_data"
  | "network_error"
  | "request_timeout"
  | "response_too_large"
  | "unexpected_response";

const ERROR_MESSAGES: Readonly<Record<ControlPlaneClientErrorCode, string>> = {
  control_plane_unavailable: "GOAT control plane is unavailable in this build.",
  invalid_auth_data: "GOAT authentication data is invalid.",
  network_error: "Unable to reach GOAT control plane.",
  request_timeout: "GOAT control plane request timed out.",
  response_too_large: "GOAT control plane returned an invalid response.",
  unexpected_response: "GOAT control plane returned an unexpected response.",
};

const POLL_NETWORK_ERROR = "Unable to complete GOAT authorization right now.";
const INVALID_GRANT_ERROR = "The login token is invalid or already used.";

export class ControlPlaneClientError extends Error {
  constructor(readonly code: ControlPlaneClientErrorCode) {
    super(ERROR_MESSAGES[code]);
    this.name = "ControlPlaneClientError";
  }
}

export interface ControlPlaneResolutionOptions {
  /** Explicit dependency injection for development and tests. Only loopback origins are accepted. */
  developmentOrigin?: string | URL;
}

/**
 * Resolve the single compiled control-plane origin. Environment values are deliberately ignored.
 * Development and tests must inject a loopback-only origin explicitly.
 */
export function resolveControlPlaneUrl(
  _env: NodeJS.ProcessEnv = process.env,
  options: ControlPlaneResolutionOptions = {},
): URL {
  const production = compiledProductionOrigin();
  if (production) return production;
  if (options.developmentOrigin !== undefined) {
    return normalizeOrigin(options.developmentOrigin, true);
  }
  throw new ControlPlaneClientError("control_plane_unavailable");
}

/** True only for the compiled production origin or an exact loopback development origin. */
export function isAllowedControlPlaneUrl(url: URL): boolean {
  let normalized: URL;
  try {
    normalized = normalizeOrigin(url, false);
  } catch {
    return false;
  }

  const production = compiledProductionOrigin();
  if (production?.origin === normalized.origin) return true;
  return isLoopback(normalized);
}

/** Construct the only URL the launcher may open for browser authentication. */
export function canonicalDeviceAuthorizationUrl(origin: URL): string {
  const normalized = requireAllowedOrigin(origin);
  return new URL(DEVICE_AUTH_PATH, normalized).toString();
}

export function createAuthApiClient(baseUrl: URL): AuthApiClient {
  const origin = requireAllowedOrigin(baseUrl);

  return {
    async createDeviceSession() {
      const response = await performEssentialRequest(origin, {
        kind: "create_device_session",
      });
      const body = parseJsonBody(response);
      if (response.statusCode !== 201)
        throw new ControlPlaneClientError("unexpected_response");
      const session = parseDeviceSession(body, origin);
      if (!session) throw new ControlPlaneClientError("unexpected_response");
      return session;
    },

    async pollDeviceToken(deviceCode) {
      if (!isOpaqueToken(deviceCode)) return invalidGrant();
      try {
        const response = await performEssentialRequest(origin, {
          kind: "poll_device_token",
          deviceCode,
        });
        return parseTokenResponse(response);
      } catch {
        return { status: "network_error", message: POLL_NETWORK_ERROR };
      }
    },

    async cancelDeviceSession(deviceCode) {
      if (!isOpaqueToken(deviceCode))
        throw new ControlPlaneClientError("invalid_auth_data");
      const response = await performEssentialRequest(origin, {
        kind: "cancel_device_session",
        deviceCode,
      });
      const body = parseJsonBody(response);
      if (response.statusCode !== 200 || !isOkResponse(body)) {
        throw new ControlPlaneClientError("unexpected_response");
      }
    },

    async refresh(refreshToken) {
      if (!isOpaqueToken(refreshToken)) return invalidGrant();
      try {
        const response = await performEssentialRequest(origin, {
          kind: "refresh",
          refreshToken,
        });
        return parseTokenResponse(response);
      } catch {
        return { status: "network_error", message: POLL_NETWORK_ERROR };
      }
    },

    async revoke(refreshToken) {
      if (!isOpaqueToken(refreshToken))
        throw new ControlPlaneClientError("invalid_auth_data");
      const response = await performEssentialRequest(origin, {
        kind: "revoke",
        refreshToken,
      });
      const body = parseJsonBody(response);
      if (response.statusCode !== 200 || !isOkResponse(body)) {
        throw new ControlPlaneClientError("unexpected_response");
      }
    },

    async getUsageSummary(accessToken) {
      if (!isOpaqueToken(accessToken)) {
        return {
          status: "unauthorized",
          message: "Invalid or expired GOAT access token.",
        };
      }
      try {
        const response = await performEssentialRequest(origin, {
          kind: "usage",
          accessToken,
        });
        return parseUsageSummaryResponse(response);
      } catch {
        return {
          status: "network_error",
          message: "Unable to reach GOAT control plane.",
        };
      }
    },
  };
}

type EssentialOperation =
  | { kind: "create_device_session" }
  | { kind: "poll_device_token"; deviceCode: string }
  | { kind: "cancel_device_session"; deviceCode: string }
  | { kind: "refresh"; refreshToken: string }
  | { kind: "revoke"; refreshToken: string }
  | { kind: "usage"; accessToken: string };

interface EssentialResponse {
  statusCode: number;
  contentType: string | undefined;
  retryAfter: string | undefined;
  body: Buffer;
}

function performEssentialRequest(
  origin: URL,
  operation: EssentialOperation,
): Promise<EssentialResponse> {
  switch (operation.kind) {
    case "create_device_session":
      return sendRequest(
        origin,
        "POST",
        ROUTES.createDeviceSession,
        AUTH_USER_AGENT,
      );
    case "poll_device_token":
      return sendRequest(
        origin,
        "POST",
        ROUTES.pollDeviceToken,
        AUTH_USER_AGENT,
        { deviceCode: operation.deviceCode },
      );
    case "cancel_device_session":
      return sendRequest(
        origin,
        "POST",
        ROUTES.cancelDeviceSession,
        AUTH_USER_AGENT,
        { deviceCode: operation.deviceCode },
      );
    case "refresh":
      return sendRequest(origin, "POST", ROUTES.refresh, AUTH_USER_AGENT, {
        refreshToken: operation.refreshToken,
      });
    case "revoke":
      return sendRequest(origin, "POST", ROUTES.revoke, AUTH_USER_AGENT, {
        refreshToken: operation.refreshToken,
      });
    case "usage":
      return sendRequest(
        origin,
        "GET",
        ROUTES.usage,
        USAGE_USER_AGENT,
        undefined,
        operation.accessToken,
      );
  }
}

function sendRequest(
  origin: URL,
  method: "GET" | "POST",
  path: (typeof ROUTES)[keyof typeof ROUTES],
  userAgent: typeof AUTH_USER_AGENT | typeof USAGE_USER_AGENT,
  jsonBody?: { deviceCode: string } | { refreshToken: string },
  accessToken?: string,
): Promise<EssentialResponse> {
  const body =
    jsonBody === undefined
      ? undefined
      : Buffer.from(JSON.stringify(jsonBody), "utf8");
  const headers: Record<string, string | number> = {
    accept: "application/json",
    "user-agent": userAgent,
  };
  if (body) {
    headers["content-type"] = "application/json";
  }
  if (accessToken !== undefined)
    headers.authorization = `Bearer ${accessToken}`;

  const requestOptions: RequestOptions = {
    protocol: origin.protocol,
    hostname: origin.hostname,
    port: origin.port || undefined,
    method,
    path,
    headers,
    agent: false,
  };
  const requestFn = origin.protocol === "https:" ? httpsRequest : httpRequest;

  return new Promise<EssentialResponse>((resolve, reject) => {
    let settled = false;
    let request: ReturnType<typeof httpRequest> | undefined;
    let response: IncomingMessage | undefined;
    let deadline: ReturnType<typeof setTimeout> | undefined;
    const clearDeadline = () => {
      if (deadline !== undefined) clearTimeout(deadline);
    };
    const finishError = (code: ControlPlaneClientErrorCode) => {
      if (settled) return;
      settled = true;
      clearDeadline();
      body?.fill(0);
      response?.destroy();
      reject(new ControlPlaneClientError(code));
    };

    try {
      request = requestFn(requestOptions, (incoming) => {
        response = incoming;
        collectResponse(incoming).then(
          (result) => {
            if (settled) {
              result.body.fill(0);
              return;
            }
            settled = true;
            clearDeadline();
            resolve(result);
          },
          (error: unknown) =>
            finishError(
              error instanceof ControlPlaneClientError
                ? error.code
                : "network_error",
            ),
        );
      });
    } catch {
      finishError("network_error");
      return;
    }

    deadline = setTimeout(() => {
      finishError("request_timeout");
      request?.destroy();
    }, REQUEST_TIMEOUT_MS);
    request.once("error", () => finishError("network_error"));
    if (body) request.end(body, () => body.fill(0));
    else request.end();
  });
}
function collectResponse(
  response: IncomingMessage,
): Promise<EssentialResponse> {
  return new Promise((resolve, reject) => {
    if (
      response.headers.location !== undefined ||
      response.headers["set-cookie"] !== undefined
    ) {
      response.resume();
      reject(new ControlPlaneClientError("unexpected_response"));
      return;
    }

    const declaredLength = parseContentLength(
      response.headers["content-length"],
    );
    if (declaredLength !== null && declaredLength > MAX_RESPONSE_BYTES) {
      response.resume();
      reject(new ControlPlaneClientError("response_too_large"));
      return;
    }

    const chunks: Buffer[] = [];
    let size = 0;
    let finished = false;
    const fail = (code: ControlPlaneClientErrorCode) => {
      if (finished) return;
      finished = true;
      for (const chunk of chunks) chunk.fill(0);
      response.destroy();
      reject(new ControlPlaneClientError(code));
    };

    response.on("data", (chunk: Buffer | string) => {
      if (finished) return;
      const buffer = Buffer.isBuffer(chunk)
        ? chunk
        : Buffer.from(chunk, "utf8");
      size += buffer.byteLength;
      if (size > MAX_RESPONSE_BYTES) {
        buffer.fill(0);
        fail("response_too_large");
        return;
      }
      chunks.push(buffer);
    });
    response.once("aborted", () => fail("network_error"));
    response.once("error", () => fail("network_error"));
    response.once("end", () => {
      if (finished) return;
      finished = true;
      const body = Buffer.concat(chunks, size);
      for (const chunk of chunks) chunk.fill(0);
      resolve({
        statusCode: response.statusCode ?? 0,
        contentType: singleHeader(response.headers["content-type"]),
        retryAfter: singleHeader(response.headers["retry-after"]),
        body,
      });
    });
  });
}

function parseJsonBody(response: EssentialResponse): unknown {
  try {
    if (
      !response.contentType ||
      !JSON_CONTENT_TYPE_PATTERN.test(response.contentType)
    ) {
      throw new ControlPlaneClientError("unexpected_response");
    }
    return JSON.parse(response.body.toString("utf8")) as unknown;
  } catch (error) {
    if (error instanceof ControlPlaneClientError) throw error;
    throw new ControlPlaneClientError("unexpected_response");
  } finally {
    response.body.fill(0);
  }
}

function parseDeviceSession(
  body: unknown,
  origin: URL,
): DeviceSessionResponse | null {
  const value = exactObject(body, [
    "verificationUrl",
    "userCode",
    "deviceCode",
    "intervalSeconds",
    "expiresAt",
    "expiresInSeconds",
  ]);
  if (!value) return null;

  const verificationUrl = canonicalDeviceAuthorizationUrl(origin);
  if (
    value.verificationUrl !== verificationUrl ||
    typeof value.userCode !== "string" ||
    !USER_CODE_PATTERN.test(value.userCode) ||
    typeof value.deviceCode !== "string" ||
    !isOpaqueToken(value.deviceCode) ||
    !isIntegerInRange(value.intervalSeconds, 1, 120) ||
    !isCanonicalIsoDate(value.expiresAt) ||
    !isIntegerInRange(value.expiresInSeconds, 1, 3_600)
  ) {
    return null;
  }

  return {
    verificationUrl,
    userCode: value.userCode,
    deviceCode: value.deviceCode,
    intervalSeconds: value.intervalSeconds,
    expiresAt: value.expiresAt,
    expiresInSeconds: value.expiresInSeconds,
  };
}

function parseTokenResponse(response: EssentialResponse): PollResult {
  const body = parseJsonBody(response);

  if (response.statusCode === 200) {
    const credentials = parseCredentials(body);
    return credentials ? { status: "authorized", credentials } : networkError();
  }

  if (response.statusCode === 202) {
    const pending = parsePendingResponse(body);
    return pending ?? networkError();
  }

  const code = parseTokenErrorCode(body);
  if (response.statusCode === 429 && code === "slow_down") {
    return {
      status: "slow_down",
      retryAfterSeconds: parseRetryAfter(response.retryAfter),
    };
  }
  if (code === "access_denied")
    return { status: "denied", message: "The login request was denied." };
  if (code === "cancelled")
    return { status: "cancelled", message: "The login request was cancelled." };
  if (code === "expired_token")
    return { status: "expired", message: "The login request expired." };
  if (code === "revoked_token")
    return { status: "revoked", message: "The refresh token was revoked." };
  if (code === "replay_detected") {
    return {
      status: "replay_detected",
      message: "Refresh token replay was detected and the session was revoked.",
    };
  }
  if (code === "invalid_grant" || code === "invalid_request")
    return invalidGrant();
  return networkError();
}

function parseCredentials(body: unknown): GoatCredentials | null {
  const value = exactObject(body, [
    "accessToken",
    "refreshToken",
    "tokenType",
    "accessTokenExpiresAt",
    "refreshTokenExpiresAt",
  ]);
  if (
    !value ||
    typeof value.accessToken !== "string" ||
    !isOpaqueToken(value.accessToken) ||
    typeof value.refreshToken !== "string" ||
    !isOpaqueToken(value.refreshToken) ||
    value.tokenType !== "Bearer" ||
    !isCanonicalIsoDate(value.accessTokenExpiresAt) ||
    !isCanonicalIsoDate(value.refreshTokenExpiresAt)
  ) {
    return null;
  }
  return {
    accessToken: value.accessToken,
    refreshToken: value.refreshToken,
    tokenType: "Bearer",
    accessTokenExpiresAt: value.accessTokenExpiresAt,
    refreshTokenExpiresAt: value.refreshTokenExpiresAt,
  };
}

function parsePendingResponse(
  body: unknown,
): Extract<PollResult, { status: "pending" }> | null {
  const value = exactObject(body, ["error", "intervalSeconds"]);
  if (!value || !isIntegerInRange(value.intervalSeconds, 1, 120)) return null;
  const error = parseErrorObject(value.error, ["authorization_pending"]);
  if (!error) return null;
  return { status: "pending", intervalSeconds: value.intervalSeconds };
}

function parseTokenErrorCode(body: unknown): string | null {
  const value = exactObject(body, ["error"]);
  if (!value) return null;
  return parseErrorObject(value.error, [
    "slow_down",
    "access_denied",
    "cancelled",
    "expired_token",
    "revoked_token",
    "replay_detected",
    "invalid_grant",
    "invalid_request",
  ]);
}

function parseUsageSummaryResponse(
  response: EssentialResponse,
): UsageSummaryResult {
  const body = parseJsonBody(response);
  if (response.statusCode === 401) {
    return isUsageError(body, "unauthorized")
      ? {
          status: "unauthorized",
          message: "Invalid or expired GOAT access token.",
        }
      : {
          status: "unexpected_response",
          message: "GOAT control plane returned an unexpected response.",
        };
  }
  if (response.statusCode === 200) {
    const summary = parseUsageSummary(body);
    return summary
      ? { status: "ok", summary }
      : {
          status: "unexpected_response",
          message: "GOAT control plane returned an unexpected response.",
        };
  }
  return isUsageError(body)
    ? {
        status: "server_error",
        message: "GOAT usage is temporarily unavailable.",
      }
    : {
        status: "unexpected_response",
        message: "GOAT control plane returned an unexpected response.",
      };
}

function parseUsageSummary(body: unknown): UsageSummaryResponse | null {
  const value = exactObject(body, [
    "version",
    "generatedAt",
    "account",
    "quota",
    "window",
    "usage",
    "recent",
  ]);
  if (
    !value ||
    value.version !== "v0.3.2" ||
    !isCanonicalIsoDate(value.generatedAt)
  ) {
    return null;
  }

  const account = exactObject(value.account, ["tier", "status"]);
  if (!account) return null;
  if (!isUsageTier(account.tier) || !isUsageAccountStatus(account.status))
    return null;

  const quota = parseUsageQuota(value.quota);
  const window = parseUsageWindow(value.window);
  const usage = parseUsageBreakdown(value.usage);
  const recent = parseUsageRecent(value.recent);
  if (!quota || !window || !usage || !recent) return null;

  return {
    version: "v0.3.2",
    generatedAt: value.generatedAt,
    account: { tier: account.tier, status: account.status },
    quota,
    window,
    usage,
    recent,
  };
}

function parseUsageQuota(input: unknown): UsageQuotaSummary | null {
  const value = exactObject(input, [
    "allowanceMicrousd",
    "usedMicrousd",
    "activeReservedMicrousd",
    "totalCommittedMicrousd",
    "remainingMicrousd",
    "lowQuota",
    "lowQuotaThresholdPercent",
  ]);
  if (
    !value ||
    !isAmountOrNull(value.allowanceMicrousd) ||
    !isAmount(value.usedMicrousd) ||
    !isAmount(value.activeReservedMicrousd) ||
    !isAmount(value.totalCommittedMicrousd) ||
    !isAmountOrNull(value.remainingMicrousd) ||
    typeof value.lowQuota !== "boolean" ||
    !isIntegerInRange(value.lowQuotaThresholdPercent, 0, 100)
  ) {
    return null;
  }
  return {
    allowanceMicrousd: value.allowanceMicrousd,
    usedMicrousd: value.usedMicrousd,
    activeReservedMicrousd: value.activeReservedMicrousd,
    totalCommittedMicrousd: value.totalCommittedMicrousd,
    remainingMicrousd: value.remainingMicrousd,
    lowQuota: value.lowQuota,
    lowQuotaThresholdPercent: value.lowQuotaThresholdPercent,
  };
}

function parseUsageWindow(input: unknown): UsageWindowSummary | null {
  const value = exactObject(input, ["seconds", "startedAt", "nextResetAt"]);
  if (
    !value ||
    !(
      value.seconds === null || isIntegerInRange(value.seconds, 1, 31_536_000)
    ) ||
    !isIsoDateOrNull(value.startedAt) ||
    !isIsoDateOrNull(value.nextResetAt)
  ) {
    return null;
  }
  return {
    seconds: value.seconds,
    startedAt: value.startedAt,
    nextResetAt: value.nextResetAt,
  };
}

function parseUsageBreakdown(input: unknown): UsageAmountBreakdown | null {
  const value = exactObject(input, [
    "regularMicrousd",
    "premiumMicrousd",
    "totalMicrousd",
  ]);
  if (
    !value ||
    !isAmount(value.regularMicrousd) ||
    !isAmount(value.premiumMicrousd) ||
    !isAmount(value.totalMicrousd)
  )
    return null;
  return {
    regularMicrousd: value.regularMicrousd,
    premiumMicrousd: value.premiumMicrousd,
    totalMicrousd: value.totalMicrousd,
  };
}

function parseUsageRecent(input: unknown): UsageRecentTotal[] | null {
  if (!Array.isArray(input) || input.length !== 2) return null;
  const parsed = input.map((item) => {
    const value = exactObject(item, [
      "label",
      "windowSeconds",
      "regularMicrousd",
      "premiumMicrousd",
      "totalMicrousd",
    ]);
    if (
      !value ||
      (value.label !== "24h" && value.label !== "7d") ||
      !isAmount(value.regularMicrousd) ||
      !isAmount(value.premiumMicrousd) ||
      !isAmount(value.totalMicrousd)
    ) {
      return null;
    }
    const expectedSeconds = value.label === "24h" ? 86_400 : 604_800;
    if (value.windowSeconds !== expectedSeconds) return null;
    return {
      label: value.label,
      windowSeconds: expectedSeconds,
      regularMicrousd: value.regularMicrousd,
      premiumMicrousd: value.premiumMicrousd,
      totalMicrousd: value.totalMicrousd,
    } satisfies UsageRecentTotal;
  });
  if (parsed.some((item) => item === null)) return null;
  const day = parsed.find((item) => item?.label === "24h");
  const week = parsed.find((item) => item?.label === "7d");
  return day && week ? [day, week] : null;
}

function isUsageError(body: unknown, expectedCode?: string): boolean {
  const wrapper = exactObject(body, ["error"]);
  if (!wrapper) return false;
  const error = objectValue(wrapper.error);
  if (
    !error ||
    !hasOnlyKeys(error, ["code", "message", "requestId"], ["requestId"])
  )
    return false;
  if (
    typeof error.code !== "string" ||
    error.code.length === 0 ||
    error.code.length > 64
  )
    return false;
  if (expectedCode !== undefined && error.code !== expectedCode) return false;
  return (
    typeof error.message === "string" &&
    error.message.length <= 256 &&
    isBoundedStringOrUndefined(error.requestId, 128)
  );
}

function parseErrorObject(
  input: unknown,
  allowedCodes: readonly string[],
): string | null {
  const error = exactObject(input, ["code", "message"]);
  if (
    !error ||
    typeof error.code !== "string" ||
    !allowedCodes.includes(error.code)
  )
    return null;
  if (typeof error.message !== "string" || error.message.length > 256)
    return null;
  return error.code;
}

function isOkResponse(body: unknown): boolean {
  const value = exactObject(body, ["ok"]);
  return value?.ok === true;
}

function exactObject(
  value: unknown,
  keys: readonly string[],
): Record<string, unknown> | null {
  const object = objectValue(value);
  if (!object || !hasOnlyKeys(object, keys)) return null;
  return object;
}

function hasOnlyKeys(
  value: Record<string, unknown>,
  allowed: readonly string[],
  optional: readonly string[] = [],
): boolean {
  const actual = Object.keys(value);
  const required = allowed.filter((key) => !optional.includes(key));
  return (
    actual.length >= required.length &&
    actual.length <= allowed.length &&
    required.every((key) => Object.prototype.hasOwnProperty.call(value, key)) &&
    actual.every((key) => allowed.includes(key))
  );
}

function objectValue(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function isUsageTier(value: unknown): value is UsageTier {
  return (
    value === "free" ||
    value === "regular" ||
    value === "premium" ||
    value === "none"
  );
}

function isUsageAccountStatus(value: unknown): value is UsageAccountStatus {
  return (
    value === "active" ||
    value === "no_entitlement" ||
    value === "quota_suspended" ||
    value === "quota_revoked"
  );
}

function isOpaqueToken(value: string): boolean {
  return OPAQUE_TOKEN_PATTERN.test(value);
}

function isCanonicalIsoDate(value: unknown): value is string {
  if (typeof value !== "string" || value.length !== 24) return false;
  const timestamp = Date.parse(value);
  return (
    Number.isFinite(timestamp) && new Date(timestamp).toISOString() === value
  );
}

function isIsoDateOrNull(value: unknown): value is string | null {
  return value === null || isCanonicalIsoDate(value);
}

function isIntegerInRange(
  value: unknown,
  minimum: number,
  maximum: number,
): value is number {
  return (
    typeof value === "number" &&
    Number.isSafeInteger(value) &&
    value >= minimum &&
    value <= maximum
  );
}

function isBoundedStringOrNull(
  value: unknown,
  maximum: number,
): value is string | null {
  return (
    value === null || (typeof value === "string" && value.length <= maximum)
  );
}

function isBoundedStringOrUndefined(value: unknown, maximum: number): boolean {
  return (
    value === undefined ||
    (typeof value === "string" && value.length <= maximum)
  );
}

function isAmount(value: unknown): value is string {
  return typeof value === "string" && AMOUNT_PATTERN.test(value);
}

function isAmountOrNull(value: unknown): value is string | null {
  return value === null || isAmount(value);
}

function parseRetryAfter(value: string | undefined): number {
  if (!value || !/^\d{1,3}$/.test(value)) return 5;
  const seconds = Number(value);
  return isIntegerInRange(seconds, 1, 120) ? seconds : 5;
}

function parseContentLength(value: string | undefined): number | null {
  if (!value || !/^\d{1,10}$/.test(value)) return null;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed >= 0 ? parsed : null;
}

function singleHeader(
  value: string | string[] | undefined,
): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function invalidGrant(): PollResult {
  return { status: "invalid_grant", message: INVALID_GRANT_ERROR };
}

function networkError(): PollResult {
  return { status: "network_error", message: POLL_NETWORK_ERROR };
}

function compiledProductionOrigin(): URL | null {
  const approvedOrigin = compiledReleasePolicyOrigin();
  if (approvedOrigin === undefined) return null;
  return normalizeOrigin(approvedOrigin, false);
}

function requireAllowedOrigin(input: URL): URL {
  const normalized = normalizeOrigin(input, false);
  const production = compiledProductionOrigin();
  if (production?.origin === normalized.origin || isLoopback(normalized))
    return normalized;
  throw new ControlPlaneClientError("control_plane_unavailable");
}

function normalizeOrigin(input: string | URL, loopbackOnly: boolean): URL {
  let url: URL;
  try {
    url = input instanceof URL ? new URL(input.toString()) : new URL(input);
  } catch {
    throw new ControlPlaneClientError("control_plane_unavailable");
  }

  if (
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    (url.pathname !== "" && url.pathname !== "/")
  ) {
    throw new ControlPlaneClientError("control_plane_unavailable");
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new ControlPlaneClientError("control_plane_unavailable");
  }
  url.pathname = "/";

  if (loopbackOnly && !isLoopback(url))
    throw new ControlPlaneClientError("control_plane_unavailable");
  if (!isLoopback(url) && url.protocol !== "https:")
    throw new ControlPlaneClientError("control_plane_unavailable");
  return url;
}

function isLoopback(url: URL): boolean {
  return (
    url.hostname === "localhost" ||
    url.hostname === "127.0.0.1" ||
    url.hostname === "[::1]"
  );
}
