export interface GoatCredentials {
  accessToken: string;
  refreshToken: string;
  tokenType: "Bearer";
  accessTokenExpiresAt: string;
  refreshTokenExpiresAt: string;
  /** Per-device attestation enrollment (v0.5.2). Optional for older stores. */
  deviceId?: string;
  deviceSecret?: string;
}

export interface DeviceCredential {
  deviceId: string;
  deviceSecret: string;
}

export interface DeviceSessionResponse {
  verificationUrl: string;
  userCode: string;
  deviceCode: string;
  intervalSeconds: number;
  expiresAt: string;
  expiresInSeconds: number;
}

export type PollResult =
  | { status: "authorized"; credentials: GoatCredentials }
  | { status: "pending"; intervalSeconds?: number }
  | { status: "slow_down"; retryAfterSeconds: number }
  | {
      status:
        | "denied"
        | "cancelled"
        | "expired"
        | "invalid_grant"
        | "revoked"
        | "replay_detected"
        | "network_error";
      message: string;
    };

export type UsageAccountStatus =
  "active" | "no_entitlement" | "quota_suspended" | "quota_revoked";

export interface UsageAccountSummary {
  status: UsageAccountStatus;
}

export interface UsageQuotaSummary {
  usedPercent: number | null;
  committedPercent: number | null;
  remainingPercent: number | null;
  lowQuota: boolean;
}

export interface UsageWindowSummary {
  kind: "rolling" | "daily";
  seconds: number | null;
  startedAt: string | null;
  nextUsageExpiresAt: string | null;
}

export interface UsageSessionSummary {
  kind: "daily";
  sessionsPerDay: number | null;
  sessionsRemaining: number | null;
  usedMinutes: number | null;
  remainingMinutes: number | null;
  sessionSeconds: number;
  roundingMinutes: number;
  graceMinutes: number;
  activeSessionId: string | null;
  activeSessionStartedAt: string | null;
  activeSessionMinutes: number;
}

export interface UsageSummaryResponse {
  version: "v0.3.2";
  generatedAt: string;
  account: UsageAccountSummary;
  quota: UsageQuotaSummary;
  session?: UsageSessionSummary;
  window: UsageWindowSummary;
}

export type UsageSummaryResult =
  | { status: "ok"; summary: UsageSummaryResponse }
  | {
      status:
        | "unauthorized"
        | "network_error"
        | "server_error"
        | "unexpected_response";
      message: string;
    };

export interface AuthApiClient {
  createDeviceSession(): Promise<DeviceSessionResponse>;
  pollDeviceToken(deviceCode: string): Promise<PollResult>;
  cancelDeviceSession(deviceCode: string): Promise<void>;
  refresh(refreshToken: string): Promise<PollResult>;
  revoke(refreshToken: string): Promise<void>;
  getUsageSummary(accessToken: string): Promise<UsageSummaryResult>;
  closeUsageSession?(
    accessToken: string,
    sessionId: string,
  ): Promise<{ chargedMinutes: number; sessionsRemaining: number | null }>;
  /**
   * Enroll (or rotate) a per-device attestation secret. Best-effort: callers
   * treat a missing implementation or failure as "no attestation" rather than
   * a login failure.
   */
  provisionDeviceCredential?(
    accessToken: string,
    deviceId: string,
    label?: string,
  ): Promise<DeviceCredential>;
}

export interface CredentialStore {
  get(): Promise<GoatCredentials | null>;
  set(credentials: GoatCredentials): Promise<void>;
  delete(): Promise<void>;
}

export interface BrowserOpener {
  open(url: string): Promise<boolean>;
}

export interface Clock {
  sleep(ms: number): Promise<void>;
  now?(): Date;
}
