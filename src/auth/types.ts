export interface GoatCredentials {
  accessToken: string;
  refreshToken: string;
  tokenType: "Bearer";
  accessTokenExpiresAt: string;
  refreshTokenExpiresAt: string;
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

export type UsageTier = "free" | "regular" | "premium" | "none";
export type UsageAccountStatus =
  "active" | "no_entitlement" | "quota_suspended" | "quota_revoked";

export interface UsageAccountSummary {
  tier: UsageTier;
  status: UsageAccountStatus;
}

export interface UsageQuotaSummary {
  allowanceMicrousd: string | null;
  usedMicrousd: string;
  activeReservedMicrousd: string;
  totalCommittedMicrousd: string;
  remainingMicrousd: string | null;
  lowQuota: boolean;
  lowQuotaThresholdPercent: number;
}

export interface UsageWindowSummary {
  seconds: number | null;
  startedAt: string | null;
  nextResetAt: string | null;
}

export interface UsageAmountBreakdown {
  regularMicrousd: string;
  premiumMicrousd: string;
  totalMicrousd: string;
}

export interface UsageRecentTotal extends UsageAmountBreakdown {
  label: "24h" | "7d";
  windowSeconds: number;
}

export interface UsageSummaryResponse {
  version: "v0.3.2";
  generatedAt: string;
  account: UsageAccountSummary;
  quota: UsageQuotaSummary;
  window: UsageWindowSummary;
  usage: UsageAmountBreakdown;
  recent: UsageRecentTotal[];
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
