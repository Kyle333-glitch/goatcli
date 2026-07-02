export interface GoatCredentials {
  accessToken: string;
  refreshToken: string;
  tokenType: string;
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
  | { status: "denied" | "cancelled" | "expired" | "invalid_grant" | "revoked" | "replay_detected" | "network_error"; message: string };

export interface AuthApiClient {
  createDeviceSession(): Promise<DeviceSessionResponse>;
  pollDeviceToken(deviceCode: string): Promise<PollResult>;
  cancelDeviceSession(deviceCode: string): Promise<void>;
  refresh(refreshToken: string): Promise<PollResult>;
  revoke(refreshToken: string): Promise<void>;
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
}