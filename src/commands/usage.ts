import type { AuthApiClient, CredentialStore, GoatCredentials, UsageSummaryResponse, UsageSummaryResult } from '../auth/types.js';

export interface UsageOptions {
  client: AuthApiClient;
  store: CredentialStore;
  stdout: Pick<NodeJS.WriteStream, 'write'>;
  stderr: Pick<NodeJS.WriteStream, 'write'>;
  json?: boolean;
  now?: () => Date;
}

type UsageErrorCode = 'no_credentials' | 'offline' | 'expired_auth' | 'unavailable';
type UsageCommandError = { code: UsageErrorCode; message: string };

const ACCESS_TOKEN_REFRESH_SKEW_MS = 60_000;
const MICRO_UNITS = 1_000_000n;

export async function runUsage(options: UsageOptions): Promise<number> {
  const now = options.now?.() ?? new Date();
  const current = await options.store.get();
  if (!current) {
    return writeUsageError(options, {
      code: 'no_credentials',
      message: 'No GOAT login credentials found. Run `goat login`.',
    });
  }

  const ready = await ensureFreshAccessToken(options, current, now);
  if ('error' in ready) return writeUsageError(options, ready.error);

  const first = await options.client.getUsageSummary(ready.credentials.accessToken);
  const summary = await resolveUsageResult(options, first, ready.credentials);
  if ('error' in summary) return writeUsageError(options, summary.error);

  if (options.json) {
    options.stdout.write(`${JSON.stringify({ ok: true, summary: summary.summary })}\n`);
  } else {
    options.stdout.write(formatUsageSummary(summary.summary));
  }
  return 0;
}

export function formatUsageSummary(summary: UsageSummaryResponse): string {
  const lines: string[] = ['GOAT usage'];
  lines.push(`Account: ${formatAccount(summary.account.displayName, summary.account.email)}`);
  lines.push(`Tier: ${titleCase(summary.account.tier)}`);
  lines.push(`Status: ${formatStatus(summary.account.status)}`);

  if (summary.quota.allowanceMicrousd === null) {
    lines.push('Quota: no active allowance');
  } else {
    const remaining = formatAmount(summary.quota.remainingMicrousd);
    const allowance = formatAmount(summary.quota.allowanceMicrousd);
    const percent = formatRemainingPercent(summary.quota.remainingMicrousd, summary.quota.allowanceMicrousd);
    lines.push(`Quota: ${remaining} of ${allowance} quota units remaining (${percent})`);
  }

  if (summary.quota.lowQuota) lines.push('Warning: GOAT quota is low.');

  if (summary.window.nextResetAt) {
    lines.push(`Next reset: ${formatUtcMinute(summary.window.nextResetAt)}`);
  } else if (summary.window.seconds === null) {
    lines.push('Next reset: no active rolling window');
  } else {
    lines.push('Next reset: after new usage in this window');
  }

  lines.push(`Usage this window: ${formatBreakdown(summary.usage)}`);
  lines.push('Recent totals:');
  for (const item of summary.recent) {
    lines.push(`  ${item.label}: ${formatBreakdown(item)}`);
  }

  return `${lines.join('\n')}\n`;
}

function writeUsageError(options: UsageOptions, error: UsageCommandError): number {
  if (options.json) {
    options.stdout.write(`${JSON.stringify({ ok: false, error })}\n`);
  } else {
    options.stderr.write(`${error.message}\n`);
  }
  return 1;
}

async function resolveUsageResult(
  options: UsageOptions,
  result: UsageSummaryResult,
  current: GoatCredentials,
): Promise<{ summary: UsageSummaryResponse } | { error: UsageCommandError }> {
  if (result.status === 'ok') return { summary: result.summary };
  if (result.status === 'network_error') return { error: offlineError() };
  if (result.status !== 'unauthorized') return { error: unavailableError() };

  const refreshed = await refreshCredentials(options, current);
  if ('error' in refreshed) return refreshed;

  const retry = await options.client.getUsageSummary(refreshed.credentials.accessToken);
  if (retry.status === 'ok') return { summary: retry.summary };
  if (retry.status === 'network_error') return { error: offlineError() };
  if (retry.status === 'unauthorized') {
    await options.store.delete();
    return { error: expiredAuthError() };
  }
  return { error: unavailableError() };
}

async function ensureFreshAccessToken(
  options: UsageOptions,
  credentials: GoatCredentials,
  now: Date,
): Promise<{ credentials: GoatCredentials } | { error: UsageCommandError }> {
  const expiresAt = Date.parse(credentials.accessTokenExpiresAt);
  if (Number.isFinite(expiresAt) && expiresAt > now.getTime() + ACCESS_TOKEN_REFRESH_SKEW_MS) {
    return { credentials };
  }
  return refreshCredentials(options, credentials);
}

async function refreshCredentials(
  options: UsageOptions,
  credentials: GoatCredentials,
): Promise<{ credentials: GoatCredentials } | { error: UsageCommandError }> {
  const result = await options.client.refresh(credentials.refreshToken);
  if (result.status === 'authorized') {
    try {
      await options.store.set(result.credentials);
    } catch {
      // The refreshed access token is usable even if persisting it fails.
    }
    return { credentials: result.credentials };
  }
  if (result.status === 'network_error') return { error: offlineError() };
  if (result.status === 'invalid_grant' || result.status === 'revoked' || result.status === 'replay_detected' || result.status === 'expired') {
    await options.store.delete();
  }
  return { error: expiredAuthError() };
}

function offlineError(): UsageCommandError {
  return { code: 'offline', message: 'Unable to reach GOAT control plane. Check your connection and try again.' };
}

function expiredAuthError(): UsageCommandError {
  return { code: 'expired_auth', message: 'GOAT login expired. Run `goat login`.' };
}

function unavailableError(): UsageCommandError {
  return { code: 'unavailable', message: 'Unable to load GOAT usage right now. Try again later.' };
}

function formatBreakdown(value: { regularMicrousd: string; premiumMicrousd: string; totalMicrousd: string }): string {
  return `${formatAmount(value.regularMicrousd)} regular, ${formatAmount(value.premiumMicrousd)} premium, ${formatAmount(value.totalMicrousd)} total`;
}

function formatAmount(value: string | null): string {
  if (value === null || !/^\d+$/.test(value)) return 'n/a';
  const raw = BigInt(value);
  const whole = raw / MICRO_UNITS;
  const fraction = (raw % MICRO_UNITS).toString().padStart(6, '0').slice(0, 2);
  return `${whole}.${fraction}`;
}

function formatRemainingPercent(remainingValue: string | null, allowanceValue: string | null): string {
  if (remainingValue === null || allowanceValue === null || !/^\d+$/.test(remainingValue) || !/^\d+$/.test(allowanceValue)) return 'n/a';
  const remaining = BigInt(remainingValue);
  const allowance = BigInt(allowanceValue);
  if (allowance <= 0n) return '0%';
  return `${(remaining * 100n) / allowance}%`;
}

function formatUtcMinute(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return 'unknown';
  const year = date.getUTCFullYear();
  const month = String(date.getUTCMonth() + 1).padStart(2, '0');
  const day = String(date.getUTCDate()).padStart(2, '0');
  const hour = String(date.getUTCHours()).padStart(2, '0');
  const minute = String(date.getUTCMinutes()).padStart(2, '0');
  return `${year}-${month}-${day} ${hour}:${minute} UTC`;
}

function formatAccount(displayName: string | null, email: string | null): string {
  if (displayName && email) return `${displayName} <${email}>`;
  if (displayName) return displayName;
  if (email) return email;
  return 'GOAT account';
}

function formatStatus(status: UsageSummaryResponse['account']['status']): string {
  if (status === 'no_entitlement') return 'No active entitlement';
  if (status === 'quota_suspended') return 'Quota suspended';
  if (status === 'quota_revoked') return 'Quota revoked';
  return 'Active';
}

function titleCase(value: string): string {
  return value.length === 0 ? value : `${value.slice(0, 1).toUpperCase()}${value.slice(1)}`;
}
