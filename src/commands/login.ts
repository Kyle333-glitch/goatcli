import type { AuthApiClient, BrowserOpener, Clock, CredentialStore, PollResult } from '../auth/types.js';

export interface LoginOptions {
  client: AuthApiClient;
  store: CredentialStore;
  opener: BrowserOpener;
  stdout: Pick<NodeJS.WriteStream, 'write'>;
  stderr: Pick<NodeJS.WriteStream, 'write'>;
  clock?: Clock;
}

const MIN_POLL_INTERVAL_SECONDS = 2;
const MAX_POLL_INTERVAL_SECONDS = 120;
const MAX_POLL_ATTEMPTS = 60;

export async function runLogin(options: LoginOptions): Promise<number> {
  const clock = options.clock ?? { sleep: (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)) };
  const session = await options.client.createDeviceSession();
  const opened = await options.opener.open(session.verificationUrl);

  options.stdout.write(`GOAT login\n`);
  if (!opened) options.stdout.write(`Open this URL in your browser: ${session.verificationUrl}\n`);
  else options.stdout.write(`Opened browser URL: ${session.verificationUrl}\n`);
  options.stdout.write(`Enter code: ${session.userCode}\n`);

  let intervalSeconds = clampInterval(session.intervalSeconds);
  const deadline = Date.parse(session.expiresAt);
  if (!Number.isFinite(deadline)) {
    options.stderr.write('GOAT login: server returned an invalid expiry date.\n');
    await options.client.cancelDeviceSession(session.deviceCode).catch(() => undefined);
    return 1;
  }
  let attempts = 0;
  while (attempts < MAX_POLL_ATTEMPTS && Date.now() < deadline) {
    attempts += 1;
    const result = await options.client.pollDeviceToken(session.deviceCode);
    const handled = await handlePollResult(result, options, clock, intervalSeconds, deadline);
    if (handled.done) return handled.exitCode;
    intervalSeconds = clampInterval(handled.intervalSeconds ?? intervalSeconds);
  }

  if (attempts >= MAX_POLL_ATTEMPTS) {
    options.stderr.write(`GOAT login stopped after ${MAX_POLL_ATTEMPTS} polling attempts. Try again.\n`);
  } else {
    options.stderr.write('GOAT login expired before authorization completed.\n');
  }
  await options.client.cancelDeviceSession(session.deviceCode).catch(() => undefined);
  return 1;
}

function clampInterval(seconds: number): number {
  if (!Number.isFinite(seconds) || seconds <= 0) return MIN_POLL_INTERVAL_SECONDS;
  if (seconds < MIN_POLL_INTERVAL_SECONDS) return MIN_POLL_INTERVAL_SECONDS;
  if (seconds > MAX_POLL_INTERVAL_SECONDS) return MAX_POLL_INTERVAL_SECONDS;
  return seconds;
}

async function handlePollResult(
  result: PollResult,
  options: LoginOptions,
  clock: Clock,
  intervalSeconds: number,
  deadline: number,
): Promise<{ done: true; exitCode: number } | { done: false; intervalSeconds?: number }> {
  if (result.status === 'authorized') {
    try {
      await options.store.set(result.credentials);
    } catch (error) {
      options.stderr.write(`Failed to store credentials: ${error instanceof Error ? error.message : String(error)}\n`);
      return { done: true, exitCode: 1 };
    }
    options.stdout.write('GOAT login complete.\n');
    return { done: true, exitCode: 0 };
  }
  if (result.status === 'pending') {
    const effectiveInterval = clampInterval(result.intervalSeconds ?? intervalSeconds);
    const sleepMs = Math.min(effectiveInterval * 1000, Math.max(0, deadline - Date.now()));
    if (sleepMs > 0) await clock.sleep(sleepMs);
    return { done: false, intervalSeconds: result.intervalSeconds };
  }
  if (result.status === 'slow_down') {
    const sleepMs = Math.min(result.retryAfterSeconds * 1000, Math.max(0, deadline - Date.now()));
    if (sleepMs > 0) await clock.sleep(sleepMs);
    return { done: false, intervalSeconds: Math.max(intervalSeconds, result.retryAfterSeconds) };
  }
  if (result.status === 'network_error') {
    const sleepMs = Math.min(intervalSeconds * 1000, Math.max(0, deadline - Date.now()));
    if (sleepMs > 0) await clock.sleep(sleepMs);
    return { done: false, intervalSeconds: Math.min(intervalSeconds * 2, MAX_POLL_INTERVAL_SECONDS) };
  }
  options.stderr.write(`${result.message}\n`);
  return { done: true, exitCode: 1 };
}