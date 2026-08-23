import { randomUUID } from "node:crypto";
import type {
  AuthApiClient,
  BrowserOpener,
  Clock,
  CredentialStore,
  PollResult,
} from "../auth/types.js";

export interface LoginOptions {
  client: AuthApiClient;
  store: CredentialStore;
  opener: BrowserOpener;
  stdout: Pick<NodeJS.WriteStream, "write">;
  stderr: Pick<NodeJS.WriteStream, "write">;
  clock?: Clock;
}

const MIN_POLL_INTERVAL_SECONDS = 2;
const MAX_POLL_INTERVAL_SECONDS = 120;

export async function runLogin(options: LoginOptions): Promise<number> {
  const clock = options.clock ?? {
    sleep: (ms: number) =>
      new Promise<void>((resolve) => setTimeout(resolve, ms)),
  };
  let previousCredentials: Awaited<ReturnType<CredentialStore["get"]>> = null;
  try {
    previousCredentials = await options.store.get();
  } catch {
    // A successful keyring write below can repair invalid or legacy state.
  }
  const session = await options.client.createDeviceSession();
  const verificationUrl = prefilledVerificationUrl(
    session.verificationUrl,
    session.userCode,
  );
  const opened = await options.opener.open(verificationUrl);

  options.stdout.write("Opening your browser to sign in...\n\n");
  if (!opened)
    options.stdout.write(`Open this URL in your browser: ${verificationUrl}\n`);
  else options.stdout.write("Opened your browser to continue.\n");
  options.stdout.write(`Enter code: ${session.userCode}\n`);

  let intervalSeconds = clampInterval(session.intervalSeconds);
  const serverDeadline = Date.parse(session.expiresAt);
  if (
    !Number.isFinite(serverDeadline) ||
    !Number.isSafeInteger(session.expiresInSeconds) ||
    session.expiresInSeconds < 1 ||
    session.expiresInSeconds > 3_600
  ) {
    options.stderr.write(
      "GOAT login: server returned an invalid expiry date.\n",
    );
    await options.client
      .cancelDeviceSession(session.deviceCode)
      .catch(() => undefined);
    return 1;
  }
  const deadline = Math.min(
    serverDeadline,
    nowMs(clock) + session.expiresInSeconds * 1000,
  );
  while (nowMs(clock) < deadline) {
    const sleepMs = Math.min(
      intervalSeconds * 1000,
      Math.max(0, deadline - nowMs(clock)),
    );
    if (sleepMs > 0) await clock.sleep(sleepMs);
    if (nowMs(clock) >= deadline) break;
    const result = await options.client.pollDeviceToken(session.deviceCode);
    const handled = await handlePollResult(
      result,
      options,
      intervalSeconds,
      previousCredentials?.refreshToken ?? null,
    );
    if (handled.done) return handled.exitCode;
    intervalSeconds = clampInterval(handled.intervalSeconds ?? intervalSeconds);
  }

  options.stderr.write("GOAT login expired before authorization completed.\n");
  await options.client
    .cancelDeviceSession(session.deviceCode)
    .catch(() => undefined);
  return 1;
}

/**
 * Append the user code to the verification URL so the browser can pre-fill
 * the code input. The code is already displayed to the user, so carrying it in
 * the URL adds no secrecy loss and removes a manual entry step.
 */
function prefilledVerificationUrl(
  verificationUrl: string,
  userCode: string,
): string {
  const url = new URL(verificationUrl);
  url.searchParams.set("code", userCode);
  return url.toString();
}

function clampInterval(seconds: number): number {
  if (!Number.isFinite(seconds) || seconds <= 0)
    return MIN_POLL_INTERVAL_SECONDS;
  if (seconds < MIN_POLL_INTERVAL_SECONDS) return MIN_POLL_INTERVAL_SECONDS;
  if (seconds > MAX_POLL_INTERVAL_SECONDS) return MAX_POLL_INTERVAL_SECONDS;
  return seconds;
}

async function handlePollResult(
  result: PollResult,
  options: LoginOptions,
  intervalSeconds: number,
  previousRefreshToken: string | null,
): Promise<
  { done: true; exitCode: number } | { done: false; intervalSeconds?: number }
> {
  if (result.status === "authorized") {
    try {
      await options.store.set(result.credentials);
    } catch {
      await discardUnstoredCredential(
        options.client,
        options.store,
        result.credentials.refreshToken,
      );
      options.stderr.write(
        "GOAT could not save credentials in the OS credential store. Run `goat login` again.\n",
      );
      return { done: true, exitCode: 1 };
    }
    // Best-effort per-device attestation enrollment. A failure must not fail
    // login: the control plane falls back to the User-Agent heuristic until
    // client attestation is required.
    try {
      const provisioned = await options.client.provisionDeviceCredential?.(
        result.credentials.accessToken,
        randomUUID(),
        "goatcli",
      );
      if (provisioned) {
        await options.store.set({ ...result.credentials, ...provisioned });
      }
    } catch {
      // Attestation remains optional; the stored base credentials are valid.
    }
    if (
      previousRefreshToken &&
      previousRefreshToken !== result.credentials.refreshToken
    ) {
      try {
        await options.client.revoke(previousRefreshToken);
      } catch {
        options.stderr.write(
          "GOAT signed in, but could not revoke the previous server session.\n",
        );
      }
    }
    options.stdout.write("✓ Signed in successfully\n");
    return { done: true, exitCode: 0 };
  }
  if (result.status === "pending") {
    return {
      done: false,
      intervalSeconds: Math.max(
        intervalSeconds,
        clampInterval(result.intervalSeconds ?? intervalSeconds),
      ),
    };
  }
  if (result.status === "slow_down") {
    return {
      done: false,
      intervalSeconds: Math.max(
        intervalSeconds,
        clampInterval(result.retryAfterSeconds),
      ),
    };
  }
  if (result.status === "network_error") {
    return {
      done: false,
      intervalSeconds: Math.min(intervalSeconds * 2, MAX_POLL_INTERVAL_SECONDS),
    };
  }
  options.stderr.write("GOAT login was not authorized. Try again.\n");
  return { done: true, exitCode: 1 };
}

function nowMs(clock: Clock): number {
  return (clock.now?.() ?? new Date()).getTime();
}

async function discardUnstoredCredential(
  client: AuthApiClient,
  store: CredentialStore,
  refreshToken: string,
): Promise<void> {
  try {
    await client.revoke(refreshToken);
  } catch {
    // Best effort: never expose the transport failure or token.
  }
  try {
    await store.delete();
  } catch {
    // The fixed storage error remains the only user-visible failure.
  }
}
