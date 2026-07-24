import {
  createHmac,
  randomBytes as systemRandomBytes,
  timingSafeEqual,
} from "node:crypto";
import { performance } from "node:perf_hooks";

export const LAUNCHER_IPC_PROTOCOL_VERSION = 1 as const;
export const LAUNCHER_IPC_MAGIC_V1 = new TextEncoder().encode("GOATIPC1");
export const LAUNCHER_IPC_SECRET_BYTES = 32;
export const LAUNCHER_IPC_TAG_BYTES = 32;
export const LAUNCHER_IPC_HEADER_MAX_BYTES = 2_048;
export const LAUNCHER_IPC_CREDENTIAL_BYTES = 43;
export const LAUNCHER_IPC_FRAME_MAX_BYTES = 4_096;
export const LAUNCHER_IPC_TIMEOUT_MS = 2_000;
export const LAUNCHER_IPC_MAX_FRAMES = 256;

export type EngineIntegrityStatus = "verified" | "development_unverified";
export type CredentialStoreStatus = "available" | "unavailable" | "not_checked";

export interface LauncherIpcTransport {
  read(signal: AbortSignal): Promise<Uint8Array | null>;
  write(bytes: Uint8Array, signal: AbortSignal): Promise<void>;
  close?(): void;
}

export type LauncherIpcErrorCode =
  | "LAUNCHER_IPC_CANCELLED"
  | "LAUNCHER_IPC_TIMEOUT"
  | "LAUNCHER_IPC_PEER_CLOSED"
  | "LAUNCHER_IPC_INVALID_BOOTSTRAP"
  | "LAUNCHER_IPC_FRAME_TOO_LARGE"
  | "LAUNCHER_IPC_AUTHENTICATION_FAILED"
  | "LAUNCHER_IPC_MESSAGE_INVALID"
  | "LAUNCHER_IPC_STALE"
  | "LAUNCHER_IPC_REPLAYED"
  | "LAUNCHER_IPC_PROCESS_MISMATCH"
  | "LAUNCHER_IPC_SESSION_MISMATCH"
  | "LAUNCHER_IPC_SEQUENCE_INVALID"
  | "LAUNCHER_IPC_CREDENTIAL_INVALID"
  | "LAUNCHER_IPC_LIMIT_EXCEEDED"
  | "LAUNCHER_IPC_WRITE_FAILED";

export class LauncherIpcError extends Error {
  readonly code: LauncherIpcErrorCode;

  constructor(code: LauncherIpcErrorCode) {
    super(ipcErrorMessage(code));
    this.name = "LauncherIpcError";
    this.code = code;
  }
}

export interface OpenLauncherIpcSessionOptions {
  readonly transport: LauncherIpcTransport;
  readonly engineIntegrity: EngineIntegrityStatus;
  readonly credentialStore: CredentialStoreStatus;
  readonly launcherPid: number;
  readonly enginePid: number;
  readonly credential?: Uint8Array;
  readonly credentialExpiresAtUnixMs?: number;
  readonly signal?: AbortSignal;
  readonly now?: () => number;
  readonly monotonicNow?: () => number;
  readonly randomBytes?: (size: number) => Uint8Array;
  readonly timeoutMs?: number;
}

export interface LauncherIpcSession {
  readonly sessionId: string;
  updateCredential(
    credential: Uint8Array,
    expiresAtUnixMs: number,
  ): Promise<void>;
  clearCredential(): Promise<void>;
  end(): Promise<void>;
  dispose(): void;
}

type CommonRequest = {
  readonly protocol_version: 1;
  readonly message_type:
    "session_start" | "credential_update" | "credential_clear" | "session_end";
  readonly session_id: string;
  readonly nonce: string;
  readonly sequence: number;
  readonly issued_at_unix_ms: number;
  readonly launcher_pid: number;
  readonly engine_pid: number;
};

type StartRequest = CommonRequest & {
  readonly message_type: "session_start";
  readonly sequence: 0;
  readonly launcher_version: "0.3.2";
  readonly installation_channel: "npm";
  readonly engine_integrity: EngineIntegrityStatus;
  readonly credential_store: CredentialStoreStatus;
  readonly credential_length: 0 | 43;
  readonly credential_expires_at_unix_ms?: number;
};

type ContinuationRequest = CommonRequest & {
  readonly message_type:
    "credential_update" | "credential_clear" | "session_end";
  readonly credential_length: 0 | 43;
  readonly credential_expires_at_unix_ms?: number;
};

type Request = StartRequest | ContinuationRequest;

type Acknowledgement = {
  readonly protocol_version: 1;
  readonly message_type: "session_ack";
  readonly session_id: string;
  readonly sequence: number;
  readonly status: "accepted";
};

type ErrorResponse = {
  readonly protocol_version: 1;
  readonly message_type: "session_error";
  readonly error_code: LauncherIpcErrorCode;
};

type Response = Acknowledgement | ErrorResponse;

const REQUEST_HMAC_DOMAIN = new TextEncoder().encode(
  "GOAT launcher IPC request v1\0",
);
const RESPONSE_HMAC_DOMAIN = new TextEncoder().encode(
  "GOAT launcher IPC response v1\0",
);
const EMPTY_CREDENTIAL = new Uint8Array();
const IDENTIFIER_PATTERN = /^(?:gsi_|gn_)[A-Za-z0-9_-]{22}$/;
const CREDENTIAL_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const MAX_TIMER_DELAY_MS = 2_147_483_647;

export function zeroizeLauncherIpcBytes(bytes: Uint8Array | undefined): void {
  bytes?.fill(0);
}

export async function openLauncherIpcSession(
  options: OpenLauncherIpcSessionOptions,
): Promise<LauncherIpcSession> {
  validateProcessId(options.launcherPid);
  validateProcessId(options.enginePid);
  validateIntegrity(options.engineIntegrity);
  validateCredentialStore(options.credentialStore);

  const now = options.now ?? Date.now;
  const monotonicNow = options.monotonicNow ?? (() => performance.now());
  const randomBytes = options.randomBytes ?? systemRandomBytes;
  const timeoutMs = validateTimeout(
    options.timeoutMs ?? LAUNCHER_IPC_TIMEOUT_MS,
  );
  const issuedAt = validateTimestamp(now());
  validateCredential(
    options.credential,
    options.credentialExpiresAtUnixMs,
    issuedAt,
  );
  if (options.credential && options.credentialStore !== "available") {
    throw new LauncherIpcError("LAUNCHER_IPC_CREDENTIAL_INVALID");
  }

  const secret = consumeRandom(randomBytes, LAUNCHER_IPC_SECRET_BYTES);
  const sessionId = randomIdentifier("gsi_", randomBytes);
  const queue = new ResponseQueue(options.transport);
  const lifetime = new AbortController();
  const usedNonces = new Set<string>();
  let sequence = 0;
  let disposed = false;
  let sending = false;

  const dispose = (): void => {
    if (disposed) return;
    disposed = true;
    options.signal?.removeEventListener("abort", dispose);
    lifetime.abort();
    queue.clear();
    usedNonces.clear();
    secret.fill(0);
    try {
      options.transport.close?.();
    } catch {
      // Closing is best-effort and never exposes a platform error.
    }
  };

  if (options.signal?.aborted) {
    dispose();
    throw new LauncherIpcError("LAUNCHER_IPC_CANCELLED");
  }
  options.signal?.addEventListener("abort", dispose, { once: true });

  const nonce = takeUniqueNonce(randomBytes, usedNonces);
  const start: StartRequest = {
    protocol_version: 1,
    message_type: "session_start",
    session_id: sessionId,
    nonce,
    sequence: 0,
    issued_at_unix_ms: issuedAt,
    launcher_pid: options.launcherPid,
    engine_pid: options.enginePid,
    launcher_version: "0.3.2",
    installation_channel: "npm",
    engine_integrity: options.engineIntegrity,
    credential_store: options.credentialStore,
    credential_length: options.credential ? 43 : 0,
    ...(options.credentialExpiresAtUnixMs === undefined
      ? {}
      : { credential_expires_at_unix_ms: options.credentialExpiresAtUnixMs }),
  };

  try {
    await withinDeadline(
      timeoutMs,
      monotonicNow,
      lifetime.signal,
      async (signal) => {
        const bootstrap = makeBootstrap(secret);
        try {
          await writeTransport(options.transport, bootstrap, signal);
        } finally {
          bootstrap.fill(0);
        }
        await sendRequest(
          options.transport,
          start,
          options.credential,
          secret,
          signal,
        );
        await expectAcknowledgement(queue, secret, sessionId, 0, signal);
      },
    );
  } catch (error) {
    dispose();
    throw fixedIpcError(error);
  }

  const sendContinuation = async (
    messageType: ContinuationRequest["message_type"],
    credential?: Uint8Array,
    expiresAt?: number,
  ): Promise<void> => {
    if (disposed || lifetime.signal.aborted) {
      throw new LauncherIpcError("LAUNCHER_IPC_CANCELLED");
    }
    if (sending) throw new LauncherIpcError("LAUNCHER_IPC_SEQUENCE_INVALID");
    if (sequence + 1 >= LAUNCHER_IPC_MAX_FRAMES) {
      dispose();
      throw new LauncherIpcError("LAUNCHER_IPC_LIMIT_EXCEEDED");
    }

    const continuationIssuedAt = validateTimestamp(now());
    validateCredential(credential, expiresAt, continuationIssuedAt);
    if (messageType === "credential_update" && !credential) {
      throw new LauncherIpcError("LAUNCHER_IPC_CREDENTIAL_INVALID");
    }
    if (
      messageType !== "credential_update" &&
      (credential || expiresAt !== undefined)
    ) {
      throw new LauncherIpcError("LAUNCHER_IPC_CREDENTIAL_INVALID");
    }

    sending = true;
    sequence += 1;
    const request: ContinuationRequest = {
      protocol_version: 1,
      message_type: messageType,
      session_id: sessionId,
      nonce: takeUniqueNonce(randomBytes, usedNonces),
      sequence,
      issued_at_unix_ms: continuationIssuedAt,
      launcher_pid: options.launcherPid,
      engine_pid: options.enginePid,
      credential_length: credential ? 43 : 0,
      ...(expiresAt === undefined
        ? {}
        : { credential_expires_at_unix_ms: expiresAt }),
    };

    try {
      await withinDeadline(
        timeoutMs,
        monotonicNow,
        lifetime.signal,
        async (signal) => {
          await sendRequest(
            options.transport,
            request,
            credential,
            secret,
            signal,
          );
          await expectAcknowledgement(
            queue,
            secret,
            sessionId,
            sequence,
            signal,
          );
        },
      );
    } catch (error) {
      dispose();
      throw fixedIpcError(error);
    } finally {
      sending = false;
    }
  };

  return {
    sessionId,
    updateCredential: async (credential, expiresAtUnixMs) => {
      await sendContinuation("credential_update", credential, expiresAtUnixMs);
    },
    clearCredential: async () => {
      await sendContinuation("credential_clear");
    },
    end: async () => {
      try {
        await sendContinuation("session_end");
      } finally {
        dispose();
      }
    },
    dispose,
  };
}

function makeBootstrap(secret: Uint8Array): Uint8Array {
  const bootstrap = new Uint8Array(
    LAUNCHER_IPC_MAGIC_V1.byteLength + secret.byteLength,
  );
  bootstrap.set(LAUNCHER_IPC_MAGIC_V1);
  bootstrap.set(secret, LAUNCHER_IPC_MAGIC_V1.byteLength);
  return bootstrap;
}

async function sendRequest(
  transport: LauncherIpcTransport,
  request: Request,
  credential: Uint8Array | undefined,
  secret: Uint8Array,
  signal: AbortSignal,
): Promise<void> {
  const frame = encodeRequest(request, credential, secret);
  try {
    await writeTransport(transport, frame, signal);
  } finally {
    frame.fill(0);
  }
}

function encodeRequest(
  request: Request,
  credential: Uint8Array | undefined,
  secret: Uint8Array,
): Uint8Array {
  const credentialBytes = credential ?? EMPTY_CREDENTIAL;
  if (request.credential_length !== credentialBytes.byteLength) {
    throw new LauncherIpcError("LAUNCHER_IPC_CREDENTIAL_INVALID");
  }

  const header = new TextEncoder().encode(JSON.stringify(request));
  if (
    header.byteLength < 1 ||
    header.byteLength > LAUNCHER_IPC_HEADER_MAX_BYTES
  ) {
    header.fill(0);
    throw new LauncherIpcError("LAUNCHER_IPC_FRAME_TOO_LARGE");
  }

  const prefix = new Uint8Array(6);
  const prefixView = new DataView(prefix.buffer);
  prefixView.setUint32(0, header.byteLength, false);
  prefixView.setUint16(4, credentialBytes.byteLength, false);
  const authenticated = joinBytes(prefix, header, credentialBytes);
  const tag = calculateTag(REQUEST_HMAC_DOMAIN, secret, authenticated);
  const frame = joinBytes(authenticated, tag);
  prefix.fill(0);
  header.fill(0);
  authenticated.fill(0);
  tag.fill(0);
  if (frame.byteLength > LAUNCHER_IPC_FRAME_MAX_BYTES) {
    frame.fill(0);
    throw new LauncherIpcError("LAUNCHER_IPC_FRAME_TOO_LARGE");
  }
  return frame;
}

async function expectAcknowledgement(
  queue: ResponseQueue,
  secret: Uint8Array,
  sessionId: string,
  sequence: number,
  signal: AbortSignal,
): Promise<void> {
  const response = await readResponse(queue, secret, signal);
  if (response.message_type === "session_error") {
    throw new LauncherIpcError(response.error_code);
  }
  if (response.session_id !== sessionId) {
    throw new LauncherIpcError("LAUNCHER_IPC_SESSION_MISMATCH");
  }
  if (response.sequence !== sequence) {
    throw new LauncherIpcError("LAUNCHER_IPC_SEQUENCE_INVALID");
  }
}

async function readResponse(
  queue: ResponseQueue,
  secret: Uint8Array,
  signal: AbortSignal,
): Promise<Response> {
  const prefix = await queue.take(6, signal);
  try {
    const view = new DataView(
      prefix.buffer,
      prefix.byteOffset,
      prefix.byteLength,
    );
    const headerLength = view.getUint32(0, false);
    const credentialLength = view.getUint16(4, false);
    const frameLength =
      6 + headerLength + credentialLength + LAUNCHER_IPC_TAG_BYTES;
    if (
      headerLength < 1 ||
      headerLength > LAUNCHER_IPC_HEADER_MAX_BYTES ||
      credentialLength !== 0 ||
      frameLength > LAUNCHER_IPC_FRAME_MAX_BYTES
    ) {
      throw new LauncherIpcError("LAUNCHER_IPC_FRAME_TOO_LARGE");
    }

    const body = await queue.take(
      headerLength + LAUNCHER_IPC_TAG_BYTES,
      signal,
    );
    try {
      const header = body.subarray(0, headerLength);
      const receivedTag = body.subarray(headerLength);
      const authenticated = joinBytes(prefix, header);
      const expectedTag = calculateTag(
        RESPONSE_HMAC_DOMAIN,
        secret,
        authenticated,
      );
      try {
        if (
          receivedTag.byteLength !== expectedTag.byteLength ||
          !timingSafeEqual(receivedTag, expectedTag)
        ) {
          throw new LauncherIpcError("LAUNCHER_IPC_AUTHENTICATION_FAILED");
        }
      } finally {
        authenticated.fill(0);
        expectedTag.fill(0);
      }

      let raw: string;
      let value: unknown;
      try {
        raw = new TextDecoder("utf-8", { fatal: true }).decode(header);
        value = JSON.parse(raw);
      } catch {
        throw new LauncherIpcError("LAUNCHER_IPC_MESSAGE_INVALID");
      }
      const response = parseResponse(value);
      if (JSON.stringify(response) !== raw) {
        throw new LauncherIpcError("LAUNCHER_IPC_MESSAGE_INVALID");
      }
      return response;
    } finally {
      body.fill(0);
    }
  } finally {
    prefix.fill(0);
  }
}

function parseResponse(value: unknown): Response {
  if (!isObject(value) || value.protocol_version !== 1) {
    throw new LauncherIpcError("LAUNCHER_IPC_MESSAGE_INVALID");
  }
  if (value.message_type === "session_ack") {
    requireExactKeys(value, [
      "protocol_version",
      "message_type",
      "session_id",
      "sequence",
      "status",
    ]);
    if (
      typeof value.session_id !== "string" ||
      !/^gsi_[A-Za-z0-9_-]{22}$/.test(value.session_id) ||
      !Number.isSafeInteger(value.sequence) ||
      (value.sequence as number) < 0 ||
      (value.sequence as number) >= LAUNCHER_IPC_MAX_FRAMES ||
      value.status !== "accepted"
    ) {
      throw new LauncherIpcError("LAUNCHER_IPC_MESSAGE_INVALID");
    }
    return {
      protocol_version: 1,
      message_type: "session_ack",
      session_id: value.session_id,
      sequence: value.sequence as number,
      status: "accepted",
    };
  }
  if (value.message_type === "session_error") {
    requireExactKeys(value, ["protocol_version", "message_type", "error_code"]);
    if (
      typeof value.error_code !== "string" ||
      !isIpcErrorCode(value.error_code)
    ) {
      throw new LauncherIpcError("LAUNCHER_IPC_MESSAGE_INVALID");
    }
    return {
      protocol_version: 1,
      message_type: "session_error",
      error_code: value.error_code,
    };
  }
  throw new LauncherIpcError("LAUNCHER_IPC_MESSAGE_INVALID");
}

class ResponseQueue {
  readonly #transport: LauncherIpcTransport;
  #buffer: Uint8Array = new Uint8Array();

  constructor(transport: LauncherIpcTransport) {
    this.#transport = transport;
  }

  async take(count: number, signal: AbortSignal): Promise<Uint8Array> {
    while (this.#buffer.byteLength < count) {
      let chunk: Uint8Array | null;
      try {
        chunk = await this.#transport.read(signal);
      } catch (error) {
        if (signal.aborted)
          throw new LauncherIpcError("LAUNCHER_IPC_CANCELLED");
        throw fixedIpcError(error, "LAUNCHER_IPC_PEER_CLOSED");
      }
      if (chunk === null)
        throw new LauncherIpcError("LAUNCHER_IPC_PEER_CLOSED");
      if (!(chunk instanceof Uint8Array) || chunk.byteLength === 0) {
        throw new LauncherIpcError("LAUNCHER_IPC_MESSAGE_INVALID");
      }
      if (
        this.#buffer.byteLength + chunk.byteLength >
        LAUNCHER_IPC_FRAME_MAX_BYTES
      ) {
        throw new LauncherIpcError("LAUNCHER_IPC_FRAME_TOO_LARGE");
      }
      const combined = joinBytes(this.#buffer, chunk);
      this.#buffer.fill(0);
      this.#buffer = combined;
    }

    const result = this.#buffer.slice(0, count);
    const remainder = this.#buffer.slice(count);
    this.#buffer.fill(0);
    this.#buffer = remainder;
    return result;
  }

  clear(): void {
    this.#buffer.fill(0);
    this.#buffer = new Uint8Array();
  }
}

async function writeTransport(
  transport: LauncherIpcTransport,
  bytes: Uint8Array,
  signal: AbortSignal,
): Promise<void> {
  try {
    await transport.write(bytes, signal);
  } catch (error) {
    if (signal.aborted) throw new LauncherIpcError("LAUNCHER_IPC_CANCELLED");
    throw fixedIpcError(error, "LAUNCHER_IPC_WRITE_FAILED");
  }
}

function withinDeadline<T>(
  timeoutMs: number,
  monotonicNow: () => number,
  parentSignal: AbortSignal,
  operation: (signal: AbortSignal) => Promise<T>,
): Promise<T> {
  const startedAt = monotonicNow();
  if (!Number.isFinite(startedAt)) {
    return Promise.reject(new LauncherIpcError("LAUNCHER_IPC_TIMEOUT"));
  }
  if (parentSignal.aborted) {
    return Promise.reject(new LauncherIpcError("LAUNCHER_IPC_CANCELLED"));
  }

  const controller = new AbortController();
  return new Promise<T>((resolve, reject) => {
    let settled = false;
    let timedOut = false;
    const finish = (callback: () => void): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      parentSignal.removeEventListener("abort", onParentAbort);
      callback();
    };
    const onParentAbort = (): void => {
      controller.abort();
      finish(() => reject(new LauncherIpcError("LAUNCHER_IPC_CANCELLED")));
    };
    const remaining = timeoutMs - (monotonicNow() - startedAt);
    if (
      !Number.isFinite(remaining) ||
      remaining <= 0 ||
      remaining > MAX_TIMER_DELAY_MS
    ) {
      reject(new LauncherIpcError("LAUNCHER_IPC_TIMEOUT"));
      return;
    }
    const timer = setTimeout(() => {
      timedOut = true;
      controller.abort();
      finish(() => reject(new LauncherIpcError("LAUNCHER_IPC_TIMEOUT")));
    }, remaining);
    parentSignal.addEventListener("abort", onParentAbort, { once: true });
    Promise.resolve(operation(controller.signal)).then(
      (value) => finish(() => resolve(value)),
      (error: unknown) =>
        finish(() =>
          reject(
            timedOut
              ? new LauncherIpcError("LAUNCHER_IPC_TIMEOUT")
              : fixedIpcError(error),
          ),
        ),
    );
  });
}

function calculateTag(
  domain: Uint8Array,
  secret: Uint8Array,
  bytes: Uint8Array,
): Uint8Array {
  return new Uint8Array(
    createHmac("sha256", secret).update(domain).update(bytes).digest(),
  );
}

function joinBytes(...parts: readonly Uint8Array[]): Uint8Array {
  const size = parts.reduce((total, part) => total + part.byteLength, 0);
  const result = new Uint8Array(size);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.byteLength;
  }
  return result;
}

function consumeRandom(
  randomBytes: (size: number) => Uint8Array,
  count: number,
): Uint8Array {
  const source = randomBytes(count);
  if (!(source instanceof Uint8Array) || source.byteLength !== count) {
    if (source instanceof Uint8Array) source.fill(0);
    throw new LauncherIpcError("LAUNCHER_IPC_CREDENTIAL_INVALID");
  }
  const copy = Uint8Array.from(source);
  source.fill(0);
  return copy;
}

function randomIdentifier(
  prefix: "gsi_" | "gn_",
  randomBytes: (size: number) => Uint8Array,
): string {
  const bytes = consumeRandom(randomBytes, 16);
  try {
    const identifier = `${prefix}${Buffer.from(bytes).toString("base64url")}`;
    if (!IDENTIFIER_PATTERN.test(identifier)) {
      throw new LauncherIpcError("LAUNCHER_IPC_MESSAGE_INVALID");
    }
    return identifier;
  } finally {
    bytes.fill(0);
  }
}

function takeUniqueNonce(
  randomBytes: (size: number) => Uint8Array,
  used: Set<string>,
): string {
  const nonce = randomIdentifier("gn_", randomBytes);
  if (used.has(nonce)) throw new LauncherIpcError("LAUNCHER_IPC_REPLAYED");
  used.add(nonce);
  return nonce;
}

function validateCredential(
  credential: Uint8Array | undefined,
  expiresAt: number | undefined,
  now: number,
): void {
  if (credential === undefined) {
    if (expiresAt !== undefined) {
      throw new LauncherIpcError("LAUNCHER_IPC_CREDENTIAL_INVALID");
    }
    return;
  }
  if (
    !(credential instanceof Uint8Array) ||
    credential.byteLength !== LAUNCHER_IPC_CREDENTIAL_BYTES ||
    !CREDENTIAL_PATTERN.test(new TextDecoder().decode(credential)) ||
    !Number.isSafeInteger(expiresAt) ||
    (expiresAt as number) <= now
  ) {
    throw new LauncherIpcError("LAUNCHER_IPC_CREDENTIAL_INVALID");
  }
}

function validateProcessId(value: number): void {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new LauncherIpcError("LAUNCHER_IPC_PROCESS_MISMATCH");
  }
}

function validateTimestamp(value: number): number {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new LauncherIpcError("LAUNCHER_IPC_STALE");
  }
  return value;
}

function validateTimeout(value: number): number {
  if (
    !Number.isSafeInteger(value) ||
    value <= 0 ||
    value > MAX_TIMER_DELAY_MS
  ) {
    throw new LauncherIpcError("LAUNCHER_IPC_TIMEOUT");
  }
  return value;
}

function validateIntegrity(
  value: string,
): asserts value is EngineIntegrityStatus {
  if (value !== "verified" && value !== "development_unverified") {
    throw new LauncherIpcError("LAUNCHER_IPC_MESSAGE_INVALID");
  }
}

function validateCredentialStore(
  value: string,
): asserts value is CredentialStoreStatus {
  if (
    value !== "available" &&
    value !== "unavailable" &&
    value !== "not_checked"
  ) {
    throw new LauncherIpcError("LAUNCHER_IPC_MESSAGE_INVALID");
  }
}

function requireExactKeys(value: object, expected: readonly string[]): void {
  const keys = Object.keys(value);
  if (
    keys.length !== expected.length ||
    keys.some((key, index) => key !== expected[index])
  ) {
    throw new LauncherIpcError("LAUNCHER_IPC_MESSAGE_INVALID");
  }
}

function isObject(value: unknown): value is { [key: string]: unknown } {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isIpcErrorCode(value: string): value is LauncherIpcErrorCode {
  return (
    value === "LAUNCHER_IPC_CANCELLED" ||
    value === "LAUNCHER_IPC_TIMEOUT" ||
    value === "LAUNCHER_IPC_PEER_CLOSED" ||
    value === "LAUNCHER_IPC_INVALID_BOOTSTRAP" ||
    value === "LAUNCHER_IPC_FRAME_TOO_LARGE" ||
    value === "LAUNCHER_IPC_AUTHENTICATION_FAILED" ||
    value === "LAUNCHER_IPC_MESSAGE_INVALID" ||
    value === "LAUNCHER_IPC_STALE" ||
    value === "LAUNCHER_IPC_REPLAYED" ||
    value === "LAUNCHER_IPC_PROCESS_MISMATCH" ||
    value === "LAUNCHER_IPC_SESSION_MISMATCH" ||
    value === "LAUNCHER_IPC_SEQUENCE_INVALID" ||
    value === "LAUNCHER_IPC_CREDENTIAL_INVALID" ||
    value === "LAUNCHER_IPC_LIMIT_EXCEEDED" ||
    value === "LAUNCHER_IPC_WRITE_FAILED"
  );
}

function fixedIpcError(
  value: unknown,
  fallback: LauncherIpcErrorCode = "LAUNCHER_IPC_MESSAGE_INVALID",
): LauncherIpcError {
  return value instanceof LauncherIpcError
    ? value
    : new LauncherIpcError(fallback);
}

function ipcErrorMessage(code: LauncherIpcErrorCode): string {
  switch (code) {
    case "LAUNCHER_IPC_CANCELLED":
      return "The GOAT launcher session was cancelled.";
    case "LAUNCHER_IPC_TIMEOUT":
      return "The GOAT launcher session timed out.";
    case "LAUNCHER_IPC_PEER_CLOSED":
      return "The GOAT launcher session pipe closed unexpectedly.";
    case "LAUNCHER_IPC_INVALID_BOOTSTRAP":
      return "The GOAT launcher session bootstrap was invalid.";
    case "LAUNCHER_IPC_FRAME_TOO_LARGE":
      return "The GOAT launcher session frame exceeded its fixed size limit.";
    case "LAUNCHER_IPC_AUTHENTICATION_FAILED":
      return "The GOAT launcher session authentication failed.";
    case "LAUNCHER_IPC_MESSAGE_INVALID":
      return "The GOAT launcher session message was invalid.";
    case "LAUNCHER_IPC_STALE":
      return "The GOAT launcher session message was stale.";
    case "LAUNCHER_IPC_REPLAYED":
      return "The GOAT launcher session nonce was reused.";
    case "LAUNCHER_IPC_PROCESS_MISMATCH":
      return "The GOAT launcher session process binding failed.";
    case "LAUNCHER_IPC_SESSION_MISMATCH":
      return "The GOAT launcher session binding failed.";
    case "LAUNCHER_IPC_SEQUENCE_INVALID":
      return "The GOAT launcher session sequence was invalid.";
    case "LAUNCHER_IPC_CREDENTIAL_INVALID":
      return "The GOAT launcher session credential was invalid.";
    case "LAUNCHER_IPC_LIMIT_EXCEEDED":
      return "The GOAT launcher session frame limit was exceeded.";
    case "LAUNCHER_IPC_WRITE_FAILED":
      return "The GOAT launcher session write failed.";
  }
}
