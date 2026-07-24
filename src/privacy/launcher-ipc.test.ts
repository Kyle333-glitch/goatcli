import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { test } from "node:test";
import {
  LAUNCHER_IPC_CREDENTIAL_BYTES,
  LAUNCHER_IPC_FRAME_MAX_BYTES,
  LAUNCHER_IPC_HEADER_MAX_BYTES,
  LAUNCHER_IPC_MAGIC_V1,
  LAUNCHER_IPC_MAX_FRAMES,
  LAUNCHER_IPC_PROTOCOL_VERSION,
  LAUNCHER_IPC_SECRET_BYTES,
  LAUNCHER_IPC_TAG_BYTES,
  LAUNCHER_IPC_TIMEOUT_MS,
  LauncherIpcError,
  openLauncherIpcSession,
  type LauncherIpcErrorCode,
  type LauncherIpcTransport,
} from "./launcher-ipc.js";

const NOW = 1_800_000_000_000;
const LAUNCHER_PID = 4_100;
const ENGINE_PID = 4_200;
const CREDENTIAL = new TextEncoder().encode(
  "abcdefghijklmnopqrstuvwxyz0123456789_-ABCDE",
);
const REQUEST_DOMAIN = new TextEncoder().encode(
  "GOAT launcher IPC request v1\0",
);
const RESPONSE_DOMAIN = new TextEncoder().encode(
  "GOAT launcher IPC response v1\0",
);

test("publishes only the bounded IPC v1 protocol constants", () => {
  assert.equal(LAUNCHER_IPC_PROTOCOL_VERSION, 1);
  assert.equal(new TextDecoder().decode(LAUNCHER_IPC_MAGIC_V1), "GOATIPC1");
  assert.equal(LAUNCHER_IPC_SECRET_BYTES, 32);
  assert.equal(LAUNCHER_IPC_TAG_BYTES, 32);
  assert.equal(LAUNCHER_IPC_HEADER_MAX_BYTES, 2_048);
  assert.equal(LAUNCHER_IPC_CREDENTIAL_BYTES, 43);
  assert.equal(LAUNCHER_IPC_FRAME_MAX_BYTES, 4_096);
  assert.equal(LAUNCHER_IPC_TIMEOUT_MS, 2_000);
  assert.equal(LAUNCHER_IPC_MAX_FRAMES, 256);
});

test("matches the engine-compatible bootstrap and authenticated start vector", async () => {
  const sources: Uint8Array[] = [];
  const values = [
    Uint8Array.from({ length: 32 }, (_, index) => index),
    new Uint8Array(16),
    Uint8Array.from(Buffer.from("000000000000000000000w", "base64url")),
  ];
  const transport = new EngineHarness();
  const session = await openLauncherIpcSession({
    transport,
    engineIntegrity: "verified",
    credentialStore: "available",
    launcherPid: LAUNCHER_PID,
    enginePid: ENGINE_PID,
    credential: CREDENTIAL,
    credentialExpiresAtUnixMs: NOW + 60_000,
    now: () => NOW,
    monotonicNow: () => 10,
    randomBytes: (size) => {
      const value = values.shift();
      assert.equal(value?.byteLength, size);
      sources.push(value!);
      return value!;
    },
  });

  assert.equal(transport.writes.length, 2);
  assert.equal(
    Buffer.from(transport.writes[0]!).toString("hex"),
    [
      Buffer.from("GOATIPC1").toString("hex"),
      Buffer.from(
        Uint8Array.from({ length: 32 }, (_, index) => index),
      ).toString("hex"),
    ].join(""),
  );
  const expectedFrame = [
    "00000192002b7b2270726f746f636f6c5f76657273696f6e223a312c226d6573736167655f74797065223a2273657373696f6e5f7374617274222c",
    "2273657373696f6e5f6964223a226773695f41414141414141414141414141414141414141414141222c226e6f6e6365223a22676e5f303030303030",
    "30303030303030303030303030303077222c2273657175656e6365223a302c226973737565645f61745f756e69785f6d73223a31383030303030303030",
    "3030302c226c61756e636865725f706964223a343130302c22656e67696e655f706964223a343230302c226c61756e636865725f76657273696f6e223a",
    "22302e332e32222c22696e7374616c6c6174696f6e5f6368616e6e656c223a226e706d222c22656e67696e655f696e74656772697479223a2276657269",
    "66696564222c2263726564656e7469616c5f73746f7265223a22617661696c61626c65222c2263726564656e7469616c5f6c656e677468223a34332c22",
    "63726564656e7469616c5f657870697265735f61745f756e69785f6d73223a313830303030303036303030307d6162636465666768696a6b6c6d6e6f70",
    "7172737475767778797a303132333435363738395f2d4142434445d4485271a3142a3930645c4fd4ecab48ffd5eb6d13823adf7a5bc2d412c71e6c",
  ].join("");
  assert.equal(
    Buffer.from(transport.writes[1]!).toString("hex"),
    expectedFrame,
  );
  assert.equal(session.sessionId, "gsi_AAAAAAAAAAAAAAAAAAAAAA");
  sources.forEach(assertZeroed);
  transport.writeReferences.forEach(assertZeroed);
  session.dispose();
  assert.equal(transport.closed, true);
});

test("sends credential update, clear, and end with ordered ACKs", async () => {
  const transport = new EngineHarness({ splitResponses: true });
  const session = await openLauncherIpcSession(baseOptions(transport));
  const replacement = new TextEncoder().encode("Z".repeat(43));

  await session.updateCredential(replacement, NOW + 120_000);
  await session.clearCredential();
  await session.end();

  const requests = transport.writes.slice(1).map(decodeRequest);
  assert.deepEqual(
    requests.map(({ header }) => [header.message_type, header.sequence]),
    [
      ["session_start", 0],
      ["credential_update", 1],
      ["credential_clear", 2],
      ["session_end", 3],
    ],
  );
  assert.deepEqual(requests[1]!.credential, replacement);
  assert.equal(
    requests[1]!.header.credential_expires_at_unix_ms,
    NOW + 120_000,
  );
  assert.equal(requests[2]!.credential.byteLength, 0);
  assert.equal(requests[3]!.credential.byteLength, 0);
  assert.equal(transport.closed, true);
  transport.writeReferences.forEach(assertZeroed);
});

test("omits optional credential fields for unauthenticated diagnostic preview", async () => {
  const transport = new EngineHarness();
  const session = await openLauncherIpcSession({
    ...baseOptions(transport),
    credentialStore: "not_checked",
    credential: undefined,
    credentialExpiresAtUnixMs: undefined,
  });
  const request = decodeRequest(transport.writes[1]!);
  assert.deepEqual(Object.keys(request.header), [
    "protocol_version",
    "message_type",
    "session_id",
    "nonce",
    "sequence",
    "issued_at_unix_ms",
    "launcher_pid",
    "engine_pid",
    "launcher_version",
    "installation_channel",
    "engine_integrity",
    "credential_store",
    "credential_length",
  ]);
  assert.equal(request.header.installation_channel, "npm");
  assert.equal(request.header.credential_length, 0);
  assert.equal(request.credential.byteLength, 0);
  session.dispose();
});

test("rejects invalid credentials and process bindings before writing", async () => {
  const badCredential = new TextEncoder().encode(`${"A".repeat(42)}=`);
  for (const overrides of [
    { launcherPid: 0 },
    { enginePid: -1 },
    { credential: badCredential },
    { credentialStore: "unavailable" as const },
    { credentialExpiresAtUnixMs: NOW },
  ]) {
    const transport = new EngineHarness();
    await assert.rejects(
      () => openLauncherIpcSession({ ...baseOptions(transport), ...overrides }),
      LauncherIpcError,
    );
    assert.equal(transport.writes.length, 0);
  }
});

test("rejects a tampered ACK without exposing response bytes", async () => {
  const transport = new EngineHarness({ tamperResponse: true });
  await assert.rejects(
    () => openLauncherIpcSession(baseOptions(transport)),
    hasCode("LAUNCHER_IPC_AUTHENTICATION_FAILED"),
  );
  assert.equal(transport.closed, true);
});

test("rejects signed ACKs with unknown fields or mismatched bindings", async () => {
  for (const responseMutation of [
    (response: Ack) => ({ ...response, arbitrary: "forbidden" }),
    (response: Ack) => ({
      ...response,
      session_id: "gsi_BBBBBBBBBBBBBBBBBBBBBB",
    }),
    (response: Ack) => ({ ...response, sequence: response.sequence + 1 }),
  ]) {
    const transport = new EngineHarness({ responseMutation });
    await assert.rejects(
      () => openLauncherIpcSession(baseOptions(transport)),
      (error) =>
        error instanceof LauncherIpcError &&
        (error.code === "LAUNCHER_IPC_MESSAGE_INVALID" ||
          error.code === "LAUNCHER_IPC_SESSION_MISMATCH" ||
          error.code === "LAUNCHER_IPC_SEQUENCE_INVALID"),
    );
  }
});

test("propagates only fixed engine session-error codes", async () => {
  const transport = new EngineHarness({
    responseMutation: () => ({
      protocol_version: 1,
      message_type: "session_error",
      error_code: "LAUNCHER_IPC_PROCESS_MISMATCH",
    }),
  });
  await assert.rejects(
    () => openLauncherIpcSession(baseOptions(transport)),
    hasCode("LAUNCHER_IPC_PROCESS_MISMATCH"),
  );
});

test("enforces total deadlines and external cancellation", async () => {
  const timeoutTransport = new EngineHarness({ suppressResponses: true });
  await assert.rejects(
    () =>
      openLauncherIpcSession({
        ...baseOptions(timeoutTransport),
        timeoutMs: 5,
        monotonicNow: () => performance.now(),
      }),
    hasCode("LAUNCHER_IPC_TIMEOUT"),
  );

  const controller = new AbortController();
  const cancelTransport = new EngineHarness({ suppressResponses: true });
  const opening = openLauncherIpcSession({
    ...baseOptions(cancelTransport),
    signal: controller.signal,
  });
  controller.abort();
  await assert.rejects(opening, hasCode("LAUNCHER_IPC_CANCELLED"));
});

test("rejects oversized response declarations and nonce reuse", async () => {
  const oversized = new EngineHarness({ oversizedResponse: true });
  await assert.rejects(
    () => openLauncherIpcSession(baseOptions(oversized)),
    hasCode("LAUNCHER_IPC_FRAME_TOO_LARGE"),
  );

  const repeated = new Uint8Array(16).fill(4);
  let call = 0;
  const replay = new EngineHarness();
  const session = await openLauncherIpcSession({
    ...baseOptions(replay),
    randomBytes: (size) => {
      call += 1;
      if (size === 32) return new Uint8Array(32).fill(1);
      if (call === 2) return new Uint8Array(16).fill(2);
      return repeated.slice();
    },
  });
  await assert.rejects(
    () => session.clearCredential(),
    hasCode("LAUNCHER_IPC_REPLAYED"),
  );
  session.dispose();
});

test("fixed launcher frames never contain privacy canaries", async () => {
  const canaries = [
    "PROMPT_SECRET_7QX9",
    "SOURCE_CODE_SECRET_4JK2",
    "TOKEN_SECRET_8MVP",
    "PATH_SECRET_3HT6",
    "ENV_SECRET_9DK1",
  ];
  const transport = new EngineHarness();
  const session = await openLauncherIpcSession({
    ...baseOptions(transport),
    credential: undefined,
    credentialExpiresAtUnixMs: undefined,
    credentialStore: "not_checked",
  });
  const wire = transport.writes.map((part) => Buffer.from(part)).join("\n");
  for (const canary of canaries) assert.equal(wire.includes(canary), false);
  session.dispose();
});

type Ack = {
  protocol_version: 1;
  message_type: "session_ack";
  session_id: string;
  sequence: number;
  status: "accepted";
};

type HarnessOptions = {
  splitResponses?: boolean;
  tamperResponse?: boolean;
  suppressResponses?: boolean;
  oversizedResponse?: boolean;
  responseMutation?: (response: Ack) => object;
};

class EngineHarness implements LauncherIpcTransport {
  readonly writes: Uint8Array[] = [];
  readonly writeReferences: Uint8Array[] = [];
  readonly #responses: Uint8Array[] = [];
  readonly #waiters: Array<(value: Uint8Array | null) => void> = [];
  readonly #options: HarnessOptions;
  #secret?: Uint8Array;
  closed = false;

  constructor(options: HarnessOptions = {}) {
    this.#options = options;
  }

  async write(bytes: Uint8Array, signal: AbortSignal): Promise<void> {
    if (signal.aborted) throw new Error("aborted");
    this.writeReferences.push(bytes);
    const copy = Uint8Array.from(bytes);
    this.writes.push(copy);
    if (
      copy.byteLength === 40 &&
      Buffer.from(copy.subarray(0, 8)).equals(Buffer.from("GOATIPC1"))
    ) {
      this.#secret = copy.slice(8);
      return;
    }
    if (!this.#secret || this.#options.suppressResponses) return;
    if (this.#options.oversizedResponse) {
      const prefix = new Uint8Array(6);
      new DataView(prefix.buffer).setUint32(
        0,
        LAUNCHER_IPC_HEADER_MAX_BYTES + 1,
        false,
      );
      this.enqueue(prefix);
      return;
    }
    const request = decodeRequest(copy).header;
    const base: Ack = {
      protocol_version: 1,
      message_type: "session_ack",
      session_id: request.session_id as string,
      sequence: request.sequence as number,
      status: "accepted",
    };
    const response = this.#options.responseMutation?.(base) ?? base;
    const frame = encodeResponse(this.#secret, response);
    if (this.#options.tamperResponse) frame[frame.byteLength - 1]! ^= 1;
    if (this.#options.splitResponses) {
      this.enqueue(frame.slice(0, 2));
      this.enqueue(frame.slice(2, 11));
      this.enqueue(frame.slice(11));
    } else {
      this.enqueue(frame);
    }
  }

  read(signal: AbortSignal): Promise<Uint8Array | null> {
    const response = this.#responses.shift();
    if (response) return Promise.resolve(response);
    if (this.closed) return Promise.resolve(null);
    return new Promise((resolve, reject) => {
      const onAbort = (): void => {
        signal.removeEventListener("abort", onAbort);
        reject(new Error("aborted"));
      };
      signal.addEventListener("abort", onAbort, { once: true });
      this.#waiters.push((value) => {
        signal.removeEventListener("abort", onAbort);
        resolve(value);
      });
    });
  }

  close(): void {
    this.closed = true;
    this.#secret?.fill(0);
    this.#secret = undefined;
    for (const waiter of this.#waiters.splice(0)) waiter(null);
    for (const response of this.#responses.splice(0)) response.fill(0);
  }

  private enqueue(bytes: Uint8Array): void {
    const waiter = this.#waiters.shift();
    if (waiter) waiter(bytes);
    else this.#responses.push(bytes);
  }
}

function baseOptions(transport: LauncherIpcTransport) {
  let randomCall = 0;
  return {
    transport,
    engineIntegrity: "verified" as const,
    credentialStore: "available" as const,
    launcherPid: LAUNCHER_PID,
    enginePid: ENGINE_PID,
    credential: CREDENTIAL,
    credentialExpiresAtUnixMs: NOW + 60_000,
    now: () => NOW,
    randomBytes: (size: number) => new Uint8Array(size).fill(++randomCall),
  };
}

function decodeRequest(frame: Uint8Array): {
  header: { [key: string]: unknown };
  credential: Uint8Array;
} {
  const view = new DataView(frame.buffer, frame.byteOffset, frame.byteLength);
  const headerLength = view.getUint32(0, false);
  const credentialLength = view.getUint16(4, false);
  const header = JSON.parse(
    new TextDecoder().decode(frame.subarray(6, 6 + headerLength)),
  ) as { [key: string]: unknown };
  return {
    header,
    credential: frame.slice(
      6 + headerLength,
      6 + headerLength + credentialLength,
    ),
  };
}

function encodeResponse(secret: Uint8Array, response: object): Uint8Array {
  const header = new TextEncoder().encode(JSON.stringify(response));
  const prefix = new Uint8Array(6);
  new DataView(prefix.buffer).setUint32(0, header.byteLength, false);
  const authenticated = Buffer.concat([
    Buffer.from(prefix),
    Buffer.from(header),
  ]);
  const tag = createHmac("sha256", secret)
    .update(RESPONSE_DOMAIN)
    .update(authenticated)
    .digest();
  return new Uint8Array(Buffer.concat([authenticated, tag]));
}

function hasCode(code: LauncherIpcErrorCode): (error: unknown) => boolean {
  return (error) => error instanceof LauncherIpcError && error.code === code;
}

function assertZeroed(bytes: Uint8Array): void {
  assert.equal(
    bytes.every((byte) => byte === 0),
    true,
  );
}
