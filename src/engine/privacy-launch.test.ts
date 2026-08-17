import assert from "node:assert/strict";
import type { ChildProcess } from "node:child_process";
import { createHmac, timingSafeEqual } from "node:crypto";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { test } from "node:test";
import { EngineContractError } from "./contract.js";
import {
  launchValidatedEngine,
  type ProcessLike,
  type SpawnEngine,
} from "./launch.js";

const REQUEST_DOMAIN = new TextEncoder().encode(
  "GOAT launcher IPC request v1\0",
);
const RESPONSE_DOMAIN = new TextEncoder().encode(
  "GOAT launcher IPC response v1\0",
);

test("launchValidatedEngine uses only fd 3/4 for an authenticated privacy session", async () => {
  const child = new IpcChild(4_200);
  const processLike = new IpcProcess();
  const observedRequests: Array<{
    header: { [key: string]: unknown };
    credential: Uint8Array;
    attestation: Uint8Array;
  }> = [];
  attachEngineResponder(child, observedRequests);
  let spawnOptions: Parameters<SpawnEngine>[2] | undefined;
  const spawnEngine: SpawnEngine = (_command, _args, options) => {
    spawnOptions = options;
    return child as unknown as ChildProcess;
  };
  const credential = new TextEncoder().encode("A".repeat(43));

  const result = await launchValidatedEngine(
    { executablePath: "C:\\GOAT\\goat-engine.exe", platform: "win32" },
    ["privacy", "diagnostics", "delete", "PATH_SECRET_3HT6"],
    {
      cwd: "C:\\work\\PATH_SECRET_3HT6",
      environment: { PROVIDER_TOKEN: "ENV_SECRET_9DK1" },
      spawnEngine,
      processLike,
      privacyIpc: {
        mode: "eager",
        engineIntegrity: "verified",
        credentialStore: "available",
        credential,
        credentialExpiresAtUnixMs: Date.now() + 60_000,
        launcherPid: processLike.pid,
      },
    },
  );

  assert.deepEqual(result, { exitCode: 0, signal: null });
  assert.deepEqual(spawnOptions?.stdio, [
    "inherit",
    "inherit",
    "inherit",
    "pipe",
    "pipe",
  ]);
  assert.equal(observedRequests.length, 1);
  const request = observedRequests[0]!;
  assert.equal(request.header.message_type, "session_start");
  assert.equal(request.header.launcher_version, "0.3.2");
  assert.equal(request.header.installation_channel, "npm");
  assert.equal(request.header.launcher_pid, processLike.pid);
  assert.equal(request.header.engine_pid, child.pid);
  assert.deepEqual(request.credential, credential);
  const ipcBytes = JSON.stringify(request.header);
  assert.equal(ipcBytes.includes("PATH_SECRET_3HT6"), false);
  assert.equal(ipcBytes.includes("ENV_SECRET_9DK1"), false);
  assert.equal(child.toEngine.destroyed, true);
  assert.equal(child.fromEngine.destroyed, true);
});

test("threads the per-device attestation blob into the session_start frame", async () => {
  const child = new IpcChild(4_200);
  const processLike = new IpcProcess();
  const observedRequests: Array<{
    header: { [key: string]: unknown };
    credential: Uint8Array;
    attestation: Uint8Array;
  }> = [];
  attachEngineResponder(child, observedRequests);
  const credential = new TextEncoder().encode("A".repeat(43));
  const deviceId = "123e4567-e89b-12d3-a456-426614174000";
  const deviceSecret = new TextEncoder().encode("Z".repeat(43));
  const attestation = new TextEncoder().encode(
    `${deviceId}:${new TextDecoder().decode(deviceSecret)}`,
  );

  const result = await launchValidatedEngine(
    { executablePath: "C:\\GOAT\\goat-engine.exe", platform: "win32" },
    ["privacy", "diagnostics", "delete", "PATH_SECRET_3HT6"],
    {
      cwd: "C:\\work",
      spawnEngine: () => child as unknown as ChildProcess,
      processLike,
      privacyIpc: {
        mode: "eager",
        engineIntegrity: "verified",
        credentialStore: "available",
        credential,
        credentialExpiresAtUnixMs: Date.now() + 60_000,
        attestation,
        launcherPid: processLike.pid,
      },
    },
  );

  assert.deepEqual(result, { exitCode: 0, signal: null });
  assert.equal(observedRequests.length, 1);
  const request = observedRequests[0]!;
  assert.equal(request.header.attestation_length, attestation.byteLength);
  assert.deepEqual(request.attestation, attestation);
  assert.equal(request.header.message_type, "session_start");
});

test("lazy IPC carries provider-attested device enrollment into the start frame", async () => {
  const child = new IpcChild(4_200);
  const processLike = new IpcProcess();
  const observedRequests: Array<{
    header: { [key: string]: unknown };
    credential: Uint8Array;
    attestation: Uint8Array;
  }> = [];
  attachEngineResponder(child, observedRequests);
  const expectedCredential = new TextEncoder().encode("B".repeat(43));
  const deviceId = "123e4567-e89b-12d3-a456-426614174000";
  const deviceSecret = new TextEncoder().encode("Y".repeat(43));
  const expectedAttestation = new TextEncoder().encode(
    `${deviceId}:${new TextDecoder().decode(deviceSecret)}`,
  );

  const resultPromise = launchValidatedEngine(
    { executablePath: "C:\\GOAT\\goat-engine.exe", platform: "win32" },
    ["run"],
    {
      cwd: "C:\\work",
      spawnEngine: () => child as unknown as ChildProcess,
      processLike,
      privacyIpc: {
        mode: "lazy",
        engineIntegrity: "verified",
        credentialStore: "unavailable",
        async credentialProvider() {
          return {
            accessToken: expectedCredential.slice(),
            expiresAtUnixMs: Date.now() + 60_000,
            deviceId,
            deviceSecret: deviceSecret.slice(),
          };
        },
        launcherPid: processLike.pid,
      },
    },
  );

  await Promise.resolve();
  child.fromEngine.write(Buffer.from("GOATIPC2"));
  const result = await resultPromise;
  assert.deepEqual(result, { exitCode: 0, signal: null });
  assert.equal(observedRequests.length, 1);
  const request = observedRequests[0]!;
  assert.equal(request.header.attestation_length, expectedAttestation.byteLength);
  assert.deepEqual(request.attestation, expectedAttestation);
});

test("lazy IPC waits for v2 activation before preparing a credential", async () => {
  const child = new IpcChild(4_200);
  const processLike = new IpcProcess();
  const observedRequests: Array<{
    header: { [key: string]: unknown };
    credential: Uint8Array;
    attestation: Uint8Array;
  }> = [];
  attachEngineResponder(child, observedRequests);
  let providerCalls = 0;
  const expectedCredential = new TextEncoder().encode("B".repeat(43));

  const resultPromise = launchValidatedEngine(
    { executablePath: "C:\\GOAT\\goat-engine.exe", platform: "win32" },
    ["run"],
    {
      cwd: "C:\\work",
      spawnEngine: () => child as unknown as ChildProcess,
      processLike,
      privacyIpc: {
        mode: "lazy",
        engineIntegrity: "verified",
        credentialStore: "unavailable",
        async credentialProvider() {
          providerCalls += 1;
          return {
            accessToken: expectedCredential.slice(),
            expiresAtUnixMs: Date.now() + 60_000,
          };
        },
        launcherPid: processLike.pid,
      },
    },
  );

  await Promise.resolve();
  assert.equal(providerCalls, 0);
  child.fromEngine.write(Buffer.from("GOATIPC2"));

  const result = await resultPromise;
  assert.deepEqual(result, { exitCode: 0, signal: null });
  assert.equal(providerCalls, 1);
  assert.equal(observedRequests.length, 1);
  assert.equal(observedRequests[0]!.header.protocol_version, 1);
  assert.equal(observedRequests[0]!.header.credential_store, "available");
  assert.deepEqual(observedRequests[0]!.credential, expectedCredential);
});

test("invalid lazy activation disables IPC without terminating the engine command", async () => {
  const child = new IpcChild(4_200);
  const processLike = new IpcProcess();
  let providerCalls = 0;
  const resultPromise = launchValidatedEngine(
    { executablePath: "C:\\GOAT\\goat-engine.exe", platform: "win32" },
    ["run"],
    {
      cwd: "C:\\work",
      spawnEngine: () => child as unknown as ChildProcess,
      processLike,
      privacyIpc: {
        mode: "lazy",
        engineIntegrity: "verified",
        credentialStore: "unavailable",
        async credentialProvider() {
          providerCalls += 1;
          return undefined;
        },
        launcherPid: processLike.pid,
      },
    },
  );

  child.fromEngine.write(Buffer.from("BAD!IPC2"));
  await new Promise<void>((resolve) => setImmediate(resolve));
  child.emit("exit", 0, null);

  await assert.doesNotReject(resultPromise);
  assert.equal(providerCalls, 0);
  assert.deepEqual(child.killedSignals, []);
});

test("credential expiry during a delayed handshake fails closed for eager IPC", async () => {
  const child = new IpcChild(4_200);
  const processLike = new IpcProcess();
  const credential = new TextEncoder().encode("A".repeat(43));

  await assert.rejects(
    () =>
      launchValidatedEngine(
        { executablePath: "C:\\GOAT\\goat-engine.exe", platform: "win32" },
        ["privacy", "diagnostics", "delete", "PATH_SECRET_3HT6"],
        {
          cwd: "C:\\work",
          spawnEngine: () => child as unknown as ChildProcess,
          processLike,
          processTerminator: () => ({ status: 1 }),
          privacyIpc: {
            mode: "eager",
            engineIntegrity: "verified",
            credentialStore: "available",
            credential,
            credentialExpiresAtUnixMs: Date.now() - 1,
            launcherPid: processLike.pid,
          },
        },
      ),
    (error) =>
      error instanceof EngineContractError &&
      error.code === "GOAT_PRIVACY_IPC_FAILED",
  );
  // The child is terminated on failure and the caller-owned credential buffer
  // is never zeroized by the launch path (only its private copy is).
  assert.deepEqual(child.killedSignals, ["SIGTERM"]);
  assert.deepEqual([...credential], new Array(43).fill(65));
});

test("malformed lazy-provider credentials disable IPC without terminating the command", async () => {
  const child = new IpcChild(4_200);
  const processLike = new IpcProcess();
  let providerCalls = 0;
  const resultPromise = launchValidatedEngine(
    { executablePath: "C:\\GOAT\\goat-engine.exe", platform: "win32" },
    ["run"],
    {
      cwd: "C:\\work",
      spawnEngine: () => child as unknown as ChildProcess,
      processLike,
      privacyIpc: {
        mode: "lazy",
        engineIntegrity: "verified",
        credentialStore: "unavailable",
        async credentialProvider() {
          providerCalls += 1;
          return {
            accessToken: new TextEncoder().encode("too-short"),
            expiresAtUnixMs: Date.now() + 60_000,
          };
        },
        launcherPid: processLike.pid,
      },
    },
  );

  child.fromEngine.write(Buffer.from("GOATIPC2"));
  await new Promise<void>((resolve) => setImmediate(resolve));
  child.emit("exit", 0, null);

  const result = await resultPromise;
  assert.deepEqual(result, { exitCode: 0, signal: null });
  assert.equal(providerCalls, 1);
  assert.deepEqual(child.killedSignals, []);
});

test("credential-provider rejection disables IPC without terminating the command", async () => {
  const child = new IpcChild(4_200);
  const processLike = new IpcProcess();
  let providerCalls = 0;
  const resultPromise = launchValidatedEngine(
    { executablePath: "C:\\GOAT\\goat-engine.exe", platform: "win32" },
    ["run"],
    {
      cwd: "C:\\work",
      spawnEngine: () => child as unknown as ChildProcess,
      processLike,
      privacyIpc: {
        mode: "lazy",
        engineIntegrity: "verified",
        credentialStore: "unavailable",
        async credentialProvider() {
          providerCalls += 1;
          throw new Error("TOKEN_SECRET_8MVP");
        },
        launcherPid: processLike.pid,
      },
    },
  );

  child.fromEngine.write(Buffer.from("GOATIPC2"));
  await new Promise<void>((resolve) => setImmediate(resolve));
  child.emit("exit", 0, null);

  const result = await resultPromise;
  assert.deepEqual(result, { exitCode: 0, signal: null });
  assert.equal(providerCalls, 1);
  assert.deepEqual(child.killedSignals, []);
});

test("transport setup failure fails closed for eager IPC", async () => {
  const child = new NoPipeChild(4_200);
  const processLike = new IpcProcess();

  await assert.rejects(
    () =>
      launchValidatedEngine(
        { executablePath: "C:\\GOAT\\goat-engine.exe", platform: "win32" },
        ["privacy", "diagnostics", "submit"],
        {
          cwd: "C:\\work",
          spawnEngine: () => child as unknown as ChildProcess,
          processLike,
          processTerminator: () => ({ status: 1 }),
          privacyIpc: {
            mode: "eager",
            engineIntegrity: "verified",
            credentialStore: "available",
            credential: new TextEncoder().encode("A".repeat(43)),
            credentialExpiresAtUnixMs: Date.now() + 60_000,
            launcherPid: processLike.pid,
          },
        },
      ),
    (error) =>
      error instanceof EngineContractError &&
      error.code === "GOAT_PRIVACY_IPC_FAILED",
  );
  assert.deepEqual(child.killedSignals, ["SIGTERM"]);
});

test("failed ACK authentication fails closed for eager IPC", async () => {
  const child = new IpcChild(4_200);
  const processLike = new IpcProcess();
  attachGarbageResponder(child);

  await assert.rejects(
    () =>
      launchValidatedEngine(
        { executablePath: "C:\\GOAT\\goat-engine.exe", platform: "win32" },
        ["privacy", "diagnostics", "submit"],
        {
          cwd: "C:\\work",
          spawnEngine: () => child as unknown as ChildProcess,
          processLike,
          processTerminator: () => ({ status: 1 }),
          privacyIpc: {
            mode: "eager",
            engineIntegrity: "verified",
            credentialStore: "available",
            credential: new TextEncoder().encode("A".repeat(43)),
            credentialExpiresAtUnixMs: Date.now() + 60_000,
            launcherPid: processLike.pid,
          },
        },
      ),
    (error) =>
      error instanceof EngineContractError &&
      error.code === "GOAT_PRIVACY_IPC_FAILED",
  );
  assert.deepEqual(child.killedSignals, ["SIGTERM"]);
});

test("child exit during IPC setup resolves the launch without an unhandled rejection", async () => {
  const child = new IpcChild(4_200);
  const processLike = new IpcProcess();
  const resultPromise = launchValidatedEngine(
    { executablePath: "C:\\GOAT\\goat-engine.exe", platform: "win32" },
    ["privacy", "diagnostics", "submit"],
    {
      cwd: "C:\\work",
      spawnEngine: () => child as unknown as ChildProcess,
      processLike,
      processTerminator: () => ({ status: 1 }),
      privacyIpc: {
        mode: "eager",
        engineIntegrity: "verified",
        credentialStore: "available",
        credential: new TextEncoder().encode("A".repeat(43)),
        credentialExpiresAtUnixMs: Date.now() + 60_000,
        launcherPid: processLike.pid,
      },
    },
  );

  child.emit("exit", 3, null);
  const result = await resultPromise;
  assert.deepEqual(result, { exitCode: 3, signal: null });
});

test("parent signal during IPC setup terminates the child", async () => {
  const child = new IpcChild(4_200);
  const processLike = new IpcProcess();
  const resultPromise = launchValidatedEngine(
    { executablePath: "C:\\GOAT\\goat-engine.exe", platform: "win32" },
    ["privacy", "diagnostics", "submit"],
    {
      cwd: "C:\\work",
      spawnEngine: () => child as unknown as ChildProcess,
      processLike,
      processTerminator: () => ({ status: 1 }),
      privacyIpc: {
        mode: "eager",
        engineIntegrity: "verified",
        credentialStore: "available",
        credential: new TextEncoder().encode("A".repeat(43)),
        credentialExpiresAtUnixMs: Date.now() + 60_000,
        launcherPid: processLike.pid,
      },
    },
  );

  processLike.emit("SIGINT");
  assert.deepEqual(child.killedSignals, ["SIGINT"]);
  child.emit("exit", 0, null);
  const result = await resultPromise;
  assert.deepEqual(result, { exitCode: 0, signal: null });
});

test("eager IPC errors never expose secret values in diagnostics", async () => {
  const child = new IpcChild(4_200);
  const processLike = new IpcProcess();
  attachGarbageResponder(child);

  await assert.rejects(
    () =>
      launchValidatedEngine(
        {
          executablePath: "C:\\PATH_SECRET_3HT6\\goat-engine.exe",
          platform: "win32",
        },
        ["privacy", "diagnostics", "delete", "PATH_SECRET_3HT6"],
        {
          cwd: "C:\\work\\PATH_SECRET_3HT6",
          spawnEngine: () => child as unknown as ChildProcess,
          processLike,
          processTerminator: () => ({ status: 1 }),
          privacyIpc: {
            mode: "eager",
            engineIntegrity: "verified",
            credentialStore: "available",
            credential: new TextEncoder().encode("A".repeat(43)),
            credentialExpiresAtUnixMs: Date.now() + 60_000,
            launcherPid: processLike.pid,
          },
        },
      ),
    (error) => {
      assert.ok(error instanceof EngineContractError);
      const rendered = JSON.stringify({
        message: error.message,
        suggestion: error.suggestion,
      });
      assert.equal(rendered.includes("PATH_SECRET_3HT6"), false);
      assert.equal(rendered.includes("TOKEN_SECRET_8MVP"), false);
      return true;
    },
  );
});

class NoPipeChild extends EventEmitter {
  readonly stdio = [null, null, null, null, null];
  readonly killedSignals: Array<NodeJS.Signals | number | undefined> = [];

  constructor(readonly pid: number) {
    super();
  }

  kill(signal?: NodeJS.Signals | number): boolean {
    this.killedSignals.push(signal);
    return true;
  }
}

function attachGarbageResponder(child: IpcChild): void {
  let responded = false;
  child.toEngine.on("data", () => {
    if (responded) return;
    responded = true;
    child.fromEngine.write(Buffer.from("GARBAGE_NOT_AN_IPC_FRAME"));
  });
}

class IpcChild extends EventEmitter {
  readonly toEngine = new PassThrough();
  readonly fromEngine = new PassThrough();
  readonly stdio = [null, null, null, this.toEngine, this.fromEngine];
  readonly killedSignals: Array<NodeJS.Signals | number | undefined> = [];

  constructor(readonly pid: number) {
    super();
  }

  kill(signal?: NodeJS.Signals | number): boolean {
    this.killedSignals.push(signal);
    return true;
  }
}

class IpcProcess extends EventEmitter implements ProcessLike {
  readonly platform = "win32";
  readonly arch = "x64";
  readonly pid = 4_100;
  readonly env: NodeJS.ProcessEnv = {};
  cwd(): string {
    return "C:\\work";
  }
}

function attachEngineResponder(
  child: IpcChild,
  observed: Array<{
    header: { [key: string]: unknown };
    credential: Uint8Array;
    attestation: Uint8Array;
  }>,
): void {
  let bytes = Buffer.alloc(0);
  child.toEngine.on("data", (chunk: Buffer) => {
    bytes = Buffer.concat([bytes, chunk]);
    if (bytes.byteLength < 46) return;
    assert.equal(bytes.subarray(0, 8).toString("utf8"), "GOATIPC1");
    const secret = bytes.subarray(8, 40);
    const headerLength = bytes.readUInt32BE(40);
    const credentialLength = bytes.readUInt16BE(44);
    const header = JSON.parse(
      bytes.subarray(46, 46 + headerLength).toString("utf8"),
    ) as { [key: string]: unknown };
    const attestationLength =
      header.message_type === "session_start"
        ? (header.attestation_length as number | undefined) ?? 0
        : 0;
    const frameLength =
      6 + headerLength + credentialLength + attestationLength + 32;
    if (bytes.byteLength < 40 + frameLength) return;

    const frame = bytes.subarray(40, 40 + frameLength);
    const authenticated = frame.subarray(0, frameLength - 32);
    const receivedTag = frame.subarray(frameLength - 32);
    const expectedTag = createHmac("sha256", secret)
      .update(REQUEST_DOMAIN)
      .update(authenticated)
      .digest();
    assert.equal(timingSafeEqual(receivedTag, expectedTag), true);
    const credentialEnd = 6 + headerLength + credentialLength;
    const credential = Uint8Array.from(
      frame.subarray(6 + headerLength, credentialEnd),
    );
    const attestation = Uint8Array.from(
      frame.subarray(credentialEnd, credentialEnd + attestationLength),
    );
    observed.push({ header, credential, attestation });

    const response = encodeAck(
      secret,
      header.session_id as string,
      header.sequence as number,
    );
    child.fromEngine.write(response, () => {
      setTimeout(() => child.emit("exit", 0, null), 5);
    });
    bytes = bytes.subarray(40 + frameLength);
  });
}

function encodeAck(
  secret: Uint8Array,
  sessionId: string,
  sequence: number,
): Buffer {
  const header = Buffer.from(
    JSON.stringify({
      protocol_version: 1,
      message_type: "session_ack",
      session_id: sessionId,
      sequence,
      status: "accepted",
    }),
  );
  const prefix = Buffer.alloc(6);
  prefix.writeUInt32BE(header.byteLength, 0);
  const authenticated = Buffer.concat([prefix, header]);
  const tag = createHmac("sha256", secret)
    .update(RESPONSE_DOMAIN)
    .update(authenticated)
    .digest();
  return Buffer.concat([authenticated, tag]);
}
