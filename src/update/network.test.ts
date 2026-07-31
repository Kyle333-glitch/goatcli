import assert from "node:assert/strict";
import test from "node:test";
import { MockManifestServer } from "../../test/v0.4.0-update/mock-manifest-server.js";
import { UpdateError } from "./errors.js";
import { FixedOriginTransport, type NetworkLimits } from "./network.js";

// Keep ordinary integration requests tolerant of loaded hosted runners. Tests
// that exercise deadline behavior override these values explicitly below.
const SMALL_LIMITS: NetworkLimits = {
  headerTimeoutMs: 1_000,
  idleTimeoutMs: 1_000,
  totalTimeoutMs: 2_000,
  maxBytes: 1024,
};

test("production transport accepts only an exact credential-free HTTPS origin", () => {
  for (const origin of [
    "http://updates.example.test",
    "https://user:password@updates.example.test",
    "https://updates.example.test/path",
    "https://updates.example.test/?query=1",
  ]) {
    assert.throws(() => productionTransport(origin), isPolicyError);
  }
  assert.doesNotThrow(() =>
    productionTransport("https://updates.example.test"),
  );
});

test("everyRedirectClassIsRejected", async (context) => {
  const server = new MockManifestServer();
  for (const status of [301, 302, 303, 307, 308] as const) {
    server.redirect(`/redirect-${status}`, status, "/metadata/timestamp.json");
  }
  await server.listen();
  context.after(() => server.close());
  const transport = testTransport(server);
  for (const status of [301, 302, 303, 307, 308] as const) {
    await assert.rejects(
      transport.readResource(`/redirect-${status}`, SMALL_LIMITS),
      isUpdateError("GOAT_UPDATE_REDIRECT_REJECTED"),
    );
  }
  assert.equal(server.requests.length, 5);
});

test("transport sends only public fixed update identity headers", async (context) => {
  const server = new MockManifestServer();
  server.bytes("/metadata/timestamp.json", Buffer.from("{}"));
  await server.listen();
  context.after(() => server.close());
  const transport = testTransport(server);
  assert.equal(
    (
      await transport.readResource("/metadata/timestamp.json", SMALL_LIMITS)
    ).toString(),
    "{}",
  );
  const request = server.requests[0]!;
  assert.equal(request.method, "GET");
  assert.equal(request.headers["accept-encoding"], "identity");
  assert.equal(request.headers["user-agent"], "GOAT-update/0.4.0");
  assert.equal(request.headers["x-goat-channel"], "stable");
  assert.equal(request.headers["x-goat-platform"], "win32");
  assert.equal(request.headers["x-goat-architecture"], "x64");
  assert.equal(request.headers.authorization, undefined);
  assert.equal(request.headers.cookie, undefined);
});

test("non-identity encoding and oversized responses are rejected", async (context) => {
  const server = new MockManifestServer();
  server.bytes("/encoded", Buffer.from("compressed"), {
    headers: { "Content-Encoding": "gzip" },
  });
  server.bytes("/large", Buffer.alloc(32));
  await server.listen();
  context.after(() => server.close());
  const transport = testTransport(server);
  await assert.rejects(
    transport.readResource("/encoded", SMALL_LIMITS),
    isUpdateError("GOAT_UPDATE_NETWORK_POLICY"),
  );
  await assert.rejects(
    transport.readResource("/large", { ...SMALL_LIMITS, maxBytes: 8 }),
    isUpdateError("GOAT_UPDATE_DOWNLOAD_TOO_LARGE"),
  );
});

test("header deadline fires when headers are withheld", async (context) => {
  const server = new MockManifestServer();
  server.route("/slow-headers", async (_request, response) => {
    await new Promise((resolve) => setTimeout(resolve, 80));
    if (!response.destroyed) response.writeHead(200).end("late");
  });
  await server.listen();
  context.after(() => server.close());
  await assert.rejects(
    testTransport(server).readResource("/slow-headers", {
      ...SMALL_LIMITS,
      headerTimeoutMs: 20,
      totalTimeoutMs: 500,
      idleTimeoutMs: 500,
    }),
    isUpdateError("GOAT_UPDATE_NETWORK_TIMEOUT"),
  );
});

test("total-response deadline fires after headers are received", async (context) => {
  const server = new MockManifestServer();
  server.route("/slow-body", async (_request, response) => {
    response.writeHead(200, { "Content-Length": "8" });
    await new Promise((resolve) => setTimeout(resolve, 120));
    if (!response.destroyed) response.end("finished");
  });
  await server.listen();
  context.after(() => server.close());
  await assert.rejects(
    testTransport(server).readResource("/slow-body", {
      ...SMALL_LIMITS,
      headerTimeoutMs: 100,
      totalTimeoutMs: 80,
      idleTimeoutMs: 200,
    }),
    isUpdateError("GOAT_UPDATE_NETWORK_TIMEOUT"),
  );
});

test("idle-body deadline fires when response stalls between chunks", async (context) => {
  const server = new MockManifestServer();
  server.route("/stall-body", async (_request, response) => {
    response.writeHead(200);
    response.write("first");
    await new Promise((resolve) => setTimeout(resolve, 120));
    if (!response.destroyed) response.end("second");
  });
  await server.listen();
  context.after(() => server.close());
  await assert.rejects(
    testTransport(server).readResource("/stall-body", {
      ...SMALL_LIMITS,
      headerTimeoutMs: 100,
      totalTimeoutMs: 500,
      idleTimeoutMs: 40,
    }),
    isUpdateError("GOAT_UPDATE_NETWORK_TIMEOUT"),
  );
});

test("resource paths cannot escape or inject URL components", async () => {
  const transport = productionTransport("https://updates.example.test");
  for (const resourcePath of [
    "https://attacker.invalid/file",
    "/../file",
    "/metadata\\timestamp.json",
    "/metadata/file?redirect=1",
    "/metadata/file#fragment",
  ]) {
    await assert.rejects(
      transport.readResource(resourcePath, SMALL_LIMITS),
      isUpdateError("GOAT_UPDATE_NETWORK_POLICY"),
    );
  }
});

function productionTransport(origin: string): FixedOriginTransport {
  return new FixedOriginTransport({
    origin,
    launcherVersion: "0.4.0",
    channel: "stable",
    platform: "win32",
    architecture: "x64",
  });
}

function testTransport(server: MockManifestServer): FixedOriginTransport {
  return new FixedOriginTransport({
    origin: server.origin,
    launcherVersion: "0.4.0",
    channel: "stable",
    platform: "win32",
    architecture: "x64",
    agent: server.agent,
  });
}

function isPolicyError(error: unknown): boolean {
  return (
    error instanceof UpdateError && error.code === "GOAT_UPDATE_NETWORK_POLICY"
  );
}

function isUpdateError(code: UpdateError["code"]): (error: unknown) => boolean {
  return (error) => error instanceof UpdateError && error.code === code;
}
