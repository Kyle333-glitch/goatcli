import assert from "node:assert/strict";
import test from "node:test";
import { MockManifestServer } from "../../test/v0.4.0-update/mock-manifest-server.js";
import { createTestTufFixture } from "../../test/v0.4.0-update/tuf-fixture.js";
import { UpdateError } from "./errors.js";
import { fetchUpdateMetadata } from "./metadata-client.js";
import { FixedOriginTransport } from "./network.js";

test("metadata client uses only fixed TUF paths and bounded root discovery", async (context) => {
  const fixture = createTestTufFixture();
  const server = new MockManifestServer();
  server.bytes("/metadata/timestamp.json", fixture.timestamp);
  server.bytes("/metadata/snapshot.json", fixture.snapshot);
  server.bytes("/metadata/targets.json", fixture.targets);
  server.bytes("/metadata/stable.json", fixture.channels.stable);
  await server.listen();
  context.after(() => server.close());

  const result = await fetchUpdateMetadata(
    testTransport(server),
    fixture.root,
    "stable",
  );

  assert.equal(result.sequentialRoots.length, 0);
  assert.deepEqual(result.timestamp, fixture.timestamp);
  assert.deepEqual(
    server.requests.map((request) => request.url),
    [
      "/metadata/2.root.json",
      "/metadata/timestamp.json",
      "/metadata/snapshot.json",
      "/metadata/targets.json",
      "/metadata/stable.json",
    ],
  );
});

test("transient metadata failures retry once but ordinary 4xx does not", async (context) => {
  const fixture = createTestTufFixture();
  const server = new MockManifestServer();
  let timestampAttempts = 0;
  server.route("/metadata/timestamp.json", (_request, response) => {
    timestampAttempts += 1;
    if (timestampAttempts === 1) {
      response.writeHead(503).end();
      return;
    }
    response
      .writeHead(200, { "Content-Length": String(fixture.timestamp.length) })
      .end(fixture.timestamp);
  });
  server.bytes("/metadata/snapshot.json", fixture.snapshot);
  server.bytes("/metadata/targets.json", fixture.targets);
  server.bytes("/metadata/stable.json", fixture.channels.stable);
  await server.listen();
  context.after(() => server.close());

  await fetchUpdateMetadata(testTransport(server), fixture.root, "stable", {
    waitBeforeRetry: async () => undefined,
  });
  assert.equal(timestampAttempts, 2);

  await assert.rejects(
    fetchUpdateMetadata(testTransport(server), fixture.root, "beta", {
      waitBeforeRetry: async () => undefined,
    }),
    isUpdateError("GOAT_UPDATE_NETWORK_FAILED"),
  );
  assert.equal(
    server.requests.filter((request) => request.url === "/metadata/beta.json")
      .length,
    1,
  );
});

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

function isUpdateError(code: UpdateError["code"]): (error: unknown) => boolean {
  return (error) => error instanceof UpdateError && error.code === code;
}
