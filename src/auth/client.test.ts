import assert from "node:assert/strict";
import {
  createServer,
  type IncomingMessage,
  type ServerResponse,
} from "node:http";
import { test } from "node:test";
import { createBrowserOpener } from "./browser.js";
import {
  ControlPlaneClientError,
  canonicalDeviceAuthorizationUrl,
  createAuthApiClient,
  resolveControlPlaneUrl,
} from "./client.js";

const DEVICE_CODE = "D".repeat(43);
const ACCESS_TOKEN = "A".repeat(43);
const REFRESH_TOKEN = "R".repeat(43);
const NOW = "2026-07-17T12:00:00.000Z";
const LATER = "2026-07-17T13:00:00.000Z";

interface RecordedRequest {
  method: string;
  url: string;
  headers: IncomingMessage["headers"];
  body: string;
}

test("production origin is fail-closed and development injection is loopback-only", () => {
  assert.throws(
    () =>
      resolveControlPlaneUrl({
        GOAT_CONTROL_PLANE_URL: "https://ENV_SECRET_9DK1.invalid",
      }),
    hasClientCode("control_plane_unavailable"),
  );
  assert.equal(
    resolveControlPlaneUrl({}, { developmentOrigin: "http://127.0.0.1:4040" })
      .origin,
    "http://127.0.0.1:4040",
  );

  for (const origin of [
    "http://control.example.com",
    "https://control.example.com",
    "http://127.0.0.1:4040/path",
    "http://127.0.0.1:4040?query=PATH_SECRET_3HT6",
    "http://user@127.0.0.1:4040",
    "file:///tmp/control-plane",
  ]) {
    assert.throws(
      () => resolveControlPlaneUrl({}, { developmentOrigin: origin }),
      hasClientCode("control_plane_unavailable"),
    );
  }
});

test("sends only the six fixed essential auth and usage request shapes", async () => {
  const captured: RecordedRequest[] = [];
  await withServer(
    async (request, response, origin) => {
      captured.push(await record(request));
      response.setHeader("content-type", "application/json");
      switch (request.url) {
        case "/v1/auth/device/sessions":
          response.statusCode = 201;
          response.end(JSON.stringify(deviceSession(origin)));
          return;
        case "/v1/auth/device/token":
        case "/v1/auth/tokens/refresh":
          response.statusCode = 200;
          response.end(JSON.stringify(credentials()));
          return;
        case "/v1/auth/device/cancel":
        case "/v1/auth/tokens/revoke":
          response.statusCode = 200;
          response.end(JSON.stringify({ ok: true }));
          return;
        case "/v1/usage/summary":
          response.statusCode = 200;
          response.end(JSON.stringify(usageSummary()));
          return;
        default:
          response.statusCode = 404;
          response.end(
            JSON.stringify({
              error: { code: "not_found", message: "not found" },
            }),
          );
      }
    },
    async (origin) => {
      const client = createAuthApiClient(origin);
      await client.createDeviceSession();
      assert.equal(
        (await client.pollDeviceToken(DEVICE_CODE)).status,
        "authorized",
      );
      await client.cancelDeviceSession(DEVICE_CODE);
      assert.equal((await client.refresh(REFRESH_TOKEN)).status, "authorized");
      await client.revoke(REFRESH_TOKEN);
      const usage = await client.getUsageSummary(ACCESS_TOKEN);
      assert.equal(usage.status, "ok");
      if (usage.status === "ok") {
        assert.equal(usage.summary.version, "v0.3.2");
        assert.deepEqual(usage.summary.account, {
          status: "active",
        });
        const sanitized = JSON.stringify(usage.summary);
        assert.equal(sanitized.includes("PROMPT_SECRET_7QX9"), false);
        assert.equal(sanitized.includes("SOURCE_CODE_SECRET_4JK2"), false);
        assert.equal(sanitized.includes("PATH_SECRET_3HT6"), false);
      }
    },
  );

  assert.deepEqual(
    captured.map((request) => [request.method, request.url]),
    [
      ["POST", "/v1/auth/device/sessions"],
      ["POST", "/v1/auth/device/token"],
      ["POST", "/v1/auth/device/cancel"],
      ["POST", "/v1/auth/tokens/refresh"],
      ["POST", "/v1/auth/tokens/revoke"],
      ["GET", "/v1/usage/summary"],
    ],
  );
  assert.deepEqual(
    captured.map((request) => request.body),
    [
      "",
      JSON.stringify({ deviceCode: DEVICE_CODE }),
      JSON.stringify({ deviceCode: DEVICE_CODE }),
      JSON.stringify({ refreshToken: REFRESH_TOKEN }),
      JSON.stringify({ refreshToken: REFRESH_TOKEN }),
      "",
    ],
  );
  for (const [index, request] of captured.entries()) {
    assert.equal(new URL(request.url, "http://loopback").search, "");
    const expectedHeaders = [
      "accept",
      "connection",
      "host",
      "user-agent",
      ...(index >= 1 && index <= 4 ? ["content-length", "content-type"] : []),
      ...(index === 0 ? ["content-length"] : []),
      ...(index === 5 ? ["authorization"] : []),
    ].sort();
    assert.deepEqual(Object.keys(request.headers).sort(), expectedHeaders);
    assert.equal(request.headers.accept, "application/json");
    assert.equal(request.headers.connection, "close");
    assert.match(request.headers.host ?? "", /^127\.0\.0\.1:\d+$/);
    assert.equal(
      request.headers["user-agent"],
      index === 5 ? "GOAT-usage/1" : "GOAT-auth/1",
    );
    if (index === 0) {
      assert.equal(request.headers["content-length"], "0");
    } else if (index >= 1 && index <= 4) {
      assert.equal(
        request.headers["content-length"],
        String(Buffer.byteLength(request.body)),
      );
      assert.equal(request.headers["content-type"], "application/json");
    }
    if (index === 5) {
      assert.equal(request.headers.authorization, `Bearer ${ACCESS_TOKEN}`);
      assert.equal(request.headers["content-type"], undefined);
    } else {
      assert.equal(request.headers.authorization, undefined);
    }
  }

  const outbound = JSON.stringify(captured);
  for (const canary of [
    "PROMPT_SECRET_7QX9",
    "SOURCE_CODE_SECRET_4JK2",
    "TOKEN_SECRET_8MVP",
    "PATH_SECRET_3HT6",
    "ENV_SECRET_9DK1",
  ]) {
    assert.equal(outbound.includes(canary), false);
  }
});

test("provisions a per-device attestation credential through the bounded request shape", async () => {
  const captured: RecordedRequest[] = [];
  const DEVICE_ID = "123e4567-e89b-12d3-a456-426614174000";
  const DEVICE_SECRET = "s".repeat(43);
  await withServer(
    async (request, response, origin) => {
      captured.push(await record(request));
      response.statusCode = 200;
      response.setHeader("content-type", "application/json");
      if (
        request.url === "/v1/auth/device/credentials" &&
        request.headers.authorization === `Bearer ${ACCESS_TOKEN}`
      ) {
        response.end(
          JSON.stringify({ deviceId: DEVICE_ID, deviceSecret: DEVICE_SECRET }),
        );
      } else {
        response.statusCode = 404;
        response.end(JSON.stringify({ error: { code: "not_found" } }));
      }
    },
    async (origin) => {
      const client = createAuthApiClient(origin);
      const provisioned = await client.provisionDeviceCredential!(
        ACCESS_TOKEN,
        DEVICE_ID,
        "goatcli",
      );
      assert.deepEqual(provisioned, {
        deviceId: DEVICE_ID,
        deviceSecret: DEVICE_SECRET,
      });
    },
  );

  assert.equal(captured.length, 1);
  const request = captured[0]!;
  assert.equal(request.method, "POST");
  assert.equal(request.url, "/v1/auth/device/credentials");
  assert.equal(request.headers.authorization, `Bearer ${ACCESS_TOKEN}`);
  assert.equal(request.headers["user-agent"], "GOAT-auth/1");
  assert.equal(request.headers.accept, "application/json");
  assert.equal(request.headers["content-type"], "application/json");
  assert.deepEqual(JSON.parse(request.body), {
    deviceId: DEVICE_ID,
    label: "goatcli",
  });
  assert.equal(new URL(request.url, "http://loopback").search, "");
  const outbound = JSON.stringify(captured);
  for (const canary of [
    "PROMPT_SECRET_7QX9",
    "SOURCE_CODE_SECRET_4JK2",
    "PATH_SECRET_3HT6",
    "ENV_SECRET_9DK1",
  ]) {
    assert.equal(outbound.includes(canary), false);
  }
});

test("provisionDeviceCredential validates inputs and responses before returning", async () => {
  const DEVICE_ID = "123e4567-e89b-12d3-a456-426614174000";
  const DEVICE_SECRET = "s".repeat(43);
  // Invalid device id or access token is rejected before any request is sent.
  let requests = 0;
  await withServer(
    async (_request, response) => {
      requests += 1;
      response.end();
    },
    async (origin) => {
      const client = createAuthApiClient(origin);
      await assert.rejects(
        () => client.provisionDeviceCredential!("TOKEN_SECRET_8MVP", DEVICE_ID),
        hasClientCode("invalid_auth_data"),
      );
      await assert.rejects(
        () => client.provisionDeviceCredential!(ACCESS_TOKEN, "not-a-uuid"),
        hasClientCode("invalid_auth_data"),
      );
    },
  );
  assert.equal(requests, 0);

  // A mismatched device id, missing secret, or unknown key is rejected.
  for (const body of [
    { deviceId: "other", deviceSecret: DEVICE_SECRET },
    { deviceId: DEVICE_ID },
    {
      deviceId: DEVICE_ID,
      deviceSecret: DEVICE_SECRET,
      extra: "ENV_SECRET_9DK1",
    },
    { deviceId: DEVICE_ID, deviceSecret: "not-a-token" },
  ]) {
    await withServer(
      async (_request, response) => {
        response.statusCode = 200;
        response.setHeader("content-type", "application/json");
        response.end(JSON.stringify(body));
      },
      async (origin) => {
        await assert.rejects(
          () =>
            createAuthApiClient(origin).provisionDeviceCredential!(
              ACCESS_TOKEN,
              DEVICE_ID,
            ),
          hasClientCode("unexpected_response"),
        );
      },
    );
  }
});

test("validates token formats before any network transmission", async () => {
  let requests = 0;
  await withServer(
    async (_request, response) => {
      requests += 1;
      response.end();
    },
    async (origin) => {
      const client = createAuthApiClient(origin);
      assert.equal(
        (await client.pollDeviceToken("TOKEN_SECRET_8MVP")).status,
        "invalid_grant",
      );
      assert.equal(
        (await client.refresh("TOKEN_SECRET_8MVP")).status,
        "invalid_grant",
      );
      assert.equal(
        (await client.getUsageSummary("TOKEN_SECRET_8MVP")).status,
        "unauthorized",
      );
      await assert.rejects(
        () => client.cancelDeviceSession("TOKEN_SECRET_8MVP"),
        hasClientCode("invalid_auth_data"),
      );
      await assert.rejects(
        () => client.revoke("TOKEN_SECRET_8MVP"),
        hasClientCode("invalid_auth_data"),
      );
    },
  );
  assert.equal(requests, 0);
});

test("strictly rejects unknown response keys and noncanonical browser URLs", async () => {
  await withServer(
    async (request, response, origin) => {
      response.statusCode = 201;
      response.setHeader("content-type", "application/json");
      response.end(
        JSON.stringify({
          ...deviceSession(origin),
          arbitrary: "SOURCE_CODE_SECRET_4JK2",
        }),
      );
    },
    async (origin) => {
      await assert.rejects(
        () => createAuthApiClient(origin).createDeviceSession(),
        hasClientCode("unexpected_response"),
      );
    },
  );

  const calls: Array<{ command: string; args: readonly string[] }> = [];
  const origin = new URL("http://127.0.0.1:4040");
  const opener = createBrowserOpener(
    "win32",
    (command, args) => {
      calls.push({ command, args });
      return { unref() {} };
    },
    origin,
  );
  assert.equal(
    await opener.open(canonicalDeviceAuthorizationUrl(origin)),
    true,
  );
  // A well-formed user-code pre-fill is opened (the code is not secret).
  assert.equal(
    await opener.open(
      `${canonicalDeviceAuthorizationUrl(origin)}?code=ABCD-EFGH`,
    ),
    true,
  );
  // Arbitrary or malformed query parameters are never opened.
  assert.equal(
    await opener.open(
      `${canonicalDeviceAuthorizationUrl(origin)}?code=PROMPT_SECRET_7QX9`,
    ),
    false,
  );
  assert.equal(
    await opener.open(
      `${canonicalDeviceAuthorizationUrl(origin)}?code=ABCD-EFGH&extra=1`,
    ),
    false,
  );
  assert.deepEqual(
    calls.map((call) => call.args),
    [
      ["http://127.0.0.1:4040/auth/device"],
      ["http://127.0.0.1:4040/auth/device?code=ABCD-EFGH"],
    ],
  );

  const hostileEnvironmentCalls: Array<{
    command: string;
    args: readonly string[];
  }> = [];
  const hostileEnvironmentOpener = createBrowserOpener(
    "win32",
    (command, args) => {
      hostileEnvironmentCalls.push({ command, args });
      return { unref() {} };
    },
    origin,
    "C:\\ENV_SECRET_9DK1\\PATH_SECRET_3HT6",
  );
  assert.equal(
    await hostileEnvironmentOpener.open(
      canonicalDeviceAuthorizationUrl(origin),
    ),
    true,
  );
  assert.deepEqual(hostileEnvironmentCalls, [
    {
      command: "C:\\Windows\\explorer.exe",
      args: ["http://127.0.0.1:4040/auth/device"],
    },
  ]);
  assert.equal(
    JSON.stringify(hostileEnvironmentCalls).includes("ENV_SECRET_9DK1"),
    false,
  );
  assert.equal(
    JSON.stringify(hostileEnvironmentCalls).includes("PATH_SECRET_3HT6"),
    false,
  );
});

test("strictly rejects usage PII, generic bags, and arbitrary nested objects", async () => {
  const invalidUsageBodies = [
    { ...usageSummary(), requestId: "PATH_SECRET_3HT6" },
    {
      ...usageSummary(),
      account: {
        ...usageSummary().account,
        displayName: "PROMPT_SECRET_7QX9",
      },
    },
    {
      ...usageSummary(),
      account: {
        ...usageSummary().account,
        email: "SOURCE_CODE_SECRET_4JK2@example.invalid",
      },
    },
    { ...usageSummary(), metadata: { arbitrary: "ENV_SECRET_9DK1" } },
    {
      ...usageSummary(),
      quota: {
        ...usageSummary().quota,
        allowanceMicrousd: "TOKEN_SECRET_8MVP",
      },
    },
  ];

  for (const body of invalidUsageBodies) {
    await withServer(
      async (_request, response) => {
        response.statusCode = 200;
        response.setHeader("content-type", "application/json");
        response.end(JSON.stringify(body));
      },
      async (origin) => {
        const result =
          await createAuthApiClient(origin).getUsageSummary(ACCESS_TOKEN);
        assert.deepEqual(result, {
          status: "unexpected_response",
          message: "GOAT control plane returned an unexpected response.",
        });
        const rendered = JSON.stringify(result);
        for (const canary of [
          "PROMPT_SECRET_7QX9",
          "SOURCE_CODE_SECRET_4JK2",
          "TOKEN_SECRET_8MVP",
          "PATH_SECRET_3HT6",
          "ENV_SECRET_9DK1",
        ]) {
          assert.equal(rendered.includes(canary), false);
        }
      },
    );
  }
});

test("rejects redirects, cookies, and responses larger than 16 KiB", async () => {
  for (const responseKind of ["redirect", "cookie", "large"] as const) {
    await withServer(
      async (_request, response) => {
        response.setHeader("content-type", "application/json");
        if (responseKind === "redirect") {
          response.statusCode = 302;
          response.setHeader("location", "/elsewhere");
          response.end("{}");
        } else if (responseKind === "cookie") {
          response.statusCode = 201;
          response.setHeader("set-cookie", "session=forbidden");
          response.end("{}");
        } else {
          response.statusCode = 201;
          response.setHeader("content-length", String(16 * 1024 + 1));
          response.end("x".repeat(16 * 1024 + 1));
        }
      },
      async (origin) => {
        await assert.rejects(
          () => createAuthApiClient(origin).createDeviceSession(),
          (error) =>
            error instanceof ControlPlaneClientError &&
            (error.code === "unexpected_response" ||
              error.code === "response_too_large"),
        );
      },
    );
  }
});

test("enforces the five-second total request deadline with a fixed error", async () => {
  await withServer(
    async () => {
      // Deliberately leave the response incomplete; the client owns the deadline.
    },
    async (origin) => {
      const startedAt = Date.now();
      await assert.rejects(
        () => createAuthApiClient(origin).createDeviceSession(),
        hasClientCode("request_timeout"),
      );
      const elapsed = Date.now() - startedAt;
      assert.ok(
        elapsed >= 4_500 && elapsed < 7_000,
        `unexpected deadline: ${elapsed}`,
      );
    },
  );
});

async function withServer(
  handler: (
    request: IncomingMessage,
    response: ServerResponse,
    origin: URL,
  ) => Promise<void>,
  run: (origin: URL) => Promise<void>,
): Promise<void> {
  let origin!: URL;
  const server = createServer((request, response) => {
    void handler(request, response, origin).catch(() => {
      response.destroy();
    });
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  assert.ok(address && typeof address === "object");
  origin = new URL(`http://127.0.0.1:${address.port}`);
  try {
    await run(origin);
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

async function record(request: IncomingMessage): Promise<RecordedRequest> {
  const chunks: Buffer[] = [];
  for await (const chunk of request) chunks.push(Buffer.from(chunk));
  return {
    method: request.method ?? "",
    url: request.url ?? "",
    headers: request.headers,
    body: Buffer.concat(chunks).toString("utf8"),
  };
}

function deviceSession(origin: URL) {
  return {
    verificationUrl: canonicalDeviceAuthorizationUrl(origin),
    userCode: "ABCD-EFGH",
    deviceCode: DEVICE_CODE,
    intervalSeconds: 2,
    expiresAt: LATER,
    expiresInSeconds: 600,
  };
}

function credentials() {
  return {
    accessToken: ACCESS_TOKEN,
    refreshToken: REFRESH_TOKEN,
    tokenType: "Bearer",
    accessTokenExpiresAt: LATER,
    refreshTokenExpiresAt: "2026-07-18T12:00:00.000Z",
  };
}

function usageSummary() {
  return {
    version: "v0.3.2",
    generatedAt: NOW,
    account: {
      status: "active",
    },
    quota: {
      usedPercent: 0,
      committedPercent: 0,
      remainingPercent: 99,
      lowQuota: false,
    },
    window: {
      kind: "rolling",
      seconds: 86400,
      startedAt: NOW,
      nextUsageExpiresAt: LATER,
    },
  };
}

function hasClientCode(
  code: ControlPlaneClientError["code"],
): (error: unknown) => boolean {
  return (error) =>
    error instanceof ControlPlaneClientError && error.code === code;
}
