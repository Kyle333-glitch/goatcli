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
          tier: "regular",
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
  assert.equal(
    await opener.open(
      `${canonicalDeviceAuthorizationUrl(origin)}?code=PROMPT_SECRET_7QX9`,
    ),
    false,
  );
  assert.deepEqual(
    calls.map((call) => call.args),
    [["http://127.0.0.1:4040/auth/device"]],
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
      recent: [...usageSummary().recent, { arbitrary: "TOKEN_SECRET_8MVP" }],
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
      tier: "regular",
      status: "active",
    },
    quota: {
      allowanceMicrousd: "100000000",
      usedMicrousd: "1000",
      activeReservedMicrousd: "0",
      totalCommittedMicrousd: "1000",
      remainingMicrousd: "99999000",
      lowQuota: false,
      lowQuotaThresholdPercent: 20,
    },
    window: { seconds: 3600, startedAt: NOW, nextResetAt: LATER },
    usage: {
      regularMicrousd: "1000",
      premiumMicrousd: "0",
      totalMicrousd: "1000",
    },
    recent: [
      {
        label: "24h",
        windowSeconds: 86400,
        regularMicrousd: "1000",
        premiumMicrousd: "0",
        totalMicrousd: "1000",
      },
      {
        label: "7d",
        windowSeconds: 604800,
        regularMicrousd: "1000",
        premiumMicrousd: "0",
        totalMicrousd: "1000",
      },
    ],
  };
}

function hasClientCode(
  code: ControlPlaneClientError["code"],
): (error: unknown) => boolean {
  return (error) =>
    error instanceof ControlPlaneClientError && error.code === code;
}
