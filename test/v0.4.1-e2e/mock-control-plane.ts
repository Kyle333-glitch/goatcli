import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";

const ACCESS_TOKEN = "A".repeat(43);
const REFRESH_TOKEN = "R".repeat(43);
const ROTATED_REFRESH_TOKEN = "N".repeat(43);
const EXPIRES_AT = "2030-01-01T00:00:00.000Z";
const USER_CODE = "ABCD-EFGH";
const DEVICE_CODE = "D".repeat(43);
const MAX_REQUEST_BYTES = 16 * 1024;

export interface MockControlPlaneRequest {
  readonly method: string;
  readonly path: string;
}

export class MockControlPlaneServer {
  readonly requests: MockControlPlaneRequest[] = [];
  validDeviceTokenRequests = 0;
  validRefreshRequests = 0;
  validInferenceRequests = 0;
  validInferenceBodies = 0;
  private server: Server | undefined;
  private baseOrigin: string | undefined;

  async listen(): Promise<string> {
    if (this.server) throw new Error("mock control plane is already listening");
    this.server = createServer((request, response) => {
      void this.handle(request, response).catch(() => {
        if (
          !response.headersSent &&
          !response.destroyed &&
          !response.writableEnded
        ) {
          writeJson(response, 500, {
            error: { code: "internal_error", message: "Fixture failure" },
          });
        } else {
          response.destroy();
        }
      });
    });

    try {
      await new Promise<void>((resolve, reject) => {
        this.server!.once("error", reject);
        this.server!.listen(0, "127.0.0.1", () => {
          this.server!.removeListener("error", reject);
          resolve();
        });
      });
    } catch (error) {
      const server = this.server;
      this.server = undefined;
      this.baseOrigin = undefined;
      if (server) await closeServer(server);
      throw error;
    }

    const server = this.server;
    const address = server?.address();
    if (!server || !address || typeof address === "string") {
      if (server) {
        this.server = undefined;
        this.baseOrigin = undefined;
        await closeServer(server);
      }
      throw new Error("mock control plane did not bind a loopback port");
    }

    this.baseOrigin = `http://127.0.0.1:${address.port}`;
    return this.baseOrigin;
  }

  get origin(): string {
    if (!this.baseOrigin)
      throw new Error("mock control plane is not listening");
    return this.baseOrigin;
  }

  async close(): Promise<void> {
    const server = this.server;
    if (!server) return;
    await closeServer(server);
    if (this.server === server) {
      this.server = undefined;
      this.baseOrigin = undefined;
    }
  }

  private async handle(
    request: IncomingMessage,
    response: ServerResponse,
  ): Promise<void> {
    const origin = this.origin;
    const url = new URL(request.url ?? "/", origin);
    this.requests.push({ method: request.method ?? "", path: url.pathname });
    const requestResult = await readRequestBody(request);
    const requestBody = requestResult.body;

    try {
      if (!requestResult.valid) {
        if (response.destroyed || response.writableEnded) return;
        writeJson(response, 400, {
          error: {
            code: "invalid_request",
            message: "Invalid fixture request",
          },
        });
        return;
      }
      await this.handleValidRequest(
        request,
        response,
        url,
        requestBody,
        origin,
      );
    } finally {
      requestBody.fill(0);
    }
  }

  private async handleValidRequest(
    request: IncomingMessage,
    response: ServerResponse,
    url: URL,
    body: Buffer,
    origin: string,
  ): Promise<void> {
    if (await this.handleDeviceSession(request, response, url, body, origin))
      return;
    if (await this.handleDeviceToken(request, response, url, body)) return;
    if (await this.handleRefresh(request, response, url, body)) return;
    if (await this.handleInference(request, response, url, body)) return;
    if (request.method === "GET" && url.pathname === "/v1/usage/summary") {
      writeJson(response, 403, {
        error: { code: "quota_exceeded", message: "Quota allowance exceeded" },
      });
      return;
    }
    writeJson(response, 404, {
      error: { code: "not_found", message: "Not found" },
    });
  }

  private async handleDeviceSession(
    request: IncomingMessage,
    response: ServerResponse,
    url: URL,
    body: Buffer,
    origin: string,
  ): Promise<boolean> {
    if (
      request.method !== "POST" ||
      url.pathname !== "/v1/auth/device/sessions"
    )
      return false;
    if (body.byteLength !== 0) {
      writeJson(response, 400, {
        error: {
          code: "invalid_request",
          message: "Device session requests must not include a body",
        },
      });
      return true;
    }
    writeJson(response, 201, {
      verificationUrl: `${origin}/auth/device`,
      userCode: USER_CODE,
      deviceCode: DEVICE_CODE,
      intervalSeconds: 1,
      expiresAt: EXPIRES_AT,
      expiresInSeconds: 600,
    });
    return true;
  }

  private async handleDeviceToken(
    request: IncomingMessage,
    response: ServerResponse,
    url: URL,
    body: Buffer,
  ): Promise<boolean> {
    if (request.method !== "POST" || url.pathname !== "/v1/auth/device/token")
      return false;
    if (!requestBodyMatches(body, `{"deviceCode":"${DEVICE_CODE}"}`)) {
      writeJson(response, 400, {
        error: { code: "invalid_device_code", message: "Invalid device code" },
      });
      return true;
    }
    this.validDeviceTokenRequests += 1;
    writeJson(response, 200, {
      accessToken: ACCESS_TOKEN,
      refreshToken: REFRESH_TOKEN,
      tokenType: "Bearer",
      accessTokenExpiresAt: EXPIRES_AT,
      refreshTokenExpiresAt: EXPIRES_AT,
    });
    return true;
  }

  private async handleRefresh(
    request: IncomingMessage,
    response: ServerResponse,
    url: URL,
    body: Buffer,
  ): Promise<boolean> {
    if (request.method !== "POST" || url.pathname !== "/v1/auth/tokens/refresh")
      return false;
    if (!requestBodyMatches(body, `{"refreshToken":"${REFRESH_TOKEN}"}`)) {
      writeJson(response, 401, {
        error: {
          code: "invalid_refresh_token",
          message: "Invalid refresh token",
        },
      });
      return true;
    }
    this.validRefreshRequests += 1;
    writeJson(response, 200, {
      accessToken: ACCESS_TOKEN,
      refreshToken: ROTATED_REFRESH_TOKEN,
      tokenType: "Bearer",
      accessTokenExpiresAt: EXPIRES_AT,
      refreshTokenExpiresAt: EXPIRES_AT,
    });
    return true;
  }

  private async handleInference(
    request: IncomingMessage,
    response: ServerResponse,
    url: URL,
    body: Buffer,
  ): Promise<boolean> {
    if (request.method !== "POST" || url.pathname !== "/v1/inference/stream")
      return false;
    if (request.headers.authorization !== `Bearer ${ACCESS_TOKEN}`) {
      writeJson(response, 401, {
        error: { code: "unauthorized", message: "Invalid access token" },
      });
      return true;
    }
    if (!requestBodyMatches(body, "{}")) {
      writeJson(response, 400, {
        error: {
          code: "invalid_request",
          message: "Invalid inference request",
        },
      });
      return true;
    }
    this.validInferenceRequests += 1;
    this.validInferenceBodies += 1;
    writeJson(response, 403, {
      error: { code: "quota_exceeded", message: "Quota allowance exceeded" },
    });
    return true;
  }
}

export function mockCredentialSet(): {
  accessToken: string;
  refreshToken: string;
  tokenType: "Bearer";
  accessTokenExpiresAt: string;
  refreshTokenExpiresAt: string;
} {
  return {
    accessToken: ACCESS_TOKEN,
    refreshToken: REFRESH_TOKEN,
    tokenType: "Bearer",
    accessTokenExpiresAt: EXPIRES_AT,
    refreshTokenExpiresAt: EXPIRES_AT,
  };
}

function writeJson(
  response: ServerResponse,
  status: number,
  body: unknown,
): void {
  if (response.destroyed || response.writableEnded) return;
  const bytes = Buffer.from(JSON.stringify(body), "utf8");
  response.writeHead(status, {
    "Content-Type": "application/json",
    "Content-Length": String(bytes.byteLength),
  });
  response.end(bytes, () => bytes.fill(0));
}

async function readRequestBody(
  request: IncomingMessage,
): Promise<{ body: Buffer; valid: boolean }> {
  const chunks: Buffer[] = [];
  let size = 0;
  let valid = true;
  try {
    for await (const chunk of request) {
      if (!valid) continue;
      const copy = Buffer.from(chunk);
      size += copy.byteLength;
      if (size > MAX_REQUEST_BYTES) {
        copy.fill(0);
        valid = false;
        continue;
      }
      chunks.push(copy);
    }
    return {
      body: valid ? Buffer.concat(chunks, size) : Buffer.alloc(0),
      valid,
    };
  } catch {
    return { body: Buffer.alloc(0), valid: false };
  } finally {
    for (const chunk of chunks) chunk.fill(0);
  }
}

function requestBodyMatches(body: Buffer, expected: string): boolean {
  const expectedBytes = Buffer.from(expected, "utf8");
  try {
    return body.equals(expectedBytes);
  } finally {
    expectedBytes.fill(0);
  }
}

async function closeServer(server: Server): Promise<void> {
  if (!server.listening) return;
  server.closeAllConnections();
  await new Promise<void>((resolve, reject) => {
    server.close((error) => {
      if (
        !error ||
        (error as NodeJS.ErrnoException).code === "ERR_SERVER_NOT_RUNNING"
      )
        resolve();
      else reject(error);
    });
  });
}
