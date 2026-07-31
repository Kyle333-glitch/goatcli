/** TEST-ONLY loopback manifest/artifact server. */
import { readFileSync } from "node:fs";
import type { IncomingMessage, ServerResponse } from "node:http";
import https, { type Server } from "node:https";

const TEST_ONLY_CERTIFICATE = readFileSync(
  new URL("./fixtures/localhost-cert.pem", import.meta.url),
);
const TEST_ONLY_PRIVATE_KEY = readFileSync(
  new URL("./fixtures/localhost-key.pem", import.meta.url),
);

export type MockRoute = (
  request: IncomingMessage,
  response: ServerResponse,
) => void | Promise<void>;

export interface RecordedMockRequest {
  readonly method: string;
  readonly url: string;
  readonly headers: Readonly<Record<string, string | string[] | undefined>>;
}

export class MockManifestServer {
  readonly requests: RecordedMockRequest[] = [];
  readonly agent = new https.Agent({
    ca: TEST_ONLY_CERTIFICATE,
    keepAlive: false,
    rejectUnauthorized: true,
  });
  private readonly routes = new Map<string, MockRoute>();
  private server: Server | undefined;
  private baseOrigin: string | undefined;

  route(pathname: string, route: MockRoute): void {
    if (!pathname.startsWith("/") || this.routes.has(pathname)) {
      throw new Error("test route must be a unique absolute path");
    }
    this.routes.set(pathname, route);
  }

  bytes(
    pathname: string,
    body: Uint8Array,
    options: {
      readonly status?: number;
      readonly headers?: Readonly<Record<string, string>>;
    } = {},
  ): void {
    this.route(pathname, (_request, response) => {
      response.writeHead(options.status ?? 200, {
        "Content-Length": String(body.byteLength),
        ...options.headers,
      });
      response.end(body);
    });
  }

  interrupted(
    pathname: string,
    body: Uint8Array,
    bytesBeforeClose: number,
  ): void {
    this.route(pathname, (_request, response) => {
      response.writeHead(200, { "Content-Length": String(body.byteLength) });
      response.write(body.subarray(0, bytesBeforeClose));
      response.socket?.destroy();
    });
  }

  redirect(
    pathname: string,
    status: 301 | 302 | 303 | 307 | 308,
    location: string,
  ): void {
    this.route(pathname, (_request, response) => {
      response.writeHead(status, { Location: location });
      response.end();
    });
  }

  async listen(): Promise<string> {
    if (this.server) throw new Error("test server is already listening");
    this.server = https.createServer(
      {
        cert: TEST_ONLY_CERTIFICATE,
        key: TEST_ONLY_PRIVATE_KEY,
        minVersion: "TLSv1.2",
      },
      (request, response) => {
        const pathname = new URL(request.url ?? "/", "https://localhost")
          .pathname;
        this.requests.push({
          method: request.method ?? "",
          url: request.url ?? "",
          headers: { ...request.headers },
        });
        const route = this.routes.get(pathname);
        if (!route) {
          response.writeHead(404).end();
          return;
        }
        Promise.resolve(route(request, response)).catch(() => {
          response.destroy();
        });
      },
    );
    await new Promise<void>((resolve, reject) => {
      this.server!.once("error", reject);
      this.server!.listen(0, "127.0.0.1", () => {
        this.server!.removeListener("error", reject);
        resolve();
      });
    });
    const address = this.server.address();
    if (!address || typeof address === "string") {
      throw new Error("test server did not bind an IP port");
    }
    this.baseOrigin = `https://127.0.0.1:${address.port}`;
    return this.baseOrigin;
  }

  get origin(): string {
    if (!this.baseOrigin) throw new Error("test server is not listening");
    return this.baseOrigin;
  }

  async close(): Promise<void> {
    if (!this.server) return;
    const current = this.server;
    this.server = undefined;
    this.baseOrigin = undefined;
    this.agent.destroy();
    await new Promise<void>((resolve, reject) =>
      current.close((error) => (error ? reject(error) : resolve())),
    );
  }
}
