import type { IncomingMessage } from "node:http";
import https from "node:https";
import { UpdateError } from "./errors.js";
import type {
  UpdateArchitecture,
  UpdateChannel,
  UpdatePlatform,
} from "./schema.js";

export interface NetworkLimits {
  readonly headerTimeoutMs: number;
  readonly idleTimeoutMs: number;
  readonly totalTimeoutMs: number;
  readonly maxBytes: number;
}

export interface NetworkResponse {
  readonly body: IncomingMessage;
  readonly contentLength?: number;
}

export type HttpsAgent = https.Agent;

export interface FixedOriginTransportOptions {
  readonly origin: string;
  readonly launcherVersion: string;
  readonly channel: UpdateChannel;
  readonly platform: UpdatePlatform;
  readonly architecture: UpdateArchitecture;
  readonly agent?: HttpsAgent;
}

export const METADATA_NETWORK_LIMITS: NetworkLimits = {
  headerTimeoutMs: 10_000,
  idleTimeoutMs: 30_000,
  totalTimeoutMs: 30_000,
  maxBytes: 256 * 1024,
};

export const ARTIFACT_NETWORK_LIMITS: NetworkLimits = {
  headerTimeoutMs: 10_000,
  idleTimeoutMs: 30_000,
  totalTimeoutMs: 10 * 60_000,
  maxBytes: 512 * 1024 * 1024,
};

export class NetworkRequestError extends UpdateError {
  constructor(
    code: "GOAT_UPDATE_NETWORK_TIMEOUT" | "GOAT_UPDATE_NETWORK_FAILED",
    readonly retryable: boolean,
    options: { cause?: unknown; statusCode?: number } = {},
  ) {
    super(code, options);
    this.name = "NetworkRequestError";
    this.statusCode = options.statusCode;
  }

  readonly statusCode: number | undefined;
}

export class FixedOriginTransport {
  private readonly origin: URL;

  constructor(private readonly options: FixedOriginTransportOptions) {
    this.origin = validateOrigin(options);
  }

  async openResource(
    resourcePath: string,
    limits: NetworkLimits,
  ): Promise<NetworkResponse> {
    const url = resolveResourceUrl(this.origin, resourcePath);
    return new Promise<NetworkResponse>((resolve, reject) => {
      let settled = false;
      let responseReceived = false;
      const fail = (error: unknown): void => {
        if (settled) return;
        settled = true;
        reject(mapNetworkError(error));
      };
      const totalTimer = setTimeout(
        () =>
          request.destroy(
            new NetworkRequestError("GOAT_UPDATE_NETWORK_TIMEOUT", true),
          ),
        limits.totalTimeoutMs,
      );
      const headerTimer = setTimeout(
        () =>
          request.destroy(
            new NetworkRequestError("GOAT_UPDATE_NETWORK_TIMEOUT", true),
          ),
        limits.headerTimeoutMs,
      );

      const request = https.request(
        url,
        {
          method: "GET",
          agent: this.options.agent,
          headers: {
            Accept: "application/octet-stream",
            "Accept-Encoding": "identity",
            "User-Agent": `GOAT-update/${this.options.launcherVersion}`,
            "X-GOAT-Channel": this.options.channel,
            "X-GOAT-Platform": this.options.platform,
            "X-GOAT-Architecture": this.options.architecture,
            Connection: "close",
          },
          setHost: true,
        },
        (response) => {
          responseReceived = true;
          clearTimeout(headerTimer);
          try {
            validateResponse(response, limits.maxBytes);
          } catch (error) {
            clearTimeout(totalTimer);
            response.resume();
            fail(error);
            return;
          }

          let idleTimer = createIdleTimer(response, limits.idleTimeoutMs);
          const resetIdle = (): void => {
            clearTimeout(idleTimer);
            idleTimer = createIdleTimer(response, limits.idleTimeoutMs);
          };
          const cleanup = (): void => {
            clearTimeout(idleTimer);
            clearTimeout(totalTimer);
            response.removeListener("readable", resetIdle);
          };
          response.on("readable", resetIdle);
          response.once("end", cleanup);
          response.once("close", cleanup);
          response.once("error", cleanup);
          settled = true;
          resolve({
            body: response,
            contentLength: parseContentLength(
              response.headers["content-length"],
            ),
          });
        },
      );

      request.once("error", (error) => {
        clearTimeout(headerTimer);
        if (!responseReceived) clearTimeout(totalTimer);
        fail(error);
      });
      request.end();
    });
  }

  async readResource(
    resourcePath: string,
    limits: NetworkLimits,
  ): Promise<Buffer> {
    const response = await this.openResource(resourcePath, limits);
    const chunks: Buffer[] = [];
    let length = 0;
    try {
      for await (const chunk of response.body) {
        const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        length += bytes.byteLength;
        if (length > limits.maxBytes) {
          response.body.destroy();
          throw new UpdateError("GOAT_UPDATE_DOWNLOAD_TOO_LARGE");
        }
        chunks.push(bytes);
      }
    } catch (error) {
      throw mapNetworkError(error);
    }
    return Buffer.concat(chunks, length);
  }
}

export function isRetryableNetworkError(error: unknown): boolean {
  return error instanceof NetworkRequestError && error.retryable;
}

export function normalizeNetworkError(error: unknown): UpdateError {
  return mapNetworkError(error);
}

function validateOrigin(options: FixedOriginTransportOptions): URL {
  let origin: URL;
  try {
    origin = new URL(options.origin);
  } catch (error) {
    throw new UpdateError("GOAT_UPDATE_NETWORK_POLICY", { cause: error });
  }
  if (
    origin.username !== "" ||
    origin.password !== "" ||
    origin.pathname !== "/" ||
    origin.search !== "" ||
    origin.hash !== "" ||
    origin.protocol !== "https:"
  ) {
    throw new UpdateError("GOAT_UPDATE_NETWORK_POLICY");
  }
  return origin;
}

function resolveResourceUrl(origin: URL, resourcePath: string): URL {
  if (
    resourcePath.length === 0 ||
    resourcePath.length > 2_048 ||
    !resourcePath.startsWith("/") ||
    resourcePath.includes("\\") ||
    resourcePath.includes("?") ||
    resourcePath.includes("#") ||
    !/^\/[A-Za-z0-9._/-]+$/.test(resourcePath) ||
    resourcePath.split("/").some((component) => component === "..")
  ) {
    throw new UpdateError("GOAT_UPDATE_NETWORK_POLICY");
  }
  const result = new URL(resourcePath, origin);
  if (result.origin !== origin.origin) {
    throw new UpdateError("GOAT_UPDATE_NETWORK_POLICY");
  }
  return result;
}

function validateResponse(response: IncomingMessage, maxBytes: number): void {
  const status = response.statusCode ?? 0;
  if (status >= 300 && status < 400) {
    throw new UpdateError("GOAT_UPDATE_REDIRECT_REJECTED");
  }
  if (status !== 200) {
    throw new NetworkRequestError(
      "GOAT_UPDATE_NETWORK_FAILED",
      status === 408 || status === 429 || status >= 500,
      { statusCode: status },
    );
  }
  const encoding = response.headers["content-encoding"];
  if (
    encoding !== undefined &&
    (Array.isArray(encoding) || encoding.toLowerCase() !== "identity")
  ) {
    throw new UpdateError("GOAT_UPDATE_NETWORK_POLICY");
  }
  const contentLength = parseContentLength(response.headers["content-length"]);
  if (contentLength !== undefined && contentLength > maxBytes) {
    throw new UpdateError("GOAT_UPDATE_DOWNLOAD_TOO_LARGE");
  }
}

function parseContentLength(
  value: string | string[] | undefined,
): number | undefined {
  if (value === undefined) return undefined;
  if (Array.isArray(value) || !/^(?:0|[1-9]\d*)$/.test(value)) {
    throw new UpdateError("GOAT_UPDATE_NETWORK_POLICY");
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) {
    throw new UpdateError("GOAT_UPDATE_NETWORK_POLICY");
  }
  return parsed;
}

function createIdleTimer(
  response: IncomingMessage,
  idleTimeoutMs: number,
): NodeJS.Timeout {
  return setTimeout(
    () =>
      response.destroy(
        new NetworkRequestError("GOAT_UPDATE_NETWORK_TIMEOUT", true),
      ),
    idleTimeoutMs,
  );
}

function mapNetworkError(error: unknown): UpdateError {
  if (error instanceof UpdateError) return error;
  const code = (error as NodeJS.ErrnoException)?.code;
  const retryable = new Set([
    "ECONNRESET",
    "ECONNREFUSED",
    "EHOSTUNREACH",
    "ENETUNREACH",
    "EAI_AGAIN",
    "ETIMEDOUT",
  ]).has(code ?? "");
  return new NetworkRequestError("GOAT_UPDATE_NETWORK_FAILED", retryable, {
    cause: error,
  });
}
