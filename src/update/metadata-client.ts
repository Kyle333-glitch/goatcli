import { randomInt } from "node:crypto";
import { UpdateError } from "./errors.js";
import { parseRootMetadata } from "./metadata.js";
import {
  METADATA_NETWORK_LIMITS,
  NetworkRequestError,
  isRetryableNetworkError,
  type FixedOriginTransport,
} from "./network.js";
import type { UpdateChannel } from "./schema.js";

export interface UpdateMetadataBundle {
  readonly sequentialRoots: readonly Buffer[];
  readonly timestamp: Buffer;
  readonly snapshot: Buffer;
  readonly targets: Buffer;
  readonly channel: Buffer;
  readonly channelName: UpdateChannel;
}

export interface FetchUpdateMetadataOptions {
  readonly waitBeforeRetry?: () => Promise<void>;
}

const MAX_ROOT_UPDATES_PER_CHECK = 32;
const MAX_SEQUENTIAL_ROOT_BYTES = 2 * 1024 * 1024;
const MAX_NORMAL_METADATA_BYTES = 1024 * 1024;

export async function fetchUpdateMetadata(
  transport: FixedOriginTransport,
  embeddedRootBytes: Uint8Array,
  channelName: UpdateChannel,
  options: FetchUpdateMetadataOptions = {},
): Promise<UpdateMetadataBundle> {
  let rootVersion =
    parseRootMetadata(embeddedRootBytes).metadata.signed.version;
  const sequentialRoots: Buffer[] = [];
  let rootBytes = 0;
  for (let count = 0; count <= MAX_ROOT_UPDATES_PER_CHECK; count += 1) {
    const candidate = await readOptionalRoot(
      transport,
      rootVersion + 1,
      options,
    );
    if (!candidate) break;
    if (count === MAX_ROOT_UPDATES_PER_CHECK) {
      throw new UpdateError("GOAT_UPDATE_MANIFEST_UNSUPPORTED");
    }
    rootBytes += candidate.byteLength;
    if (rootBytes > MAX_SEQUENTIAL_ROOT_BYTES) {
      throw new UpdateError("GOAT_UPDATE_MANIFEST_TOO_LARGE");
    }
    const parsed = parseRootMetadata(candidate);
    if (parsed.metadata.signed.version !== rootVersion + 1) {
      throw new UpdateError("GOAT_UPDATE_METADATA_REPLAYED");
    }
    sequentialRoots.push(candidate);
    rootVersion += 1;
  }

  const timestamp = await readMetadata(
    transport,
    "/metadata/timestamp.json",
    options,
  );
  const snapshot = await readMetadata(
    transport,
    "/metadata/snapshot.json",
    options,
  );
  const targets = await readMetadata(
    transport,
    "/metadata/targets.json",
    options,
  );
  const channel = await readMetadata(
    transport,
    `/metadata/${channelName}.json`,
    options,
  );
  const normalBytes =
    timestamp.byteLength +
    snapshot.byteLength +
    targets.byteLength +
    channel.byteLength;
  if (normalBytes > MAX_NORMAL_METADATA_BYTES) {
    throw new UpdateError("GOAT_UPDATE_MANIFEST_TOO_LARGE");
  }
  return {
    sequentialRoots,
    timestamp,
    snapshot,
    targets,
    channel,
    channelName,
  };
}

async function readOptionalRoot(
  transport: FixedOriginTransport,
  version: number,
  options: FetchUpdateMetadataOptions,
): Promise<Buffer | null> {
  try {
    return await readMetadata(
      transport,
      `/metadata/${version}.root.json`,
      options,
    );
  } catch (error) {
    if (error instanceof NetworkRequestError && error.statusCode === 404) {
      return null;
    }
    throw error;
  }
}

async function readMetadata(
  transport: FixedOriginTransport,
  resourcePath: string,
  options: FetchUpdateMetadataOptions,
): Promise<Buffer> {
  for (let attempt = 1; attempt <= 2; attempt += 1) {
    try {
      return await transport.readResource(
        resourcePath,
        METADATA_NETWORK_LIMITS,
      );
    } catch (error) {
      if (attempt === 2 || !isRetryableNetworkError(error)) throw error;
      await (options.waitBeforeRetry ?? randomizedBackoff)();
    }
  }
  throw new UpdateError("GOAT_UPDATE_NETWORK_FAILED");
}

async function randomizedBackoff(): Promise<void> {
  await new Promise<void>((resolve) =>
    setTimeout(resolve, randomInt(250, 1_001)),
  );
}
