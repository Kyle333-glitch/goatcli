import type { Writable } from "node:stream";
import { UpdateError } from "../update/errors.js";
import type { UpdateChannel } from "../update/schema.js";
import {
  runVerifiedUpdate,
  type RunVerifiedUpdateOptions,
  type VerifiedUpdatePolicy,
  type VerifiedUpdateResult,
} from "../update/updater.js";

export interface UpdateCommandOptions {
  readonly args: readonly string[];
  readonly appDataDirectory: string;
  readonly policy: VerifiedUpdatePolicy | null;
  readonly stdout: Pick<Writable, "write">;
  readonly stderr: Pick<Writable, "write">;
  readonly runner?: (
    options: RunVerifiedUpdateOptions,
  ) => Promise<VerifiedUpdateResult>;
}

export async function runUpdateCommand(
  options: UpdateCommandOptions,
): Promise<void> {
  const requestedChannel = parseRequestedChannel(options.args);
  if (!options.policy) throw new UpdateError("GOAT_UPDATE_DISABLED");
  const result = await (options.runner ?? runVerifiedUpdate)({
    appDataDirectory: options.appDataDirectory,
    policy: options.policy,
    requestedChannel,
  });
  if (result.status === "updated") {
    options.stdout.write(
      `GOAT updated to ${result.productVersion} (${result.channel}, release ${result.releaseSequence}).\n`,
    );
  } else {
    options.stdout.write(
      `GOAT ${result.productVersion} is already current (${result.channel}, release ${result.releaseSequence}).\n`,
    );
  }
  if (result.deferredCleanupPaths.length > 0) {
    options.stderr.write(
      `GOAT update completed; cleanup of ${result.deferredCleanupPaths.length} superseded installation(s) was deferred.\n`,
    );
  }
}

export function parseRequestedChannel(
  args: readonly string[],
): UpdateChannel | undefined {
  if (args.length === 0) return undefined;
  if (
    args.length !== 2 ||
    args[0] !== "--channel" ||
    (args[1] !== "stable" && args[1] !== "beta" && args[1] !== "development")
  ) {
    throw new UpdateError("GOAT_UPDATE_INVALID_ARGUMENT");
  }
  return args[1];
}
