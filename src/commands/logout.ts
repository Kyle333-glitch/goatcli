import { CredentialStoreError } from "../auth/credentials.js";
import type { AuthApiClient, CredentialStore } from "../auth/types.js";

export interface LogoutOptions {
  client: AuthApiClient;
  store: CredentialStore;
  stdout: Pick<NodeJS.WriteStream, "write">;
  stderr: Pick<NodeJS.WriteStream, "write">;
  localOnly?: boolean;
}

export async function runLogout(options: LogoutOptions): Promise<number> {
  let credentials;
  try {
    credentials = await options.store.get();
  } catch (error) {
    if (
      error instanceof CredentialStoreError &&
      (error.code === "GOAT_CREDENTIAL_MIGRATION_FAILED" ||
        error.code === "GOAT_CREDENTIALS_INVALID")
    ) {
      options.stderr.write("GOAT login must be renewed. Run `goat login`.\n");
      return 1;
    }
    throw error;
  }
  if (!credentials) {
    options.stdout.write("No GOAT login credentials found.\n");
    return 0;
  }

  let serverRevoked = true;
  if (!options.localOnly) {
    try {
      await options.client.revoke(credentials.refreshToken);
    } catch {
      options.stderr.write(
        "GOAT logout could not revoke the server session.\n",
      );
      serverRevoked = false;
    }
  }

  await options.store.delete();
  if (options.localOnly) {
    options.stdout.write("Removed local GOAT credentials.\n");
  } else if (serverRevoked) {
    options.stdout.write("GOAT logout complete.\n");
  } else {
    options.stdout.write(
      "Removed local GOAT credentials, but server session revocation failed.\n",
    );
  }
  return serverRevoked ? 0 : 1;
}
