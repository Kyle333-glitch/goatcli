import type { AuthApiClient, CredentialStore } from "../auth/types.js";

export interface LogoutOptions {
  client: AuthApiClient;
  store: CredentialStore;
  stdout: Pick<NodeJS.WriteStream, "write">;
  stderr: Pick<NodeJS.WriteStream, "write">;
  localOnly?: boolean;
}

export async function runLogout(options: LogoutOptions): Promise<number> {
  const credentials = await options.store.get();
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
