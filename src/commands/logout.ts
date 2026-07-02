import type { AuthApiClient, CredentialStore } from '../auth/types.js';

export interface LogoutOptions {
  client: AuthApiClient;
  store: CredentialStore;
  stdout: Pick<NodeJS.WriteStream, 'write'>;
  stderr: Pick<NodeJS.WriteStream, 'write'>;
  localOnly?: boolean;
}

export async function runLogout(options: LogoutOptions): Promise<number> {
  const credentials = await options.store.get();
  if (!credentials) {
    options.stdout.write('No GOAT login credentials found.\n');
    return 0;
  }

  let serverRevoked = true;
  if (!options.localOnly) {
    try {
      await options.client.revoke(credentials.refreshToken);
    } catch (error) {
      options.stderr.write(`GOAT logout failed to revoke the server session: ${errorMessage(error)}\n`);
      serverRevoked = false;
    }
  }

  await options.store.delete();
  options.stdout.write(options.localOnly ? 'Removed local GOAT credentials.\n' : 'GOAT logout complete.\n');
  return serverRevoked ? 0 : 1;
}

function errorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  if (typeof error === 'string') return error;
  return String(error);
}