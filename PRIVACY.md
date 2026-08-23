# goatcli privacy behavior

This document describes the public `goatcli` launcher as implemented in v0.4.0. It does not describe every engine or control-plane behavior. The launcher has no independent analytics, telemetry, lifecycle-event, consent-reporting, exception-upload, or diagnostic-upload client.

## Data that the launcher never transmits

Launcher-owned network requests never include CLI arguments, working directories, paths, filenames, usernames, environment variable names or values, repository or Git information, child-process output, terminal or command output, exception messages, stack traces, or arbitrary strings.

Turning engine telemetry off does not activate any launcher network behavior. Launcher startup, shutdown, cancellation, launch failure, update failure, and integrity failure produce no launcher telemetry request.

## Essential launcher network operations

The launcher owns two purpose-bound network clients:

1. **Auth/usage client** — communicates with a fixed compiled control-plane origin.
2. **Verified-update transport** — fetches TUF metadata and engine artifacts from fixed compiled origins.

### Auth/usage client

The auth/usage client's origin is compiled into the launcher, routes are fixed, requests have a five-second total deadline, responses are limited to 16 KiB, and redirects and cookies are rejected. Requests use no proxy discovery, query string, fragment, URL user information, cookie jar, redirect following, or arbitrary header bag.

v0.4.0 has no compiled production origin and therefore fails closed. `GOAT_CONTROL_PLANE_URL` and other environment variables cannot select a destination. Tests may inject an HTTP or HTTPS loopback origin explicitly; non-loopback development injection is rejected.

| Purpose               | Method and route                | Application fields sent               | Fixed headers                                          |
| --------------------- | ------------------------------- | ------------------------------------- | ------------------------------------------------------ |
| Create device session | `POST /v1/auth/device/sessions` | None                                  | `Accept: application/json`, `User-Agent: GOAT-auth/1`  |
| Poll device session   | `POST /v1/auth/device/token`    | JSON `deviceCode`                     | Auth headers plus `Content-Type: application/json`     |
| Cancel device session | `POST /v1/auth/device/cancel`   | JSON `deviceCode`                     | Auth headers plus `Content-Type: application/json`     |
| Refresh credentials   | `POST /v1/auth/tokens/refresh`  | JSON `refreshToken`                   | Auth headers plus `Content-Type: application/json`     |
| Revoke credentials    | `POST /v1/auth/tokens/revoke`   | JSON `refreshToken`                   | Auth headers plus `Content-Type: application/json`     |
| Read usage            | `GET /v1/usage/summary`         | `Authorization: Bearer <accessToken>` | `Accept: application/json`, `User-Agent: GOAT-usage/1` |

The HTTP transport supplies `Host: <approved-host[:port]>`, `Connection: close`, and the applicable `Content-Length` (including zero for the bodyless session-creation POST). These are operational HTTP framing fields, not application metadata. No other application metadata is added. Device codes, access tokens, and refresh tokens must be exactly 43 base64url characters before transmission.

The client strictly reconstructs the PII-free usage response and rejects unknown top-level and nested fields, including `displayName`, `email`, `requestId`, generic metadata bags, and arbitrary objects in arrays. Human and JSON usage output contain no name, email, or request identifier. Server, DNS, TLS, timeout, parsing, and transport failures become fixed path-free launcher errors. Response bodies, exception messages, and stacks are neither printed automatically nor uploaded.

Browser authentication opens only `<approved-origin>/auth/device`. The launcher never appends a user code, device code, query, fragment, or server-returned arbitrary URL.

### Verified-update transport

`goat update` uses a fixed-origin HTTPS transport to fetch TUF metadata and engine artifacts. The transport's origins are compiled into the launcher and cannot be overridden by environment variables or command-line arguments.

The verified-update transport:

- Rejects all HTTP redirects (3xx responses).
- Rejects non-HTTPS origins, query strings, URL fragments, URL credentials, and origin-crossing resource paths.
- Sends only fixed HTTP framing headers: `Accept`, `Accept-Encoding: identity`, `User-Agent: GOAT-update/<version>`, `X-GOAT-Channel`, `X-GOAT-Platform`, `X-GOAT-Architecture`, and `Connection: close`.
- Enforces header, idle, and total timeout deadlines.
- Enforces maximum byte limits for metadata (256 KiB) and artifacts (512 MiB) including both `Content-Length` and streamed-byte guards.
- Retries only retryable transient HTTP failures (5xx, 408, 429, ECONNRESET, ETIMEDOUT, etc.) at most once with randomized backoff for idempotent GET requests. Non-retryable errors and non-GET methods are never retried.
- Includes no cookies, no proxy discovery, no query string, no fragment, and no arbitrary header bag.

The `User-Agent`, channel, platform, and architecture headers are operational routing identifiers necessary for the update server to select the correct release. They do not include user-identifying information.

Update metadata and artifacts are accessed only through this fixed-origin transport. No other network path can fetch, download, or inspect update material.

### Native installer channel

The standalone native installer has one additional essential network operation: it downloads the fixed, platform-specific GOAT engine package from `https://registry.npmjs.org`. The URL, package name, engine version, platform, and architecture are compiled into the installer; command-line arguments and environment variables cannot select another origin or package. Windows uses PowerShell's HTTPS request and macOS uses `curl` with a fixed `GOAT-native-installer/<version>` user agent. No cookies, proxy configuration, query string, fragment, credentials, or user data are sent.

The installer extracts only the expected engine executable, package metadata, and manifest. Release binaries embed the approved Ed25519 public key and cryptographically verify the stable manifest signature plus executable SHA-256 before activation and before every launch. Builds without embedded trust material fail closed when an engine is requested. The native installer sends no telemetry, diagnostic data, usage data, credentials, paths, working directories, arguments, or child-process output.

### What the verified-update channel does not transmit

The verified-update transport never transmits:

- CLI arguments beyond the fixed channel/platform/architecture routing identifiers
- Working directories or file paths
- Usernames or environment variables
- Repository or Git information
- Child-process output
- Exception messages or stack traces
- Credential material (access tokens, refresh tokens, device codes)
- Diagnostic content

Update success, failure, and integrity-check results produce no launcher telemetry request. The launcher reports update status only to the local terminal via fixed messages. No update event, lifecycle event, or error report is uploaded.

## Credentials

The active credential store is the operating-system keyring: Windows Credential Manager or macOS Keychain, under service `goatcli` and account `goat-auth`. The stored object has exactly five fields: `accessToken`, `refreshToken`, `tokenType`, `accessTokenExpiresAt`, and `refreshTokenExpiresAt`. Both tokens must be 43-character base64url values and `tokenType` must be `Bearer`.

There is no plaintext credential fallback. A legacy `auth.json` is never read or auto-migrated: without keyring credentials it fails closed with a fixed re-login instruction. After a verified keyring write (or on logout), a verified regular legacy file and its matching stale temporary files are removed.

If a newly issued or rotated credential cannot be verified in the keyring, the launcher does not use it. It best-effort revokes the new refresh token, clears ambiguous local credential state, and returns a fixed error without transport or keyring details.

## Local package and engine operations

Binary discovery, package inspection, engine manifest parsing, compatibility checking, SHA-256 verification, archive extraction, code-signing verification, health checking, activation, rollback verification, and update state management are all local essential operations. No engine file content, manifest content, or update state is transmitted to a network endpoint by the launcher outside the verified-update metadata and artifact fetches described above.

## Launcher self-update

The v0.4.0 Node launcher owns verified engine updates through `goat update` as described in [README.md](./README.md). The standalone native launcher also owns its local engine bootstrap and can re-install the pinned engine with `goat update`; it does not self-update its own native binary. Native installer binaries are updated through the GitHub release assets. The npm package is updated through the standard npm installation flow (`npm install -g goatcli`).

`goat upgrade` and other unrecognized commands are forwarded to the verified local engine, along with the working directory, inherited environment, and terminal streams. The launcher strips only its fixed routing keys (`GOAT_CONTROL_PLANE_URL`, `GOAT_ENGINE_PATH`, `GOAT_DEV_ENGINE_PATH`, and `GOATCLI_DEV`). It does not buffer child output or include any child input in a launcher request.

v0.4.0 has no compiled production origin and therefore fails closed; launcher-owned browser login, token refresh, revocation, usage requests, and verified updates are unavailable in a production build until approved production trust material is compiled into a later build. An environment variable cannot select a destination or override the trust configuration.

`goat doctor` is local-only. It may display local paths and diagnostic details to the user in the current terminal, but the launcher does not send doctor results or failures to a network request, IPC diagnostic field, or error reporter.

## `goat privacy` delegation

Most privacy commands are fully engine-local and start no launcher IPC session or launcher network request:

- `goat privacy`
- `goat privacy status`
- `goat privacy telemetry on`
- `goat privacy telemetry off`
- `goat privacy telemetry reset`

The launcher creates a version 1 authenticated anonymous-pipe session only for:

- `goat privacy telemetry delete-remote`
- `goat privacy diagnostics preview`
- `goat privacy diagnostics submit`
- `goat privacy diagnostics delete <diagnostic-id>`

Descriptors 3 and 4 carry the `GOATIPC1` protocol with a random 32-byte in-memory secret, HMAC-SHA-256 authentication, canonical JSON, a 2 KiB header limit, 4 KiB frame limit, two-second deadline, nonce/sequence/process binding, and exact acknowledgements. On Windows, every supported Node version uses GOAT's native `STARTUPINFOEX` spawn path. Its child CRT descriptor table contains descriptors 0 through 4, while `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` contains only valid duplicated standard-stream handles and the two child privacy-pipe handles. Standard input, output, and error remain terminal streams and are not IPC transports. The launcher ends and every unrelated handle are non-inheritable. If the matching native package is absent or invalid, a Windows privacy launch fails closed without falling back to Node's ordinary spawn path. On macOS, unrelated descriptors remain closed by the existing spawn path.

The native binding, inherited handle values, IPC secret, and access token are never added to the child argument vector or environment. The two privacy channels are anonymous pipes; the launcher does not replace them with named pipes, sockets, standard streams, or filesystem rendezvous.

The initial frame contains only protocol version, message type, random session and nonce identifiers, sequence, timestamp, launcher and engine process IDs, launcher version, installation channel `npm`, engine integrity (`verified` or `development_unverified`), keyring status, credential length, and optional credential expiry. It carries the exact 43-byte access token only when authentication is required. Diagnostic preview uses no credential. The launcher omits OS session identifiers and launcher diagnostic checks.

Arguments and diagnostic identifiers remain opaque engine arguments and never enter launcher network requests or IPC metadata. The launcher does not read diagnostic preview bytes. Diagnostic creation, preview, submission, deletion, and any associated user confirmation remain engine-owned. If a compatible engine does not continue listening after the initial acknowledgement, the launcher closes the descriptors after engine exit and does not compensate with another channel.

## Error reporting

The launcher has no Sentry, analytics, generic event, or error-reporting integration. Local launch/auth/update failures are mapped to fixed codes or messages. Raw spawn errors, network errors, server bodies, exception messages, and stack traces are not uploaded and are not included in essential requests.
