# goatcli privacy behavior

This document describes the public `goatcli` launcher as implemented in v0.3.2. It does not describe every engine or control-plane behavior. The launcher has no independent analytics, telemetry, lifecycle-event, consent-reporting, exception-upload, or diagnostic-upload client.

## Data that the launcher never transmits

Launcher-owned network requests never include CLI arguments, working directories, paths, filenames, usernames, environment variable names or values, repository or Git information, child-process output, terminal or command output, exception messages, stack traces, or arbitrary strings.

Turning engine telemetry off does not activate any launcher network behavior. Launcher startup, shutdown, cancellation, launch failure, update failure, and integrity failure produce no launcher telemetry request.

## Essential launcher network operations

There is one purpose-bound auth/usage client. Its origin is compiled into the launcher, routes are fixed, requests have a five-second total deadline, responses are limited to 16 KiB, and redirects and cookies are rejected. Requests use no proxy discovery, query string, fragment, URL user information, cookie jar, redirect following, or arbitrary header bag.

v0.3.2 has no compiled production origin and therefore fails closed. `GOAT_CONTROL_PLANE_URL` and other environment variables cannot select a destination. Tests may inject an HTTP or HTTPS loopback origin explicitly; non-loopback development injection is rejected.

| Purpose               | Method and route                | Application fields sent               | Fixed headers                                          |
| --------------------- | ------------------------------- | ------------------------------------- | ------------------------------------------------------ |
| Create device session | `POST /v1/auth/device/sessions` | None                                  | `Accept: application/json`, `User-Agent: GOAT-auth/1`  |
| Poll device session   | `POST /v1/auth/device/token`    | JSON `deviceCode`                     | Auth headers plus `Content-Type: application/json`     |
| Cancel device session | `POST /v1/auth/device/cancel`   | JSON `deviceCode`                     | Auth headers plus `Content-Type: application/json`     |
| Refresh credentials   | `POST /v1/auth/tokens/refresh`  | JSON `refreshToken`                   | Auth headers plus `Content-Type: application/json`     |
| Revoke credentials    | `POST /v1/auth/tokens/revoke`   | JSON `refreshToken`                   | Auth headers plus `Content-Type: application/json`     |
| Read usage            | `GET /v1/usage/summary`         | `Authorization: Bearer <accessToken>` | `Accept: application/json`, `User-Agent: GOAT-usage/1` |

The HTTP transport supplies `Host: <approved-host[:port]>`, `Connection: close`, and the applicable `Content-Length` (including zero for the bodyless session-creation POST). These are operational HTTP framing fields, not application metadata. No other application metadata is added. Device codes, access tokens, and refresh tokens must be exactly 43 base64url characters before transmission.

The client strictly reconstructs the PII-free `v0.3.2` usage response and rejects unknown top-level and nested fields, including `displayName`, `email`, `requestId`, generic metadata bags, and arbitrary objects in arrays. Human and JSON usage output contain no name, email, or request identifier. Server, DNS, TLS, timeout, parsing, and transport failures become fixed path-free launcher errors. Response bodies, exception messages, and stacks are neither printed automatically nor uploaded.

Browser authentication opens only `<approved-origin>/auth/device`. The launcher never appends a user code, device code, query, fragment, or server-returned arbitrary URL.

## Credentials

The active credential store is the operating-system keyring: Windows Credential Manager or macOS Keychain, under service `goatcli` and account `goat-auth`. The stored object has exactly five fields: `accessToken`, `refreshToken`, `tokenType`, `accessTokenExpiresAt`, and `refreshTokenExpiresAt`. Both tokens must be 43-character base64url values and `tokenType` must be `Bearer`.

There is no plaintext credential fallback. A valid legacy `auth.json` may be migrated once only after a keyring write and readback match. Successful migration removes the legacy file and stale temporary files. If migration cannot be verified, the launcher leaves the original file for recovery, does not authenticate from it, and returns a fixed re-login instruction without its path.

If a newly issued or rotated credential cannot be verified in the keyring, the launcher does not use it. It best-effort revokes the new refresh token, clears ambiguous local credential state, and returns a fixed error without transport or keyring details.

## Local package and engine operations

Binary discovery, package inspection, engine manifest parsing, compatibility checking, and SHA-256 verification are local essential package operations. v0.3.2 implements no launcher download request, update check, update download, manifest download, or integrity-reporting request.

## Launcher self-update

The v0.3.2 launcher does not implement a self-update command. `goat upgrade` is treated as an ordinary engine command and is forwarded to the verified local engine, along with the working directory, inherited environment, and terminal streams. The launcher strips only its fixed routing keys (`GOAT_CONTROL_PLANE_URL`, `GOAT_ENGINE_PATH`, `GOAT_DEV_ENGINE_PATH`, and `GOATCLI_DEV`). It does not buffer child output or include any child input in a launcher request.

v0.3.2 has no compiled production origin and therefore fails closed; launcher-owned browser login, token refresh, revocation, and usage requests are unavailable in a production build until an approved origin is compiled into a later build. An environment variable cannot select a production destination.

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

Descriptors 3 and 4 carry the `GOATIPC1` protocol with a random 32-byte in-memory secret, HMAC-SHA-256 authentication, canonical JSON, a 2 KiB header limit, 4 KiB frame limit, two-second deadline, nonce/sequence/process binding, and exact acknowledgements. Node 24.16.0 is required so Windows uses libuv's explicit inherited-handle allowlist; unrelated descriptors remain closed on macOS.

The initial frame contains only protocol version, message type, random session and nonce identifiers, sequence, timestamp, launcher and engine process IDs, launcher version `0.3.2`, installation channel `npm`, engine integrity (`verified` or `development_unverified`), keyring status, credential length, and optional credential expiry. It carries the exact 43-byte access token only when authentication is required. Diagnostic preview uses no credential. The launcher omits OS session identifiers and launcher diagnostic checks.

Arguments and diagnostic identifiers remain opaque engine arguments and never enter launcher network requests or IPC metadata. The launcher does not read diagnostic preview bytes. Diagnostic creation, preview, submission, deletion, and any associated user confirmation remain engine-owned. If a compatible engine does not continue listening after the initial acknowledgement, the launcher closes the descriptors after engine exit and does not compensate with another channel.

## Error reporting

The launcher has no Sentry, analytics, generic event, or error-reporting integration. Local launch/auth failures are mapped to fixed codes or messages. Raw spawn errors, network errors, server bodies, exception messages, and stack traces are not uploaded and are not included in essential requests.
