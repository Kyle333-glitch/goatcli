# GOAT v0.3.2 goatcli Privacy Implementation Report

Date: 2026-07-17
Branch: feat/v0.3.2-privacy-telemetry
Repository modified: D:/goat/goatcli only
Task classification: security-sensitive launcher and cross-repository contract implementation

## Outcome

goatcli v0.3.2 now implements the locked launcher privacy boundary without an independent telemetry or diagnostic-upload client. Launcher-owned networking is limited to one purpose-bound auth/usage client with exactly six routes. The production origin is intentionally unset, so all production auth/usage operations fail closed.

The implementation passes all local Windows x64 launcher gates, a real Node 24.16 fd 3/4 IPC handshake, package verification, built-output scans, package-payload canary scans, and the complete non-PostgreSQL cross-repository runner. The final runner passed 87 engine privacy tests, 56 control-plane contract tests, and all 10 adversarial cross-repository canary tests before re-verifying the canonical schemas, control-plane typecheck, and production build.

The launcher is ready for cross-repository integration testing. It is not production-ready, and the full cross-platform release gate is not complete. Release blockers are listed below.

No commit, merge, push, staging operation, or change to main was performed. The private goat-engine and goat-control-plane working trees were not edited or licensed by this work.

## Sources and interface verification

The implementation used:

- D:/goat/01-locked-privacy-contract.md
- D:/goat/goat-control-plane/02-control-plane-implementation-report.md
- D:/goat/goat-engine/03-engine-implementation-report.md
- D:/goat/goat-engine/docs/goat/launcher-privacy-ipc.md
- D:/goat/goat-engine/docs/goat/privacy.md
- The actual feat/v0.3.2-privacy-telemetry working trees in goat-engine and goat-control-plane

Reports were treated as supporting evidence. Route names, response fields, IPC enums, canonical ordering, pipe descriptors, timeouts, optional fields, and known gaps were verified in current source and tests.

## Files changed

### Package, build, CI, license, and public documentation

- .github/workflows/test.yml
- package.json
- package-lock.json
- tsconfig.json
- tsconfig.build.json
- README.md
- PRIVACY.md
- LICENSE
- NOTICE
- 04-cli-implementation-report.md
- scripts/clean-dist.mjs
- scripts/check-privacy-architecture.mjs
- scripts/test-cross-repo.mjs
- scripts/verify-package.mjs

### Production launcher source

- src/index.ts
- src/version.ts
- src/cli.ts
- src/platform.ts
- src/auth/browser.ts
- src/auth/client.ts
- src/auth/credentials.ts
- src/auth/types.ts
- src/commands/doctor.ts
- src/commands/login.ts
- src/commands/logout.ts
- src/commands/usage.ts
- src/engine/contract.ts
- src/engine/launch.ts
- src/engine/validate.ts
- src/privacy/credential-session.ts
- src/privacy/launcher-ipc.ts
- src/privacy/node-transport.ts
- src/utils/paths.ts
- src/utils/system.ts

### Tests

- src/auth/client.test.ts
- src/auth/credentials.test.ts
- src/cli.test.ts
- src/commands/auth-commands.test.ts
- src/engine/launch.test.ts
- src/engine/privacy-launch.test.ts
- src/engine/privacy-routing.test.ts
- src/engine/validate.test.ts
- src/platform.test.ts
- src/privacy/credential-session.test.ts
- src/privacy/launcher-ipc.test.ts
- src/privacy/node-transport.test.ts
- src/utils/engine-paths.test.ts
- src/utils/paths.test.ts
- src/utils/system.test.ts
- test/v0.1.1-local-integration/integration.test.ts
- test/auth.test.ts was removed because it tested the retired fetch client and plaintext credential fallback.

## Essential launcher network operations

The compiled production origin is null. Tests can inject only an exact loopback HTTP or HTTPS origin through explicit dependency injection. GOAT_CONTROL_PLANE_URL is ignored and cannot select a destination.

All requests use a five-second total deadline, a 16 KiB response limit, no redirects, no cookie jar, no proxy discovery, no query, no fragment, no URL user information, no retries, and a one-request connection.

| Purpose               | Exact request                 | Application fields                                       | Application headers                                               |
| --------------------- | ----------------------------- | -------------------------------------------------------- | ----------------------------------------------------------------- |
| Create device session | POST /v1/auth/device/sessions | No body fields                                           | Accept: application/json; User-Agent: GOAT-auth/1                 |
| Poll device session   | POST /v1/auth/device/token    | JSON deviceCode                                          | Accept; User-Agent: GOAT-auth/1; Content-Type: application/json   |
| Cancel device session | POST /v1/auth/device/cancel   | JSON deviceCode                                          | Accept; User-Agent: GOAT-auth/1; Content-Type: application/json   |
| Refresh credentials   | POST /v1/auth/tokens/refresh  | JSON refreshToken                                        | Accept; User-Agent: GOAT-auth/1; Content-Type: application/json   |
| Revoke credentials    | POST /v1/auth/tokens/revoke   | JSON refreshToken                                        | Accept; User-Agent: GOAT-auth/1; Content-Type: application/json   |
| Read usage            | GET /v1/usage/summary         | Authorization: Bearer plus the 43-character access token | Accept: application/json; User-Agent: GOAT-usage/1; Authorization |

Node supplies only these additional HTTP framing fields:

- Host: approved-host with the operational port when non-default
- Connection: close
- Applicable Content-Length, including zero for the bodyless session-creation POST

Device codes, access tokens, and refresh tokens are validated as exactly 43 base64url characters before transmission. The request recorder asserts the complete header-name set for every operation and rejects any extra header.

The launcher accepts only the control plane's PII-free `v0.3.2` usage response. It rejects `displayName`, `email`, `requestId`, generic metadata bags, unknown nested fields, and arbitrary objects in arrays. Human and JSON usage output contain no name, email, or request identifier.

Browser authentication opens only the canonical approved-origin/auth/device URL. It adds no user code, device code, query, fragment, or returned arbitrary URL.

## Operations with no launcher network request

The following remain local essential package operations and transmit no fields:

- Binary discovery
- Platform and architecture selection
- Engine-manifest parsing
- Compatibility validation
- SHA-256 engine integrity verification
- npm package inspection
- goat doctor diagnostics

There is no launcher download client, update checker, update download, manifest download, integrity-report request, install event, launch event, failure event, consent event, lifecycle event, exception upload, or error-reporting integration.

The architecture lint requires the sole network client to declare exactly the six approved /v1 routes. This is the negative update/download/telemetry-route gate.

## Credentials

The OS keyring is the only active credential store:

- Service: goatcli
- Account: goat-auth
- Windows: Credential Manager
- macOS: Keychain

The credential object must have exactly accessToken, refreshToken, tokenType, accessTokenExpiresAt, and refreshTokenExpiresAt. Unknown fields are rejected. Both tokens must be 43-character base64url values and tokenType must be Bearer.

Plaintext fallback authentication was removed. A legacy auth.json is bounded to 4 KiB, must be a regular file containing the exact schema and valid UTF-8, and is migrated only after keyring write plus matching readback. Successful migration removes the legacy file and matching stale temporary files. Failed migration preserves the original file, never authenticates from it, and returns a fixed path-free error.

Newly issued or rotated credentials are used only after a verified keyring write. If persistence fails, login, usage, and authenticated privacy commands fail closed, best-effort revoke the new refresh token, clear ambiguous local credential state, and expose no transport, keyring, or token details.

## Engine spawning and local errors

Production GOAT_ENGINE_PATH, GOAT_DEV_ENGINE_PATH, GOATCLI_DEV, and GOAT_CONTROL_PLANE_URL routing is ignored. Test/development engines require an explicit ResolvedEngine dependency and cannot be selected with a production environment variable.

The launcher:

- Verifies the deterministic Windows or macOS local install path.
- Requires an exact, unknown-field-rejecting goat-engine.json manifest for production installs.
- Verifies platform, x64/arm64 architecture, release channel, executable name, compatibility range, and SHA-256.
- Spawns without a shell.
- Forwards arguments and the working directory directly.
- Inherits engine environment values while removing the four fixed launcher-routing keys.
- Inherits child stdin, stdout, and stderr and never buffers or inspects engine output.
- Maps validation and spawn failures to fixed path-free errors.
- Does not upload local errors.

goat doctor remains explicitly local-only. It may show local paths, filenames, environment-derived diagnostic values, and local command failures to the current user. None enter a launcher network request, IPC diagnostic field, or error reporter.

## goat privacy IPC

The public launcher producer independently implements engine IPC v1:

- GOATIPC1 bootstrap magic
- Random 32-byte in-memory secret
- HMAC-SHA-256 request and response domains
- Canonical JSON
- 2 KiB header and 4 KiB frame limits
- Two-second total operation deadline
- Fresh timestamp, unique nonce, sequence, session, launcher PID, and engine PID checks
- Exact ACK and fixed session-error parsing
- Deterministic descriptor closure and secret/frame/credential-buffer zeroization
- Node 24.16 minimum for the Windows inherited-handle allowlist
- Anonymous child descriptors 3 and 4; stdin/stdout/stderr remain inherited

IPC is created only for:

- goat privacy telemetry delete-remote
- goat privacy diagnostics preview
- goat privacy diagnostics submit
- goat privacy diagnostics delete diagnostic-id

The local commands privacy, status, telemetry on, telemetry off, and telemetry reset read no launcher credential, create no IPC, and make no launcher network request. Startup, normal exit, spawn failure, and signal termination were tested with forbidden auth/keyring proxies and zero accesses.

Preview sends no credential and reports credential_store as not_checked. Authenticated operations refresh or acquire the access token immediately before launch. Arguments, diagnostic identifiers, paths, environment values, and child output never enter IPC metadata.

The producer implements credential_update, credential_clear, and session_end with ordered ACKs. The current engine gap prevents production use of those continuation frames; the launcher does not compensate with another channel.

## Canary and privacy tests

The exact required canaries were exercised:

- PROMPT_SECRET_7QX9
- SOURCE_CODE_SECRET_4JK2
- TOKEN_SECRET_8MVP
- PATH_SECRET_3HT6
- ENV_SECRET_9DK1

Coverage includes:

- CLI arguments and opaque diagnostic identifiers
- Environment variable names and values
- Working directories
- Binary and manifest paths
- Download/update absence contexts
- Filenames
- Spawn exception messages
- Raw child stdout and stderr through a test-injected capture
- Auth, refresh, keyring, and network failures
- Unknown server response fields and usage PII
- Browser queries
- IPC frames and diagnostic metadata
- URLs, query strings, full header sets, user agents, bodies, and captured requests
- Launcher-owned output and fixed errors
- Built dist and extracted npm tarball
- Telemetry and error-reporting dependency/source scans

The child-output test first asserts that production launch requested inherited stdio, then its injected test spawn substitutes pipes solely to capture and prove that the exact canaries remain child-owned. The test does not print those canaries to the terminal. Production launcher code neither buffers nor inspects child output, and the launcher result contains only exitCode and signal.

Final scan results:

- Captured launcher network requests: zero canary hits
- Launcher IPC metadata/frames: zero canary hits
- Built dist: zero canary hits
- Extracted npm tarball: zero canary hits
- Telemetry/error-reporting integrations: zero hits
- Launcher-owned child-output collection: structurally absent; the injected test capture contains only the expected child canaries
- Tarball source/test/private-engine artifacts: zero hits

## Verification commands and results

Environment:

- Windows x64
- Node 24.16.0
- Bun 1.3.14
- Native @napi-rs/keyring module loaded successfully without modifying credentials

Launcher:

| Command                                        | Result                                                                    |
| ---------------------------------------------- | ------------------------------------------------------------------------- |
| npm ci                                         | Passed; 36 packages installed; 0 vulnerabilities                          |
| npm run format:check                           | Passed                                                                    |
| npm run lint                                   | Passed; 20 production files checked                                       |
| npm run typecheck                              | Passed                                                                    |
| npm run build                                  | Passed                                                                    |
| npm test                                       | Passed; 94/94; 0 skipped                                                  |
| npm run test:privacy                           | Passed; 42/42; 0 skipped                                                  |
| npm run test:cross-repo                        | Passed; 87 engine, 59 control-plane, and 10 cross-repository canary tests |
| npm run verify:package                         | Passed                                                                    |
| npm pack --dry-run --json --ignore-scripts     | Passed; 45 files; 42,093 bytes compressed; no bundled dependencies        |
| npm audit --omit=dev --audit-level=low --json  | Passed; 0 vulnerabilities                                                 |
| git diff --check                               | Passed                                                                    |
| Extracted tarball canary/private-artifact scan | Passed; 0 hits                                                            |

One final npm ci attempt initially failed with EPERM because the original timed-out test run had left its verified goatcli Node/tsx/esbuild process tree alive. Only that exact stale tree was terminated. The immediate retry and all later checks passed.

Actual engine:

- bun test --timeout 30000 test/privacy plus the three privacy CLI suites
- Passed: 87/87 across 15 files; 3,054 assertions
- The cold global-teardown import that blocked the preceding run was replaced in goat-engine with a lifecycle registry and the exact launcher-driven selection completed without a hook timeout.

Actual control plane:

- Passed: 59/59 auth, usage, privacy-contract, privacy-route, and privacy-store tests; 299 assertions
- Passed: 10/10 adversarial cross-repository v0.3.2 canary tests
- Canonical privacy schema verification, typecheck, and the 550-module production build passed.
- PostgreSQL integration tests were explicitly skipped because `GOAT_TEST_DATABASE_URL` is unset.

Coordinated follow-up on 2026-07-21:

- The engine manifest producer and launcher Ed25519 trust-chain verifier are aligned to the signed release policy. The launcher now requests/owns the v2 session lazily for ordinary execution, and the engine consumes continuation frames through the same authenticated session.
- Focused signed-manifest, launch, v2 activation, routing, and minimal-environment regressions passed: 31 tests, 0 failed. `npm run typecheck` and `npm run build` passed.

## Platform coverage

| Surface                                    | Windows x64                                               | Windows arm64                     | macOS x64                                | macOS arm64                              |
| ------------------------------------------ | --------------------------------------------------------- | --------------------------------- | ---------------------------------------- | ---------------------------------------- |
| Discovery/manifest/platform contract tests | Passed                                                    | Passed by injected contract tests | Passed by injected contract tests        | Passed by injected contract tests        |
| Native process spawn/cancellation          | Passed                                                    | Not run natively                  | Not run natively                         | Not run natively                         |
| Native fd 3/4 IPC handshake                | Passed on Node 24.16                                      | Not run natively                  | CI configured, not run in this workspace | CI configured, not run in this workspace |
| Native keyring implementation              | Module load passed; read/write tests use injected keyring | Not run                           | Not run                                  | Not run                                  |

The CI workflow runs Node 24.16 on windows-latest and macos-latest and records the actual architecture. No remote CI run was available because this work was not pushed. Native macOS and arm64 results remain a release gate.

## Dependency and license review

goatcli alone is MIT licensed with Copyright (c) 2026 GOAT Contributors. NOTICE states that goat-engine, goat-control-plane, and distributed engine binaries are separate works not covered by the launcher MIT license.

All locked launcher dependencies declare MIT, Apache-2.0, or ISC licenses. The production dependency audit has zero known vulnerabilities.

The private repositories retain their required upstream license declarations and were not edited.

## Residual risks and cross-repository blockers

Release-blocking:

1. No approved production control-plane origin is compiled into goatcli or the engine. Auth, refresh, revoke, usage, and remote privacy operations therefore fail closed.
2. The signed manifest producer and verifier are implemented, but no approved production manifest-signing key, signed release artifact, provenance record, notarization, or distribution evidence exists yet.
3. The lazy v2 ordinary/explicit session, continuation listener, hosted transport, and minimal child-environment allowlist are implemented and locally tested. Packaged Windows/macOS lifecycle, handle/descriptor inheritance, cancellation, and network-capture evidence remains required.
4. Native macOS and arm64 launcher/IPC/keyring runs have not yet executed.
5. PostgreSQL auth/privacy integration suites require an unavailable disposable `GOAT_TEST_DATABASE_URL`.

External release evidence still required:

- Infrastructure egress and log-retention validation
- Approved production origin and TLS/DNS policy
- Native signing/notarization and engine distribution
- Real OS keyring read/write validation on release runners
- PostgreSQL integration results

## Deferred work

- Select and compile the approved production control-plane origin.
- Finalize a production engine manifest with an approved signing key and record artifact provenance, notarization, and distribution evidence.
- Execute packaged ordinary and explicit v2 sessions through the approved engine transport on every release platform, including lifecycle/cancellation and zero-work capture.
- Run Windows arm64 and native macOS x64/arm64 gates.
- Run the PostgreSQL integration suites with a disposable test database.
- Collect infrastructure, signing, notarization, and production egress evidence.

No launcher telemetry, download, update, exception-upload, or diagnostic-upload work is deferred; those channels are intentionally absent.

## Diff and repository review

- Every changed production launcher source, package/build file, public document, and relevant test was reviewed.
- The sole production network imports are node:http and node:https in src/auth/client.ts.
- The network client route set is statically locked to exactly six operations.
- Engine spawning contains no stdout or stderr reads.
- Production and dist canary scans passed.
- Extracted package scans passed.
- git diff --check passed.
- goat-engine and goat-control-plane remained on feat/v0.3.2-privacy-telemetry with their pre-existing privacy worktrees; no source or license change was made there.
- goatcli remains intentionally uncommitted and unstaged on feat/v0.3.2-privacy-telemetry.

## Readiness decision

Ready for cross-repository integration testing: Yes. The launcher has already passed the current engine and control-plane non-PostgreSQL contract suites on Windows x64.

Ready for production release: No.

Formal all-platform integration gate complete: No. Native macOS/arm64, live PostgreSQL, approved production origin, signed/notarized release artifacts, packaged transport, and infrastructure evidence remain.
