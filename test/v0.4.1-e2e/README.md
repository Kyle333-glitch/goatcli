# GOAT v0.4.1 Windows/macOS coverage

This directory contains test-only, deterministic launcher coverage. It uses real
Node child processes and a loopback HTTP server with fixture tokens only. It does
not contact a production control plane, provider, registry, keychain, OAuth
provider, Gatekeeper, or SmartScreen.

## Coverage map

- `launcher.test.ts`: installation path/name resolution, spaces, Unicode paths,
  exact argv/cwd forwarding, executable permissions, Ctrl+C termination,
  listener cleanup, device login, refresh rotation, quota-route rejection at
  the loopback bearer/body boundary, offline response handling, and bounded
  direct-child termination verification.
- `goatcli/src/engine/validate.test.ts`: manifest and checksum rejection.
- `goatcli/src/update/archive.test.ts` and `code-signing.test.ts`: archive
  link/reparse protections and platform signing verification.
- `goatcli/src/update/recovery.test.ts` and `rollback.test.ts`: interrupted
  installation recovery and automatic rollback.
- `goat-engine/packages/opencode/test/cli/run/run-process.test.ts`: real engine
  subprocess streaming and tool-call continuation behavior.
- `goat-engine/packages/opencode/test/cli/run/run-ovh-integration.test.ts`:
  loopback direct OVH-compatible streaming and cancellation.
- `goat-engine/packages/opencode/test/privacy/hosted-inference-client.test.ts`:
  hosted SSE, origin, credential, redirect, and protocol behavior.
- `goat-engine/packages/opencode/test/sponsor/sponsor.test.ts` and
  `goat-control-plane/tests/sponsor-routes.test.ts`: sponsor payload
  validation, fail-closed absence/no-network behavior, and mocked route
  failure handling; they do not contact a live sponsor service.
- `goat-control-plane/tests/auth.test.ts` and
  `inference-routes.test.ts`: mocked auth/refresh, quota rejection, and
  inference settlement behavior.

The engine and control-plane suites are intentionally separate mocked layers.
They share fixture-only contracts but are not presented as a single production-service deployment. The  launcher fixture’s auth counters are request-boundary
assertions using fixture tokens, not full control-plane authorization semantics;
it also does not claim to exercise the full inference-client mapping. Direct
launcher-child shutdown and native descendant-process/no-orphan inspection are
covered by the dedicated suites. Real signing prompts, OS credential UI, OAuth
browser redirects, and external provider availability remain deferred.

## Evidence boundaries

- **Hostile collectors and loopback fixtures are mocked evidence.** The
  `MockControlPlaneServer` and fixture credential sets prove request-boundary
  contracts (paths, methods, counters, bearer/body rejection) but do not prove
  production deployment behavior, proxy retention, CDN behavior, or real
  control-plane authorization semantics.
- **Retry-cache idempotency is process-local.** Refresh retry/grace-period
  behavior proven in `goat-control-plane` tests is an in-memory cache inside a
  single process. It is not evidence of restart or multi-instance idempotency
  unless a durable store explicitly implements it.
- **Artifact fixtures do not prove the final production bundle.** Archive,
  checksum, signature, rollback, and recovery tests use fixture manifests and
  fixture archives. They verify the verification logic, not that the signed
  release artifacts shipped by CI match those fixtures.
- **Real Windows/macOS process-tree cleanup and Windows-safe legacy keyring
  credential migration are Sol-owned.** This suite verifies descendant cleanup
  with real Windows Job Objects and macOS process groups. The Windows native
  harness generates a real `CTRL_C_EVENT`; on runner images where redirected
  Node processes do not receive that console event, it uses a bounded native
  process termination fallback and still requires the launcher-owned Job Object
  to reap every descendant while preserving the sentinel. Windows Credential
  Manager migration, Gatekeeper, and SmartScreen verification require
  Sol-level native/deployment evidence.
- **Deployment and proxy retention require Sol-level evidence.** Nothing in
  this directory contacts a real provider, registry, keychain, OAuth provider,
  Gatekeeper, or SmartScreen.

## CI prerequisites

The enforced cross-repository job requires the private
`test/v0.4.1-windows-macos-e2e` branch to exist in `goatcli`, `goat-engine`, and
`goat-control-plane`, plus the repository secret `GOAT_REPO_READ_TOKEN` with
read-only access to both private adjacent repositories. The job fails closed
when either prerequisite is missing; it never falls back to a production
service or silently skips the mocked suites.
