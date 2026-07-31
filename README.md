# GOAT CLI

`goatcli` is the public npm launcher for GOAT, a coding-agent product. The npm package name is `goatcli`; the installed terminal command and product display name are `goat` and GOAT.

The launcher discovers, verifies, and launches a separately installed GOAT engine executable. Starting with v0.4.0, the launcher also owns verified engine updates: it can download, authenticate, install, and report on engine releases without forwarding update requests to the engine. The launcher does not implement an independent telemetry, diagnostic-upload, or analytics channel.

## Requirements

- Node.js 24.16.0 or newer
- Windows or macOS
- x64 or arm64
- A compatible GOAT engine (installed manually or via `goat update`)

Install the public launcher with:

```shell
npm install --global goatcli
```

Then run:

```shell
goat
```

This v0.4.0 package ships fail-closed because no production update origin, TUF root, or signing key material is compiled into the repository. Consequently, launcher-owned verified updates, browser login, token refresh, revocation, and usage requests are unavailable in a production build until approved production trust material is compiled into a later build. An environment variable cannot select a production destination or override the trust configuration.

## Launcher-owned verified updates

`goat update` is owned by the launcher. It does not forward to the engine.

### Supported update channels

- **stable** — production releases (no prerelease identifiers)
- **beta** — beta releases (prerelease identifier `beta.<number>`)
- **development** — development releases (prerelease identifier `dev.<number>`)

### Supported platform and architecture tuples

| Platform          | Architecture |
| ----------------- | ------------ |
| Windows (`win32`) | x64, arm64   |
| macOS (`darwin`)  | x64, arm64   |

### Update command usage

```shell
goat update                      # update to the latest authenticated release on the configured channel
goat update --channel stable     # explicitly select the stable channel
goat update --channel beta       # select the beta channel
goat update --channel development # select the development channel
```

The update command accepts only no arguments or an optional `--channel stable|beta|development`. All other arguments are rejected. There is no downgrade, force, or version-pinning override.

### What happens during a verified update

1. **Metadata fetch and authentication.** The launcher fetches TUF (The Update Framework) metadata from a fixed, compiled metadata origin over HTTPS. All metadata is cryptographically authenticated against an embedded TUF root before any artifact is downloaded. Unknown, revoked, expired, replayed, or malformed metadata is rejected.

2. **Target selection.** The launcher selects the authenticated update target matching the current channel, platform, and architecture. It rejects downgrades, ambiguous matches, revoked artifacts, and launcher-incompatible releases.

3. **Artifact download.** The launcher downloads the signed engine archive from a fixed, compiled artifact origin over HTTPS. The download enforces streaming SHA-256 verification, signed size limits, header/idle/total timeout deadlines, and strict redirect rejection.

4. **Archive extraction and verification.** The launcher extracts the ZIP archive into a private staging area. It rejects traversal paths, absolute paths, symlinks, hardlinks, junctions, unexpected entry types, and resource-limit violations (entry count, per-entry size, total expansion, compression ratio). Every extracted file is re-hashed and cross-checked against the signed manifest.

5. **Compatibility and code-signing verification.** The launcher verifies launcher compatibility ranges, engine protocol compatibility, release-policy digest binding, and platform code signing (Windows Authenticode or macOS Apple Developer ID) before activation.

6. **Health check.** The launcher runs a bounded health check on the staged engine before committing it as the active installation.

7. **Activation.** The launcher atomically activates the verified engine into a versioned installation slot. The previous installation is preserved as rollback material. Superseded installations are cleaned up after successful activation; if the active executable is locked (Windows), cleanup is deferred.

8. **Persistence and reporting.** The launcher persists an authenticated target receipt, updater state, activation chain, and transaction journal. The user is informed whether the update succeeded or the installation is already current. Deferred cleanup paths are reported if applicable.

### Fail-closed behavior

When the production trust configuration is absent (no compiled TUF root, metadata origin, artifact origin, or signing keys), `goat update` fails immediately with a fixed error and performs no network request. The launcher cannot be configured to use a custom update server through environment variables or command-line arguments.

### Update metadata and artifact access

Update metadata and artifacts are accessed only through the launcher's fixed-origin HTTPS transport. The transport rejects all HTTP redirects, query strings, URL fragments, URL credentials, non-HTTPS origins, and origin-crossing resource paths. Metadata and artifacts are served from separate fixed origins compiled into the launcher.

## Expanded launcher-owned version command

`goat version` is owned by the launcher and does not spawn the engine. It reports:

- GOAT product version
- goatcli launcher version
- OpenCode baseline version
- Engine launch contract version
- Privacy protocol versions
- Current platform and architecture
- Installed engine version, channel, release sequence, target, manifest hash
- TUF root hash
- Signing key identifiers
- Integrity status
- Rollback availability
- Whether verified updates are enabled or disabled

`goat --version` and `goat -v` print only the launcher version string.

## Engine discovery and integrity

The launcher selects the local engine for the current platform, architecture, and release channel from per-user application data:

- Windows: `%LOCALAPPDATA%\goat\engines\<channel>\win32-<arch>\bin\goat-engine.exe`
- macOS: `~/Library/Application Support/goat/engines/<channel>/darwin-<arch>/bin/goat-engine`

If no compatible engine is installed, use `goat update` (see [Launcher-owned verified updates](#launcher-owned-verified-updates) above).

The adjacent `goat-engine.json` manifest is required for normal installations. The launcher rejects unknown manifest fields, verifies the platform, architecture, release channel, executable name, launcher compatibility range, and SHA-256 checksum, and then spawns the engine without a shell. Production environment overrides such as `GOAT_ENGINE_PATH` and `GOAT_DEV_ENGINE_PATH` are ignored and removed before the child handoff. Explicit development engines are available only through test/development dependency injection, not a production environment variable.

GOAT inherits the engine process environment so engine-owned providers, shells, LSPs, MCP servers, and tools continue to work. The launcher does not serialize or transmit that environment. Command arguments, the working directory, and child terminal output are also handed only to the local engine process. Child stdin, stdout, and stderr remain inherited; the launcher does not buffer or inspect them.

## Commands owned by the launcher

- `goat --version` and `goat -v` print the launcher version.
- `goat version` prints expanded launcher, engine, platform, and update-trust details without spawning the engine.
- `goat update` performs a launcher-owned verified engine update as described above.
- `goat doctor` runs local-only diagnostics. Its results and failures are never uploaded by the launcher.
- `goat login`, `goat logout`, and `goat usage` use the bounded auth/usage operations documented in [PRIVACY.md](./PRIVACY.md) when an approved control-plane origin is compiled.
- Other commands are forwarded to the verified engine. The launcher does not buffer or inspect child output.

`goat privacy` is engine-owned. The launcher creates authenticated anonymous-pipe IPC only for remote telemetry deletion and engine diagnostic preview, submission, or deletion. It does not inspect diagnostic content and does not upload diagnostics itself. See [PRIVACY.md](./PRIVACY.md) for the exact command routing and fields.

## Privacy and license

The complete launcher privacy boundary is documented in [PRIVACY.md](./PRIVACY.md).

The public `goatcli` launcher source is licensed under the MIT License. The private engine, private control plane, and distributed engine binaries are separate works and are not licensed by this package; see [NOTICE](./NOTICE).
