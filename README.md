# GOAT CLI

`goatcli` is the public npm launcher for GOAT, a coding-agent product. The npm package name is `goatcli`; the installed terminal command and product display name are `goat` and GOAT.

The launcher is intentionally narrow. It discovers and verifies a separately installed private `goat-engine` executable, then forwards the command line, working directory, environment, and terminal streams directly to that child process. It does not implement an independent telemetry, diagnostic-upload, download, or update channel.

## Requirements

- Node.js 24.16.0 or newer
- Windows or macOS
- x64 or arm64
- A separately installed, compatible GOAT engine

Install the public launcher with:

```shell
npm install --global goatcli
```

Then run:

```shell
goat
```

This v0.3.2 package ships fail-closed because no production control-plane origin is compiled into the repository. Consequently, launcher-owned browser login, token refresh, revocation, and usage requests are unavailable in a production build until an approved origin is compiled into a later build. An environment variable cannot select a production destination.

## Engine discovery and integrity

The launcher performs no engine download or update request. It selects the local engine for the current platform, architecture, and release channel:

- Windows: `%LOCALAPPDATA%\goat\engines\<channel>\win32-<arch>\bin\goat-engine.exe`
- macOS: `~/Library/Application Support/goat/engines/<channel>/darwin-<arch>/bin/goat-engine`

The adjacent `goat-engine.json` manifest is required for normal installations. The launcher rejects unknown manifest fields, verifies the platform, architecture, release channel, executable name, launcher compatibility range, and SHA-256 checksum, and then spawns the engine without a shell. Production environment overrides such as `GOAT_ENGINE_PATH` and `GOAT_DEV_ENGINE_PATH` are ignored and removed before the child handoff. Explicit development engines are available only through test/development dependency injection, not a production environment variable.

GOAT inherits the engine process environment so engine-owned providers, shells, LSPs, MCP servers, and tools continue to work. The launcher does not serialize or transmit that environment. Command arguments, the working directory, and child terminal output are also handed only to the local engine process. Child stdin, stdout, and stderr remain inherited; the launcher does not buffer or inspect them.

## Commands owned by the launcher

- `goat --version` and `goat version` print the launcher version.
- `goat doctor` runs local-only diagnostics. Its results and failures are never uploaded by the launcher.
- `goat login`, `goat logout`, and `goat usage` use the bounded auth/usage operations documented in [PRIVACY.md](./PRIVACY.md) when an approved control-plane origin is compiled.
- Other commands (including `goat upgrade`) are forwarded to the verified engine. The launcher performs no self-update, download, or registry request.

`goat privacy` is engine-owned. The launcher creates authenticated anonymous-pipe IPC only for remote telemetry deletion and engine diagnostic preview, submission, or deletion. It does not inspect diagnostic content and does not upload diagnostics itself. See [PRIVACY.md](./PRIVACY.md) for the exact command routing and fields.

## Privacy and license

The complete launcher privacy boundary is documented in [PRIVACY.md](./PRIVACY.md).

The public `goatcli` launcher source is licensed under the MIT License. The private engine, private control plane, and distributed engine binaries are separate works and are not licensed by this package; see [NOTICE](./NOTICE).
