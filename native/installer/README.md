# Native GOAT installer

This crate builds the standalone `goat-installer`/`goat` executable. It is the no-Node, no-npm installation path for Windows and macOS on x64 and arm64.

The binary has two modes:

- When run as the downloaded installer, it installs itself to the per-user GOAT directory, adds that directory to the user PATH, and downloads the matching standalone engine.
- When run from the installed path, it verifies the local engine and forwards commands directly to it. `goat update` downloads the pinned engine release again.

The installer has no runtime services beyond its small cryptography/JSON dependencies. Downloads use the operating system's built-in PowerShell (`windows`) or `curl` (`macOS`) and extraction uses the operating system's `tar`. The origin, package name, platform, architecture, and engine version are compiled into the binary; no environment variable or command-line option can redirect the download.

Build targets:

| OS      | Architecture | Rust target               |
| ------- | ------------ | ------------------------- |
| Windows | x64          | `x86_64-pc-windows-msvc`  |
| Windows | arm64        | `aarch64-pc-windows-msvc` |
| macOS   | x64          | `x86_64-apple-darwin`     |
| macOS   | arm64        | `aarch64-apple-darwin`    |

The installer embeds the production Ed25519 public key at release build time and verifies the signed engine manifest plus executable SHA-256 before activation and before each launch. Development builds without embedded trust material fail closed when an engine is requested. The release pipeline must publish the four matching engine packages before publishing native installer binaries.
