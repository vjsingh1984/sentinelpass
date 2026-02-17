# SentinelPass Documentation Index

Quick reference to all project documentation. Most docs live at the repository root; this index serves as a table of contents.

## Project

| Document | Description | Keywords |
|----------|-------------|----------|
| [README.md](../README.md) | Project overview, installation, and quick start | install, setup, quick start, runtime, daemon |
| [BUILD.md](../BUILD.md) | Toolchain requirements, build commands, coverage gates | cargo, npm, build, coverage, toolchain, platform |
| [CONTRIBUTING.md](../CONTRIBUTING.md) | Contribution workflow, quality gates, PR process | PR, commit, lint, clippy, fmt, test, branch |
| [CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md) | Community standards and expectations | conduct, community |
| [SUPPORT.md](../SUPPORT.md) | How to get help | help, support, issues |

## Security

| Document | Description | Keywords |
|----------|-------------|----------|
| [SECURITY.md](../SECURITY.md) | Vulnerability reporting policy | CVE, vulnerability, disclosure, reporting |
| [SECURITY_ARCHITECTURE.md](../SECURITY_ARCHITECTURE.md) | Cryptographic design, threat model, hardening | Argon2id, AES-256-GCM, key hierarchy, KDF, nonce, zeroize, IPC token, biometric, threat model |

## Development

| Document | Description | Keywords |
|----------|-------------|----------|
| [CLAUDE.md](../CLAUDE.md) | Architecture reference, commands, protocols, coding style | architecture, IPC, native messaging, vault, crypto, TOTP, SSH, CLI, Tauri, daemon |
| [AGENTS.md](../AGENTS.md) | Multi-agent task delegation configuration | agents, delegation |
| [TECHNICAL_DEBT.md](../TECHNICAL_DEBT.md) | Verified issues tracker and roadmap | debt, migration, refinery, IPC token, constant-time |

## Subsystem Docs

| Document | Description | Keywords |
|----------|-------------|----------|
| [docs/OSS_RELEASE_CHECKLIST.md](./OSS_RELEASE_CHECKLIST.md) | Open-source release governance checklist | release, Apache-2.0, license, artifacts |
| [browser-extension/chrome/DEBUGGING.md](../browser-extension/chrome/DEBUGGING.md) | Chrome extension debugging guide | extension, DevTools, content script, background worker, autofill |
| [browser-extension/e2e/README.md](../browser-extension/e2e/README.md) | Browser integration test setup and usage | Playwright, e2e, extension test |
| [sentinelpass-ui/README.md](../sentinelpass-ui/README.md) | Tauri desktop UI build and architecture | Tauri, UI, TypeScript, app.ts, native host |

## Blog & Marketing

| Document | Description |
|----------|-------------|
| [blogs/](../blogs/) | Launch articles and technical infographics |

## Topic Quick-Reference

Looking for something specific? Use these pointers:

| Topic | Where to look |
|-------|---------------|
| **Vault CRUD** | [CLAUDE.md](../CLAUDE.md) § Architecture Overview, `sentinelpass-core/src/vault/` |
| **Crypto (KDF, cipher)** | [SECURITY_ARCHITECTURE.md](../SECURITY_ARCHITECTURE.md), `sentinelpass-core/src/crypto/` |
| **IPC protocol** | [CLAUDE.md](../CLAUDE.md) § IPC, `sentinelpass-core/src/daemon/ipc.rs` |
| **Native messaging** | [CLAUDE.md](../CLAUDE.md) § Native Messaging Protocol, `sentinelpass-core/src/daemon/native_messaging.rs` |
| **Browser extension** | [DEBUGGING.md](../browser-extension/chrome/DEBUGGING.md), `browser-extension/chrome/` |
| **TOTP** | [CLAUDE.md](../CLAUDE.md) § Adding a New Native Message Type, `sentinelpass-core/src/totp.rs` |
| **SSH keys** | `sentinelpass-core/src/ssh.rs` (comprehensive Rust doc comments) |
| **Biometrics** | `sentinelpass-core/src/biometric.rs` (comprehensive Rust doc comments) |
| **Auto-lock** | `sentinelpass-core/src/daemon/autolock.rs` (comprehensive Rust doc comments) |
| **Database models** | `sentinelpass-core/src/database/models.rs`, `sentinelpass-core/src/database/schema.rs` |
| **Testing** | [CLAUDE.md](../CLAUDE.md) § Common Commands → Test, [BUILD.md](../BUILD.md) |
| **Release process** | [OSS_RELEASE_CHECKLIST.md](./OSS_RELEASE_CHECKLIST.md), `.github/workflows/release.yml` |
| **Rust API docs** | Run `cargo doc --no-deps --open` locally |
