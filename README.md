# SentinelPass

Local-first password manager with a Rust core, Tauri desktop UI, and browser extension.

## At a Glance

| Area | What SentinelPass does |
| --- | --- |
| Secret model | Zero-knowledge, local vault; no cloud dependency |
| Crypto | Argon2id key derivation + AES-256-GCM encryption |
| App surfaces | CLI (`sentinelpass`), daemon, desktop UI, browser extension |
| Platforms | Windows, macOS, Linux |
| License | Apache License 2.0 |

## System Map

| Component | Path | Responsibility |
| --- | --- | --- |
| Core library | `sentinelpass-core/` | Crypto, vault, DB, IPC contracts |
| CLI | `sentinelpass-cli/` | Vault operations from terminal |
| Daemon | `sentinelpass-daemon/` | Background unlock/lock state + IPC |
| Native host | `sentinelpass-host/` | Browser native messaging bridge |
| Desktop app | `sentinelpass-ui/` | Tauri UI and user unlock workflow |
| Browser extension | `browser-extension/` | Autofill + save prompts |

## Runtime Flow

```text
Browser Extension -> sentinelpass-host -> sentinelpass-daemon -> sentinelpass-core (vault)
                         ^
                         |
                    sentinelpass-ui (unlock + state)
```

## Quick Start

### 1) Build

```bash
npm install
npm run web:build
cargo build --release
```

### 2) Install (user-level, no admin)

```bash
# Windows
./install.ps1

# macOS / Linux
./install.sh
```

### 3) Run

```bash
sentinelpass-ui
```

UI startup coordinates daemon startup; unlocking in UI enables browser save/autofill paths.

## Developer Loop

| Task | Command |
| --- | --- |
| Rust format check | `cargo fmt --all -- --check` |
| Rust lint (deny warnings) | `cargo clippy --workspace --all-targets -- -D warnings` |
| Rust tests | `cargo test --workspace` |
| TypeScript typecheck | `npm run web:typecheck` |
| TypeScript tests + coverage | `npm run test:ts` |
| Rust coverage (LLVM) | `bash scripts/coverage-rust.sh` |

## Release Artifacts

| Trigger | Workflow | Output |
| --- | --- | --- |
| Git tag `v*` | `Release CI` | cross-platform binaries + installer bundles |
| Push / PR | `Rust CI`, `Security CI`, `extension-e2e` | lint, tests, security scans, extension e2e |

## OSS and Contribution Docs

| Topic | File |
| --- | --- |
| Contribution process | `CONTRIBUTING.md` |
| Security reporting | `SECURITY.md` |
| Code of conduct | `CODE_OF_CONDUCT.md` |
| OSS release checklist | `docs/OSS_RELEASE_CHECKLIST.md` |
| Build details | `BUILD.md` |
| Security internals | `SECURITY_ARCHITECTURE.md` |
