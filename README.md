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

## Install

| Platform | Method |
| --- | --- |
| macOS | Download the DMG from [Releases](../../releases), open it, drag SentinelPass to Applications |
| Windows | Download the MSI installer from [Releases](../../releases) and run it |
| Linux (Debian/Ubuntu) | `sudo dpkg -i sentinelpass-*.deb` |
| Linux (Fedora/RHEL) | `sudo dnf install sentinelpass-*.rpm` |
| Build from source | `npm install && npm run web:build && cargo build --release` |

> **Tip:** GitHub release links use 302 redirects — use `curl -L -O <url>` when downloading from the command line.

## First Launch

1. Open **SentinelPass** from your Applications folder / Start Menu / launcher.
2. Create a new vault and set a master password.
3. The app automatically starts the background daemon and registers the native messaging host for Chrome, Chromium, and Firefox.

## Browser Extension

| Browser | Steps |
| --- | --- |
| Chrome | `chrome://extensions/` → enable **Developer mode** → **Load unpacked** → select `browser-extension/chrome/` |
| Firefox | `about:debugging#/runtime/this-firefox` → **Load Temporary Add-on** → select `browser-extension/firefox/manifest.json` |

After installing the extension, **restart the browser** so it picks up the native messaging host manifest written by the app.

## Verify

1. Visit any login page — an autofill icon should appear next to password fields.
2. If not, check the Troubleshooting section below.

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| "Specified native messaging host not found" | Restart the browser after launching SentinelPass at least once |
| Autofill icon doesn't appear | Ensure the daemon is running (check SentinelPass UI status) |
| "Vault is locked" | Unlock the vault in the SentinelPass UI first |
| Extension installed but not working | Open DevTools → Console → filter for `[SentinelPass]` logs |

You can also re-register the native host manually:

```bash
# macOS / Linux — from installed app bundle
./installation/install.sh --from-app-bundle

# macOS / Linux — from source build
./installation/install.sh
```

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
