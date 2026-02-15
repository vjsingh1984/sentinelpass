# Build Guide

## Toolchain Matrix

| Tool | Minimum |
| --- | --- |
| Rust | 1.70+ |
| Node.js | 20+ |
| npm | 10+ |
| PowerShell (Windows install scripts) | 5.1+ |

## Platform Dependencies

| Platform | Extra system packages |
| --- | --- |
| Windows | None (Tauri Windows toolchain is sufficient) |
| macOS | `brew install openssl` |
| Ubuntu/Debian | `libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev libssl-dev build-essential` |

## Build Commands

```bash
npm install
npm run web:build
cargo build --release
```

## Fast Dev Commands

| Task | Command |
| --- | --- |
| UI (debug) | `cargo run --package sentinelpass-ui` |
| Daemon | `cargo run --package sentinelpass-daemon` |
| CLI help | `cargo run --package sentinelpass-cli -- --help` |
| Rust tests | `cargo test --workspace` |
| Rust lint | `cargo clippy --workspace --all-targets -- -D warnings` |
| TS typecheck | `npm run web:typecheck` |
| TS tests | `npm run test:ts` |

## Coverage Gates

| Coverage gate | Command |
| --- | --- |
| Rust LLVM coverage | `bash scripts/coverage-rust.sh` |
| TypeScript coverage | `npm run test:ts` |

## Release CI (tagged)

| Step | Detail |
| --- | --- |
| Trigger | Push tag `v*` |
| Workflow | `.github/workflows/release.yml` |
| Binaries | `sentinelpass`, `sentinelpass-daemon`, `sentinelpass-host`, `sentinelpass-ui` |
| Install bundles | user-level installers for Windows/macOS/Linux |
| Native installers | NSIS/MSI (Windows), DMG/pkg (macOS), AppImage/DEB/RPM (Linux, runner dependent) |

## Browser Native Host Registration (Chrome)

```powershell
./register-chrome.ps1 -ExtensionId <YOUR_32_CHAR_EXTENSION_ID> -InstallDir <INSTALL_DIR>
```

If Chrome reports native host permission errors, re-run registration and restart Chrome.

