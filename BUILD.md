# Building SentinelPass

## Windows

### Building from Windows (Recommended)
Open **PowerShell** or **Command Prompt** and run:

```powershell
# Build all components
cargo build --release

# Run the UI
cargo run --package sentinelpass-ui

# Run the CLI
cargo run --package sentinelpass-cli -- --help
```

No additional dependencies required - Tauri for Windows bundles everything needed.

### WSL Users
If you try to build from WSL, you will get GTK library errors. To build the UI from WSL, you must install GTK development libraries:

```bash
sudo apt update
sudo apt install -y libwebkit2gtk-4.1-dev \
    build-essential \
    curl \
    wget \
    file \
    libssl-dev \
    libgtk-3-dev \
    libayatana-appindicator3-dev \
    librsvg2-dev
```

However, **building from native Windows is recommended** as it produces a proper Windows executable and doesn't require installing system libraries.

## macOS

```bash
# Install dependencies
brew install openssl

# Build
cargo build --release
```

## Linux

```bash
# Install dependencies (Ubuntu/Debian)
sudo apt update
sudo apt install -y libwebkit2gtk-4.1-dev \
    build-essential \
    curl \
    wget \
    file \
    libssl-dev \
    libgtk-3-dev \
    libayatana-appindicator3-dev \
    librsvg2-dev

# Build
cargo build --release
```

## Development Builds

For faster development builds without optimizations:

```bash
cargo build --package sentinelpass-ui
```

## Release Builds

For optimized release builds:

```bash
cargo build --release --package sentinelpass-ui
```

The release binary will be at:
- Windows: `target/release/sentinelpass-ui.exe`
- macOS/Linux: `target/release/sentinelpass-ui`

## Automated Release CI

GitHub Actions release automation runs when you push a version tag (`v*`), for example:

```bash
git tag v0.1.6
git push origin v0.1.6
```

The `Release CI` workflow builds and publishes platform executables for:
- Ubuntu (`linux`)
- macOS (`macos`)
- Windows (`windows`)

Each tagged release now publishes:
- Portable archives with binaries (`sentinelpass`, `sentinelpass-daemon`, `sentinelpass-host`, `sentinelpass-ui`)
- User-level installer bundles (`sentinelpass-installer-<tag>-<platform>.*`) with one-click launchers:
  - Windows: `install-user.cmd`
  - macOS: `install-user.command`
  - Linux: `install-user.sh`
- `sha256sums.txt`

Installer bundles run the same user-scoped install flow as local scripts (`install.ps1` / `install.sh`) without requiring admin privileges.

In addition, `Release CI` now builds native platform installers from Tauri bundles:
- Windows: NSIS/MSI
- macOS: DMG (and pkg/app artifacts when available)
- Linux: AppImage/DEB/RPM (depending on runner capabilities)

Signed builds are enabled automatically when signing secrets are configured in repository settings; otherwise unsigned artifacts are still produced for release testing.

For local native installer builds, use:

```bash
./scripts/build-native-installers.sh
```

or on Windows:

```powershell
.\scripts\build-native-installers.ps1
```

## Browser Integration Tests (Extension)

An end-to-end browser automation suite is available at:

- `browser-extension/e2e/`

It validates save-prompt behavior and explicit no-save/save audit paths.

## Chrome Native Host Troubleshooting

If browser logs show `Access to the specified native messaging host is forbidden`:

1. Copy your extension ID from `chrome://extensions/` (or extension background logs).
2. Re-register the native host manifest:

```powershell
.\register-chrome.ps1 -ExtensionId <YOUR_32_CHAR_EXTENSION_ID> -InstallDir "$env:LOCALAPPDATA\SentinelPass"
```

3. Restart Chrome and re-test.

This updates `allowed_origins` in the native messaging host manifest to include:
`chrome-extension://<YOUR_EXTENSION_ID>/`.
