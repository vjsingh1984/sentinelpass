# SentinelPass

A secure, local-first password manager with browser autofill support.

## Features

- **Zero-Knowledge Architecture**: Master password never leaves your device
- **Military-Grade Encryption**: Argon2id KDF + AES-256-GCM encryption
- **Browser Autofill**: Chrome extension with seamless autofill
- **TOTP Support**: RFC 6238 codes with `otpauth://` provisioning support
- **Desktop TOTP Setup & Copy**: Configure/remove TOTP and copy current codes from entry details
- **Offline-First**: No cloud dependencies, works completely offline
- **Cross-Platform**: Windows, macOS, and Linux support

## Security

- **Key Derivation**: Argon2id (m=256MB, t=3, p=4)
- **Encryption**: AES-256-GCM with unique nonces per entry
- **Memory Safety**: Rust's memory safety guarantees + secure buffer handling
- **Zero-Knowledge**: Your master password is never stored or transmitted
- **Clipboard Hygiene**: Copied secrets are auto-cleared after 30 seconds when unchanged

## Getting Started

### Prerequisites

- Rust 1.70 or later
- Node.js 20+ (for TypeScript web/extension builds)
- Chrome or Chromium-based browser
- For Windows: PowerShell 5.1+
- For Unix: Bash and standard Unix tools

### Installation

#### One-Click Installer (Release Assets)

Tagged GitHub releases include user-level installer bundles per platform:

- Windows: `sentinelpass-installer-<tag>-windows.zip` → run `install-user.cmd`
- macOS: `sentinelpass-installer-<tag>-macos.tar.gz` → run `install-user.command`
- Linux: `sentinelpass-installer-<tag>-linux.tar.gz` → run `install-user.sh`

These installers default to user-scope paths (no admin needed).

#### Build Native Installers Locally

To generate platform-native installers (NSIS/MSI, DMG, AppImage/DEB) locally:

```bash
# macOS/Linux
./scripts/build-native-installers.sh

# Windows (PowerShell)
.\scripts\build-native-installers.ps1
```

Both scripts package `sentinelpass-daemon` and `sentinelpass-host` into UI bundle resources before `cargo tauri build`.

#### From Source

```bash
# Clone the repository
git clone https://github.com/vjsingh1984/sentinelpass.git
cd sentinelpass

# Build the project
npm install
npm run web:build
cargo build --release

# Install (Windows, user-level one-stop)
.\install.ps1

# Install (macOS/Linux, user-level one-stop)
./install.sh

# Optional: preconfigure Chrome native host for your unpacked extension ID
./install.sh --chrome-extension-id <YOUR_32_CHAR_EXTENSION_ID>
# Windows:
.\install.ps1 -ExtensionId <YOUR_32_CHAR_EXTENSION_ID>
```

### Initial Setup

```bash
# Create a new vault
sentinelpass init

# Add a credential
sentinelpass add --title "GitHub" --username "user@example.com" --url "https://github.com"

# List all credentials
sentinelpass list

# Search credentials
sentinelpass search github

# Add TOTP from an otpauth URI (from QR payload)
sentinelpass totp-add --entry-id 1 --otpauth-uri "otpauth://totp/Acme:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Acme"

# Get current TOTP code
sentinelpass totp-code --entry-id 1

# Check biometric unlock status
sentinelpass biometric-status

# Enable biometric unlock (if platform support is available)
sentinelpass biometric-enable

# Unlock with biometric
sentinelpass unlock-biometric

# Disable biometric unlock
sentinelpass biometric-disable

# Check SSH agent availability
sentinelpass ssh-agent-status

# Add private key to SSH agent
sentinelpass ssh-agent-add ~/.ssh/id_ed25519

# Add stored vault SSH key (by ID) to SSH agent without writing to disk
sentinelpass ssh-agent-add-stored 1

# Clear all identities from SSH agent
sentinelpass ssh-agent-clear

# Add an SSH key pair to vault
sentinelpass ssh-key-add --name "Work Laptop" --private-key-file ~/.ssh/id_ed25519

# List SSH keys in vault
sentinelpass ssh-key-list

# Show SSH key metadata (and optionally private key)
sentinelpass ssh-key-get 1
sentinelpass ssh-key-get 1 --show-private

# Delete an SSH key
sentinelpass ssh-key-delete 1
```

### Running the Daemon

Browser autofill and save require the daemon:

- `sentinelpass-ui` now auto-starts `sentinelpass-daemon` in locked mode on app launch.
- Unlocking the vault in UI also unlocks the daemon for browser integration.
- You can still run the daemon manually for CLI-only workflows:

```bash
sentinelpass-daemon

# Start daemon using biometric unlock flow
sentinelpass-daemon --biometric

# Start daemon without interactive prompt (for orchestration)
sentinelpass-daemon --start-locked
```

The daemon will:
- Start locked when launched by UI (or with `--start-locked`)
- Prompt for master password only in interactive mode (or use `--biometric`)
- Start the IPC server for communication with the browser extension
- Auto-lock after 5 minutes of inactivity (configurable)

### Browser Extension

1. Start `sentinelpass-ui` (it auto-starts the daemon)
2. Open Chrome and navigate to `chrome://extensions/`
3. Enable "Developer mode"
4. Click "Load unpacked"
5. Select the `browser-extension/chrome/` directory
6. The extension is now ready to use

**Using Autofill:**
- Navigate to a login page
- Click the autofill button (🔒) that appears next to password fields
- Or use the keyboard shortcut: `Ctrl+Shift+U` (Windows/Linux) or `Cmd+Shift+U` (macOS)
- Credentials will be filled automatically

## Development

```bash
# Run tests
cargo test --workspace

# Type-check web/extension TypeScript
npm run web:typecheck

# Run TypeScript unit tests with coverage (TDD gate)
npm run test:ts

# Run Clippy
cargo clippy --workspace --all-targets -- -D warnings

# Format code
cargo fmt --all

# Run the daemon
cargo run --bin sentinelpass-daemon

# Build everything
cargo build --workspace
```

## Test & Coverage Gates

- Rust tests: `bash scripts/test-rust.sh`
- Rust LLVM coverage: `bash scripts/coverage-rust.sh` (requires `cargo-llvm-cov`)
- TypeScript tests + coverage: `bash scripts/test-web.sh`
- Pre-commit hook runs lint + tests for touched Rust/TS files (`.githooks/pre-commit`)

## Project Structure

```
sentinelpass/
├── sentinelpass-core/     # Core library (crypto, database, IPC)
├── sentinelpass-cli/      # Command-line interface
├── sentinelpass-daemon/   # Background service for vault management
├── sentinelpass-host/     # Native messaging host for browser extension
├── browser-extension/     # Chrome/Firefox extension (TypeScript sources + emitted JS)
├── sentinelpass-ui/       # Tauri desktop frontend (TypeScript app + dist assets)
└── installation/          # Installation scripts
```

## Security Architecture

See [SECURITY_ARCHITECTURE.md](SECURITY_ARCHITECTURE.md) for detailed security documentation.

## License

Apache-2.0 License - see LICENSE file for details

## Contributing

Contributions are welcome! Please read SECURITY_ARCHITECTURE.md before making changes to security-critical code.

## Architecture

```
┌─────────────────┐
│  Chrome Browser │
│                 │
│  ┌───────────┐  │
│  │ Extension │  │
│  └─────┬─────┘  │
└────────┼────────┘
         │ native messaging
         ▼
┌─────────────────────────┐
│   sentinelpass-host     │
│  (Native Messaging)     │
└────────┬────────────────┘
         │ IPC (Unix socket / named pipe)
         ▼
┌─────────────────────────┐
│  sentinelpass-daemon    │
│   └── DaemonVault       │
│       └── VaultManager  │
│           ├── Crypto    │
│           └── Database  │
└─────────────────────────┘
```
