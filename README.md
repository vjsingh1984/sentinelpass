# SentinelPass

A secure, local-first password manager with browser autofill support.

## Features

- **Zero-Knowledge Architecture**: Master password never leaves your device
- **Military-Grade Encryption**: Argon2id KDF + AES-256-GCM encryption
- **Browser Autofill**: Chrome extension with seamless autofill
- **Offline-First**: No cloud dependencies, works completely offline
- **Cross-Platform**: Windows, macOS, and Linux support

## Security

- **Key Derivation**: Argon2id (m=256MB, t=3, p=4)
- **Encryption**: AES-256-GCM with unique nonces per entry
- **Memory Safety**: Rust's memory safety guarantees + secure buffer handling
- **Zero-Knowledge**: Your master password is never stored or transmitted

## Getting Started

### Prerequisites

- Rust 1.70 or later
- Chrome or Chromium-based browser
- For Windows: PowerShell 5.1+
- For Unix: Bash and standard Unix tools

### Installation

#### From Source

```bash
# Clone the repository
git clone https://github.com/vjsingh1984/sentinelpass.git
cd sentinelpass

# Build the project
cargo build --release

# Install (Windows - run PowerShell as Administrator)
.\installation\install.ps1

# Install (macOS/Linux)
sudo ./installation/install.sh
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
```

### Running the Daemon

The daemon must be running for browser autofill to work:

```bash
sentinelpass-daemon
```

The daemon will:
- Prompt for your master password to unlock the vault
- Start the IPC server for communication with the browser extension
- Auto-lock after 5 minutes of inactivity (configurable)

### Browser Extension

1. Start the daemon: `sentinelpass-daemon`
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

# Run Clippy
cargo clippy --workspace --all-targets -- -D warnings

# Format code
cargo fmt --all

# Run the daemon
cargo run --bin sentinelpass-daemon

# Build everything
cargo build --workspace
```

## Project Structure

```
sentinelpass/
├── sentinelpass-core/     # Core library (crypto, database, IPC)
├── sentinelpass-cli/      # Command-line interface
├── sentinelpass-daemon/   # Background service for vault management
├── sentinelpass-host/     # Native messaging host for browser extension
├── browser-extension/     # Chrome extension
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
