# Password Manager

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
git clone https://github.com/yourusername/passwordmanager.git
cd passwordmanager

# Build the project
just build

# Install the native messaging host
just install-host-windows  # Windows
# or
just install-host-unix     # macOS/Linux
```

### Initial Setup

```bash
# Create a new vault
pm-cli init

# Unlock your vault
pm-cli unlock

# Add a credential
pm-cli add --title "GitHub" --username "user@example.com" --url "https://github.com"

# List all credentials
pm-cli list

# Search credentials
pm-cli search github
```

### Browser Extension

1. Open Chrome and navigate to `chrome://extensions/`
2. Enable "Developer mode"
3. Click "Load unpacked"
4. Select the `browser-extension/chrome/` directory
5. The extension is now ready to use

## Development

```bash
# Run tests
just test

# Run Clippy
just clippy

# Format code
just fmt

# Run the daemon
just daemon

# Build everything
just build
```

## Project Structure

```
passwordmanager/
├── pm-core/              # Core library (crypto, database, IPC)
├── pm-cli/               # Command-line interface
├── pm-daemon/            # Background service for vault management
├── pm-host/              # Native messaging host for browser extension
├── browser-extension/    # Chrome extension
├── migrations/           # Database migrations
└── installation/         # Installation scripts
```

## Security Architecture

See [SECURITY_ARCHITECTURE.md](SECURITY_ARCHITECTURE.md) for detailed security documentation.

## License

MIT License - see LICENSE file for details

## Contributing

Contributions are welcome! Please read SECURITY_ARCHITECTURE.md before making changes to security-critical code.
