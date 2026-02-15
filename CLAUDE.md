# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SentinelPass is a secure, local-first password manager written in Rust with a Tauri desktop UI, browser extensions (Chrome/Firefox), and native messaging architecture. The project uses zero-knowledge architecture with military-grade encryption (Argon2id KDF + AES-256-GCM).

## Common Commands

### Build Commands
```bash
# Build all workspace members (release)
cargo build --release

# Build specific package
cargo build --package sentinelpass-ui
cargo build --package sentinelpass-cli

# Development build (faster)
cargo build --workspace
```

### Test Commands
```bash
# Run all tests
cargo test --workspace

# Run tests with output
cargo test --workspace -- --nocapture

# Run integration tests
cargo test --workspace --test '*'

# Run security tests
cargo test --workspace security

# Run specific test
cargo test --package sentinelpass-core crypto::tests
```

### Linting & Formatting
```bash
# Format code
cargo fmt --all

# Check formatting
cargo fmt --all -- --check

# Run Clippy linter
cargo clippy --workspace --all-targets -- -D warnings
```

### Running Applications
```bash
# Run daemon (required for browser extension)
cargo run --bin sentinelpass-daemon

# Run CLI
cargo run --bin sentinelpass-cli -- [args]

# Run Tauri UI
cargo run --package sentinelpass-ui

# Run native messaging host
cargo run --bin sentinelpass-host
```

### Using Just (Command Runner)
The project includes a `justfile` with common commands:
```bash
just build          # Build release
just test           # Run tests
just lint           # Run clippy + fmt-check
just ci             # Run full CI pipeline
just daemon         # Run daemon
just cli            # Run CLI
```

### Browser Extension Installation (Windows)
```powershell
# Install native messaging host
.\install.ps1

# Register Chrome extension
.\register-chrome.ps1 <EXTENSION_ID>

# Register Firefox extension
.\register-firefox.ps1
```

## Architecture Overview

### Component Architecture

```
Browser Extension (Chrome/Firefox)
    ↓ Native Messaging (stdio JSON)
sentinelpass-host
    ↓ IPC (Unix socket / TCP)
sentinelpass-daemon
    ├── VaultManager (CRUD operations)
    ├── Crypto (Argon2id + AES-256-GCM)
    └── Database (SQLite with encrypted entries)
```

### Key Components

**sentinelpass-core/** - Core library containing:
- `crypto/` - Argon2id KDF, AES-256-GCM encryption, keyring management
- `database/` - SQLite schema, migrations, models
- `daemon/` - IPC server, native messaging protocol, vault state management
- `vault.rs` - VaultManager with lock/unlock operations
- `audit.rs` - Security event logging
- `lockout.rs` - Failed attempt lockout (exponential backoff)
- `biometric.rs` - OS keystore integration (Keychain/DPAPI)
- `ssh.rs` - SSH key storage and ssh-agent integration

**sentinelpass-daemon/** - Background service:
- Runs Tokio async runtime
- Manages DaemonVault with auto-lock (5 min default)
- IPC server: Unix socket on Linux/macOS, TCP on Windows
- Handles native messaging requests from browser

**sentinelpass-host/** - Native messaging bridge:
- stdin/stdout JSON protocol (length-prefixed)
- Translates between browser extension and daemon
- Must be registered in OS registry/manifest

**sentinelpass-cli/** - Command-line interface:
- Clap-based CLI with subcommands
- Commands: init, add, list, search, edit, delete, generate

**sentinelpass-ui/** - Tauri desktop application:
- `src-tauri/src/` - Tauri backend (Rust commands)
- `app.js` - Vanilla JS frontend
- `index.html` - UI markup (login screen, vault list, entry detail)

**browser-extension/** - Chrome & Firefox extensions:
- `chrome/manifest.json` - MV3 manifest
- `chrome/background.js` - Service worker, native messaging client
- `chrome/content.js` - Password field detection, autofill button injection
- `firefox/` - MV2 manifest (reuses chrome scripts)

## Communication Protocols

### Native Messaging Protocol

**Message Format:** Length-prefixed JSON
```
[4 bytes: message length as little-endian u32][JSON payload]
```

**Request Types:**
- `get_credential` - Retrieve credentials for domain
- `save_credential` - Save new credentials
- `check_credential_exists` - Check if credential exists
- `check_vault_status` - Check if vault is unlocked

**Response Structure:**
```json
{
  "version": 1,
  "type": "credential_response",
  "request_id": "uuid",
  "success": true,
  "data": { "username": "...", "password": "...", "title": "..." },
  "error": null
}
```

### IPC (Inter-Process Communication)

**Unix (Linux/macOS):** Unix domain socket at `/tmp/sentinelpass.sock`
**Windows:** TCP localhost at `tcp://127.0.0.1:35873`

## Cryptographic Architecture

### Key Derivation
- Algorithm: Argon2id
- Memory: 256 MB (m=262,144 blocks)
- Iterations: 3 (t=3)
- Parallelism: 4 lanes (p=4)
- Salt: 16 random bytes
- Output: 32-byte master key

### Encryption
- Algorithm: AES-256-GCM
- Per-entry unique nonces (96-bit)
- Authentication tag: 128-bit
- No nonce reuse (critical for security)

### Key Hierarchy
```
Master Password
  ↓ Argon2id
Master Key (32 bytes)
  ↓
┌──────────────┬──────────────┬──────────────┐
│  Vault Key  │  HMAC Key   │  Biometric  │
│  (wrapped)  │  (derived)  │   Wrapper   │
└──────────────┴──────────────┴──────────────┘
  ↓
Data Encryption Key (DEK)
  ↓
Per-entry AES-256-GCM encryption
```

## Security-Critical Development Rules

### NEVER:
1. **Log secrets** - Use redacted logging for sensitive data
2. **Use `String` for passwords** - Always use `SecureBuffer` from `crypto/keyring.rs`
3. **Compare passwords with `==`** - Use constant-time compare from `subtle` crate
4. **Reuse nonces** - Always generate random per-entry nonce
5. **Skip authentication tag validation** - GCM tag is mandatory
6. **Write plaintext to disk** - Even for debugging
7. **Trust domain from browser** - Validate daemon-side with TLD matching
8. **Return full vault to extension** - Only return requested credential

### ALWAYS:
1. Use parameterized queries only (SQL injection protection)
2. Call `zeroize()` on secrets before dropping
3. Use `mlock()` via `memsec` crate to prevent swap
4. Validate domain on daemon-side, not browser-side
5. Use exponential backoff for failed auth attempts
6. Implement constant-time operations for secret comparison
7. Run `cargo clippy` and `cargo test` before committing

## Testing Browser Extension

### Debugging Content Script
1. Open DevTools (F12) → Console tab
2. Filter for `[SentinelPass]` logs
3. Look for: `[SentinelPass] Content script loaded`
4. Check password field detection logs

### Debugging Background Worker
1. Navigate to `chrome://extensions/`
2. Find "SentinelPass" extension
3. Click "Service worker" link
4. Look for `[SentinelPass Background]` logs

### Manual Testing Checklist
- [ ] Content script loads on page
- [ ] Password fields detected (check console count)
- [ ] Autofill button appears next to password fields
- [ ] Save prompt appears after registration form submission
- [ ] Credentials saved to vault (verify via CLI)
- [ ] Background script communicates with native host

See `browser-extension/chrome/DEBUGGING.md` for detailed debugging guide.

## Platform-Specific Notes

### Windows
- Build from native Windows (not WSL) for proper executable
- Registry paths for native messaging:
  - Chrome: `HKCU\Software\Google\Chrome\NativeMessagingHosts\`
  - Firefox: `HKCU\Software\Mozilla\NativeMessagingHosts\`
- IPC uses TCP localhost (not Unix sockets)

### macOS
- OS keystore: Keychain for biometric wrapper
- IPC uses Unix domain sockets
- Native messaging: `~/Library/Application Support/Mozilla/NativeMessagingHosts/`

### Linux
- Install GTK development libraries for Tauri UI
- IPC uses Unix domain sockets
- Native messaging: `~/.config/mozilla/native-messaging-hosts/`

## Common Development Workflows

### Adding a New Credential Field
1. Update `database/schema.rs` (add column to table)
2. Create migration in `migrations/` folder
3. Update `database/models.rs` (struct field)
4. Update `native_messaging.rs` (request/response serialization)
5. Update extension `background.js` and `content.js`
6. Update Tauri UI `app.js` and `index.html`

### Adding a New Native Message Type
1. Add message type constant to `daemon/native_messaging.rs`
2. Create request/response structs with serde
3. Add handler in `NativeMessagingHost::handle_message()`
4. Update extension `background.js` to send new message type
5. Add documentation to CLAUDE.md and DEBUGGING.md

### Testing Database Changes
```bash
# Initialize dev database
cargo run --bin pm-cli -- init --dev

# Run migrations
cargo run --bin pm-daemon  # Daemon auto-runs migrations

# Verify schema
sqlite3 ~/.sentinelpass/vault.db ".schema"
```

## Important File Locations

- **Vault database:** `~/.sentinelpass/vault.db` (SQLite, encrypted entries)
- **Daemon logs:** Platform-specific (Windows: Event Viewer, Unix: syslog)
- **Native messaging config:**
  - Windows: `C:\Program Files\PasswordManager\com.passwordmanager.host.json`
  - macOS/Linux: `~/.config/mozilla/native-messaging-hosts/`

## Known Limitations

1. Single-user vault (multi-user schema exists but not implemented)
2. TOTP is available in core + CLI; browser/UI setup flows are still maturing
3. SSH key storage and CLI management are implemented; advanced SSH workflows (UI, richer key lifecycle ops) remain limited
4. No KeePass import/export yet (schema exists)
5. Biometric unlock is integrated with Windows Hello and macOS LocalAuthentication (Touch ID); Linux remains unsupported

## CI/CD Pipeline

The project uses GitHub Actions (`.github/workflows/rust.yml`):
- Format check (`cargo fmt --all -- --check`)
- Clippy lint (`cargo clippy --workspace --all-targets -- -D warnings`)
- Tests (`cargo test --workspace --verbose`)
- Security audit (`cargo audit`)
- Build (`cargo build --release --workspace`)

All checks must pass before merging to main branch.

## Git Workflow

- **Main branch:** `main` (protected, requires CI + review)
- **Development branch:** `develop`
- **Commit format:** Conventional Commits (`feat:`, `fix:`, `docs:`, etc.)
- **Branch protection:** CI required, 1 approval, no force pushes

## Dependencies Note

The workspace uses centralized dependency management in `Cargo.toml` [workspace.dependencies]. When adding new dependencies, prefer:
- Adding to workspace dependencies if used by multiple crates
- Using workspace version (`{ workspace = true }`) in crate Cargo.toml
