# PASSWORD MANAGER - SECURITY ARCHITECTURE SPECIFICATION

## 1. HIGH-LEVEL ARCHITECTURE

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           USER INTERFACES                                     │
├──────────────┬──────────────┬──────────────┬──────────────┬─────────────────┤
│   Desktop    │   Chrome    │   Safari    │   Firefox   │    SSH Agent    │
│   (Tauri)    │ Extension   │ Extension   │ Extension   │   Integration   │
└──────┬───────┴──────┬───────┴──────┬───────┴──────┬──────┴────────┬────────┘
       │              │              │              │               │
       │    Native    │    Native    │    Native    │               │
       │   Messaging  │   Messaging  │   Messaging  │               │
       │              │              │              │               │
       └──────────────┴──────────────┴──────────────┘               │
                              │                                       │
                              ▼                                       │
                    ┌─────────────────────┐                          │
                    │   Core Daemon       │                          │
                    │   (Rust Binary)     │                          │
                    └──────────┬──────────┘                          │
                               │                                       │
                               ▼                                       │
                    ┌─────────────────────┐                          │
                    │  Crypto Engine      │                          │
                    │  - Argon2id KDF     │                          │
                    │  - AES-256-GCM      │                          │
                    │  - Key Management   │                          │
                    └──────────┬──────────┘                          │
                               │                                       │
                               ▼                                       │
                    ┌─────────────────────┐                          │
                    │  SQLite Database    │                          │
                    │  (Encrypted .kdbx)  │                          │
                    └─────────────────────┘                          │
                                                                       │
                               ┌──────────────────────────────────────┘
                               ▼
                    ┌─────────────────────┐
                    │  OS Keystore       │
                    │  - Keychain (macOS)│
                    │  - DPAPI (Windows) │
                    └─────────────────────┘
```

---

## 2. THREAT MODEL AND MITIGATIONS

| Threat | Attack Vector | Mitigation Strategy |
|--------|---------------|---------------------|
| **Stolen Laptop** | Physical access to encrypted database | • Argon2id with high memory cost (256MB)<br>• Master password required<br>• No plaintext keys stored<br>• Biometric unlock only stores wrapped key |
| **Malware** | Process memory reading | • Zeroization on unlock timeout<br>• mlock() to prevent swap<br>• Memory encryption for sensitive buffers<br>• ASLR and PIE enabled |
| **Memory Scraping** | Heap inspection for keys | • SecureString wrappers with zeroize<br>• Secrets in locked memory pages<br>• No string copies of secrets<br>• Minimize time in memory |
| **Clipboard Snooping** | Other apps reading clipboard | • Auto-clear clipboard after 30s<br>• Protected API on macOS<br>• User notification on copy |
| **Keylogging** | Input capture of master password | • Virtual keyboard option (desktop)<br>• Biometric bypass<br>• Password quality meter |
| **Browser Extension Compromise** | Malicious extension accessing vault | • Native messaging whitelist<br>• Domain matching enforced daemon-side<br>• User approval per domain<br>• No API access to full vault |
| **SQLite File Theft** | Copy of database file | • Full DB encryption with AES-256-GCM<br>• Per-file random salt<br>• Key wrapping with KDF<br>• No plaintext anywhere |
| **Offline Brute Force** | Dictionary attacks on DB | • Argon2id: t=3, m=256MB, p=4<br>• Exponential backoff on failures<br>• Account lockout after 10 attempts<br>• No timing leak on password check |
| **Timing Attacks** | Response time analysis | • Constant-time comparisons<br>• Fixed delay on auth<br>• Dummy operations for padding |
| **Phishing** | Fake websites requesting credentials | • Domain matching with TLD validation<br>• Visual domain confirmation<br>• URL bar integration |
| **CSRF on Autofill** | Malicious site triggering fill | • User gesture required<br>• Origin validation<br>• Frame depth checking |

---

## 3. CRYPTOGRAPHIC DESIGN

### 3.1 Algorithm Specifications

```
┌─────────────────────────────────────────────────────────────────┐
│                    KEY DERIVATION                               │
├─────────────────────────────────────────────────────────────────┤
│  Algorithm: Argon2id                                           │
│  Salt: 16 random bytes (stored in DB header)                   │
│  Memory: 256 MB (m=262144 blocks)                              │
│  Iterations: 3 (t=3)                                           │
│  Parallelism: 4 lanes (p=4)                                    │
│  Output: 32-byte master key                                     │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                    ENCRYPTION                                   │
├─────────────────────────────────────────────────────────────────┤
│  Algorithm: AES-256-GCM                                        │
│  Key: 32 bytes                                                 │
│  Nonce: 96-bit (12 bytes) random per entry                     │
│  Tag: 128-bit authentication                                    │
│  Mode: Per-entry encryption (not whole-file)                   │
└─────────────────────────────────────────────────────────────────┘
```

### 3.2 Key Hierarchy

```
                    MASTER PASSWORD
                           │
                           ▼
                    ┌──────────────┐
                    │   Argon2id   │
                    └──────┬───────┘
                           │
                  32-byte Master Key
                           │
           ┌───────────────┼───────────────┐
           ▼               ▼               ▼
    ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
    │  Vault Key  │ │  HMAC Key   │ │  Biometric  │
    │  (wrapped)  │ │  (derived)  │ │   Wrapper   │
    └──────┬──────┘ └─────────────┘ └──────┬──────┘
           │                                 │
           ▼                                 ▼
    ┌─────────────┐                 ┌─────────────┐
    │ AES-256-GCM │                 │   OS        │
    │ for entries │                 │ Keystore    │
    └─────────────┘                 └─────────────┘
```

### 3.3 Cryptographic Flow

**Setup (First Run):**
```
1. User generates master password
2. Generate 16-byte salt: salt = randombytes(16)
3. Derive master key: MK = Argon2id(password, salt, t=3, m=256MB, p=4)
4. Generate data encryption key: DEK = randombytes(32)
5. Wrap DEK: WDEK = AES-256-GCM-Encrypt(MK, nonce1, DEK)
6. Store: salt, nonce1, WDEK in database header
7. Zero all intermediate keys from memory
```

**Unlock:**
```
1. User enters master password
2. Retrieve salt, nonce1, WDEK from DB
3. Derive MK = Argon2id(password, salt, ...)
4. Decrypt DEK = AES-256-GCM-Decrypt(MK, nonce1, WDEK)
5. Verify authentication tag (constant-time compare)
6. DEK kept in locked memory (mlock)
7. Zero MK immediately after DEK extraction
```

**Biometric Enrollment:**
```
1. After successful password unlock
2. Wrap DEK with OS keystore:
   - macOS: Secure Enclave + Keychain
   - Windows: DPAPI with current user scope
3. Store reference ID in database
4. Future biometric unlock retrieves wrapped DEK
```

**Entry Encryption:**
```
For each credential entry:
1. Generate entry_nonce = randombytes(12)
2. Serialize entry to JSON/MessagePack
3. ciphertext = AES-256-GCM-Encrypt(DEK, entry_nonce, plaintext)
4. Store: entry_nonce || ciphertext || auth_tag
```

---

## 4. SQLITE DATABASE SCHEMA

```sql
-- ============================================================================
-- DATABASE SCHEMA VERSION 1.0
-- ============================================================================

-- Database metadata and versioning
CREATE TABLE db_metadata (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    version INTEGER NOT NULL,
    kdf_params BLOB NOT NULL,           -- JSON: algorithm, salt, mem, iter, parallelism
    wrapped_dek BLOB NOT NULL,          -- Wrapped Data Encryption Key
    dek_nonce BLOB NOT NULL,            -- Nonce for DEK encryption (12 bytes)
    created_at INTEGER NOT NULL,        -- Unix timestamp
    last_modified INTEGER NOT NULL,     -- Unix timestamp
    biometric_ref TEXT,                  -- Reference to OS keystore entry
    CHECK(version = 1)
);

-- Insert initial metadata row
CREATE TRIGGER metadata_init AFTER INSERT ON db_metadata WHEN NEW.id != 1
BEGIN
    SELECT RAISE(ABORT, 'Only one metadata row allowed');
END;

-- Users (single-user for now, schema for future)
CREATE TABLE users (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    kdf_salt BLOB NOT NULL,             -- Per-user salt (16 bytes)
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    is_active INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0, 1))
);

-- Vaults/folders for organization
CREATE TABLE vaults (
    vault_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name BLOB NOT NULL,                 -- Encrypted
    parent_vault_id INTEGER,             -- NULL for top-level vaults
    icon BLOB,                          -- Optional encrypted metadata
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    FOREIGN KEY (user_id) REFERENCES users(user_id),
    FOREIGN KEY (parent_vault_id) REFERENCES vaults(vault_id)
);

-- Credential entries (the core table)
CREATE TABLE entries (
    entry_id INTEGER PRIMARY KEY AUTOINCREMENT,
    vault_id INTEGER NOT NULL,
    title BLOB NOT NULL,                -- Encrypted
    username BLOB NOT NULL,             -- Encrypted
    password BLOB NOT NULL,             -- Encrypted
    url BLOB,                           -- Encrypted (nullable)
    notes BLOB,                         -- Encrypted (nullable)
    custom_fields BLOB,                 -- Encrypted JSON: [{name, value, type}]
    entry_nonce BLOB NOT NULL,          -- Per-entry nonce (12 bytes)
    auth_tag BLOB NOT NULL,             -- GCM auth tag (16 bytes)
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    modified_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    last_used_at INTEGER,               -- For sorting/favorites
    favorite INTEGER NOT NULL DEFAULT 0 CHECK(favorite IN (0, 1)),
    FOREIGN KEY (vault_id) REFERENCES vaults(vault_id)
);

-- SSH keys storage
CREATE TABLE ssh_keys (
    ssh_id INTEGER PRIMARY KEY AUTOINCREMENT,
    vault_id INTEGER NOT NULL,
    name BLOB NOT NULL,                 -- Encrypted
    private_key BLOB NOT NULL,           -- Encrypted (PEM or OpenSSH format)
    public_key BLOB,                     -- Encrypted (for convenience)
    passphrase BLOB,                      -- Encrypted (nullable)
    key_type TEXT NOT NULL,              -- 'rsa', 'ed25519', 'ecdsa'
    key_bits INTEGER,                    -- For RSA: 2048, 4096, etc.
    fingerprint BLOB,                    -- Unencrypted (for identification)
    entry_nonce BLOB NOT NULL,
    auth_tag BLOB NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    FOREIGN KEY (vault_id) REFERENCES vaults(vault_id)
);

-- TOTP secrets
CREATE TABLE totp_secrets (
    totp_id INTEGER PRIMARY KEY AUTOINCREMENT,
    entry_id INTEGER NOT NULL,           -- Link to credential entry
    secret BLOB NOT NULL,                -- Encrypted base32 secret
    algorithm TEXT NOT NULL DEFAULT 'SHA1',  -- SHA1, SHA256, SHA512
    digits INTEGER NOT NULL DEFAULT 6 CHECK(digits IN (6, 8)),
    period INTEGER NOT NULL DEFAULT 30,     -- Seconds
    entry_nonce BLOB NOT NULL,
    auth_tag BLOB NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    FOREIGN KEY (entry_id) REFERENCES entries(entry_id) ON DELETE CASCADE
);

-- Domain mappings for autofill security
CREATE TABLE domain_mappings (
    mapping_id INTEGER PRIMARY KEY AUTOINCREMENT,
    entry_id INTEGER NOT NULL,
    domain TEXT NOT NULL,                -- Canonical domain (e.g., 'example.com')
    is_primary INTEGER NOT NULL DEFAULT 1 CHECK(is_primary IN (0, 1)),
    added_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    FOREIGN KEY (entry_id) REFERENCES entries(entry_id) ON DELETE CASCADE,
    UNIQUE(entry_id, domain)
);

-- Audit log for security events
CREATE TABLE audit_log (
    log_id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,            -- 'unlock', 'entry_view', 'entry_modify', etc.
    resource_type TEXT,                  -- 'entry', 'vault', 'ssh_key'
    resource_id INTEGER,
    details BLOB,                        -- Encrypted details
    timestamp INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    success INTEGER NOT NULL DEFAULT 1 CHECK(success IN (0, 1))
);

-- Failed unlock attempts (for rate limiting)
CREATE TABLE unlock_attempts (
    attempt_id INTEGER PRIMARY KEY AUTOINCREMENT,
    attempt_time INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    success INTEGER NOT NULL CHECK(success IN (0, 1)),
    ip_address TEXT                      -- For future remote access
);

-- Performance indexes
CREATE INDEX idx_entries_vault ON entries(vault_id);
CREATE INDEX idx_entries_favorite ON entries(favorite, last_used_at DESC);
CREATE INDEX idx_ssh_keys_vault ON ssh_keys(vault_id);
CREATE INDEX idx_domain_mapping ON domain_mappings(domain);
CREATE INDEX idx_audit_timestamp ON audit_log(timestamp DESC);
```

---

## 5. RUST IMPLEMENTATION

### 5.1 Why Rust is Preferred

| Aspect | Rust | Python |
|--------|------|--------|
| Memory Safety | Compile-time guarantees, no GC pauses | GC pauses, reference cycles |
| Secret Zeroization | Explicit control with zeroize | Relies on GC, unpredictable |
| Binary Size | Static linking, single binary | Requires Python runtime |
| WebAssembly | Easy wasm-pack for future | Pyodide is slow |
| Concurrency | Fearless concurrency, no data races | GIL limitations |
| FFI | Excellent C interop for OS APIs | ctypes, but slower |
| Distribution | Single binary, no dependencies | venv, pip, dependency hell |
| **Verdict: RUST** | More secure, predictable, better for security-critical software | |

### 5.2 Project Structure

```
passwordmanager/
├── Cargo.toml
├── Cargo.lock
├── src/
│   ├── main.rs                 # Daemon entry point
│   ├── lib.rs                  # Library exports
│   ├── crypto/
│   │   ├── mod.rs
│   │   ├── kdf.rs              # Argon2id implementation
│   │   ├── cipher.rs           # AES-256-GCM wrapper
│   │   ├── keyring.rs          # Key hierarchy management
│   │   └── zero.rs             # Zeroization utilities
│   ├── database/
│   │   ├── mod.rs
│   │   ├── schema.rs           # Table definitions
│   │   ├── migrations.rs       # Version migrations
│   │   └── models.rs           # ORM-like structs
│   ├── vault/
│   │   ├── mod.rs
│   │   ├── entries.rs          # CRUD for entries
│   │   ├── ssh_keys.rs         # SSH key management
│   │   └── totp.rs             # TOTP generation
│   ├── daemon/
│   │   ├── mod.rs
│   │   ├── native_messaging.rs # Browser comm protocol
│   │   └── ipc.rs              # Local socket/pipe server
│   ├── platform/
│   │   ├── mod.rs
│   │   ├── macos.rs            # Touch ID, Keychain
│   │   └── windows.rs          # Windows Hello, DPAPI
│   ├── clipboard/
│   │   ├── mod.rs
│   │   └── manager.rs          # Secure clipboard handling
│   └── ssh/
│       ├── mod.rs
│       └── agent.rs            # ssh-agent integration
├── migrations/
│   └── v1_initial.sql
├── tauri-app/                  # Desktop UI (optional)
│   ├── src/
│   ├── src-tauri/
│   └── package.json
├── browser-extension/
│   ├── chrome/
│   │   ├── manifest.json
│   │   ├── background.js
│   │   └── content.js
│   ├── safari/
│   └── firefox/
└── tests/
    ├── integration/
    └── crypto/
```

### 5.3 Core Dependencies

```toml
[package]
name = "passwordmanager"
version = "0.1.0"
edition = "2021"

[dependencies]
# Cryptography
argon2 = "0.5"
aes-gcm = "0.10"
rand = "0.8"
zeroize = { version = "1.7", features = ["zeroize_derive"] }

# Database
rusqlite = { version = "0.30", features = ["bundled", "backup"] }
refinery = { version = "0.8", features = ["rusqlite"] }

# Serialization
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"

# Async runtime
tokio = { version = "1.35", features = ["full"] }
tokio-util = { version = "0.7", features = ["io"] }

# Platform-specific (conditional compilation)
[target.'cfg(target_os = "macos")'.dependencies]
security-framework = "2.9"
objc = "0.2"

[target.'cfg(target_os = "windows")'.dependencies]
windows = { version = "0.52", features = [
    "Win32_Security_Cryptography",
    "Win32_Foundation",
    "Win32_System_Memory",
] }

# SSH handling
ssh-key = { version = "0.6", features = ["encryption"] }

# TOTP
totp-rs = { version = "5.4", features = ["gen_secret"] }

# KeePass compatibility
kdbx-rs = "0.6"

# Error handling
anyhow = "1.0"
thiserror = "1.0"

# Logging
tracing = "0.1"
tracing-subscriber = "0.3"

# Memory locking
memlock2 = "0.2"

[dev-dependencies]
criterion = "0.5"
tempfile = "3.8"
```

---

## 6. BROWSER EXTENSION DESIGN (PRIORITY)

### 6.1 Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                       Browser Extension                             │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │  content.js  |  Injected into each page                        │  │
│  │              |  - Detect password fields                        │  │
│  │              |  - Inject autofill button                         │  │
│  │              |  - Communicate with background                   │  │
│  └──────────────────────┬────────────────────────────────────────┘  │
│                         │                                           │
│  ┌──────────────────────┴────────────────────────────────────────┐  │
│  │  background.js (Service Worker for MV3)                       │  │
│  │              |  - Native messaging client                      │  │
│  │              |  - Domain validation                           │  │
│  │              |  - Credential caching (memory only)              │  │
│  └──────────────────────┬────────────────────────────────────────┘  │
└─────────────────────────┼────────────────────────────────────────────┘
                          │
                          │ Native Messaging Protocol
                          │ (JSON over stdin/stdout)
                          ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    Native Messaging Host                            │
│  (Separate binary installed with desktop app)                      │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │  Reads JSON from stdin                                        │  │
│  │  Validates message format and origin                          │  │
│  │  Forwards to daemon via local socket/pipe                      │  │
│  │  Writes response to stdout                                     │  │
│  └───────────────────────────────────────────────────────────────┘  │
└─────────────────────────┼────────────────────────────────────────────┘
                          │
                          │ Local IPC (named pipe/Unix socket)
                          ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      Core Daemon                                    │
│  - Domain matching                                                 │
│  - Credential lookup                                              │
│  - Returns ONLY requested credential, not full vault               │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 7. SECURITY HARDENING CHECKLIST

| Category | Item | Implementation |
|----------|------|----------------|
| **Memory** | Zeroization | `zeroize` crate on all secrets |
| **Memory** | Locked pages | `memlock2::Mlock` prevents swap |
| **Memory** | No string copies | Use `SecureBuffer`, never `String` for secrets |
| **Timing** | Constant-time compare | `subtle` crate for password checks |
| **Timing** | Fixed delay on auth | Always delay 200ms on unlock attempt |
| **Brute Force** | Exponential backoff | 100ms → 200ms → 400ms → 800ms |
| **Brute Force** | Account lockout | 10 failed attempts = 5 min lockout |
| **Auto-lock** | Timeout | Default 5 min inactivity |
| **Auto-lock** | Lock on sleep | Detect system sleep/wake events |
| **Auto-lock** | Lock on screen lock | Platform-specific APIs |
| **Clipboard** | Auto-clear | 30 second timeout |
| **Clipboard** | Clear on exit | Clear clipboard on daemon shutdown |
| **Audit Log** | Track access | Log all entry access (encrypted) |
| **SQL Injection** | Parameterized queries | Use rusqlite bindings, never concat |
| **Updates** | Signature verification | Verify binary signatures |
| **Updates** | Secure channel | HTTPS with cert pinning |
| **Process Isolation** | Sandboxing | Platform-specific sandboxing |
| **Anti-debug** | Detect debugger | Platform-specific checks |
| **Anti-dump** | Encrypt secrets | Memory encryption for critical buffers |

---

## 8. DEVELOPMENT ROADMAP

### Phase 1: Core Foundation (Weeks 1-4)
1. Project setup, dependencies
2. Crypto module implementation
3. Database schema and migrations
4. Basic CLI for vault operations
5. Unit tests for crypto

### Phase 2: Desktop Client (Weeks 5-8)
1. Tauri UI development
2. Vault CRUD operations
3. Entry management UI
4. Search functionality
5. Clipboard integration

### Phase 3: Browser Extension (Weeks 9-12) **PRIORITY**
1. Native messaging protocol
2. Chrome extension (MV3)
3. Domain matching logic
4. Autofill injection
5. Phishing protection

### Phase 4: SSH Support (Weeks 13-14)
1. SSH key storage
2. ssh-agent integration
3. Key loading functionality

### Phase 5: Biometrics (Weeks 15-16)
1. macOS Touch ID
2. Windows Hello
3. Fallback handling

### Phase 6: Advanced Features (Weeks 17-20)
1. TOTP authenticator
2. KeePass import/export
3. Audit log
4. Additional browsers (Safari, Firefox)

### Phase 7: Hardening & Testing (Weeks 21-24)
1. Security audit
2. Penetration testing
3. Performance optimization
4. Documentation

---

## 9. COMMON MISTAKES TO AVOID

1. **Never log secrets** - Use safe logging that redacts sensitive data
2. **Never use `String` for passwords** - Always use `SecureBuffer`
3. **Never compare passwords with `==`** - Use constant-time compare
4. **Never store keys in environment variables** - Use locked memory or OS keystore
5. **Never reuse nonces** - Always generate random per-entry nonce
6. **Never skip authentication tag validation** - GCM tag is mandatory
7. **Never write plaintext to disk** - Even for debugging
8. **Never trust domain from browser** - Validate daemon-side
9. **Never return full vault to extension** - Only return requested credential
10. **Never forget to zeroize** - Drop all secret buffers promptly
