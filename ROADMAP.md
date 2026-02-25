# SentinelPass Roadmap

**Last Updated:** 2026-02-24
**Current Version:** 0.1.0
**Status:** Active Development

## Executive Summary

SentinelPass is a secure, local-first password manager with exceptional cryptographic foundations. This roadmap tracks our journey from current state to a competitive, feature-complete password manager.

### Current State Assessment
- **Security:** ⭐⭐⭐⭐⭐ Exceptional (Argon2id + AES-256-GCM)
- **Architecture:** ⭐⭐⭐⭐⭐ Excellent (Local-first, zero-knowledge)
- **Desktop:** ⭐⭐⭐⭐ Good (Windows, macOS, Linux)
- **Mobile:** ⭐ Missing (Critical gap)
- **Features:** ⭐⭐⭐ Basic (Missing standard PM features)

### Strategic Priorities
1. **Mobile Apps** (Critical - next 6 months)
2. **Password Health & Security Monitoring** (High priority)
3. **Enhanced Sync Options** (High priority)
4. **User Experience Polish** (Medium priority)
5. **Enterprise Features** (Long term)

---

## Version Roadmap

### v0.2.0 - Security & Stability (Current Sprint)
**Target:** Q1 2026
**Status:** In Progress

#### Security Hardening
- [ ] Fix Windows IPC plaintext transmission (encrypt TCP messages)
- [ ] Complete migration system (wire up refinery)
- [ ] Add comprehensive input validation on CLI
- [ ] Add timing side-channel tests for crypto
- [ ] Implement rate limiting on IPC endpoints

#### Quality Improvements
- [ ] Improve test coverage to 60% minimum
- [ ] Add fuzzing for crypto functions
- [ ] Fix UI global variables refactoring
- [ ] Add comprehensive error recovery

**Files:**
- `sentinelpass-core/src/daemon/ipc.rs`
- `sentinelpass-core/src/database/migrations.rs`
- `sentinelpass-cli/src/main.rs`
- `sentinelpass-ui/app.ts`

---

### v0.3.0 - Password Health Monitoring
**Target:** Q2 2026
**Status:** Planned

#### Core Features
- [ ] Implement password strength analysis API
- [ ] Add breach detection integration (Have I Been Pwned API/k-anonymity)
- [ ] Password reuse detection across vault
- [ ] Age-based password change reminders
- [ ] Security score dashboard
- [ ] Weak password alerts
- [ ] Exposed credential notifications

#### UI Components
- [ ] Password health dashboard in desktop UI
- [ ] Health indicators in entry list
- [ ] One-click password change workflow
- [ ] Bulk password update tool

**New Files:**
- `sentinelpass-core/src/health/` - Password health module
- `sentinelpass-core/src/breach/` - Breach detection module
- Browser extension health indicators

---

### v0.4.0 - Mobile Apps (CRITICAL)
**Target:** Q2-Q3 2026
**Status:** In Progress - Bridge complete, iOS app scaffolded

#### iOS App (iPhone/iPad)
- [x] Core data layer using sentinelpass-core (via C FFI)
- [x] Swift/SwiftUI native iOS app scaffold
- [x] Face ID / Touch ID biometric unlock UI
- [ ] Auto-fill integration with iOS Password Manager
- [ ] Camera QR code for TOTP setup
- [ ] Local-only mode with optional iCloud sync
- [ ] Secure enclave integration for master key
- [ ] Complete entry CRUD operations testing
- [ ] Add unit tests for VaultBridge

#### Android App (Phone/Tablet)
- [x] Core data layer using sentinelpass-core (JNI)
- [x] Kotlin/Jetpack Compose native Android app scaffold
- [x] Biometric unlock (fingerprint, face unlock) UI
- [ ] Auto-fill service integration (service stub created)
- [ ] Camera QR code for TOTP setup
- [ ] Local-only mode with optional Google Drive sync
- [ ] Complete entry CRUD operations testing
- [ ] Add unit tests for VaultBridge

#### Cross-Platform Considerations
- [x] Mobile bridge (FFI/JNI) implemented
- [ ] Mobile sync architecture (relay.json or cloud APIs)
- [ ] Mobile-specific crypto implementations (platform KeyStore)
- [x] Responsive design patterns (iOS/Android scaffolded)
- [x] Offline-first architecture

**New Directories:**
- [x] `sentinelpass-mobile-bridge/` - FFI/JNI bridge layer (COMPLETE)
- [x] `ios/SentinelPass/` - iOS app scaffold (COMPLETE)
- [x] `android/SentinelPass/` - Android app scaffold (COMPLETE)

**Key Design Decisions:**
1. Use platform-native UIs (not React Native/Flutter) for security
2. Share Rust core via FFI (iOS) and JNI (Android)
3. Implement platform-specific secure enclave/key store
4. Support cloud sync (iCloud/Google Drive) + optional relay

---

### v0.5.0 - Enhanced Sync & Organization
**Target:** Q3 2026
**Status:** Planned

#### Sync Options
- [ ] iCloud sync for Apple ecosystem
- [ ] Google Drive sync for Google ecosystem
- [ ] Dropbox sync option
- [ ] Sync conflict UI (replace LWW-only)
- [ ] Selective sync (per-device/folder)
- [ ] Sync status indicators

#### Organization Features
- [ ] Folders/collections system
- [ ] Tags for entries
- [ ] Custom fields per entry
- [ ] Favorites/pinned entries
- [ ] Advanced search (folders, tags, custom fields)

#### Import/Export
- [ ] 1Password import (1pux/opvault)
- [ ] Bitwarden import (json)
- [ ] KeePass import (kdbx)
- [ ] LastPass import
- [ ] Export to all above formats
- [ ] Import validation and conflict resolution

**Database Schema Changes:**
- Add `folders` table
- Add `tags` table
- Add `entry_tags` junction table
- Add `custom_fields` table
- Migration path for existing vaults

---

### v0.6.0 - Browser Enhancement & Thick Client Auto-fill
**Target:** Q4 2026
**Status:** Planned

#### Browser Extension Improvements
- [ ] Settings UI in extension popup
- [ ] Inline TOTP codes in autofill
- [ ] Save prompts for all forms (not just registration)
- [ ] Password generation in-page
- [ ] Site-specific settings
- [ ] Keyboard shortcut customization
- [ ] Safari extension (using Web Extension API)
- [ ] Edge extension

#### Thick Client Auto-fill (Windows/macOS)
- [ ] Windows Credential Provider integration
- [ ] macOS keychain-like integration (where legal)
- [ ] Auto-fill in native apps (not just browsers)
- [ ] Quick-access hotkey (global)
- [ ] System tray integration with quick copy
- [ ] Drag-and-drop password to apps

**Platform Integration:**
- Windows: Credential Provider API
- macOS: Accessibility API for text insertion
- Linux: DBus interface for native apps

---

### v0.7.0 - Advanced Security Features
**Target:** Q1 2027
**Status:** Planned

#### Emergency Access
- [ ] Trusted contacts design
- [ ] Time-delayed emergency access
- [ ] Request/approval workflow
- [ ] Inheritance planning (dead man's switch)
- [ ] Emergency access revocation

#### Advanced Monitoring
- [ ] Watchtower-style security dashboard
- [ ] 2FA code expiration monitoring
- [ ] Compromised website alerts
- [ ] Password reuse visualization
- [ ] Login attempt notifications

#### Hardware Security
- [ ] YubiKey/U2F support for 2FA
- [ ] Hardware key as master password alternative
- [ ] Smart card integration
- [ ] TPM integration for Windows

---

### v1.0.0 - Enterprise Readiness
**Target:** Q2 2027
**Status:** Planned

#### Team/Business Features
- [ ] Shared vaults with role-based access
- [ ] Team management interface
- [ ] Audit log export
- [ ] SSO integration (SAML/OIDC)
- [ ] Directory sync (LDAP/AD)
- [ ] Policy enforcement (password requirements)
- [ ] Business tier licensing

#### Advanced Integrations
- [ ] API for third-party developers
- [ ] Plugin architecture
- [ ] Secrets engine for devops
- [ ] CI/CD integrations

---

## Technical Debt Tracking

### High Priority
1. **Windows IPC Security** - Plaintext password over TCP
   - File: `sentinelpass-core/src/daemon/ipc.rs`
   - Fix: Add TLS or message encryption
   - Target: v0.2.0

2. **Migration System** - Refinery not wired
   - File: `sentinelpass-core/src/database/migrations.rs`
   - Fix: Implement versioned migrations
   - Target: v0.2.0

3. **UI Global State** - Global variables in app.ts
   - File: `sentinelpass-ui/app.ts`
   - Fix: Refactor to proper state management
   - Target: v0.2.0

### Medium Priority
1. **Missing Input Validation** - CLI entrypoints
   - File: `sentinelpass-cli/src/main.rs`
   - Target: v0.2.0

2. **No Pagination** - list_entries loads all
   - File: `sentinelpass-core/src/vault.rs`
   - Target: v0.5.0

3. **Limited Fuzzing** - Crypto functions
   - Target: v0.3.0

### Low Priority
1. **Concurrent Access Testing** - Multi-connection scenarios
   - Target: v0.5.0

2. **Large Vault Performance** - Stress testing needed
   - Target: v0.5.0

---

## Research & Exploration

### Mobile Platform Research
- [ ] iOS Keychain Services vs Secure Enclave
- [ ] Android Keystore system limitations
- [ ] Cross-platform biometric unlock patterns
- [ ] Mobile auto-fill APIs (iOS Password AutoFill, Android Autofill Framework)
- [ ] Cloud sync security model (iCloud/Google Drive E2E)

### Thick Client Research
- [ ] Windows Credential Provider API
- [ ] macOS Accessibility API for text insertion
- [ ] Linux X11/Wayland text insertion methods
- [ ] Anti-virus false positive prevention

### Security Research
- [ ] Timing side-channel analysis
- [ ] Memory forensics resistance
- [ ] Secure deletion patterns (SSD TRIM considerations)
- [ ] Post-quantum cryptography migration path

---

## Dependencies & External Libraries

### Current Rust Dependencies
- Argon2 (KDF)
- AES-256-GCM (encryption)
- Ed25519 (signing)
- SQLite (storage)
- Tokio (async runtime)

### Future Dependencies (Under Evaluation)
- Mobile: iOS CryptoKit, Android Jetpack Security
- Thick client: Platform-specific APIs
- Breach detection: HIBP k-anonymity API
- Hardware keys: yubihq.rs, u2f-rs

---

## Milestone Dates

| Milestone | Target Date | Status |
|-----------|-------------|--------|
| v0.2.0 - Security Hardening | Q1 2026 | In Progress |
| v0.3.0 - Password Health | Q2 2026 | Planned |
| v0.4.0 - Mobile Apps | Q2-Q3 2026 | Planned |
| v0.5.0 - Sync & Organization | Q3 2026 | Planned |
| v0.6.0 - Browser & Thick Client | Q4 2026 | Planned |
| v0.7.0 - Advanced Security | Q1 2027 | Planned |
| v1.0.0 - Enterprise | Q2 2027 | Planned |

---

## Success Metrics

### Technical Metrics
- [ ] Test coverage > 60%
- [ ] Zero critical security vulnerabilities
- [ ] Mobile app store approval (iOS + Android)
- [ ] 99.9% uptime for relay server (if hosted)

### User Metrics
- [ ] 1,000 active users
- [ ] < 5% crash rate across platforms
- [ ] < 2 second average unlock time
- [ ] 4.5+ star rating on app stores

### Feature Completeness
- [ ] Feature parity with Bitwarden free tier
- [ ] Mobile apps available
- [ ] At least 3 sync options
- [ ] Support for 5+ import formats

---

## Open Questions

1. **Business Model:** Freemium? Paid only? Enterprise licenses?
2. **Hosting:** Host relay service or community-hosted only?
3. **Mobile Development:** In-house or contract development?
4. **Cloud Sync:** Implement ourselves or partner with existing services?
5. **Audit Trail:** Third-party security audit before v1.0?

---

## References

- [SECURITY_ARCHITECTURE.md](./SECURITY_ARCHITECTURE.md) - Detailed security design
- [TECHNICAL_DEBT.md](./TECHNICAL_DEBT.md) - Known technical debt
- [CLAUDE.md](./CLAUDE.md) - Development guide
- [SYNC.md](./docs/SYNC.md) - Sync protocol reference
