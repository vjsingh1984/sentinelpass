# SentinelPass Gap Review (2026-02-26)

## Scope

This review covers vision, security, feature completeness, capability, design, and implementation gaps across the current SentinelPass workspace.

It is evidence-based and focused on what is present in the codebase today, not target-state claims.

## Update After Phase 1 Implementation (same date)

The following items from the initial review are now partially mitigated in code:

- Relay config wiring / cleanup / rate limiting hardening landed in `sentinelpass-relay/` (with new relay tests).
- Windows IPC loopback TCP path now uses token-derived AES-GCM message encryption as an interim mitigation in `sentinelpass-core/src/daemon/ipc.rs`.

Remaining gaps still stand:

- Windows transport is still loopback TCP (named pipes + ACLs still recommended).
- Relay public endpoint abuse controls and registration trust proof need deeper hardening beyond baseline rate limiting.
- Extension sender validation is now improved, but broader frame/scheme policy hardening should continue.

## What Is Already Strong

- Local-first architecture with Rust core and encrypted vault.
- KDF + AEAD crypto primitives are implemented and documented in code (`sentinelpass-core/src/crypto/kdf.rs`, `sentinelpass-core/src/crypto/cipher.rs`).
- Lockout and audit logging are integrated into vault open flows (`sentinelpass-core/src/vault/mod.rs`).
- Desktop + daemon + native host + browser extension path is functional.
- Sync protocol and self-hosted relay exist and are usable as a foundation.
- Mobile bridge and native mobile app scaffolds exist.

## Top Findings (Prioritized)

## 1. Critical: Relay hardening controls are documented/configured but not consistently enforced

### Why it matters

The relay is on the security boundary for multi-device sync. Several safeguards exist as code or config concepts but are not wired into runtime behavior, which creates a false sense of protection.

### Evidence

- Config exposes controls (`rate_limit_per_minute`, `pairing_ttl_secs`, `max_active_pairings`, `nonce_window_secs`) in `sentinelpass-relay/src/config.rs:13` through `sentinelpass-relay/src/config.rs:17`.
- Relay startup loads config but does not start cleanup tasks in `sentinelpass-relay/src/main.rs:44` through `sentinelpass-relay/src/main.rs:64`.
- Cleanup task exists but is unused in `sentinelpass-relay/src/cleanup.rs:9`.
- Rate limiter exists but is unused in `sentinelpass-relay/src/rate_limit.rs:1`.
- Router applies permissive CORS globally in `sentinelpass-relay/src/server.rs:42`.
- Pairing TTL and max active pairings are hardcoded (`300`, `5`) in `sentinelpass-relay/src/handlers/pairing.rs:41` and `sentinelpass-relay/src/handlers/pairing.rs:52`.
- Auth freshness window is hardcoded (`300s`) in `sentinelpass-relay/src/auth.rs:97` through `sentinelpass-relay/src/auth.rs:100`.
- `docs/SYNC.md` presents these relay knobs as configurable behavior in `docs/SYNC.md:157` through `docs/SYNC.md:167`.

### Gap type

- Security
- Implementation
- Documentation truthfulness

### Required remediation

- Wire config values into auth and pairing handlers.
- Start cleanup task at relay boot.
- Apply rate-limiting middleware to authenticated and public abuse-prone endpoints.
- Replace permissive CORS default with explicit allowlist/off-by-default server policy.
- Add tests proving enforcement of each configured control.

## 2. High: Windows daemon IPC still uses localhost TCP (interim message encryption landed, but OS-native IPC is still preferred)

### Why it matters

Localhost TCP is still not equivalent to OS-protected IPC (named pipes with per-user ACLs). An interim mitigation can encrypt frames, but the transport boundary remains weaker than OS-native IPC on Windows.

### Evidence

- IPC comment still says Windows named pipes in `sentinelpass-core/src/daemon/ipc.rs:1` through `sentinelpass-core/src/daemon/ipc.rs:4` (doc mismatch).
- `IpcMessage::UnlockVault` carries `master_password: String` in `sentinelpass-core/src/daemon/ipc.rs:52` through `sentinelpass-core/src/daemon/ipc.rs:54`.
- Windows server path binds a TCP listener in `sentinelpass-core/src/daemon/ipc.rs:288` through `sentinelpass-core/src/daemon/ipc.rs:299`.
- Windows client path connects using `TcpStream` in `sentinelpass-core/src/daemon/ipc.rs:684` through `sentinelpass-core/src/daemon/ipc.rs:697`.
- Default Windows IPC endpoint is `tcp://127.0.0.1:35873` in `sentinelpass-core/src/daemon/ipc.rs:789` through `sentinelpass-core/src/daemon/ipc.rs:794`.
- Interim transport encryption is now implemented for Windows TCP frames in `sentinelpass-core/src/daemon/ipc.rs` (server/client Windows branches and helper functions).

### Gap type

- Security
- Design
- Documentation truthfulness

### Required remediation

- Migrate Windows IPC to named pipes with per-user ACLs (preferred).
- Keep authenticated message encryption as interim defense-in-depth until named pipes ship.
- Add a platform-specific IPC security status table to docs.

## 3. High: Browser extension background trusts claimed domain payloads without sender URL validation

### Why it matters

The background worker forwards domain values from extension messages to native messaging without verifying `sender.tab.url` matches the claimed domain. This weakens origin validation and phishing resistance.

### Evidence

- `handleGetCredential` forwards `domain` directly to native messaging in `browser-extension/chrome/background.ts:347` through `browser-extension/chrome/background.ts:355`.
- `handleSaveCredential` forwards `data.domain` and password payloads to native messaging in `browser-extension/chrome/background.ts:390` through `browser-extension/chrome/background.ts:416`.
- `chrome.runtime.onMessage` dispatches requests without validating `sender.tab.url` or frame context in `browser-extension/chrome/background.ts:627` through `browser-extension/chrome/background.ts:683`.
- Content script generates requests using `window.location.hostname` in `browser-extension/chrome/content.ts:1005` through `browser-extension/chrome/content.ts:1016`, but this is not independently validated by the background worker.

### Gap type

- Security
- Design
- Implementation

### Required remediation

- Validate `sender.tab.url`, `sender.frameId`, and request domain consistency in the background worker.
- Normalize and compare hostnames in one shared utility (extension + daemon).
- Deny autofill for unsupported schemes/frames by default; require explicit user action for exceptions.

## 4. High: Relay device registration and pairing endpoints are public with weak abuse controls

### Why it matters

Public endpoints are expected, but the current design allows unauthenticated registration and pairing bootstrap uploads without strong anti-abuse gating. This can enable denial-of-service, metadata scraping attempts, or operational noise.

### Evidence

- Public routes include `/devices/register` and pairing bootstrap endpoints in `sentinelpass-relay/src/server.rs:30` through `sentinelpass-relay/src/server.rs:37`.
- Device registration is unauthenticated and can create vault/device records directly in `sentinelpass-relay/src/handlers/devices.rs:33` through `sentinelpass-relay/src/handlers/devices.rs:92`.
- Pairing bootstrap endpoints are unauthenticated in `sentinelpass-relay/src/handlers/pairing.rs:26` through `sentinelpass-relay/src/handlers/pairing.rs:96`.
- Pairing token is stored and queried directly (not hashed) in `sentinelpass-relay/src/handlers/pairing.rs:56` through `sentinelpass-relay/src/handlers/pairing.rs:60` and `sentinelpass-relay/src/handlers/pairing.rs:76` through `sentinelpass-relay/src/handlers/pairing.rs:83`.

### Gap type

- Security
- Architecture
- Operational readiness

### Required remediation

- Introduce pairing-bound proof for device registration (or challenge/response tied to an existing device).
- Add public-endpoint rate limiting and abuse quotas.
- Hash pairing tokens at rest and compare by hash.
- Add optional CAPTCHA/proxy controls only in hosted/private deployments (not protocol-mandated).

## 5. Medium: Security posture docs and roadmap overstate implementation maturity

### Why it matters

Overclaiming controls is a trust and governance risk, especially for a password manager. This impacts audits, user trust, and prioritization.

### Evidence

- `SECURITY_ARCHITECTURE.md` threat mitigations include items such as `mlock()`, "memory encryption", "virtual keyboard", "user approval per domain", and "URL bar integration" in `SECURITY_ARCHITECTURE.md:56` through `SECURITY_ARCHITECTURE.md:66`, but these are not clearly marked as target-state.
- `docs/SYNC.md` presents relay config as active behavior in `docs/SYNC.md:157` through `docs/SYNC.md:167`, while several controls are hardcoded or unused in relay code (see Findings 1 and 4).
- `ROADMAP.md` (pre-reset) tracked already-resolved items such as refinery migration work and UI state refactor, creating stale planning signals (`ROADMAP.md` before this review; see `TECHNICAL_DEBT.md` for resolved notes).

### Gap type

- Documentation
- Planning governance

### Required remediation

- Adopt status markers in security/design docs (`Implemented`, `Partial`, `Planned`).
- Keep roadmap tied to evidence-based gap review and requirement IDs.
- Treat prompt templates as governance artifacts (not one-time brainstorming text).

## 6. Medium: Extension logging is too verbose for a security-sensitive release build

### Why it matters

While values are often redacted, the extension logs page URLs, hostnames, password-flow events, and password length signals. This increases privacy leakage and support-log risk.

### Evidence

- Content script logs URL and hostname on every page load in `browser-extension/chrome/content.ts:3` through `browser-extension/chrome/content.ts:5`.
- Submission flow logs credential capture events and password length in `browser-extension/chrome/content.ts:906` through `browser-extension/chrome/content.ts:908`.
- Manifest injects content script on `<all_urls>` and all frames in `browser-extension/chrome/manifest.json:15` through `browser-extension/chrome/manifest.json:17` and `browser-extension/chrome/manifest.json:22` through `browser-extension/chrome/manifest.json:28`.

### Gap type

- Security hygiene
- Privacy
- Release engineering

### Required remediation

- Introduce debug-log gating for extension builds.
- Remove password-length and sensitive flow logs in production builds.
- Document permission rationale and minimization strategy per browser.

## 7. Medium: Relay has no automated tests today (0 tests)

### Why it matters

The relay handles auth, replay prevention, device registration, and sync sequencing. Zero tests here increases regression and security risk.

### Evidence

- `cargo test -p sentinelpass-relay --quiet` (run on 2026-02-26) reports `running 0 tests`.
- `rg -n "#\\[test\\]" sentinelpass-relay/src` returns no results.

### Gap type

- Testing
- Security verification
- Operational readiness

### Required remediation

- Add unit tests for auth parsing/verification failures and replay checks.
- Add handler tests for pairing TTL/consumption and device registration authz.
- Add integration tests for sync push/pull sequence monotonicity.

## Product / Capability Gaps (Non-security)

## Product completeness gaps

- Browser extension popup still lacks core parity features (search/add/settings are partially implemented or missing in the current roadmap and UI).
- Password health/watchtower-style functionality is not yet implemented.
- Import/export breadth is limited relative to established password managers.
- Mobile apps are scaffolded but autofill integrations and testing depth remain incomplete.

## Commercialization and packaging gaps

- No documented free-tier vs paid-tier boundary.
- No documented rule for what must remain open source (trust-critical surfaces).
- No two-repo operating model for OSS core plus private paid features/hosted services.

## Design and process gaps

- Planning artifacts were fragmented across roadmap, technical debt notes, and a generic prompt file.
- Security architecture doc mixes target-state and current-state claims.
- No requirement IDs or acceptance criteria linking roadmap items to verification.

## Immediate Priorities (Recommended Order)

1. Fix relay hardening wiring and add relay tests.
2. Harden Windows IPC transport on Windows.
3. Add extension sender URL/domain validation and release log gating.
4. Publish planning stack (PRD, requirements, design, implementation plan, OSS strategy).
5. Resume feature-completeness work with security gates and tiering boundaries established.

## New Planning Artifacts Created From This Review

- `ROADMAP.md`
- `docs/PRD.md`
- `docs/REQUIREMENTS.md`
- `docs/SOLUTION_DESIGN.md`
- `docs/IMPLEMENTATION_PLAN.md`
- `docs/OSS_COMMERCIAL_STRATEGY.md`
- `passwordmanager_prompt.txt` (rewritten as an evidence-based audit/planning prompt)
