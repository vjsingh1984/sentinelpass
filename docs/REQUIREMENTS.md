# SentinelPass Requirements (Traceable)

**Version:** 1.0  
**Date:** 2026-02-26  
**Status:** Active

This document converts the gap review into traceable requirements with acceptance criteria.

## 1. Status Vocabulary

- `Must`: required for security posture or core product viability
- `Should`: strongly recommended for completeness/usability
- `Could`: opportunistic or later-phase

## 2. Functional Requirements

## FR-CORE (Core vault and local-first)

- `FR-CORE-001 (Must)` SentinelPass must support fully local vault creation, unlock, lock, CRUD, TOTP, and SSH key storage without cloud dependency.
  - Acceptance: Core workflows function with network disabled.

- `FR-CORE-002 (Must)` SentinelPass must preserve backward compatibility for existing local vault files or provide explicit migration paths.
  - Acceptance: schema version validation and migration behavior documented and tested.

## FR-BROWSER (Browser extension and autofill)

- `FR-BROWSER-001 (Must)` Browser extension must request credentials and TOTP through native host/daemon only (no direct vault access in extension).
  - Acceptance: architecture path remains extension -> native host -> daemon -> core.

- `FR-BROWSER-002 (Must)` Background worker must validate sender tab URL/frame context against claimed request domain before credential retrieval or save.
  - Acceptance: negative tests for mismatched sender URL/domain are present.

- `FR-BROWSER-003 (Should)` Browser extension popup must support search, save/add credential, and settings for baseline usability.
  - Acceptance: user can complete common tasks without desktop app context switches.

- `FR-BROWSER-004 (Should)` Extension release builds must use reduced logging, with debug logging gated by explicit build flag.
  - Acceptance: production bundle excludes verbose credential-flow logs.

## FR-SYNC (Sync and relay)

- `FR-SYNC-001 (Must)` Relay must enforce configured limits for pairing TTL, active pairings, nonce freshness, and request body size.
  - Acceptance: config-driven tests verify behavior changes when values are changed.

- `FR-SYNC-002 (Must)` Relay must run cleanup for nonces, expired pairings, and tombstones in production runtime.
  - Acceptance: startup path spawns cleanup task and logs lifecycle.

- `FR-SYNC-003 (Must)` Relay must enforce rate limiting for authenticated and public abuse-prone endpoints.
  - Acceptance: tests verify throttling behavior and 429 responses.

- `FR-SYNC-004 (Should)` Relay must support self-host deployment behind a reverse proxy/TLS terminator with documented hardening profile.
  - Acceptance: docs include minimal production deployment guidance and defaults.

- `FR-SYNC-005 (Should)` Sync UX must expose conflict and device status signals to users.
  - Acceptance: user-visible sync state and device management workflows exist.

## FR-MOBILE (Mobile)

- `FR-MOBILE-001 (Must)` iOS and Android clients must complete autofill integrations before SentinelPass is positioned as feature-complete for consumers.
  - Acceptance: platform autofill services can retrieve and fill stored credentials.

- `FR-MOBILE-002 (Should)` Mobile bridge and app layers must have automated tests for CRUD and unlock flows.
  - Acceptance: CI executes mobile bridge tests or documented automated smoke coverage.

## FR-IMPORT (Import/export and migrations)

- `FR-IMPORT-001 (Should)` SentinelPass must support at least KeePass and Bitwarden imports in the baseline completeness phase.
  - Acceptance: import fixtures and validation/error handling tests exist.

- `FR-IMPORT-002 (Should)` Import/export flows must provide validation and conflict handling (duplicate detection, invalid rows, partial import summary).
  - Acceptance: UI/CLI outputs structured summary and error counts.

## 3. Security Requirements

## SR-IPC (Daemon IPC and local boundaries)

- `SR-IPC-001 (Must)` Windows IPC transport must not rely on plaintext localhost TCP for sensitive vault operations in GA releases.
  - Acceptance: named pipes with per-user ACLs (preferred) or equivalent authenticated encryption and local access controls are implemented.

- `SR-IPC-002 (Must)` IPC protocol documentation must accurately describe the actual platform transport per OS.
  - Acceptance: no doc mismatch between implementation and IPC docs/comments.

## SR-EXT (Extension safety)

- `SR-EXT-001 (Must)` Extension background must enforce origin validation independent of content script claims.
  - Acceptance: sender URL normalization and comparison are centrally implemented and tested.

- `SR-EXT-002 (Should)` Autofill must be constrained by frame and scheme safety rules by default.
  - Acceptance: unsupported/unsafe contexts are denied or require explicit user action.

## SR-RELAY (Relay auth and abuse resistance)

- `SR-RELAY-001 (Must)` Relay public endpoints must have abuse controls (rate limits, quotas, and telemetry hooks for hosted deployments).
  - Acceptance: `/devices/register` and pairing endpoints are throttled.

- `SR-RELAY-002 (Must)` Relay pairing and device registration flows must require an explicit trust proof tied to pairing/bootstrap flow for non-initial devices.
  - Acceptance: registration path cannot silently join arbitrary vaults without possession of valid pairing material or equivalent proof.

- `SR-RELAY-003 (Must)` Replay protection must be tested and config-driven.
  - Acceptance: tests cover nonce reuse rejection and freshness-window enforcement.

- `SR-RELAY-004 (Should)` Pairing tokens should be stored hashed at rest on the relay.
  - Acceptance: token lookup is hash-based and migration path is documented.

## SR-DOCS (Security claim governance)

- `SR-DOCS-001 (Must)` Security/design docs must label controls as `Implemented`, `Partial`, or `Planned`.
  - Acceptance: no ambiguous mitigation tables for major controls.

- `SR-DOCS-002 (Must)` Security claims must include code/test evidence references for implemented controls.
  - Acceptance: docs link to files/tests or to a status matrix.

## 4. Testing and Verification Requirements

- `TV-001 (Must)` All trust-boundary components (IPC, extension request validation, relay auth/pairing/sync handlers) must have automated negative-path tests.
  - Acceptance: CI runs tests and artifacts show coverage of reject cases.

- `TV-002 (Should)` Relay must have integration tests for push/pull sequencing, replay protection, and device revocation.
  - Acceptance: test suite simulates multi-device flows.

- `TV-003 (Should)` Security-sensitive crates/features must be included in fuzz/property-based testing where practical.
  - Acceptance: documented fuzz/property test targets and run commands.

- `TV-004 (Must)` Release readiness checklists must include docs/runtime alignment review for security claims.
  - Acceptance: release checklist references status matrix and gap review updates.

## 5. Operational Requirements

- `OP-001 (Must)` Self-host relay documentation must define minimum production deployment assumptions (TLS termination, storage path, backups, logs).
  - Acceptance: docs provide a supported baseline profile.

- `OP-002 (Should)` Relay should expose health and structured logs appropriate for self-hosting and managed hosting.
  - Acceptance: health endpoint documented; logs identify auth/rate-limit/cleanup events without leaking secrets.

- `OP-003 (Should)` Official builds should distinguish debug and release logging profiles across UI and extension.
  - Acceptance: build/release process documents log profile behavior.

## 6. Commercialization and Tiering Requirements

- `CM-001 (Must)` Trust-critical components (crypto, vault format, sync protocol, local client path) must remain open and auditable.
  - Acceptance: these components live in the public repo under OSS license.

- `CM-002 (Must)` Paid features must be additive and optional; local-first core must not require a paid service.
  - Acceptance: free tier remains functional without account or subscription.

- `CM-003 (Should)` Entitlement checks should control UX/capability access, not cryptographic correctness.
  - Acceptance: security behavior remains identical regardless of paid status for shared core paths.

- `CM-004 (Should)` Hosted relay service may be private, but protocol and self-host relay compatibility must remain documented and versioned.
  - Acceptance: hosted and self-host variants share protocol compatibility contract.

## 7. Repository and Governance Requirements

- `RG-001 (Must)` Public and private repos must share a stable interface contract (crates/APIs/protocol schemas) to avoid long-lived forks.
  - Acceptance: versioned compatibility matrix and contract tests exist.

- `RG-002 (Must)` Public repo is the source of truth for protocol definitions and trust-critical interfaces.
  - Acceptance: private repo consumes tagged public releases rather than maintaining divergent copies.

- `RG-003 (Should)` Roadmap, PRD, requirements, design, and implementation plan must be updated together for major direction changes.
  - Acceptance: linked docs and update date are maintained.

## 8. Traceability Map

- Gap Review: `docs/GAP_REVIEW_2026-02-26.md`
- Product scope and packaging: `docs/PRD.md`
- Design response: `docs/SOLUTION_DESIGN.md`
- Delivery sequencing: `docs/IMPLEMENTATION_PLAN.md`
- Long-range milestones: `ROADMAP.md`
- OSS/private repo model: `docs/OSS_COMMERCIAL_STRATEGY.md`
