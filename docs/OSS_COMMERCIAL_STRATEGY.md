# SentinelPass OSS / Free / Paid Strategy and Two-Repo Model

**Version:** 1.0  
**Date:** 2026-02-26  
**Status:** Proposed operating strategy

## 1. Core Principle: Separate Pricing From Source Availability

These are different decisions:

- `Open source vs private` = what code users can inspect and self-host
- `Free vs paid` = what product/package/services users pay for

A healthy SentinelPass model can have:

- open-source core,
- free official binaries,
- paid hosted and enterprise add-ons.

## 2. What Must Remain Open Source (Trust-Critical Surfaces)

These should remain public and auditable:

- vault file format and schema migrations
- cryptographic implementations and key hierarchy
- local unlock/lock flows
- daemon/native host protocols
- browser extension -> host -> daemon message contracts
- sync protocol and relay wire/auth protocol
- self-host relay reference implementation
- threat model and security architecture docs

Reason:

- Closing these surfaces undermines user trust and makes security claims hard to verify.

## 3. Proposed Tier Model

## Tier A: Community OSS (source + self-build/self-host)

Includes:

- `sentinelpass-core`
- CLI
- daemon + native host
- desktop UI (core features)
- browser extension
- TOTP + SSH key storage
- self-host relay
- protocol docs and migration docs

Target user:

- developers, self-hosters, privacy-focused users

## Tier B: Free Official (signed releases, no subscription)

Includes:

- official signed desktop binaries
- official browser extension releases
- local-first use without account
- self-host relay compatibility
- baseline local password health features (when implemented)

Value:

- easier onboarding and trust through official distribution

## Tier C: Paid Personal / Pro

Includes (private services and/or private modules):

- managed encrypted relay hosting
- advanced breach and password health integrations
- premium convenience UX (device management, enhanced sync insights)
- priority support

Important:

- Pro features should not require changing the trust model (no server-side plaintext access).

## Tier D: Paid Teams / Business / Enterprise

Includes:

- shared vaults and RBAC
- admin console and policy engine
- SSO/SCIM
- audit export / SIEM integrations
- deployment and compliance features

## 4. Component Boundary Recommendation (Open vs Private)

## Open-source (public repo)

- Core vault, crypto, database, migrations
- Daemon IPC and native host protocols
- Browser extension core autofill/save
- Desktop client core UX
- Self-host relay server (single-tenant/community)
- Mobile bridge and client core path (recommended, even if staged)
- Protocol specs and docs

## Private / paid (private repo)

- Hosted relay control plane (multi-tenant)
- Billing, subscriptions, entitlement issuance
- Enterprise admin/policy backend
- SSO/SCIM connectors
- Advanced risk/breach data pipelines and licensed integrations
- Premium support tooling and hosted observability

## Borderline components (recommend open interface, private implementation)

- `BreachProvider`
- `EntitlementProvider`
- `PolicyProvider`
- `TelemetrySink` (opt-in only)
- Hosted sync provider integrations

## 5. Two-Repo Strategy (Recommended)

## Repo 1: Public OSS repo (`sentinelpass`)

Purpose:

- Trust-critical code
- Public interfaces and protocols
- Community development
- Self-host reference deployments

Governance:

- Source of truth for protocol schemas and core interfaces
- Tagged releases with semver / compatibility notes

## Repo 2: Private commercial repo (`sentinelpass-enterprise` or `sentinelpass-pro`)

Purpose:

- Paid features and hosted operations
- Enterprise connectors and admin capabilities
- Commercial deployment tooling

Governance:

- Must consume public repo by tag or commit pin
- Must not fork/copy public core code as a divergent codebase

## 6. How to Avoid a Long-Lived Fork (Most Important)

Do this:

- Design extension points in public repo first.
- Keep protocol and interface definitions public.
- Have private repo implement traits/adapters/plugins.
- Add compatibility/contract tests in private repo that run against public tags.

Do not do this:

- Copy public crates into private repo and modify them.
- Patch cryptographic or protocol behavior only in private code.
- Let private repo define protocol contracts that public repo later reverse-engineers.

## 7. Integration Mechanics (Practical)

## Rust

- Private repo depends on public crates via git tag or published internal registry mirrors.
- Public crates expose feature flags and extension traits.
- Private implementations live in separate crates (for example `sentinelpass-enterprise-policy`, `sentinelpass-hosted-sync`).

## TypeScript / UI

- Public repo defines capability manifest schema and extension points.
- Private repo provides premium UI modules or backend APIs.
- UI should render based on signed capabilities, not ad-hoc build forks where possible.

## Protocols / schemas

- Keep message schemas and protocol versions in public repo.
- Private services must remain compatible or explicitly version-gate differences.

## 8. Release and CI Strategy Across Two Repos

## Public repo release flow

1. Tag release in public repo (`vX.Y.Z`)
2. Publish changelog with protocol/interface changes
3. Build OSS/self-host artifacts

## Private repo release flow

1. Bump dependency pins to public tags
2. Run compatibility test matrix
3. Build paid/private artifacts and hosted deploys

## Required CI checks

- Public:
  - protocol schema tests
  - security-sensitive tests
  - packaging and docs checks
- Private:
  - compatibility against pinned public tags
  - entitlement/capability integration tests
  - hosted service abuse-control and ops tests

## 9. Licensing Direction (Suggested)

## Public repo

- Keep Apache-2.0 (already used) for core OSS components.

## Private repo

- Commercial license / EULA for paid modules and hosted operations.

Notes:

- If future enterprise server components need source availability, consider a source-available license separately, but do not mix trust-critical cryptography into closed/server-only code.

## 10. Initial Feature Packaging Recommendation (What to Monetize)

Monetize convenience and administration, not trust:

- Managed relay hosting
- Advanced breach monitoring integrations
- Team features (sharing, RBAC, policy)
- Enterprise SSO/SCIM and audit exports
- Premium support / managed deployments

Keep free/OSS:

- local vault use
- browser autofill
- daemon/native host
- self-host sync relay
- TOTP and SSH key management
- import/export baseline formats

## 11. Rollout Strategy (Pragmatic)

### Step 1 (now)

- Publish this boundary model and commit to "trust-critical remains open."

### Step 2

- Create extension interfaces/capability manifest in public repo.

### Step 3

- Stand up private repo using public tags (no copied core code).

### Step 4

- Launch free official builds and self-host docs as the baseline.

### Step 5

- Layer paid personal hosted sync and advanced monitoring.

### Step 6

- Add teams/admin/enterprise features after core hardening and product completeness.

## 12. Decision Checklist (Before Closing a Component)

Ask these questions:

1. Does this component affect cryptography, vault format, or protocol trust?
2. Would closing it reduce users' ability to verify security claims?
3. Is this feature primarily convenience/admin/operations rather than trust?
4. Can it be built as a plugin/service without modifying public core behavior?

If `1` or `2` is yes, keep it open.
