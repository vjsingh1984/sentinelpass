# Contributing to SentinelPass

Thanks for contributing. This project is Apache-2.0 licensed and security-sensitive; keep changes small, test-backed, and reviewable.

## Workflow

| Step | Action |
| --- | --- |
| 1 | Open an issue (bug, feature, security-safe proposal) |
| 2 | Create a branch from `develop` |
| 3 | Implement + add/adjust tests |
| 4 | Run local quality gates |
| 5 | Open PR with clear evidence |

## Local Quality Gates

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
npm run web:typecheck
npm run test:ts
```

## Commit Style

Use focused commits. Preferred format:

```text
type(scope): imperative summary
```

Examples:
- `fix(daemon): gate save path when vault is locked`
- `feat(ui): add manual refresh action for entries`

## Pull Request Checklist

- [ ] Problem and solution are described clearly.
- [ ] Security impact is noted (or marked none).
- [ ] Tests added/updated for behavior changes.
- [ ] Commands run and outcomes included.
- [ ] UI/extension changes include screenshots or logs.

## Security-sensitive Areas

Changes touching these paths need extra care and explicit reasoning:
- `sentinelpass-core/src/crypto/`
- `sentinelpass-core/src/vault.rs`
- `sentinelpass-core/src/daemon/`
- `sentinelpass-host/`
- `browser-extension/`

Read `SECURITY.md` and `SECURITY_ARCHITECTURE.md` before submitting security-critical changes.

## License

By contributing, you agree your contributions are licensed under Apache License 2.0.

