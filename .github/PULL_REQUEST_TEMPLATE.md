## Summary

## Motivation

## Changes

- 

## Validation

Commands run and outcomes:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
npm run web:typecheck
npm run test:ts
```

## Security Impact

- [ ] None
- [ ] Yes (describe)

## UI / Extension Evidence

Screenshots or logs (if applicable).

## Checklist

- [ ] Tests added/updated where behavior changed
- [ ] Docs updated if UX/operations changed
- [ ] No plaintext secrets in diffs or logs
