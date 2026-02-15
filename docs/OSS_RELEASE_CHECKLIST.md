# OSS Release Checklist (Apache-2.0)

## Governance

| Item | Status target |
| --- | --- |
| `LICENSE` contains Apache-2.0 text | Required |
| `NOTICE` file present | Required |
| `CONTRIBUTING.md` present | Required |
| `CODE_OF_CONDUCT.md` present | Recommended |
| `SECURITY.md` present | Required |

## Metadata

| Item | Location |
| --- | --- |
| Rust license metadata | `Cargo.toml` workspace + crates |
| Repo URL/homepage | `Cargo.toml` workspace |
| CI release automation | `.github/workflows/release.yml` |

## Release Hygiene

| Gate | Command |
| --- | --- |
| Rust lint | `cargo clippy --workspace --all-targets -- -D warnings` |
| Rust tests | `cargo test --workspace` |
| TS typecheck | `npm run web:typecheck` |
| TS tests | `npm run test:ts` |
| Security scan | `.github/workflows/security.yml` |

## Artifacts

| Platform | Expected installer path |
| --- | --- |
| Windows | `sentinelpass-installer-<tag>-windows.zip` |
| macOS | `sentinelpass-installer-<tag>-macos.tar.gz` |
| Linux | `sentinelpass-installer-<tag>-linux.tar.gz` |

All installers should default to user-level install paths and avoid admin requirements.

