# Repository Guidelines

## Project Structure & Module Organization
This repository is a Rust workspace centered on `sentinelpass-*` crates:
- `sentinelpass-core/`: crypto, vault, database, IPC, and shared domain logic.
- `sentinelpass-cli/`: `sentinelpass` command-line binary.
- `sentinelpass-daemon/`: background unlock/autolock service for extension access.
- `sentinelpass-host/`: native messaging bridge used by browser extensions.
- `sentinelpass-ui/`: Tauri desktop app (`src-tauri/` plus web assets).
- `browser-extension/`: Chrome and Firefox extension code.
- `installation/`, `native-host/`, `migrations/`: install scripts, host manifests, schema setup.

## Build, Test, and Development Commands
- `cargo build --workspace`: build all crates in debug mode.
- `cargo build --release --workspace`: optimized production build.
- `cargo run --package sentinelpass-cli -- --help`: run CLI locally.
- `cargo run --package sentinelpass-daemon`: run daemon for extension testing.
- `cargo run --package sentinelpass-ui`: launch desktop UI.
- `cargo test --workspace --verbose`: run full Rust test suite.
- `cargo clippy --workspace --all-targets -- -D warnings`: fail on lint warnings.
- `cargo fmt --all` and `cargo fmt --all -- --check`: format/check formatting.
- `just ci` / `just lint` / `just test`: task aliases for common workflows.

## Coding Style & Naming Conventions
Use Rust 2021 idioms and keep code `rustfmt`-clean. Rust uses 4-space indentation; extension JavaScript currently uses 2 spaces. Follow standard naming: `snake_case` for files/modules/functions, `CamelCase` for structs/enums/traits, and `SCREAMING_SNAKE_CASE` for constants. Prefer explicit error handling with `Result` and avoid panics in production paths.

## Testing Guidelines
Most tests are inline unit tests (`#[cfg(test)]`) inside modules, especially in `sentinelpass-core/src/*`. Add tests close to changed code, and use descriptive behavior-focused names (for example: `locks_after_failed_attempts`). Run `cargo test --workspace` before opening a PR; for focused work use `cargo test -p sentinelpass-core`.

## Commit & Pull Request Guidelines
Recent history favors Conventional Commit style, e.g. `feat(ui): add ...` and `feat(security): ...`. Use `type(scope): imperative summary` when possible, keep commits focused, and avoid mixing refactors with behavior changes. PRs should include:
- clear summary and rationale,
- linked issue (if available),
- test evidence (commands run, outcomes),
- screenshots/GIFs for UI or extension changes.

Protected branches require passing CI and at least one approving review.

## Security & Configuration Tips
Read `SECURITY_ARCHITECTURE.md` before touching crypto, vault, IPC, lockout, or audit logic. Never commit vault data, plaintext secrets, or machine-specific credentials. Keep extension/native-host manifest changes synchronized across `browser-extension/`, `native-host/`, and `installation/`.
