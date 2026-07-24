# BSDM-Proxy Workspace Rules

## Formatting and Linting
- **ALWAYS** run `cargo fmt --all` before committing any Rust code changes in this workspace. The CI pipeline strictly enforces formatting and will fail if the code is not formatted correctly.
- **ALWAYS** run `cargo clippy --workspace --all-targets --all-features -- -D warnings` before committing if you make logical changes, to ensure no linting errors are introduced.
