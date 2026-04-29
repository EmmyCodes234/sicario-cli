# Contributing to Sicario

Thank you for your interest in contributing. This document covers everything you need to get started.

## Getting started

1. Fork the repository and clone your fork
2. Install Rust 1.75+ stable: https://rustup.rs
3. On Linux, install system dependencies:
   ```bash
   sudo apt-get install -y libsecret-1-dev pkg-config
   ```
4. Build and run tests:
   ```bash
   cargo build
   cargo test --workspace
   ```

## Development workflow

```bash
git checkout -b feat/my-feature   # branch from main
# make changes
cargo test --workspace            # all tests must pass
cargo clippy --workspace -- -D warnings
cargo fmt --all
# open a pull request against main
```

## Code style

- Follow standard Rust conventions
- Run `cargo fmt` before committing
- Public items should have doc comments
- New modules should include unit tests
- Property-based tests (proptest) are encouraged for core logic

## Adding security rules

Rules live in `sicario-cli/rules/<language>/` as YAML files. Drop a file in and it's picked up automatically.

1. Create a YAML file in the appropriate language directory
2. Follow the format of existing rules (see any file in `rules/` for examples)
3. Include at least 3 true-positive and 3 true-negative test cases
4. Validate: `cargo run -- rules validate`
5. Test: `cargo run -- rules test`

## Working on the Convex backend

The cloud backend lives in `convex/convex/`. The frontend (`sicario-frontend/`) consumes these functions.

1. Install Node.js 18+ and run `npm install` in `convex/`
2. Set `CONVEX_DEPLOYMENT` in `convex/.env.local`
3. Run `npx convex dev` for hot reload
4. Schema changes go in `convex/convex/schema.ts`

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add LDAP injection detection for Go
fix: correct false positive in Python SQL injection rule
docs: update CLI reference in README
test: add property tests for confidence scorer
chore: bump tree-sitter to 0.21
```

## Pull request guidelines

- One feature or fix per PR
- Clear description of what changed and why
- Tests for new functionality
- Documentation updated if the public API changes
- Link related issues with `Closes #123`

## Reporting bugs

Open an issue with:
- Sicario version (`sicario --version`)
- OS and architecture
- Steps to reproduce
- Expected vs actual behavior
- Log output (`RUST_LOG=debug sicario scan .`)

## Security vulnerabilities

Do **not** open a public issue for security vulnerabilities. See [SECURITY.md](SECURITY.md).

## License

By contributing, you agree your contributions will be licensed under the MIT License.
