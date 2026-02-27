# Contributing to HDDS

Thank you for considering contributing to HDDS! This document explains the rules and process for contributing.

## Code of Conduct

This project is governed by the [HDDS Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## Contribution Policy

### AI-Assisted Code

AI-generated or AI-assisted code is **accepted**, provided it passes the same quality gates as human-written code. No exceptions.

**Required:** all contributions must pass the audit scan:

```bash
bash scripts/extrem-audit-scan.sh
```

**Acceptance thresholds:**

| Severity | Maximum |
|----------|---------|
| CRITICAL | **0** |
| HIGH | **0** |
| MEDIUM | < 200 |
| LOW | < 50 |

Any CRITICAL or HIGH violation is an automatic rejection.

### Author Identity

Commit signatures must reference a **contactable human**. We accept:

- Real names with a verifiable email
- Pseudonyms with a contactable email (GPG-signed)

We do **not** accept:

- Bot accounts with no human contact
- Anonymous identities with no way to reach the author
- AI model names as authors (GPT-5, Gemini, Grok, Claude, Ollama models, etc.)

If an AI tool assisted your contribution, mention it in the commit body (e.g., `Co-Authored-By: Claude <noreply@anthropic.com>`), but the primary author must be a human we can contact.

### DCO Sign-Off

All commits must include a Developer Certificate of Origin sign-off:

```
Signed-off-by: Your Name <your.email@example.com>
```

Use `git commit -s` to add it automatically.

### No Personal Data

Do not include personal information in code, comments, or documentation:

- No personal email addresses (use project addresses)
- No real names in code comments or error messages
- No phone numbers, physical addresses, or social media handles

Use `HDDS Team` and `contact@hdds.io` for any contact references.

## How to Contribute

### Reporting Bugs

Before creating a bug report, check existing issues. When reporting:

- **Clear, descriptive title**
- **Exact steps to reproduce**
- **Code snippets or config files**
- **Observed vs. expected behavior**
- **Logs** with `RUST_LOG=debug`
- **Environment**: OS, Rust version, HDDS version

### Pull Requests

1. Fork the repo and branch from `main`
2. Follow the coding rules below
3. Add tests for any new functionality
4. New features must include architecture documentation in `docs/`
5. Ensure all quality gates pass (see below)
6. Write a clear commit message with DCO sign-off

## Quality Gates

Every PR must pass these gates before merge:

```bash
# 1. Format
cargo fmt --all -- --check

# 2. Clippy (warnings = errors)
cargo clippy --all-targets --all-features -- -D warnings

# 3. Tests
cargo test --all-features

# 4. Audit scan
bash scripts/extrem-audit-scan.sh

# 5. Golden vectors (if serialization changed)
cargo test --test golden_vectors
```

## Coding Rules

### Rust Style

- Follow the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- `cargo fmt` for formatting
- `cargo clippy` with zero warnings

### `#[allow(...)]` is Forbidden

Do **not** suppress warnings with `#[allow(...)]` in production code. If code triggers a warning:

1. **Fix the underlying issue** (remove dead code, fix the cast, handle the error)
2. If it is a false positive, open an issue with justification

**Exceptions:**
- `#[cfg(test)]` modules
- Generated code blocks (`include!(...)`)
- `#[cfg_attr(...)]` for feature-gated dead code (with comment explaining why)

### Safety Requirements

- All `unsafe` blocks must have a `// SAFETY:` comment
- No panics in production code -- use `Result`
- No `unwrap()` except in tests

### No Vendored Dependencies

All dependencies go through `Cargo.toml`. Do not copy-paste external crate code into the tree.

### Serialization Changes

Any change to CDR2 encoding/decoding must:

1. Update or add golden vectors in `crates/hdds/tests/golden/cdr2/`
2. Regenerate with `GOLDEN_REGEN=1 cargo test --test golden_vectors`
3. Update `MANIFEST.md` with the new vector description

### New Features

New features require:

1. Architecture documentation in `docs/` (design rationale, not just API docs)
2. Unit tests in the same module
3. Integration test if the feature involves network/discovery

### Performance

- Zero-allocation hot paths where possible
- Lock-free data structures when appropriate
- Profile before optimizing -- no speculative optimization

### Testing

- Unit tests go in the same file as the code
- Integration tests go in `tests/`
- Use `#[cfg(test)]` for test-only code

## Commit Messages

- Present tense, imperative mood ("Add feature" not "Added feature")
- First line: 72 characters max
- Reference issues after the first line
- Include DCO sign-off

## License

By contributing, you agree that your contributions will be licensed under the same dual license as the project (Apache-2.0 OR MIT).

## Questions?

Open an issue or reach out at contact@hdds.io.
