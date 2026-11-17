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
| MEDIUM | <= 240 |
| LOW | < 50 |

Any CRITICAL or HIGH violation is an automatic rejection.

### Author Identity

Commit signatures must reference a **contactable human**. We accept:

- Real names with a verifiable email
- Pseudonyms with a contactable email (GPG-signed)

We do **not** accept:

- Bot accounts with no human contact
- Anonymous identities with no way to reach the author
- AI assistants or model names as authors

If an AI tool assisted your contribution, you are still its author and answer for it. Do not add the tool as an author or co-author: `.githooks/commit-msg` rejects `Co-Authored-By` trailers that name an AI assistant or its vendor. Enable the hooks with `git config core.hooksPath .githooks`.

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

1. Fork the repo and branch from `master`. The public repository receives one commit per release; development happens upstream between releases. A merged pull request is applied to the development line with your authorship preserved, and you are credited in the next release commit (`Co-authored-by`) and in the CHANGELOG "Contributors" section
2. Follow the coding rules below
3. Add tests for any new functionality
4. New features must include architecture documentation in `docs/`
5. Ensure all quality gates pass (see below)
6. Write a clear commit message with DCO sign-off

## Quality Gates

Every PR must pass these gates before merge. They are **a script**, not a list
of commands to retype:

```bash
bash scripts/gates.sh            # full set -- before a merge
bash scripts/gates.sh --quick    # slow lanes skipped -- before every commit
bash scripts/gates.sh --list     # what it runs, in order
bash scripts/gates.sh --help     # all flags
```

The script runs **every** gate even after one fails, redirects each gate to its
own log under `target/gate-logs/<timestamp>/`, prints the actual numbers (test
counts passed/failed/ignored, error counts, per-target results) in a summary
table, and exits `1` if any gate failed, `0` otherwise. The exit status is a
verdict, never a count.

### What the script covers beyond the plain commands

- **Cross-target checks.** `scripts/gates.sh` runs
  `cargo check -p hdds --lib --target <T>` for `x86_64-apple-darwin`,
  `aarch64-apple-darwin`, `x86_64-pc-windows-gnu` and
  `aarch64-unknown-linux-gnu`, and reports a target whose toolchain is not
  installed as a loud, labelled **SKIP**, never as a pass. Install a missing
  one with `rustup target add <T>`.
- **A cross target needs a C compiler too.** `scripts/extrem-audit-scan.sh`
  checks `--lib --examples`, and the examples pull `ring`, which builds C. So a
  musl or mingw target also needs its `gcc` on `PATH` (for example
  `aarch64-linux-musl-gcc` from a musl cross toolchain). The gate probes for
  it and reports a MEDIUM skip naming the missing tool, rather than a code
  defect. Put the toolchain `bin/` directory on your `PATH` (shell profile), or
  that target is skipped on every run.
- **Non-default features.** Code behind a non-default feature is invisible to
  `cargo check -p hdds-c`, which only compiles the default feature set. The
  script gives `cargo check -p hdds-c --features rmw` its own row.

### The gate set

| Gate | Command | Lane |
|------|---------|------|
| `fmt` | `cargo fmt --all -- --check` | fast |
| `punctuation` | tracked `*.rs` free of prose punctuation and accents (see [Source Text](#source-text-is-ascii)) | fast |
| `clippy` | `cargo clippy --all-targets --all-features -- -D warnings` | fast |
| `test` | `cargo test --all-features` | fast |
| `audit` | `bash scripts/extrem-audit-scan.sh` | slow |
| `check-ws` | `cargo check --workspace --all-targets` | fast |
| `hdds-c-rmw` | `cargo check -p hdds-c --features rmw` | fast |
| `cross:<T>` | `cargo check -p hdds --lib --target <T>`, four targets | slow |

`--quick` skips the **slow** lanes. Acceptance thresholds for the audit scan
are the table in [AI-Assisted Code](#ai-assisted-code) above; the script reads
the scan's own verdict, including its `exit 2` for a *degraded* scan -- a check
group that could not run is not a check group that passed.

If serialization changed, also run the golden vectors:

```bash
cargo test --test golden_vectors
```

### Two environment facts the script handles for you

**Sample type generation.** The Rust SDK samples `include!` files under
`sdk/samples/**/generated/`. Those files are gitignored, no `build.rs` produces
them. `Cargo.toml` keeps those crates out of `default-members` precisely so a
clean-checkout `cargo clippy` and `cargo test` at the root do not trip over
them, so **only the `--workspace` gate compiles the samples**.

The generator needs the `hddsgen` binary, which lives in the **separate**
`hdds_gen` repository -- it is not vendored here and cargo will not fetch it:

```bash
cargo install --path /path/to/hdds_gen --force   # or: export HDDSGEN=/abs/path/to/hddsgen
bash sdk/samples/scripts/gen_rust_types.sh
```

On a tree where that step has not run, the sample crates fail to compile under
`--workspace`. The script **classifies** those errors rather than counting
them: any error **outside** `sdk/samples/` is a failure; errors **inside** it
are reported as a labelled, non-fatal note naming the generation step.

The raw error count is not a measurement: a crate stops emitting diagnostics
once it fails, and the parallel build front differs run to run. For the same
reason, sample failures can mask later diagnostics in those same sample
crates: only a tree where `gen_rust_types.sh` has run gives a complete check of
them.

**Multicast routed into a VPN.** Tests that need two participants to discover
each other pin themselves to loopback automatically
(`crates/hdds/src/test_support/network.rs`, wired through the domain-lease
helper every such test already calls), so a plain `cargo test` is hermetic on a
normal machine. If you still see a test fail at `SPDP discovery never
completed`, or a UDP round-trip time out, your host is very likely routing
multicast into a VPN/tunnel interface instead of the LAN. One command names the
cause, and the script runs it for you and prints the answer:

```bash
ip route get 239.255.0.2
```

If that names a tunnel device (a VPN client, WireGuard, a container bridge, ...), force
the interface HDDS itself would need in that deployment:

```bash
HDDS_INTERFACE=lo cargo test --all-features
```

To **test** the pin rather than trust it, run `bash scripts/gates.sh
--hermeticity`: it runs the suite with and without `HDDS_INTERFACE` and fails
if the two results differ, naming the tests that differed. It is opt-in because
it runs the suite twice.

Read its failure carefully: two runs disagreeing proves **non-determinism**,
not a hole in the pin. A flaky test landing on one side of the A/B produces the
same signature, so re-run the failing test in isolation and in its whole
binary, with and without the variable, before blaming the interface pin.

## Coding Rules

### Rust Style

- Follow the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- `cargo fmt` for formatting
- `cargo clippy` with zero warnings

### Source Text is ASCII

Source files are **pure ASCII, English only**. This is gated by the
`punctuation` row of `scripts/gates.sh`, which lists every offending
`file:line`.

Forbidden in tracked `*.rs`, including inside comments and doc comments:

| Forbidden | Write instead |
|-----------|---------------|
| em dash `U+2014`, en dash `U+2013` | `-`, or a comma, parentheses or `:` |
| rightwards arrow `U+2192` | `->` |
| ellipsis `U+2026` | `...` |
| guillemets `U+00AB` `U+00BB` | `"` |
| accented Latin letters (`U+00C0`-`U+017F`) | unaccented English |

The gate is **deliberately narrow**: it rejects the characters listed above
and does not claim to reject every other non-ASCII character.

### `#[allow(...)]` is Forbidden

Do **not** suppress warnings with `#[allow(...)]` in production code. If code triggers a warning:

1. **Fix the underlying issue** (remove dead code, fix the cast, handle the error)
2. If it is a false positive, open an issue with justification

**Exceptions:**
- `#[cfg(test)]` modules
- Generated code blocks (`include!(...)`)
- `#[cfg_attr(...)]` for feature-gated dead code (with comment explaining why)

### Safety Requirements

- Every new `unsafe` block must have a `// SAFETY:` comment (`clippy::undocumented_unsafe_blocks` is the check)
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
