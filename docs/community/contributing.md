# Contributing to HDDS

Thank you for your interest in contributing to HDDS! This guide explains how to get started.

## Contribution Policy

The binding rules live in [CONTRIBUTING.md](../../CONTRIBUTING.md) at the root of the repository; this page is the practical guide around them. In short:

- **DCO sign-off**: every commit must carry a Developer Certificate of Origin sign-off. Use `git commit -s`, which appends `Signed-off-by: Your Name <your.email@example.com>`.
- **Author identity**: commit signatures must reference a contactable human. Bot accounts, anonymous identities and AI assistants or model names are not accepted as authors or co-authors. AI-assisted code is accepted, and you remain its author.
- **Quality gates**: contributions must pass the audit scan (`bash scripts/extrem-audit-scan.sh`); any CRITICAL or HIGH finding is an automatic rejection.
- **No personal data** in code, comments or documentation.

## Ways to Contribute

### Report Issues

Found a bug or have a feature request?

1. Check [existing issues](https://git.hdds.io/hdds/hdds/issues) first
2. If not found, [create a new issue](https://git.hdds.io/hdds/hdds/issues/new)
3. Use the appropriate template:
   - **Bug Report**: For bugs and unexpected behavior
   - **Feature Request**: For new functionality

### Submit Code

Ready to contribute code?

1. Fork the repository
2. Create a feature branch from `master`
3. Make your changes
4. Submit a pull request (see [CONTRIBUTING.md](../../CONTRIBUTING.md) for how accepted changes reach a release and how contributors are credited)

### Improve Documentation

Documentation contributions are always welcome:

- Fix typos and clarify wording
- Add examples and tutorials
- Translate to other languages
- Improve API documentation

## Development Setup

### Prerequisites

```bash
# Rust (1.90 builds this release, 1.85 does not)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup update stable

# Development tools
cargo install cargo-watch cargo-nextest cargo-llvm-cov
```

### Clone and Build

```bash
git clone https://git.hdds.io/hdds/hdds.git
cd hdds

# Build the default set: the engine, the tools and the SDK crates
cargo build

# Run tests
cargo nextest run

# Run an example that needs no generated code
cargo run -p hdds --example basic_pubsub
```

`cargo build` and `cargo nextest run` cover the default workspace members. The Rust
sample programs under `sdk/samples/` include generated types that are not checked in,
so `cargo build --workspace` only works after you generate them (see
[Sample types](#sample-types) below).

### Sample types

The sample programs are binaries of the crates under `sdk/samples/<group>/rust/`, not
Cargo examples. Install the code generator (`hddsgen` 2.0 or later, from the separate
`hdds_gen` repository), generate the types, then run a sample:

```bash
git clone https://git.hdds.io/hdds/hdds_gen.git && cargo install --path hdds_gen
sdk/samples/scripts/generate.sh

cd sdk/samples/01_basics/rust
cargo run --bin hello_world           # Terminal 1: subscriber
cargo run --bin hello_world -- pub    # Terminal 2: publisher
```

### Project Structure

```
hdds/
+-- crates/
|   +-- hdds/             # Core DDS library
|   |   +-- src/
|   |   |   +-- dds/          # Participant, publisher, subscriber, readers, writers
|   |   |   +-- transport/    # Network transports
|   |   |   +-- core/discovery/  # SPDP/SEDP discovery
|   |   |   +-- qos/          # QoS policies
|   |   |   +-- protocol/     # RTPS and discovery wire formats
|   |   +-- examples/
|   |   +-- tests/
|   +-- hdds-codegen/     # Derive macro for Rust types
|   +-- hdds-c/           # C API
|   +-- hdds-micro/       # no_std embedded implementation
|   +-- ...               # router, gateway, recording, persistence, ...
+-- tools/                # Command-line tools (hddsctl, hdds-debugger, ...)
+-- sdk/                  # Rust, C, C++, Python and TypeScript SDKs, and samples/
+-- rmw_hdds/             # ROS 2 RMW layer
+-- docs/                 # Documentation (Markdown)
+-- scripts/              # Gates and maintenance scripts
```

The IDL code generator (`hddsgen`) lives in the separate `hdds_gen` repository.

## Code Guidelines

### Rust Style

Follow Rust idioms and conventions:

```rust
// Good: Use Result for fallible operations
pub fn create_topic(&self, name: &str) -> Result<Topic, hdds::Error> {
    // ...
}

// Good: Use fluent builder pattern
let writer = topic
    .writer()
    .qos(QoS::reliable().keep_last(10))
    .build()?;

// Good: Document public APIs
/// Creates a new DataWriter for the specified topic.
///
/// # Errors
///
/// Returns `hdds::Error::TopicNotFound` if the topic doesn't exist.
pub fn create_datawriter(&self, topic: &Topic) -> Result<DataWriter, hdds::Error> {
    // ...
}
```

### Formatting

```bash
# Format code
cargo fmt

# Check formatting
cargo fmt --check
```

### Linting

```bash
# Run clippy
cargo clippy --workspace --all-targets -- -D warnings

# With pedantic lints (recommended for new code)
cargo clippy --workspace -- -W clippy::pedantic
```

### Testing

```bash
# Run all tests
cargo nextest run

# Run specific test
cargo nextest run -p hdds a_reliable_burst_lost_on_the_way_is_repaired

# Run with coverage
cargo llvm-cov nextest --workspace

# Integration tests
cargo test --release
```

## Pull Request Process

### Before Submitting

1. **Ensure tests pass**:
   ```bash
   cargo nextest run
   cargo clippy --workspace -- -D warnings
   cargo fmt --check
   ```

2. **Add tests** for new functionality

3. **Update documentation** if needed

4. **Write a clear commit message**:
   ```
   feat(transport): add shared memory transport

   Implements zero-copy shared memory transport for same-host
   communication. Supports automatic fallback to UDP.

   Closes #123

   Signed-off-by: Your Name <your.email@example.com>
   ```

### Commit Message Format

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `style`: Formatting, no code change
- `refactor`: Code change, no new feature or fix
- `perf`: Performance improvement
- `test`: Adding tests
- `chore`: Build process or tooling

### PR Review Process

1. **Automated checks** run on all PRs:
   - Build and test on Linux, macOS, Windows
   - Clippy lints
   - Format check
   - Security audit

2. **Code review** by maintainers:
   - Architecture and design
   - Code quality
   - Test coverage
   - Documentation

3. **Approval and merge**:
   - At least one maintainer approval required
   - All checks must pass
   - Squash merge preferred

## Adding New Features

### Proposing Changes

For significant changes:

1. Open an issue describing the proposal
2. Discuss with maintainers
3. Get approval before implementing

### Feature Branches

```bash
# Create a feature branch from master
git checkout -b feat/shared-memory-transport master

# Make changes and commit
git add .
git commit -m "feat(transport): implement shared memory"

# Push and create PR
git push origin feat/shared-memory-transport
```

### Example: Adding a New QoS Policy

1. **Define the policy** in a new module under `crates/hdds/src/qos/`:

```rust
#[derive(Clone, Debug, Default)]
pub struct NewPolicy {
    pub setting: bool,
}
```

2. **Add to QoS builders**:

```rust
impl DataWriterQos {
    pub fn new_policy(mut self, policy: NewPolicy) -> Self {
        self.new_policy = policy;
        self
    }
}
```

3. **Implement the wire format** in the discovery encoder and parser under
   `crates/hdds/src/protocol/discovery/sedp/` (`build/qos.rs` and `parse.rs`), with the
   parameter id in `crates/hdds/src/protocol/discovery/constants.rs`

4. **Add tests**:

```rust
#[test]
fn test_new_policy() {
    let qos = QoS::reliable().new_policy(true);
    assert!(qos.new_policy);
}
```

5. **Update documentation**

## Documentation Contributions

### Editing Docs

The pages under `docs/` are plain Markdown and need no build step. Keep links relative
and check that every command and snippet you add runs as written.

### Doc Structure

```
docs/
+-- getting-started/     # Tutorials
+-- guides/              # How-to guides
+-- concepts/            # Explanations
+-- api/                 # API reference per language
+-- reference/           # Limits, error codes, environment variables
+-- tools/               # Tool documentation
```

### Writing Style

- Use clear, concise language
- Include code examples
- Add diagrams where helpful
- Test all code snippets

## Release Process

### Versioning

HDDS follows [Semantic Versioning](https://semver.org/):

- **Major (1.x.x)**: Breaking changes
- **Minor (x.1.x)**: New features, backwards compatible
- **Patch (x.x.1)**: Bug fixes

### Release Checklist

1. Update `docs/changelog.md`
2. Update the workspace version in `Cargo.toml`
3. Create release tag
4. Build and publish crates
5. Update documentation

## Getting Help

### Questions

- [Contact](mailto:contact@hdds.io)

## Recognition

Contributors are credited in the release commit (`Co-authored-by`) and in the
"Contributors" section of the changelog (`docs/changelog.md`).

Thank you for contributing to HDDS!
