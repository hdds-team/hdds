# Contributing to HDDS

Thank you for your interest in contributing to HDDS! This guide explains how to get started.

## Ways to Contribute

### Report Issues

Found a bug or have a feature request?

1. Check [existing issues](https://git.hdds.io/hdds/hdds/issues) first
2. If not found, [create a new issue](https://git.hdds.io/hdds/hdds/issues/new)
3. Use the appropriate template:
   - **Bug Report**: For bugs and unexpected behavior
   - **Feature Request**: For new functionality
   - **Documentation**: For doc improvements

### Submit Code

Ready to contribute code?

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

### Improve Documentation

Documentation contributions are always welcome:

- Fix typos and clarify wording
- Add examples and tutorials
- Translate to other languages
- Improve API documentation

## Development Setup

### Prerequisites

```bash
# Rust (1.75+)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup update stable

# Development tools
cargo install cargo-watch cargo-nextest cargo-llvm-cov
```

### Clone and Build

```bash
git clone https://git.hdds.io/hdds/hdds.git
cd hdds

# Build all components
cargo build --workspace

# Run tests
cargo nextest run

# Run with debug logging
RUST_LOG=hdds=debug cargo run --example hello_world
```

### Project Structure

```
hdds/
├── hdds/                 # Core DDS library
│   ├── src/
│   │   ├── domain/       # Domain participant
│   │   ├── transport/    # Network transports
│   │   ├── discovery/    # SPDP/SEDP
│   │   ├── qos/          # QoS policies
│   │   └── rtps/         # RTPS protocol
│   └── tests/
├── hdds-gen/             # Code generator
├── hdds-derive/          # Proc macros
├── tools/
│   ├── hdds-viewer/      # Traffic analyzer
│   └── hdds-studio/      # Visual editor
└── examples/             # Usage examples
```

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
cargo nextest run test_reliable_delivery

# Run with coverage
cargo llvm-cov nextest --workspace

# Integration tests
cargo test --test integration
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
# Create feature branch
git checkout -b feat/shared-memory-transport

# Make changes and commit
git add .
git commit -m "feat(transport): implement shared memory"

# Push and create PR
git push origin feat/shared-memory-transport
```

### Example: Adding a New QoS Policy

1. **Define the policy** in `hdds/src/qos/mod.rs`:

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

3. **Implement wire format** in `hdds/src/rtps/parameter.rs`

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

### Building Docs

```bash
cd docs
npm install
npm run start  # Local preview
npm run build  # Production build
```

### Doc Structure

```
docs/
├── getting-started/     # Tutorials
├── guides/              # How-to guides
├── concepts/            # Explanations
├── reference/           # API reference
└── tools/               # Tool documentation
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

1. Update `CHANGELOG.md`
2. Update version in `Cargo.toml`
3. Create release tag
4. Build and publish crates
5. Update documentation

## Getting Help

### Questions

- [Contact](mailto:contact@hdds.io)

### Real-Time Chat

Join our Discord server for:
- Development discussions
- Quick questions
- Community support

## Recognition

Contributors are recognized in:

- `CONTRIBUTORS.md` file
- Release notes
- Annual contributor spotlight

Thank you for contributing to HDDS!
