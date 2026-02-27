---
sidebar_position: 4
title: Building from Source
description: Compile HDDS from source code
---

# Building HDDS from Source

This guide covers building HDDS from source for contributors, customization, or platforms without pre-built packages.

## Prerequisites

### All Platforms

- **Git**
- **Rust 1.75+** with `cargo`
- **CMake 3.16+** (for C/C++ bindings)

### Linux

```bash
# Ubuntu/Debian
sudo apt install build-essential git cmake pkg-config libssl-dev

# Fedora/RHEL
sudo dnf install gcc gcc-c++ git cmake openssl-devel

# Arch
sudo pacman -S base-devel git cmake openssl
```

### macOS

```bash
xcode-select --install
brew install cmake openssl
```

### Windows

- Visual Studio 2019+ with C++ workload
- [Git for Windows](https://git-scm.com/download/win)
- [CMake](https://cmake.org/download/)

## Clone the Repository

```bash
git clone https://git.hdds.io/hdds/hdds.git
cd hdds
```

## Build HDDS (Rust)

### Debug Build

```bash
cargo build
```

### Release Build (Optimized)

```bash
cargo build --release
```

### With All Features

```bash
cargo build --release --all-features
```

### Run Tests

```bash
cargo test

# With verbose output
cargo test -- --nocapture

# Integration tests only
cargo test --test integration
```

### Run Benchmarks

```bash
cargo bench
```

## Build C/C++ SDKs

The simplest way to build the C++ SDK:

```bash
make sdk-cxx
```

This runs `cargo build --release -p hdds-c` (C FFI layer) then builds `libhdds_cxx.a` (C++ RAII wrappers) via CMake.

To also build all C++ samples:

```bash
make samples-cpp samples-cpp-qos
```

For a step-by-step tutorial on creating your own C++ project with HDDS, see **[Hello World C++](/getting-started/hello-world-cpp)**.

<details>
<summary>Manual build steps (without make targets)</summary>

```bash
# 1. Build Rust core + C FFI (standalone, no ROS 2)
cargo build --release -p hdds-c

# 2. Build C++ SDK
cd sdk/cxx
cmake -B build
cmake --build build

# 3. Your application links both libraries:
#    hdds_cxx hdds_c pthread dl m
```

Output:
- `target/release/libhdds_c.a` -- C FFI layer
- `sdk/cxx/build/libhdds_cxx.a` -- C++ RAII wrappers

</details>

:::warning Standalone vs ROS 2
`cargo build --release` (full workspace) compiles all crates including `rmw-hdds`, which adds ROS 2 symbol dependencies to `libhdds_c`. If you don't use ROS 2, build only the C crate:
```bash
cargo build --release -p hdds-c
```
:::

:::tip ROS 2 Support
ROS 2 features are optional. By default, the SDK builds in standalone mode. To enable ROS 2 support, define `HDDS_WITH_ROS2` and ensure ROS 2 headers are available.
:::

## Build Python Bindings

```bash
cd sdk/python

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\activate   # Windows

# Install build dependencies
pip install maturin

# Build and install
maturin develop --release

# Or build wheel
maturin build --release
pip install target/wheels/hdds-*.whl
```

## Build Documentation

```bash
# Rust docs
cargo doc --no-deps --open

# Full docs with dependencies
cargo doc --open
```

## Project Structure

```
hdds/
├── Cargo.toml              # Workspace root
├── crates/
│   ├── hdds/               # Core DDS library (RTPS, SPDP, SEDP)
│   ├── hdds-c/             # C FFI bindings (cbindgen)
│   ├── hdds-codegen/       # Build-time IDL code generation
│   ├── hdds-async/         # Async (tokio) wrapper
│   ├── hdds-micro/         # Lightweight embedded profile
│   ├── hdds-router/        # DDS routing service
│   ├── hdds-gateway/       # Protocol gateway
│   ├── hdds-recording/     # Data recording/replay
│   ├── hdds-persistence/   # Durable storage backend
│   └── rmw-hdds/           # ROS 2 middleware layer
├── sdk/
│   ├── c/                  # C headers (hdds.h)
│   ├── cxx/                # C++ SDK (hdds.hpp, RAII wrappers)
│   ├── cmake/              # CMake find_package config
│   └── samples/            # Example applications (C++, C, Python, Rust)
├── tools/                  # hdds-ws (WebSocket bridge), scripts
├── tests/                  # Integration tests
└── benches/                # Benchmarks
```

## Development Workflow

### Format Code

```bash
cargo fmt

# Check only (CI)
cargo fmt -- --check
```

### Run Clippy

```bash
cargo clippy --all-targets --all-features -- -D warnings
```

### Run All Checks

```bash
# This is what CI runs
cargo fmt -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo doc --no-deps
```

## Cross-Compilation

### Linux ARM64 (from x86_64)

```bash
# Add target
rustup target add aarch64-unknown-linux-gnu

# Install cross-compiler
sudo apt install gcc-aarch64-linux-gnu

# Build
cargo build --release --target aarch64-unknown-linux-gnu
```

### Using `cross`

```bash
# Install cross
cargo install cross

# Build for ARM64
cross build --release --target aarch64-unknown-linux-gnu

# Build for Windows from Linux
cross build --release --target x86_64-pc-windows-gnu
```

## Embedded Builds (no_std)

For embedded targets:

```bash
cd crates/hdds-micro

# Build for Cortex-M4
cargo build --release --target thumbv7em-none-eabihf

# Build for ESP32
cargo build --release --target xtensa-esp32-none-elf
```

## Troubleshooting

### Build Errors

**"Can't find OpenSSL"**

```bash
# Linux
sudo apt install libssl-dev

# macOS
brew install openssl
export OPENSSL_DIR=$(brew --prefix openssl)

# Windows: Download from slproweb.com/products/Win32OpenSSL.html
```

**"Linker error on Windows"**

Ensure you have the Visual Studio C++ workload installed and are using the correct MSVC toolchain:

```powershell
rustup default stable-x86_64-pc-windows-msvc
```

### Performance Issues

For maximum performance:

```bash
# Enable LTO and native CPU optimizations
RUSTFLAGS="-C target-cpu=native -C lto=fat" cargo build --release
```

## Contributing

See [CONTRIBUTING.md](https://git.hdds.io/hdds/hdds/src/branch/main/CONTRIBUTING.md) for:

- Code style guidelines
- Pull request process
- Issue reporting

## Next Steps

- **[Hello World C++](/getting-started/hello-world-cpp)** - C++ pub/sub tutorial
- **[Hello World Rust](/getting-started/hello-world-rust)** - Rust pub/sub tutorial
- **[C++ API Reference](/api/cpp)** - Complete C++ SDK reference
- **[Contributing](/community/contributing)** - Contribute to HDDS
