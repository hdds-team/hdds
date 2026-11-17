---
sidebar_position: 4
title: Building from Source
description: Compile HDDS from source code
---

# Building HDDS from Source

This guide covers building HDDS from source for contributors and customization. HDDS is not distributed as a package: building from source is the supported way to use it.

## Prerequisites

### All Platforms

- **Git**
- **A current stable Rust toolchain. The project declares no `rust-version`; the dependencies of the default workspace require Rust 1.89 or newer, and 1.90 is the version this release is built and tested with (1.85 does not work)**, with `cargo`
- **A C compiler** (some dependencies build C code)
- **CMake 3.16+** (for the C++ SDK only)

### Linux

```bash
# Ubuntu/Debian
sudo apt install build-essential git cmake

# Fedora/RHEL
sudo dnf install gcc gcc-c++ git cmake

# Arch
sudo pacman -S base-devel git cmake
```

HDDS does not link OpenSSL: its TLS and cryptography features use `rustls` and
`ring`.

### macOS

```bash
xcode-select --install
# CMake, only for the C++ SDK (from Homebrew, MacPorts or cmake.org)
brew install cmake
```

### Windows

Platform status: Linux (tested); Windows: cross-built, test suites run on Windows 11 and under Wine, with known test-portability failures; macOS: tested natively on macOS 14 (x86_64), Apple Silicon not yet tested.

The scripted, repeatable Windows build is a cross-build from Linux with the
`x86_64-pc-windows-gnu` target and mingw-w64; see the
[Windows page](windows.md). No MSI installer, vcpkg port or MSVC-ABI
`hdds_c.lib` is built.

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

# Library unit tests of the core crate only
cargo test -p hdds --lib
```

### Run Benchmarks

```bash
cargo bench
```

## Build C/C++ SDKs

The C SDK is the `hdds-c` crate: the header is `sdk/c/include/hdds.h`, and the
build produces `target/release/libhdds_c.a` and `libhdds_c.so`
(`libhdds_c.dylib` on macOS):

```bash
make sdk-c       # same as: cargo build --release -p hdds-c
```

The simplest way to build the C++ SDK:

```bash
make sdk-cxx
```

This runs `cargo build --release -p hdds-c` (C FFI layer) then builds `libhdds_cxx.a` (C++ RAII wrappers) via CMake.

To also build all C++ samples:

```bash
make samples-cpp samples-cpp-qos
```

For a step-by-step tutorial on creating your own C++ project with HDDS, see **[Hello World C++](../hello-world-cpp.md)**.

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

The Python SDK is a pure-Python `ctypes` package: no Rust compile happens in
the Python build, the wheel is `py3-none-any` and it loads `libhdds_c.so`
(built above with `cargo build --release -p hdds-c`) at first use.

```bash
cd sdk/python

# Build the wheel offline with the host's setuptools (>= 77).
# setuptools writes build/, dist/ and hdds.egg-info/ next to the sources;
# all three are gitignored.
python3 -m pip wheel --no-build-isolation --no-deps --no-index -w dist .

# Create a virtual environment and install the wheel
python3 -m venv .venv
source .venv/bin/activate  # Linux/macOS
pip install --no-index dist/hdds-*-py3-none-any.whl

# Tell the loader where libhdds_c.so is (strict override) and check
export HDDS_LIB_PATH=/path/to/hdds/target/release
python -c "import hdds; print(hdds.library_path(), hdds.version())"
```

Without `HDDS_LIB_PATH` the loader probes `<repo>/target/{release,debug}`
(source checkout only), `/usr/local/lib`, `/usr/lib`, then the system
dynamic linker, and fails closed with an `ImportError` listing every path
tried. Details: `sdk/python/README.md`.

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
+-- Cargo.toml              # Workspace root
+-- crates/
|   +-- hdds/               # Core DDS library (RTPS, SPDP, SEDP)
|   +-- hdds-c/             # C FFI bindings (cbindgen)
|   +-- hdds-codegen/       # Derive macro (#[derive(DDS)])
|   +-- hdds-micro/         # Lightweight no_std profile
|   +-- hdds-micro-c/       # C FFI for hdds-micro
|   +-- hdds-router/        # DDS routing service
|   +-- hdds-gateway/       # REST API gateway
|   +-- hdds-recording/     # Data recording/replay
|   +-- hdds-persistence/   # Durable storage backend
|   +-- hdds-discovery-server/  # Standalone discovery server
|   +-- rmw-hdds/           # ROS 2 middleware layer (Rust side)
|   +-- ...                 # Other service and integration crates
+-- rmw_hdds/               # ROS 2 rmw package (CMake/colcon)
+-- sdk/
|   +-- c/                  # C header (include/hdds.h)
|   +-- cxx/                # C++ SDK (include/hdds.hpp, RAII wrappers)
|   +-- cmake/              # CMake find_package config
|   +-- python/             # Python package (ctypes)
|   +-- typescript/         # TypeScript SDK
|   +-- rust/               # Rust SDK crate
|   +-- samples/            # Example applications
+-- tools/                  # Command-line tools and Docker/interop helpers
+-- scripts/                # Gates, benchmarks and helper scripts
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

`scripts/gates.sh` is the project's definition of a clean tree (formatting,
clippy, tests, audit scan and the cross-target checks):

```bash
bash scripts/gates.sh --quick    # slow lanes skipped, before every commit
bash scripts/gates.sh            # the full set, before a merge
bash scripts/gates.sh --list     # what it runs, in order
```

## Cross-Compilation

The release gates type-check the `hdds` library for four targets:
`x86_64-apple-darwin`, `aarch64-apple-darwin`, `x86_64-pc-windows-gnu` and
`aarch64-unknown-linux-gnu`:

```bash
rustup target add aarch64-unknown-linux-gnu
cargo check -p hdds --lib --target aarch64-unknown-linux-gnu
```

Producing a linked binary for a foreign target also needs a linker for that
target (for example `gcc-aarch64-linux-gnu` on Debian or Ubuntu, named in a
`linker` entry of `.cargo/config.toml`).

### Windows from Linux

```bash
rustup target add x86_64-pc-windows-gnu
sudo apt install gcc-mingw-w64-x86-64
cargo build --release --target x86_64-pc-windows-gnu -p hdds-c
```

See the [Windows page](windows.md) for what this produces.

## Embedded Builds (no_std)

`hdds-micro` is a `no_std` crate that type-checks for a Cortex-M4F target:

```bash
rustup target add thumbv7em-none-eabihf
cargo check --manifest-path crates/hdds-micro/Cargo.toml --target thumbv7em-none-eabihf
```

The ESP32 example (`crates/hdds-micro/esp32-example`) is outside the workspace and
builds with the `esp` toolchain named in its own `rust-toolchain.toml`.

## Troubleshooting

### Build Errors

**"error: failed to run custom build command" for a crate that compiles C code**

Install a C compiler (`build-essential` on Debian and Ubuntu, `xcode-select
--install` on macOS).

**Linker error on Windows**

The supported Windows build is the cross-build above. For a native Windows
build, use a Rust toolchain whose linker is installed, and see the
[Windows page](windows.md) for the platform status.

### Performance Issues

For a release build tuned to the build machine's CPU:

```bash
RUSTFLAGS="-C target-cpu=native -C lto=fat" cargo build --release
```

The measured figures of the project are on the
[benchmarks page](../../guides/performance/benchmarks.md), with the build
settings they use.

## Contributing

See [CONTRIBUTING.md](https://git.hdds.io/hdds/hdds/src/branch/master/CONTRIBUTING.md) for:

- Code style guidelines
- Pull request process
- Issue reporting

## Next Steps

- **[Hello World C++](../hello-world-cpp.md)** - C++ pub/sub tutorial
- **[Hello World Rust](../hello-world-rust.md)** - Rust pub/sub tutorial
- **[C++ API Reference](../../api/cpp.md)** - Complete C++ SDK reference
- **[Contributing](../../community/contributing.md)** - Contribute to HDDS
