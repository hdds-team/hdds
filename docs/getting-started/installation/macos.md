# Installing HDDS on macOS

This guide covers building HDDS from source on macOS.

Platform status: Linux (tested); Windows: cross-built, test suites run on Windows 11 and under Wine, with known test-portability failures; macOS: tested natively on macOS 14 (x86_64), Apple Silicon not yet tested.

HDDS is not distributed through Homebrew or any other package manager: there is
no Homebrew tap, installer or binary package. Build it from source as shown
below.

## Prerequisites

- **Xcode Command Line Tools**: `xcode-select --install`
- **A current stable Rust toolchain**, via [rustup](https://rustup.rs): the project does not declare a minimum supported Rust version; the dependencies of the default workspace declare Rust 1.89 or newer
- **Git**
- **CMake 3.16+** (only for the C++ SDK)

```bash
# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
```

## Clone and Build

```bash
git clone https://git.hdds.io/hdds/hdds.git
cd hdds

# Core library and the C library
cargo build --release -p hdds-c

# Run the core unit tests
cargo test -p hdds --lib
```

The C build produces `target/release/libhdds_c.dylib` (shared) and
`target/release/libhdds_c.a` (static); the header is `sdk/c/include/hdds.h`.

## Rust Projects

The versions published on crates.io may lag this repository: use a path
dependency on your clone.

```toml
[dependencies]
hdds = { path = "/path/to/hdds/crates/hdds" }
```

Optional features (for example `security`) are listed on the
[Linux page](linux.md#available-features).

Install the IDL code generator (separate repository):

```bash
git clone https://git.hdds.io/hdds/hdds_gen.git
cargo install --path hdds_gen

# Verify (2.0 or later for HDDS 1.5)
hddsgen --version
```

## Python Installation

The Python SDK is a pure-Python `ctypes` package built from this repository;
it is not on PyPI. Build the native library and the wheel as described in
[Build from source](from-source.md#build-python-bindings), then point the
loader at the library:

```bash
cargo build --release -p hdds-c                # target/release/libhdds_c.dylib
cd sdk/python
python3 -m pip wheel --no-build-isolation --no-deps --no-index -w dist .
python3 -m pip install --no-index dist/hdds-*-py3-none-any.whl
export HDDS_LIB_PATH=/path/to/hdds/target/release

# Verify
python3 -c "import hdds; print(hdds.library_path(), hdds.__version__)"
```

## C/C++ Development

Build the C library and, optionally, install the header, libraries, a
pkg-config file and the CMake config under a prefix:

```bash
make sdk-c
make install-c PREFIX=$HOME/.local
```

```bash
# Compile a C program against the installed library
export PKG_CONFIG_PATH=$HOME/.local/lib/pkgconfig
clang -o myapp myapp.c $(pkg-config --cflags --libs hdds_c)

# The shared library needs to be found at run time
DYLD_LIBRARY_PATH=$HOME/.local/lib ./myapp
```

For the C++ SDK, run `make sdk-cxx` (see [Build from source](from-source.md#build-cc-sdks)).

### CMake Integration

```cmake
# C API only
find_package(hdds REQUIRED COMPONENTS c)
target_link_libraries(myapp PRIVATE hdds::hdds_c)

# C++ SDK
find_package(hdds REQUIRED)
target_link_libraries(myapp PRIVATE hdds::hdds)
```

```bash
cmake -B build -DCMAKE_PREFIX_PATH=/path/to/hdds/sdk/cmake
```

(`-DCMAKE_PREFIX_PATH=$HOME/.local` when using the prefix installed above.)

## Verify Installation

```bash
# From the root of the hdds clone: generate the sample types, then run the
# Hello World sample in two terminals
sdk/samples/scripts/generate.sh
cd sdk/samples/01_basics/rust
cargo run --bin hello_world           # Terminal 1: subscriber
cargo run --bin hello_world -- pub    # Terminal 2: publisher
```

## macOS-Specific Configuration

### Firewall

The macOS firewall may block incoming DDS traffic. Allow your application in
**System Settings** -> **Network** -> **Firewall** -> **Options**, or allow it
from the command line:

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /path/to/your/app
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --unblockapp /path/to/your/app
```

### Multicast

Discovery uses UDP multicast (SPDP on 239.255.0.1). If participants do not find
each other, check that the interface carrying multicast is up:

```bash
ifconfig en0 | grep MULTICAST
```

### Sleep Prevention

For long-running DDS applications:

```bash
# Prevent sleep while app runs
caffeinate -i ./my_dds_app
```

## Troubleshooting

### "Library not loaded" Error

```bash
# Point the loader at the directory holding libhdds_c.dylib
export DYLD_LIBRARY_PATH=/path/to/hdds/target/release:$DYLD_LIBRARY_PATH
```

### Multicast Not Working

```bash
# Check interface multicast capability
ifconfig en0 | grep MULTICAST

# List the applications known to the firewall
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --listapps
```

### Apple Silicon

The native macOS test run was on an x86_64 machine; Apple Silicon has not been
tested. The `aarch64-apple-darwin` target is type-checked by the release gates
(`cargo check -p hdds --lib`).

## Next Steps

- **[Windows Installation](../../getting-started/installation/windows.md)** - Install on Windows
- **[Hello World Rust](../../getting-started/hello-world-rust.md)** - Your first HDDS application
