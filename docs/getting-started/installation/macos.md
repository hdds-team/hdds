# Installing HDDS on macOS

This guide covers installing HDDS on macOS (Intel and Apple Silicon).

## Prerequisites

- **macOS 12+** (Monterey or later)
- **Xcode Command Line Tools**: `xcode-select --install`
- **Homebrew** (recommended): [brew.sh](https://brew.sh)

## Quick Install (Homebrew)

The easiest way to install HDDS on macOS:

```bash
# Add the HDDS tap
brew tap hdds/hdds

# Install HDDS
brew install hdds

# Verify installation
hdds --version
```

This installs:
- HDDS runtime library
- C/C++ headers
- CLI tools (hdds_gen, hdds_viewer)
- Python bindings

## Cargo Installation (Rust)

For Rust development:

```bash
# Ensure Rust is installed
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Add HDDS to your project
cargo add hdds

# Install CLI tools
cargo install hdds-gen

# Verify
hdds-gen --version
```

### Feature Flags

```toml
[dependencies]
hdds = { version = "1.0", features = ["async", "security"] }
```

:::note Apple Silicon
HDDS is fully native on Apple Silicon (M1/M2/M3). No Rosetta needed.
:::

## Python Installation

```bash
# Using pip
pip3 install hdds

# Using Homebrew Python
brew install python
pip3 install hdds

# Verify
python3 -c "import hdds; print(hdds.__version__)"
```

## C/C++ Development

After installing via Homebrew:

```bash
# Check pkg-config
pkg-config --cflags --libs hdds

# Compile a C program
clang -o myapp myapp.c $(pkg-config --cflags --libs hdds)
```

### CMake Integration

```cmake
find_package(hdds REQUIRED)

add_executable(myapp main.cpp)
target_link_libraries(myapp PRIVATE hdds::hdds)
```

## Verify Installation

```bash
# Check version
hdds --version

# Run self-test
hdds self-test

# List interfaces
hdds interfaces
```

Expected output:

```
HDDS 1.0.0
Platform: macOS arm64
RTPS Version: 2.5
Security: Enabled

Self-test: PASSED (12/12 tests)

Network Interfaces:
  - en0: 192.168.1.100 (multicast: enabled)
  - lo0: 127.0.0.1 (multicast: disabled)
```

## macOS-Specific Configuration

### Firewall

macOS Firewall may block DDS traffic. Allow it:

1. Open **System Preferences** → **Security & Privacy** → **Firewall**
2. Click **Firewall Options**
3. Add your application or allow incoming connections

Or via command line:

```bash
# Disable firewall for testing (not recommended for production)
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate off
```

### Multicast

macOS supports multicast by default. Verify:

```bash
# Check multicast route
netstat -rn | grep 239

# If missing, add route
sudo route add -net 239.255.0.0/16 -interface en0
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
# Set library path
export DYLD_LIBRARY_PATH=/usr/local/lib:$DYLD_LIBRARY_PATH
```

### Multicast Not Working

```bash
# Check interface multicast capability
ifconfig en0 | grep MULTICAST

# Check firewall
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --listapps
```

### Apple Silicon Compatibility

HDDS is native ARM64. If you see Rosetta warnings:

```bash
# Verify architecture
file $(which hdds)
# Should show: Mach-O 64-bit executable arm64
```

## Next Steps

- **[Windows Installation](../../getting-started/installation/windows.md)** - Install on Windows
- **[Hello World Rust](../../getting-started/hello-world-rust.md)** - Your first HDDS application
