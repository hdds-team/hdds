# Installing HDDS on Windows

This guide covers installing HDDS on Windows 10 and Windows 11.

## Prerequisites

- **Windows 10 1903+** or **Windows 11**
- **Visual Studio 2019+** with C++ workload (for C/C++ development)
- **Rust** (for Rust development): [rustup.rs](https://rustup.rs)
- **Python 3.10+** (for Python bindings)

## Quick Install (MSI Installer)

Download and run the MSI installer:

1. Download from [hdds.io/download](https://hdds.io/download)
2. Run `hdds-1.0.0-x64.msi`
3. Follow the installation wizard
4. Restart your terminal

The installer adds HDDS to your PATH and installs:
- HDDS runtime DLL
- C/C++ headers and import libraries
- CLI tools (hdds_gen.exe, hdds_viewer.exe)

### Verify Installation

Open PowerShell or Command Prompt:

```powershell
hdds --version
```

## Cargo Installation (Rust)

For Rust development:

```powershell
# Ensure Rust is installed
winget install Rustlang.Rust.MSVC

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

## Python Installation

```powershell
# Using pip
pip install hdds

# Verify
python -c "import hdds; print(hdds.__version__)"
```

## C/C++ Development

### Visual Studio

1. Install via MSI or add to your project manually
2. Configure project properties:

**Include Directories:**
```
C:\Program Files\HDDS\include
```

**Library Directories:**
```
C:\Program Files\HDDS\lib
```

**Linker Input:**
```
hdds.lib
```

### CMake

```cmake
# Find HDDS
find_package(hdds REQUIRED)

add_executable(myapp main.cpp)
target_link_libraries(myapp PRIVATE hdds::hdds)
```

Configure with:

```powershell
cmake -B build -DCMAKE_PREFIX_PATH="C:\Program Files\HDDS"
cmake --build build
```

### vcpkg

```powershell
# Install via vcpkg
vcpkg install hdds:x64-windows

# Use in CMake
cmake -B build -DCMAKE_TOOLCHAIN_FILE=[vcpkg-root]/scripts/buildsystems/vcpkg.cmake
```

## Verify Installation

```powershell
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
Platform: Windows x86_64
RTPS Version: 2.5
Security: Enabled

Self-test: PASSED (12/12 tests)

Network Interfaces:
  - Ethernet: 192.168.1.100 (multicast: enabled)
  - Loopback: 127.0.0.1 (multicast: disabled)
```

## Windows Firewall Configuration

DDS uses UDP multicast. Configure Windows Firewall:

### Using PowerShell (Administrator)

```powershell
# Allow HDDS through firewall
New-NetFirewallRule -DisplayName "HDDS DDS" `
    -Direction Inbound `
    -Protocol UDP `
    -LocalPort 7400-7500 `
    -Action Allow

# Or for your specific application
New-NetFirewallRule -DisplayName "My DDS App" `
    -Program "C:\path\to\your\app.exe" `
    -Action Allow
```

### Using GUI

1. Open **Windows Security** → **Firewall & network protection**
2. Click **Allow an app through firewall**
3. Click **Change settings** → **Allow another app**
4. Add your application or allow ports 7400-7500 UDP

## Multicast Configuration

Windows supports multicast by default on most networks. Verify:

```powershell
# Check route table
route print | findstr 239

# If multicast isn't working, try:
route add 239.255.0.0 mask 255.255.0.0 192.168.1.1
```

:::warning VPN and Virtual Adapters
VPNs and virtual network adapters (VMware, VirtualBox, Docker) can interfere with multicast. Try disabling them for testing.
:::

## WSL2 Considerations

If using WSL2:

```bash
# In WSL2, multicast may require additional configuration
# Use host networking or configure port forwarding
```

For best performance, use native Windows builds rather than WSL.

## Troubleshooting

### "DLL not found" Error

```powershell
# Add HDDS to PATH
$env:PATH += ";C:\Program Files\HDDS\bin"

# Or copy DLLs to application directory
copy "C:\Program Files\HDDS\bin\hdds.dll" .\
```

### "Access Denied" on Ports

Run as Administrator or use ports above 1024.

### Multicast Not Working

```powershell
# Check if multicast is enabled on your adapter
Get-NetAdapter | Get-NetIPInterface | Select-Object InterfaceAlias, InterfaceMetric

# Disable firewall temporarily for testing
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
```

### Visual Studio Linker Errors

Ensure you're using the correct architecture:
- x64 project → `hdds.lib` from `lib/x64`
- x86 project → `hdds.lib` from `lib/x86`

## Next Steps

- **[Building from Source](../../getting-started/installation/from-source.md)** - Compile HDDS yourself
- **[Hello World Rust](../../getting-started/hello-world-rust.md)** - Your first HDDS application
