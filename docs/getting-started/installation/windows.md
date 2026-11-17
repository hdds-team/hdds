# Installing HDDS on Windows

This guide covers building HDDS for Windows from source.

Platform status: Linux (tested); Windows: cross-built, test suites run on Windows 11 and under Wine, with known test-portability failures; macOS: tested natively on macOS 14 (x86_64), Apple Silicon not yet tested.

HDDS is not distributed as an MSI installer, a vcpkg port or a Windows package,
and no MSVC-ABI import library (`hdds_c.lib`) is built. What the project builds
for Windows is the GNU-ABI artifacts below.

## Cross-Build from Linux

The scripted Windows build (`scripts/windows-gate.sh`) cross-compiles from Linux
with the `x86_64-pc-windows-gnu` target and mingw-w64:

```bash
rustup target add x86_64-pc-windows-gnu
sudo apt install gcc-mingw-w64-x86-64     # Debian, Ubuntu

git clone https://git.hdds.io/hdds/hdds.git
cd hdds
cargo build --release --target x86_64-pc-windows-gnu -p hdds-c
```

The artifacts are in `target/x86_64-pc-windows-gnu/release/`:

| File | Use |
|------|-----|
| `hdds_c.dll` | C library (shared) |
| `libhdds_c.dll.a` | Import library for `hdds_c.dll` (GNU toolchains) |
| `libhdds_c.a` | Static library |

The C header is `sdk/c/include/hdds.h`. The `windows-gate.sh` script also builds
the command-line tools for this target and runs the `hdds` test suites under
Wine.

## Building on Windows

On a Windows host the same Cargo commands apply (`cargo build --release -p hdds-c`
produces `target\release\hdds_c.dll`). The project's test suites have been run
on Windows 11; some tests fail there for reasons of test portability, and the
changelog lists the known issues. The MSVC target is type-checked by the release
gates on the crates that need no C runtime, but a full MSVC build, link and run
is not part of them.

## Rust Projects

The versions published on crates.io may lag this repository: use a path
dependency on your clone.

```toml
[dependencies]
hdds = { path = "C:/path/to/hdds/crates/hdds" }
```

Install the IDL code generator (separate repository):

```powershell
git clone https://git.hdds.io/hdds/hdds_gen.git
cargo install --path hdds_gen

# Verify (2.0 or later for HDDS 1.5)
hddsgen --version
```

## Python Installation

The Python SDK is a pure-Python `ctypes` package built from this repository;
it is not on PyPI. Build the native library and the wheel as described in
[Build from source](from-source.md#build-python-bindings), then point the
loader at the directory holding `hdds_c.dll`:

```powershell
cargo build --release -p hdds-c                # target\release\hdds_c.dll
cd sdk\python
python -m pip wheel --no-build-isolation --no-deps --no-index -w dist .
python -m pip install --no-index (Get-Item dist\hdds-*-py3-none-any.whl)
$env:HDDS_LIB_PATH = "C:\path\to\hdds\target\release"

# Verify
python -c "import hdds; print(hdds.library_path(), hdds.__version__)"
```

## Windows Firewall Configuration

DDS uses UDP multicast. Domain `D` uses the 250 UDP ports from `7400 + 250 x D`
to `7649 + 250 x D` (RTPS 2.5 Sec. 9.6.1.1; see the table on the
[Linux page](linux.md#firewall-configuration)): 7400-7649 for domain 0.

### Using PowerShell (Administrator)

```powershell
# Allow the DDS ports of domain 0
New-NetFirewallRule -DisplayName "HDDS DDS" `
    -Direction Inbound `
    -Protocol UDP `
    -LocalPort 7400-7649 `
    -Action Allow

# Or for your specific application
New-NetFirewallRule -DisplayName "My DDS App" `
    -Direction Inbound `
    -Program "C:\path\to\your\app.exe" `
    -Action Allow
```

### Using GUI

1. Open **Windows Security** -> **Firewall & network protection**
2. Click **Allow an app through firewall**
3. Click **Change settings** -> **Allow another app**
4. Add your application, or allow the UDP ports of your domain

## Multicast Configuration

Discovery uses UDP multicast (SPDP on 239.255.0.1). Check the route table:

```powershell
route print | findstr 239
```

:::warning VPN and Virtual Adapters
VPNs and virtual network adapters (VMware, VirtualBox, Docker) can interfere with multicast. Try disabling them for testing.
:::

## WSL2 Considerations

Under WSL2 the Linux build applies, but multicast between WSL2 and the Windows
host may need additional network configuration.

## Troubleshooting

### "DLL not found" Error

Put the directory holding `hdds_c.dll` on `PATH`, or copy the DLL next to your
application:

```powershell
$env:PATH += ";C:\path\to\hdds\target\release"
copy C:\path\to\hdds\target\release\hdds_c.dll .\
```

### "Access Denied" or "Address in Use" on Ports

On Windows HDDS binds the unicast ports of a participant exclusively
(`SO_EXCLUSIVEADDRUSE`). Another participant on the same domain, or another
process, that holds one of them makes the bind fail. Close it, or give the
participants distinct participant ids.

### Multicast Not Working

```powershell
# Check if multicast is enabled on your adapter
Get-NetAdapter | Get-NetIPInterface | Select-Object InterfaceAlias, InterfaceMetric
```

## Next Steps

- **[Building from Source](../../getting-started/installation/from-source.md)** - Compile HDDS yourself
- **[Hello World Rust](../../getting-started/hello-world-rust.md)** - Your first HDDS application
