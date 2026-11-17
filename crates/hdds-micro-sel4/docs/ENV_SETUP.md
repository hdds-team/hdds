# ENV_SETUP - reproducible environment

Versions pinned by `scripts/bootstrap.sh`.
`scripts/bootstrap.sh` is the machine-readable form of this document -
treat this file as the English explanation, the script as the truth.

## Host

- Debian 13 trixie (amd64). Ubuntu 24.04 should work; only the apt
  package names diverge, and only for `lld` (same name on both).
- CPU: x86_64 host running `qemu-system-aarch64` to execute AArch64
  Microkit images. No real hardware needed for the QEMU flows.

## Pinned versions

| Component | Version | Source |
|---|---|---|
| Microkit SDK | `2.2.0` | [seL4/microkit release](https://github.com/seL4/microkit/releases/tag/2.2.0) |
| Microkit tarball SHA-256 | `4cac711ad0591f206c77aca6d33067fc06532c8830d1adf71bfddb274fdb10ba` | `microkit-sdk-2.2.0-linux-x86-64.tar.gz` |
| rust-sel4 | `main` as of 2026-04-18 | [seL4/rust-sel4](https://github.com/seL4/rust-sel4) - pinned to compatible with Microkit 2.2.0 per its README |
| Rust nightly | `nightly-2026-03-18` | required by rust-sel4's `rust-toolchain.toml` |
| QEMU | `10.0.7` (Debian package) | anything `>= 8.x` is fine |
| Clang / ld.lld | `19.1.7` | Debian trixie stock |

## Toolchain decision: LLVM instead of `aarch64-none-elf-gcc`

Microkit's Makefile defaults to `aarch64-none-elf-gcc` as the cross
compiler. Debian (and Ubuntu) do **not** ship a packaged bare-metal
AArch64 GCC. Two workarounds exist:

1. Download ARM's prebuilt `gcc-arm-*-aarch64-none-elf.tar.xz` from
   developer.arm.com (~130 MB, manual install).
2. Pass `LLVM=True` to Microkit's Makefile to use the system
   `clang` + `ld.lld`. Zero extra download.

**We picked option 2.** Clang 19 + lld 19 build the SDK's C examples
without complaint, and it's already how several rust-sel4 CI jobs
work. `scripts/bootstrap.sh` sets `LLVM=True` unconditionally.

## Paths

`scripts/bootstrap.sh` requires two environment variables: `MICROKIT_SDK`
(SDK install directory, for example `/opt/microkit-sdk-2.2.0`) and
`SEL4_ROOT` (a user-owned work directory). The other `scripts/*.sh`
need `MICROKIT_SDK` and `SDDF_ROOT` (an sDDF checkout).

| Path | Contents | Ownership |
|---|---|---|
| `$MICROKIT_SDK/` | prebuilt SDK (tool, boards, examples) | `root:root`, readable by all |
| `$SEL4_ROOT/rust-sel4/` | cloned `seL4/rust-sel4` | user |
| `$SEL4_ROOT/hello-build/` | C hello build artefacts | user |
| `$SEL4_ROOT/rust-hello-build/` | rust-sel4 hello `loader.img` | user |
| `/tmp/sel4-target/` | `CARGO_TARGET_DIR` for **our** `hdds-micro-sel4` crate | user, ephemeral |
| `/tmp/sel4-rust-target/` | `CARGO_TARGET_DIR` for rust-sel4 examples | user, ephemeral |

No build artefact ever lands inside the HDDS repo. All `cargo build`
invocations set `CARGO_TARGET_DIR` to `/tmp/...` explicitly.

## Running the smoke tests manually

After `scripts/bootstrap.sh` succeeds once, you can re-run the QEMU
smoke tests any time:

```bash
# C hello
qemu-system-aarch64 -machine virt,virtualization=on -cpu cortex-a53 \
    -m size=2G -nographic -serial mon:stdio \
    -device loader,file=$SEL4_ROOT/hello-build/loader.img,addr=0x70000000,cpu-num=0
# => "hello, world"

# Rust hello
qemu-system-aarch64 -machine virt,virtualization=on -cpu cortex-a53 \
    -m size=2G -nographic -serial mon:stdio \
    -device loader,file=$SEL4_ROOT/rust-hello-build/loader.img,addr=0x70000000,cpu-num=0
# => "Hello, World!"
```

Exit QEMU with `Ctrl-A X`.

## Bootstrap checklist

| Item | Status | Notes |
|---|---|---|
| Microkit C hello boots under QEMU | checked by `scripts/bootstrap.sh` | Expects `hello, world` |
| rust-sel4 hello boots under QEMU | checked by `scripts/bootstrap.sh` | Expects `Hello, World!`. The rust-sel4 `hello` example ships a single PD, so it does not exercise a 2-PD IPC path. |
| `ENV_SETUP.md` documents exact versions | OK | This file |
| `scripts/bootstrap.sh` recreates from scratch on Ubuntu 24.04 | partial | Written for Debian 13; Ubuntu 24.04 expected to work, not validated on a fresh VM |

## Known gaps / follow-ups

- **Ubuntu 24.04 validation.** Bootstrap script was written on Debian
  13; a clean Ubuntu 24.04 VM run is still pending. Most likely the
  only tweak needed is adding `clang lld` to the apt line (already
  assumed installed on Debian trixie).
- **GPG signature verification.** The SDK tarball is signed but we
  only check SHA-256. Upgrading to `gpg --verify` requires importing
  the Microkit maintainer key - low priority, SHA-256 + HTTPS is
  already solid.
- **2-PD Rust IPC smoke test.** Not shipped by rust-sel4 out of the
  box. The intra-guest pub/sub system (`scripts/run-inguest.sh`)
  runs two Rust PDs over the same sDDF net virtualizer.
