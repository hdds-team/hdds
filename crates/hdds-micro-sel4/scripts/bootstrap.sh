#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2026 naskel.com
#
# Bootstrap for hdds-micro-sel4.
#
# Reproducibly installs the toolchain + Microkit SDK + rust-sel4 repo
# needed to build the seL4/Microkit port of hdds-micro, then runs two
# smoke tests under QEMU:
#   1. the C `hello` example shipped in the SDK
#   2. the Rust `hello` example from github.com/seL4/rust-sel4
#
# Tested on Debian 13 trixie. Ubuntu 24.04 should work the
# same - see docs/ENV_SETUP.md for the diff.
#
# Usage:
#   SEL4_ROOT=<dir> MICROKIT_SDK=<dir> scripts/bootstrap.sh
#   SEL4_ROOT=<dir> MICROKIT_SDK=<dir> scripts/bootstrap.sh --skip-run
#
# Environment (both required):
#   SEL4_ROOT     user-owned work directory (downloads, rust-sel4 clone,
#                 smoke-test builds)
#   MICROKIT_SDK  Microkit SDK install directory, for example
#                 /opt/microkit-sdk-2.2.0 (written with sudo if missing)
#
# Side effects:
#   - runs `sudo apt install` (one package: lld)
#   - writes the Microkit SDK to $MICROKIT_SDK (requires sudo)
#   - writes under $SEL4_ROOT                (user-owned)
#   - writes under /tmp/sel4-*-target        (build artefacts, ephemeral)
#
# Exits non-zero on the first failure (pipefail + errexit).

set -euo pipefail

# ---- Pinned versions ------------------------------------------------

MICROKIT_VERSION="2.2.0"
MICROKIT_SHA256="4cac711ad0591f206c77aca6d33067fc06532c8830d1adf71bfddb274fdb10ba"
MICROKIT_HOST="linux-x86-64"
RUST_NIGHTLY="nightly-2026-03-18"
MIN_QEMU_MAJOR=8

SEL4_ROOT="${SEL4_ROOT:?set SEL4_ROOT to a user-owned work directory}"
MICROKIT_SDK="${MICROKIT_SDK:?set MICROKIT_SDK to the Microkit SDK install directory}"
RUST_SEL4_DIR="${SEL4_ROOT}/rust-sel4"
HELLO_C_BUILD="${SEL4_ROOT}/hello-build"
HELLO_RUST_BUILD="${SEL4_ROOT}/rust-hello-build"

SKIP_RUN=0
for arg in "$@"; do
    case "$arg" in
        --skip-run) SKIP_RUN=1 ;;
        *) echo "unknown arg: $arg"; exit 2 ;;
    esac
done

log() { printf '\033[1;34m[bootstrap]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[bootstrap]\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31m[bootstrap]\033[0m %s\n' "$*" >&2; exit 1; }

# ---- 0. Sanity checks -----------------------------------------------

log "checking prerequisites"

for bin in curl tar make python3 dtc clang cargo rustup qemu-system-aarch64 gpg; do
    command -v "$bin" >/dev/null || die "missing: $bin"
done

qemu_major=$(qemu-system-aarch64 --version | head -1 | sed -E 's/.*version ([0-9]+)\..*/\1/')
[ "${qemu_major:-0}" -ge "$MIN_QEMU_MAJOR" ] \
    || die "qemu-system-aarch64 >=${MIN_QEMU_MAJOR} required, found ${qemu_major}"

# ---- 1. APT deps ----------------------------------------------------

if ! command -v ld.lld >/dev/null; then
    log "installing lld (required for Microkit LLVM=True build path)"
    sudo apt install -y lld
fi

# ---- 2. Rust toolchains ---------------------------------------------

log "adding aarch64-unknown-none* rust targets (host Rust for the Transport trait impl)"
rustup target add aarch64-unknown-none aarch64-unknown-none-softfloat

if ! rustup toolchain list | grep -q "^${RUST_NIGHTLY}"; then
    log "installing rust ${RUST_NIGHTLY} (+rust-src for build-std)"
    rustup toolchain install "${RUST_NIGHTLY}" --component rust-src --profile minimal
fi

# ---- 3. Microkit SDK ------------------------------------------------

if [ ! -d "${MICROKIT_SDK}/bin" ]; then
    log "downloading Microkit SDK ${MICROKIT_VERSION}"
    mkdir -p "${SEL4_ROOT}"
    cd "${SEL4_ROOT}"
    base_url="https://github.com/seL4/microkit/releases/download/${MICROKIT_VERSION}"
    tarball="microkit-sdk-${MICROKIT_VERSION}-${MICROKIT_HOST}.tar.gz"
    curl -sSL -o "${tarball}" "${base_url}/${tarball}"
    curl -sSL -o "${tarball}.asc" "${base_url}/${tarball}.asc"
    # GPG signature check is informational for now - verified manually
    # once per version (see docs/ENV_SETUP.md for the recommended key).
    if [ -n "${MICROKIT_SHA256}" ]; then
        printf '%s  %s\n' "${MICROKIT_SHA256}" "${tarball}" | sha256sum -c -
    fi
    log "installing SDK to ${MICROKIT_SDK}"
    sudo mkdir -p "${MICROKIT_SDK%/*}"
    sudo tar -xzf "${tarball}" -C "${MICROKIT_SDK%/*}"
    sudo chmod -R a+rX "${MICROKIT_SDK}"
else
    log "Microkit SDK already present at ${MICROKIT_SDK} - skipping download"
fi

# ---- 4. rust-sel4 -----------------------------------------------------

if [ ! -d "${RUST_SEL4_DIR}/.git" ]; then
    log "cloning seL4/rust-sel4"
    git clone --depth 1 https://github.com/seL4/rust-sel4 "${RUST_SEL4_DIR}"
else
    log "rust-sel4 already cloned at ${RUST_SEL4_DIR}"
fi

# ---- 5. C smoke test: Microkit hello --------------------------------

log "building Microkit C hello example (LLVM=True)"
rm -rf "${HELLO_C_BUILD}"
mkdir -p "${HELLO_C_BUILD}"
make -C "${MICROKIT_SDK}/example/hello" \
    BUILD_DIR="${HELLO_C_BUILD}" \
    MICROKIT_BOARD=qemu_virt_aarch64 \
    MICROKIT_CONFIG=debug \
    MICROKIT_SDK="${MICROKIT_SDK}" \
    LLVM=True >/dev/null

if [ "${SKIP_RUN}" -eq 0 ]; then
    log "smoke test: running C hello under QEMU (expect 'hello, world')"
    out=$(timeout 15 qemu-system-aarch64 \
        -machine virt,virtualization=on -cpu cortex-a53 -m size=2G \
        -nographic -serial mon:stdio \
        -device "loader,file=${HELLO_C_BUILD}/loader.img,addr=0x70000000,cpu-num=0" \
        2>&1 || true)
    echo "${out}" | grep -qF 'hello, world' \
        || { echo "---qemu output---"; echo "${out}"; die "C hello did not print expected message"; }
    log "  OK 'hello, world' observed"
fi

# ---- 6. Rust smoke test: rust-sel4 hello ----------------------------

log "building rust-sel4 microkit-hello PD"
rm -rf "${HELLO_RUST_BUILD}"
mkdir -p "${HELLO_RUST_BUILD}"
(
    cd "${RUST_SEL4_DIR}/crates/examples/microkit/hello/pds/hello"
    SEL4_INCLUDE_DIRS="${MICROKIT_SDK}/board/qemu_virt_aarch64/debug/include" \
    CARGO_TARGET_DIR=/tmp/sel4-rust-target \
    cargo "+${RUST_NIGHTLY}" build \
        --target "${RUST_SEL4_DIR}/support/targets/aarch64-sel4-microkit.json" \
        -Z build-std=core,compiler_builtins,alloc \
        -Z build-std-features=compiler-builtins-mem \
        -Z json-target-spec >/dev/null
)
cp /tmp/sel4-rust-target/aarch64-sel4-microkit/debug/microkit-hello.elf "${HELLO_RUST_BUILD}/"
"${MICROKIT_SDK}/bin/microkit" \
    "${RUST_SEL4_DIR}/crates/examples/microkit/hello/hello.system" \
    --search-path "${HELLO_RUST_BUILD}" \
    --board qemu_virt_aarch64 --config debug \
    -o "${HELLO_RUST_BUILD}/loader.img" \
    -r "${HELLO_RUST_BUILD}/report.txt" >/dev/null

if [ "${SKIP_RUN}" -eq 0 ]; then
    log "smoke test: running rust-sel4 hello under QEMU (expect 'Hello, World!')"
    out=$(timeout 15 qemu-system-aarch64 \
        -machine virt,virtualization=on -cpu cortex-a53 -m size=2G \
        -nographic -serial mon:stdio \
        -device "loader,file=${HELLO_RUST_BUILD}/loader.img,addr=0x70000000,cpu-num=0" \
        2>&1 || true)
    echo "${out}" | grep -qF 'Hello, World!' \
        || { echo "---qemu output---"; echo "${out}"; die "rust-sel4 hello did not print expected message"; }
    log "  OK 'Hello, World!' observed"
fi

log "bootstrap complete."
log "  Microkit SDK : ${MICROKIT_SDK}"
log "  rust-sel4    : ${RUST_SEL4_DIR}"
log "  C hello      : ${HELLO_C_BUILD}/loader.img"
log "  Rust hello   : ${HELLO_RUST_BUILD}/loader.img"
