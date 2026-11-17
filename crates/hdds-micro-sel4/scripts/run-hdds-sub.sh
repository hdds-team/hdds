#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2026 naskel.com
#
# Subscriber boot script: same overlay machinery as run-hdds-pub.sh
# but builds the `client2_rust` staticlib with `--features subscriber`.
# The PD's `notified()` parses each inbound UDP datagram as RTPS DATA
# via hdds-micro MicroReader and logs `RX seq=<n>` lines to the kernel
# debug UART (visible in the QEMU serial log).
#
# Pair with hdds_pub (see scripts/test-interop-linux-to-sel4.sh for the full
# integration check):
#
#   crates/hdds-micro-sel4/host-tools/hdds_pub/target/release/hdds_pub --count 200
#
# Usage:
#   crates/hdds-micro-sel4/scripts/run-hdds-sub.sh           # overlay + build + boot, idle
#   crates/hdds-micro-sel4/scripts/run-hdds-sub.sh --build   # force rebuild
#   crates/hdds-micro-sel4/scripts/run-hdds-sub.sh --revert  # restore stock upstream

set -euo pipefail

MICROKIT_SDK="${MICROKIT_SDK:?set MICROKIT_SDK to the Microkit SDK root}"
SDDF_ROOT="${SDDF_ROOT:?set SDDF_ROOT to the sDDF checkout}"
ECHO_DIR="${SDDF_ROOT}/examples/echo_server"
BUILD_DIR="${ECHO_DIR}/build"
LOADER_IMG="${BUILD_DIR}/loader.img"
QEMU_LOG="${QEMU_LOG:-/tmp/hdds-sub-qemu.log}"
LLVM_BIN="${LLVM_BIN:-/usr/lib/llvm-19/bin}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SEL4_CRATE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
OVERLAY_DIR="${SEL4_CRATE_DIR}/microkit"

FORCE_BUILD=0
DO_REVERT=0
for arg in "$@"; do
    case "$arg" in
        --build)   FORCE_BUILD=1 ;;
        --revert)  DO_REVERT=1 ;;
        *) echo "unknown arg: $arg" >&2; exit 2 ;;
    esac
done

[[ -d "${MICROKIT_SDK}"  ]] || { echo "MICROKIT_SDK not found: ${MICROKIT_SDK}" >&2; exit 1; }
[[ -d "${ECHO_DIR}"      ]] || { echo "echo_server not found: ${ECHO_DIR}" >&2; exit 1; }
[[ -d "${LLVM_BIN}"      ]] || { echo "LLVM 19 not found: ${LLVM_BIN}" >&2; exit 1; }
[[ -d "${OVERLAY_DIR}"   ]] || { echo "overlay dir not found: ${OVERLAY_DIR}" >&2; exit 1; }
[[ -d "${SEL4_CRATE_DIR}/client2_rust" ]] || { echo "client2_rust crate not found" >&2; exit 1; }
command -v qemu-system-aarch64 >/dev/null || { echo "qemu-system-aarch64 not in PATH" >&2; exit 1; }
command -v cargo >/dev/null || { echo "cargo not in PATH" >&2; exit 1; }

if (( DO_REVERT == 1 )); then
    echo "[run-hdds-sub] restoring stock upstream sDDF echo_server"
    (cd "${SDDF_ROOT}" && git checkout examples/echo_server/)
    exit 0
fi

echo "[run-hdds-sub] applying overlay to ${ECHO_DIR}"
cp -f "${OVERLAY_DIR}/meta.py"           "${ECHO_DIR}/meta.py"
cp -f "${OVERLAY_DIR}/echo.mk"           "${ECHO_DIR}/echo.mk"
cp -f "${OVERLAY_DIR}/single_core.json"  "${ECHO_DIR}/core_config/single_core.json"
cp -f "${OVERLAY_DIR}/client2_rust_wrapper.c" "${ECHO_DIR}/client2_rust_wrapper.c"

# echo.mk's staticlib rule is FORCE-marked - cargo always runs and
# picks up the CARGO_FEATURES change vs any previous build flavor.

if (( FORCE_BUILD == 1 )) || [[ ! -f "${LOADER_IMG}" ]]; then
    echo "[run-hdds-sub] building (with overlay, --features subscriber)..."
    cd "${ECHO_DIR}"
    [[ -d build ]] && rm -rf build
    PATH="${LLVM_BIN}:${PATH}" \
        MICROKIT_SDK="${MICROKIT_SDK}" \
        MICROKIT_BOARD=qemu_virt_aarch64 \
        MICROKIT_CONFIG=debug \
        TOOLCHAIN=clang \
        SEL4_CRATE_DIR="${SEL4_CRATE_DIR}" \
        CARGO_FEATURES=subscriber \
        make BUILD_DIR=build
else
    echo "[run-hdds-sub] refreshing Rust staticlib (subscriber feature)..."
    cd "${ECHO_DIR}"
    PATH="${LLVM_BIN}:${PATH}" \
        MICROKIT_SDK="${MICROKIT_SDK}" \
        MICROKIT_BOARD=qemu_virt_aarch64 \
        MICROKIT_CONFIG=debug \
        TOOLCHAIN=clang \
        SEL4_CRATE_DIR="${SEL4_CRATE_DIR}" \
        CARGO_FEATURES=subscriber \
        make BUILD_DIR=build
fi

[[ -f "${LOADER_IMG}" ]] || { echo "build did not produce loader.img" >&2; exit 1; }

echo "[run-hdds-sub] starting QEMU (log: ${QEMU_LOG})"
cd "${BUILD_DIR}"

# Pre-arm trap with empty QEMU_PID so a signal between `&` and the
# assignment cannot orphan the QEMU process.
QEMU_PID=''
trap 'if [[ -n "${QEMU_PID}" ]]; then kill "${QEMU_PID}" 2>/dev/null || true; wait "${QEMU_PID}" 2>/dev/null || true; fi' EXIT INT TERM

qemu-system-aarch64 \
    -machine virt,virtualization=on -cpu cortex-a53 \
    -m size=2G \
    -serial "file:${QEMU_LOG}" \
    -global virtio-mmio.force-legacy=false \
    -device loader,file=loader.img,addr=0x70000000,cpu-num=0 \
    -device virtio-net-device,netdev=netdev0,bus=virtio-mmio-bus.0 \
    -nographic -display none \
    -netdev user,id=netdev0,hostfwd=udp::1235-10.0.2.15:1235,hostfwd=udp::1238-10.0.2.16:1235,hostfwd=udp::1241-10.0.2.17:1235 \
    -d guest_errors </dev/null >/dev/null 2>&1 &
QEMU_PID=$!

for _ in $(seq 1 20); do
    if grep -q "IP address for netif client0" "${QEMU_LOG}" 2>/dev/null \
       && grep -q "IP address for netif client1" "${QEMU_LOG}" 2>/dev/null; then
        break
    fi
    sleep 1
done

if ! grep -q "Microkit Monitor started" "${QEMU_LOG}" 2>/dev/null; then
    echo "[run-hdds-sub] BOOT FAILED - Microkit Monitor never started. Last log lines:" >&2
    tail -30 "${QEMU_LOG}" >&2 || true
    exit 1
fi

sleep 1

echo "[run-hdds-sub] ready. PD subscriber listening on guest 10.0.2.17:1235 (host port 1241)."
echo "[run-hdds-sub] In another shell, run:"
echo "[run-hdds-sub]   ${SEL4_CRATE_DIR}/host-tools/hdds_pub/target/release/hdds_pub --count 200"
echo "[run-hdds-sub] Tail incoming-sample log:"
echo "[run-hdds-sub]   tail -F ${QEMU_LOG} | grep RX"
echo "[run-hdds-sub] Ctrl-C to stop."
wait
