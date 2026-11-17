#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2026 naskel.com
#
# Publisher boot script: same overlay machinery as run-echo-rust.sh
# but builds the `client2_rust` staticlib with `--features publisher`
# so the PD's `notified()` emits one CDR-encoded Temperature sample per
# inbound kick (instead of echoing). Pair with hdds_sub (see
# scripts/test-interop-sel4-to-linux.sh for the full integration check) or
# poke with `nc` for ad-hoc validation.
#
# Usage:
#   crates/hdds-micro-sel4/scripts/run-hdds-pub.sh           # overlay + build + boot, idle
#   crates/hdds-micro-sel4/scripts/run-hdds-pub.sh --build   # force rebuild
#   crates/hdds-micro-sel4/scripts/run-hdds-pub.sh --revert  # restore stock upstream
#
# Once booted, in another shell:
#   crates/hdds-micro-sel4/host-tools/hdds_sub/target/release/hdds_sub --count 200
#
# The PD listens on host port 1241 (SLIRP hostfwd -> guest
# 10.0.2.17:1235) and replies with one RTPS DATA per inbound packet.

set -euo pipefail

MICROKIT_SDK="${MICROKIT_SDK:?set MICROKIT_SDK to the Microkit SDK root}"
SDDF_ROOT="${SDDF_ROOT:?set SDDF_ROOT to the sDDF checkout}"
ECHO_DIR="${SDDF_ROOT}/examples/echo_server"
BUILD_DIR="${ECHO_DIR}/build"
LOADER_IMG="${BUILD_DIR}/loader.img"
QEMU_LOG="${QEMU_LOG:-/tmp/hdds-pub-qemu.log}"
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
    echo "[run-hdds-pub] restoring stock upstream sDDF echo_server"
    (cd "${SDDF_ROOT}" && git checkout examples/echo_server/)
    echo "[run-hdds-pub] done. Re-run any of the hdds-micro-sel4 boot scripts to re-apply the overlay."
    exit 0
fi

echo "[run-hdds-pub] applying overlay to ${ECHO_DIR}"
cp -f "${OVERLAY_DIR}/meta.py"           "${ECHO_DIR}/meta.py"
cp -f "${OVERLAY_DIR}/echo.mk"           "${ECHO_DIR}/echo.mk"
cp -f "${OVERLAY_DIR}/single_core.json"  "${ECHO_DIR}/core_config/single_core.json"
cp -f "${OVERLAY_DIR}/client2_rust_wrapper.c" "${ECHO_DIR}/client2_rust_wrapper.c"

# Note: the staticlib build rule in echo.mk is FORCE-marked so cargo
# always runs and detects the feature swap (echo <-> publisher) on its
# own. No explicit `touch` is needed here to invalidate make's
# timestamps.

if (( FORCE_BUILD == 1 )) || [[ ! -f "${LOADER_IMG}" ]]; then
    echo "[run-hdds-pub] building (with overlay, --features publisher)..."
    cd "${ECHO_DIR}"
    [[ -d build ]] && rm -rf build
    PATH="${LLVM_BIN}:${PATH}" \
        MICROKIT_SDK="${MICROKIT_SDK}" \
        MICROKIT_BOARD=qemu_virt_aarch64 \
        MICROKIT_CONFIG=debug \
        TOOLCHAIN=clang \
        SEL4_CRATE_DIR="${SEL4_CRATE_DIR}" \
        CARGO_FEATURES=publisher \
        make BUILD_DIR=build
else
    # Even without --build, make must re-evaluate the Rust staticlib
    # rule under CARGO_FEATURES=publisher so cargo notices the feature
    # change. The rule is FORCE-marked, so make always re-runs it; we
    # just need make to run with the right env.
    echo "[run-hdds-pub] refreshing Rust staticlib (publisher feature)..."
    cd "${ECHO_DIR}"
    PATH="${LLVM_BIN}:${PATH}" \
        MICROKIT_SDK="${MICROKIT_SDK}" \
        MICROKIT_BOARD=qemu_virt_aarch64 \
        MICROKIT_CONFIG=debug \
        TOOLCHAIN=clang \
        SEL4_CRATE_DIR="${SEL4_CRATE_DIR}" \
        CARGO_FEATURES=publisher \
        make BUILD_DIR=build
fi

[[ -f "${LOADER_IMG}" ]] || { echo "build did not produce loader.img" >&2; exit 1; }

echo "[run-hdds-pub] starting QEMU (log: ${QEMU_LOG})"
cd "${BUILD_DIR}"
# Pre-arm the cleanup trap with an empty QEMU_PID so an interrupt
# between the `&` and the `QEMU_PID=$!` assignment cannot orphan the
# QEMU process. The handler is a no-op until QEMU_PID is populated.
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

# Same boot-ready gate as the echo reproducer: wait for both lwIP
# clients to finish DHCP (proves the network plane is up) before
# claiming the system is ready.
for _ in $(seq 1 20); do
    if grep -q "IP address for netif client0" "${QEMU_LOG}" 2>/dev/null \
       && grep -q "IP address for netif client1" "${QEMU_LOG}" 2>/dev/null; then
        break
    fi
    sleep 1
done

if ! grep -q "Microkit Monitor started" "${QEMU_LOG}" 2>/dev/null; then
    echo "[run-hdds-pub] BOOT FAILED - Microkit Monitor never started. Last log lines:" >&2
    tail -30 "${QEMU_LOG}" >&2 || true
    exit 1
fi

# Tiny settle for the Rust binding's silent init (no per-PD log line).
sleep 1

echo "[run-hdds-pub] ready. PD publisher listening on host port 1241."
echo "[run-hdds-pub] In another shell, run:"
echo "[run-hdds-pub]   ${SEL4_CRATE_DIR}/host-tools/hdds_sub/target/release/hdds_sub --count 200"
echo "[run-hdds-pub] Or poke manually with:"
echo "[run-hdds-pub]   echo -n kick | nc -u -w1 127.0.0.1 1241 | xxd | head"
echo "[run-hdds-pub] Ctrl-C to stop."
wait
