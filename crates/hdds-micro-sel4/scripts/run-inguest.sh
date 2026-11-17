#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2026 naskel.com
#
# hdds-micro-sel4 intra-guest reproducer: build and boot the intra-guest
# pub/sub system. Two Rust client PDs (client2_rust = publisher,
# client3_rust = subscriber) talk RTPS over a loopback "driver" PD
# that reflects TX frames into RX without touching any hardware NIC.
# QEMU launches with NO `-device virtio-net-device` and NO `-netdev`,
# so the host's network stack is provably outside the data plane.
#
# Overlay files (all from crates/hdds-micro-sel4/microkit/):
#   - meta_loopback.py        -> ${ECHO_DIR}/meta_loopback.py
#   - echo_loopback.mk        -> ${ECHO_DIR}/echo.mk
#   - loopback_driver.c       -> ${ECHO_DIR}/loopback_driver.c
#   - client2_rust_wrapper.c  -> ${ECHO_DIR}/client2_rust_wrapper.c
#   - client3_rust_wrapper.c  -> ${ECHO_DIR}/client3_rust_wrapper.c
#
# Usage:
#   crates/hdds-micro-sel4/scripts/run-inguest.sh            # overlay+build+boot+test
#   crates/hdds-micro-sel4/scripts/run-inguest.sh --no-test  # boot only, wait
#   crates/hdds-micro-sel4/scripts/run-inguest.sh --build    # force clean rebuild
#   crates/hdds-micro-sel4/scripts/run-inguest.sh --revert   # restore stock upstream

set -euo pipefail

MICROKIT_SDK="${MICROKIT_SDK:?set MICROKIT_SDK to the Microkit SDK root}"
SDDF_ROOT="${SDDF_ROOT:?set SDDF_ROOT to the sDDF checkout}"
ECHO_DIR="${SDDF_ROOT}/examples/echo_server"
BUILD_DIR="${ECHO_DIR}/build"
LOADER_IMG="${BUILD_DIR}/loader.img"
QEMU_LOG="${QEMU_LOG:-/tmp/hdds-inguest-qemu.log}"
LLVM_BIN="${LLVM_BIN:-/usr/lib/llvm-19/bin}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SEL4_CRATE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
OVERLAY_DIR="${SEL4_CRATE_DIR}/microkit"

# Number of consecutive `RX seq=` lines we require for a green run.
# Big enough to exercise the ping-pong loop multiple times; small
# enough to stay under the 30 s test timeout. The publisher emits one
# sample per probe so a value of 100 means 100 round-trips through
# the loopback driver.
RX_TARGET="${RX_TARGET:-100}"

DO_TEST=1
FORCE_BUILD=0
DO_REVERT=0
for arg in "$@"; do
    case "$arg" in
        --no-test) DO_TEST=0 ;;
        --build)   FORCE_BUILD=1 ;;
        --revert)  DO_REVERT=1 ;;
        *) echo "unknown arg: $arg" >&2; exit 2 ;;
    esac
done

[[ -d "${MICROKIT_SDK}" ]] || { echo "MICROKIT_SDK not found: ${MICROKIT_SDK}" >&2; exit 1; }
[[ -d "${ECHO_DIR}"     ]] || { echo "echo_server not found: ${ECHO_DIR}" >&2; exit 1; }
[[ -d "${LLVM_BIN}"     ]] || { echo "LLVM 19 not found: ${LLVM_BIN}" >&2; exit 1; }
[[ -d "${OVERLAY_DIR}"  ]] || { echo "overlay dir not found: ${OVERLAY_DIR}" >&2; exit 1; }
command -v qemu-system-aarch64 >/dev/null || { echo "qemu-system-aarch64 not in PATH" >&2; exit 1; }
command -v cargo >/dev/null || { echo "cargo not in PATH" >&2; exit 1; }
python3 -c 'import importlib.util as u; from importlib.metadata import version; raise SystemExit(u.find_spec("sdfgen") is None or version("sdfgen") != "0.29.0")' \
    || { echo "sdfgen 0.29.0 is required; see crates/hdds-micro-sel4/README.md" >&2; exit 1; }

if (( DO_REVERT == 1 )); then
    echo "[run-inguest] restoring stock upstream sDDF echo_server"
    (cd "${SDDF_ROOT}" && git checkout examples/echo_server/)
    # Best-effort cleanup of intra-guest-only files that git checkout
    # would not remove (they were never tracked upstream).
    rm -f "${ECHO_DIR}/meta_loopback.py" \
          "${ECHO_DIR}/loopback_driver.c" \
          "${ECHO_DIR}/client3_rust_wrapper.c"
    echo "[run-inguest] done."
    exit 0
fi

echo "[run-inguest] applying overlay to ${ECHO_DIR}"
cp -f "${OVERLAY_DIR}/meta_loopback.py"       "${ECHO_DIR}/meta_loopback.py"
cp -f "${OVERLAY_DIR}/echo_loopback.mk"       "${ECHO_DIR}/echo.mk"
cp -f "${OVERLAY_DIR}/loopback_driver.c"      "${ECHO_DIR}/loopback_driver.c"
cp -f "${OVERLAY_DIR}/client2_rust_wrapper.c" "${ECHO_DIR}/client2_rust_wrapper.c"
cp -f "${OVERLAY_DIR}/client3_rust_wrapper.c" "${ECHO_DIR}/client3_rust_wrapper.c"

# Always invoke `make` so its mtime-based dependency tracking picks up
# changes to the overlay sources or Cargo artifacts. `--build` only
# adds the `rm -rf build` clean-slate step on top. Skipping `make`
# would let a manual rerun PASS against a stale `loader.img`.
echo "[run-inguest] building (intra-guest overlay)..."
cd "${ECHO_DIR}"
if (( FORCE_BUILD == 1 )) && [[ -d build ]]; then
    rm -rf build
fi
PATH="${LLVM_BIN}:${PATH}" \
    MICROKIT_SDK="${MICROKIT_SDK}" \
    MICROKIT_BOARD=qemu_virt_aarch64 \
    MICROKIT_CONFIG=debug \
    TOOLCHAIN=clang \
    SEL4_CRATE_DIR="${SEL4_CRATE_DIR}" \
    make BUILD_DIR=build

[[ -f "${LOADER_IMG}" ]] || { echo "build did not produce loader.img" >&2; exit 1; }

# Pre-arm the QEMU PID before the trap so a build failure above does
# not leak a kill -SIGTERM 0 (which would kill our own process group).
QEMU_PID=
trap '[[ -n "${QEMU_PID}" ]] && kill ${QEMU_PID} 2>/dev/null; wait 2>/dev/null || true' EXIT

echo "[run-inguest] starting QEMU (log: ${QEMU_LOG})"
cd "${BUILD_DIR}"
# Critical: NO -netdev and NO -device virtio-net-device
# on the command line. The DTB still advertises virtio_mmio slots but
# nothing attaches to them, and our loopback_driver consumes no MMIO
# / IRQ either way. This is the proof that the data plane is sealed
# inside the guest.
qemu-system-aarch64 \
    -machine virt,virtualization=on -cpu cortex-a53 \
    -m size=2G \
    -serial "file:${QEMU_LOG}" \
    -global virtio-mmio.force-legacy=false \
    -device loader,file=loader.img,addr=0x70000000,cpu-num=0 \
    -nographic -display none \
    -d guest_errors </dev/null >/dev/null 2>&1 &
QEMU_PID=$!

# Wait for both PDs to print their init markers. The loopback driver
# prints "LOOPBACK|INIT" (see loopback_driver.c) and the
# subscriber prints "hdds-sel4: subscriber ready". If either marker
# never appears within 20 s, the boot stalled - dump the tail and
# bail. The publisher's own "publisher ready" banner is not required
# here: the RX sample count below proves it is running.
for _ in $(seq 1 20); do
    if grep -q "LOOPBACK|INIT" "${QEMU_LOG}" 2>/dev/null \
       && grep -q "hdds-sel4: subscriber ready" "${QEMU_LOG}" 2>/dev/null; then
        break
    fi
    sleep 1
done

if ! grep -q "LOOPBACK|INIT" "${QEMU_LOG}" 2>/dev/null \
   || ! grep -q "hdds-sel4: subscriber ready" "${QEMU_LOG}" 2>/dev/null; then
    echo "[run-inguest] BOOT FAILED - init markers missing. Last log lines:" >&2
    tail -40 "${QEMU_LOG}" >&2 || true
    exit 1
fi

if (( DO_TEST == 0 )); then
    echo "[run-inguest] boot OK, sleeping forever (Ctrl-C to stop)"
    wait
    exit 0
fi

echo "[run-inguest] boot OK, waiting for ${RX_TARGET} RX samples..."

# Poll the QEMU log for `RX seq=` markers emitted by subscriber.rs at
# every successful decode. We give the ping-pong loop a generous 30 s
# (well over 1 ms/sample on emulation) before declaring failure.
RX_COUNT=0
for _ in $(seq 1 30); do
    # `grep -c` exits 1 on zero matches. We want a numeric default
    # without the `|| echo 0` trick (which would emit "<n>\n0" on
    # later iterations once matches appear and break the (( )) test).
    RX_COUNT=$(grep -c "RX seq=" "${QEMU_LOG}" 2>/dev/null) || RX_COUNT=0
    if (( RX_COUNT >= RX_TARGET )); then
        break
    fi
    sleep 1
done

# Monotonicity check: the publisher emits sequence numbers starting
# at 1 and incrementing. BEST_EFFORT may drop, but never re-order.
# `last_seq` warnings would emit `WARN non-monotonic`; we treat any
# such line as a failure.
if grep -q "WARN non-monotonic" "${QEMU_LOG}" 2>/dev/null; then
    echo "[run-inguest] FAIL - non-monotonic seq detected in log:" >&2
    grep "WARN non-monotonic" "${QEMU_LOG}" >&2
    exit 1
fi

# Same with the decode-failure marker: a single failed CDR decode
# is a real interop bug.
if grep -q "WARN decode failed" "${QEMU_LOG}" 2>/dev/null; then
    echo "[run-inguest] FAIL - decode failure detected:" >&2
    grep "WARN decode failed" "${QEMU_LOG}" >&2
    exit 1
fi

if (( RX_COUNT < RX_TARGET )); then
    echo "[run-inguest] FAIL - only ${RX_COUNT}/${RX_TARGET} RX samples received" >&2
    echo "--- last 40 lines of QEMU serial log ---" >&2
    tail -40 "${QEMU_LOG}" >&2 || true
    exit 1
fi

# Hold QEMU alive until the caller has finished its seal check. The
# wrapper test-inguest.sh sets SEAL_HANDSHAKE and creates that file
# after it has inspected the QEMU child. Without the hold, QEMU can exit
# as soon as the RX count is reached, before the wrapper looks at it.
if [[ -n "${SEAL_HANDSHAKE:-}" ]]; then
    for _ in $(seq 1 120); do
        [[ -e "${SEAL_HANDSHAKE}" ]] && break
        sleep 0.5
    done
    [[ -e "${SEAL_HANDSHAKE}" ]] || { echo "[run-inguest] FAIL - seal check never completed" >&2; exit 1; }
fi

echo "[run-inguest] PASS - ${RX_COUNT} RX samples received intra-guest, zero data plane"
