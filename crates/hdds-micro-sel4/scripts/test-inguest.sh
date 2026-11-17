#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2026 naskel.com
#
# Intra-guest CI test: boot the loopback / intra-guest pub-sub
# system, verify the subscriber logs >= N_TARGET sequenced RX samples,
# AND assert the data plane is sealed inside the guest (no QEMU
# socket open on any host IP). Exit 0 only if both hold.
#
# This is a thin wrapper over run-inguest.sh - that script already
# enforces the RX count / monotonicity / decode-error checks. The job
# here is the structural seal proof: the QEMU command line was built
# without `-netdev` or `-device virtio-net-device`, and we double-
# check at runtime that no qemu-system-aarch64 process owns a TCP or
# UDP socket. With those two truths, no PD-emitted byte can have left
# the guest, regardless of the loopback driver's behaviour.
#
# Usage:
#   crates/hdds-micro-sel4/scripts/test-inguest.sh           # default
#   RX_TARGET=500 crates/hdds-micro-sel4/scripts/test-inguest.sh   # custom count

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN_SCRIPT="${SCRIPT_DIR}/run-inguest.sh"
QEMU_LOG="${QEMU_LOG:-/tmp/hdds-inguest-qemu.log}"

[[ -x "${RUN_SCRIPT}" ]] || { echo "[test-inguest] run script missing: ${RUN_SCRIPT}" >&2; exit 1; }

# The seal check below uses `ss` to enumerate kernel sockets. If `ss`
# is missing (or fails for any other reason), the `|| true` on its
# pipeline would yield an empty LEAKED_SOCKETS and we'd report PASS
# without actually proving the seal. Pre-flight `ss` here so absence
# is a loud failure rather than a silently-degraded check.
command -v ss >/dev/null \
    || { echo "[test-inguest] FAIL: ss is not installed; seal check cannot run" >&2; exit 1; }

# Do not kill processes owned by another test. Refuse to start if an earlier
# loader-backed QEMU is still active, and let the caller decide how to handle it.
RUNNING_QEMU=$(ps -eo pid=,comm=,args= \
    | awk '$2 ~ /^qemu-system/ && $0 ~ /loader\.img/ { print }')
if [[ -n "${RUNNING_QEMU}" ]]; then
    echo "[test-inguest] FAIL: a loader-backed QEMU is already running:" >&2
    echo "${RUNNING_QEMU}" >&2
    exit 1
fi

RUN_PID=''
SEAL_HANDSHAKE="${QEMU_LOG}.seal-done"
rm -f "${SEAL_HANDSHAKE}"
cleanup() {
    [[ -n "${RUN_PID}" ]] || return 0
    if kill -0 "${RUN_PID}" 2>/dev/null; then
        kill "${RUN_PID}" 2>/dev/null || true
        wait "${RUN_PID}" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

QEMU_LOG="${QEMU_LOG}" SEAL_HANDSHAKE="${SEAL_HANDSHAKE}" "${RUN_SCRIPT}" --build &
RUN_PID=$!

# We let run-inguest.sh manage QEMU's lifecycle but check on the
# child process for the sealing assertion mid-flight. Wait for the
# boot markers (same logic as inside run-inguest.sh) so we know
# QEMU is up before scanning sockets.
for _ in $(seq 1 25); do
    if grep -q "LOOPBACK|INIT" "${QEMU_LOG}" 2>/dev/null \
       && grep -q "hdds-sel4: subscriber ready" "${QEMU_LOG}" 2>/dev/null; then
        break
    fi
    if ! kill -0 "${RUN_PID}" 2>/dev/null; then
        echo "[test-inguest] run script died before boot; see ${QEMU_LOG}" >&2
        wait "${RUN_PID}" || true
        exit 1
    fi
    sleep 1
done

# Scope the seal check to the QEMU child of this runner. Looking at every QEMU
# on the host can attribute an unrelated test's socket to this one.
# `ps` exits 1 when no child matches; that must reach the count check below,
# not abort the script silently under pipefail.
QEMU_PIDS=$(ps -o pid=,comm= --ppid "${RUN_PID}" \
    | awk '$2 ~ /^qemu-system/ { print $1 }' || true)
QEMU_COUNT=$(wc -w <<< "${QEMU_PIDS}")
if (( QEMU_COUNT != 1 )); then
    echo "[test-inguest] FAIL: expected one QEMU child, found ${QEMU_COUNT}" >&2
    exit 1
fi

QEMU_PID=${QEMU_PIDS//[[:space:]]/}
LEAKED_SOCKETS=$(ss -tunap 2>/dev/null | grep -F "pid=${QEMU_PID}," || true)
if [[ -n "${LEAKED_SOCKETS}" ]]; then
    echo "[test-inguest] FAIL: QEMU owns host sockets (data plane leaked):" >&2
    echo "${LEAKED_SOCKETS}" >&2
    exit 1
fi

echo "[test-inguest] seal verified: qemu PID ${QEMU_PID} owns no TCP/UDP host sockets"
touch "${SEAL_HANDSHAKE}"

# Now wait for the run script to complete its in-script RX-count
# assertion. A non-zero exit there is a count/monotonicity failure
# we propagate verbatim.
if ! wait "${RUN_PID}"; then
    echo "[test-inguest] FAIL: run-inguest.sh reported failure (see above)" >&2
    exit 1
fi
RUN_PID=''

echo "[test-inguest] ALL CHECKS PASS: intra-guest pub/sub validated"
