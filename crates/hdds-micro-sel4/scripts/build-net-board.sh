#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2026 naskel.com
#
# Build the network system (sDDF genet NIC driver, two HDDS PDs on the
# wire) for the Raspberry Pi 4 8 GB board, without booting it.
#
# Usage:
#   crates/hdds-micro-sel4/scripts/build-net-board.sh OUT_DIR
#
# Environment (all required unless noted):
#   MICROKIT_SDK   Microkit SDK root
#   SDDF_ROOT      isolated sDDF checkout; examples/echo_server/echo.mk,
#                  meta_net.py and tools/make/board/rpi4b_8gb.mk are
#                  overwritten (use a private clone)
#   DTB_FILE       device tree in sdfgen's form: sDDF dts/rpi4b_1gb.dts
#                  compiled with "dtc -q -I dts -O dtb"
#   PUB_IP         IPv4 of the publisher PD on the LAN (dotted quad)
#   SUB_IP         IPv4 of the subscriber PD on the LAN (dotted quad)
#   SDFGEN_PYTHONPATH  directory holding the sdfgen 0.29.0 package and
#                  libcsdfgen (optional; prepended to PYTHONPATH)
#   CARGO_LOCK     if set, the make run (which invokes cargo) holds flock
#   LLVM_BIN       LLVM 19 bin directory (default /usr/lib/llvm-19/bin)
#   BOARD          Microkit board (default rpi4b_8gb)
#
# Prints the loader.img path and its md5 on success.

set -euo pipefail

[[ $# -eq 1 ]] || { echo "usage: $0 OUT_DIR" >&2; exit 2; }
OUT_DIR="$(realpath -m "$1")"

MICROKIT_SDK="${MICROKIT_SDK:?set MICROKIT_SDK to the Microkit SDK root}"
SDDF_ROOT="${SDDF_ROOT:?SDDF_ROOT must point at a private sDDF checkout}"
DTB_FILE="$(realpath -e "${DTB_FILE:?set DTB_FILE to the compiled sDDF rpi4b_1gb device tree}")"
PUB_IP="${PUB_IP:?set PUB_IP (publisher PD IPv4)}"
SUB_IP="${SUB_IP:?set SUB_IP (subscriber PD IPv4)}"
LLVM_BIN="${LLVM_BIN:-/usr/lib/llvm-19/bin}"
BOARD="${BOARD:-rpi4b_8gb}"

ipv4_octets() {
    local ip="$1"
    [[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] \
        || { echo "not a dotted IPv4: $ip" >&2; exit 2; }
    local o
    for o in "${BASH_REMATCH[@]:1}"; do
        (( o <= 255 )) || { echo "octet out of range in $ip" >&2; exit 2; }
    done
    local IFS=,
    echo "${BASH_REMATCH[*]:1}"
}
PUB_OCTETS="$(ipv4_octets "$PUB_IP")"
SUB_OCTETS="$(ipv4_octets "$SUB_IP")"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SEL4_CRATE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
OVERLAY_DIR="${SEL4_CRATE_DIR}/microkit"
ECHO_DIR="${SDDF_ROOT}/examples/echo_server"

[[ -d "${MICROKIT_SDK}/board/${BOARD}" ]] \
    || { echo "board ${BOARD} not in ${MICROKIT_SDK}" >&2; exit 1; }
[[ -d "${ECHO_DIR}" ]] || { echo "echo_server not found: ${ECHO_DIR}" >&2; exit 1; }

if [[ -n "${SDFGEN_PYTHONPATH:-}" ]]; then
    export PYTHONPATH="${SDFGEN_PYTHONPATH}${PYTHONPATH:+:${PYTHONPATH}}"
fi
python3 -c 'import sdfgen' 2>/dev/null \
    || { echo "sdfgen not importable (set SDFGEN_PYTHONPATH)" >&2; exit 1; }

cp -f "${OVERLAY_DIR}/meta_net.py"           "${ECHO_DIR}/meta_net.py"
cp -f "${OVERLAY_DIR}/echo_net.mk"           "${ECHO_DIR}/echo.mk"
cp -f "${OVERLAY_DIR}/board/rpi4b_8gb.mk"    "${SDDF_ROOT}/tools/make/board/rpi4b_8gb.mk"

MAKE_CMD=(make -C "${ECHO_DIR}" BUILD_DIR="${OUT_DIR}"
          MICROKIT_SDK="${MICROKIT_SDK}" MICROKIT_BOARD="${BOARD}"
          MICROKIT_CONFIG=debug TOOLCHAIN=clang
          SEL4_CRATE_DIR="${SEL4_CRATE_DIR}" DTB_FILE="${DTB_FILE}"
          PUB_IP_OCTETS="${PUB_OCTETS}" SUB_IP_OCTETS="${SUB_OCTETS}")
if [[ -n "${CARGO_LOCK:-}" ]]; then
    MAKE_CMD=(flock "${CARGO_LOCK}" "${MAKE_CMD[@]}")
fi

PATH="${LLVM_BIN}:${PATH}" "${MAKE_CMD[@]}"

[[ -f "${OUT_DIR}/loader.img" ]] || { echo "build did not produce loader.img" >&2; exit 1; }
md5sum "${OUT_DIR}/loader.img"
