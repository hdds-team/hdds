#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com
#
# Regenerate tools/docker-ros2/symbols/<distro>.txt.
#
# The authority is ros2/rmw_implementation: its src/functions.cpp resolves
# every rmw entry point out of the loaded middleware .so through the
# GET_SYMBOL / EXPAND_AND_LOAD macros. Anything on that list that librmw_hdds.so
# does not define is a nullptr at runtime that only explodes when a node
# happens to call it - which is exactly why the gate compares the whole list
# instead of trusting "the talker works".
#
# The lists are COMMITTED so the gate itself needs no network. This script is
# how they are refreshed, deliberately, when a distro branch moves; it needs
# the network and it prints what changed.
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
DISTROS=("${@:-humble iron jazzy}")
[[ $# -gt 0 ]] && DISTROS=("$@") || DISTROS=(humble iron jazzy)

for distro in "${DISTROS[@]}"; do
    url="https://raw.githubusercontent.com/ros2/rmw_implementation/${distro}/rmw_implementation/src/functions.cpp"
    out="${HERE}/symbols/${distro}.txt"
    tmp=$(mktemp)
    echo "[extract] ${distro} <- ${url}"
    curl -fsSL "$url" -o "$tmp"

    {
        echo "# rmw entry points rmw_implementation resolves on ROS 2 ${distro}."
        echo "# Source: ros2/rmw_implementation @ branch ${distro},"
        echo "#         rmw_implementation/src/functions.cpp (GET_SYMBOL / EXPAND_AND_LOAD)."
        echo "# Regenerate with tools/docker-ros2/extract-required-symbols.sh ${distro}."
        # RMW_INTERFACE_FN(name, ...) declares one forwarded entry point each and
        # is the complete list (GET_SYMBOL alone misses rmw_take_sequence, which
        # rmw_implementation resolves through a different path). The macro
        # DEFINITIONS use parameter names (x, symbol_name, ...), so keep only
        # arguments that are themselves rmw_ names.
        tr '\n' ' ' < "$tmp" \
            | grep -oE '\b(RMW_INTERFACE_FN|GET_SYMBOL|EXPAND_AND_LOAD_SYMBOL|EXPAND_AND_LOAD)[[:space:]]*\([[:space:]]*rmw_[A-Za-z0-9_]+' \
            | grep -oE 'rmw_[A-Za-z0-9_]+' \
            | sort -u
    } > "${out}.new"

    count=$(grep -cvE '^\s*(#|$)' "${out}.new")
    if [[ "$count" -lt 50 ]]; then
        echo "[extract] REFUSING to write ${out}: only ${count} symbols extracted" >&2
        rm -f "$tmp" "${out}.new"
        exit 1
    fi
    if [[ -f "$out" ]]; then
        diff -u "$out" "${out}.new" || true
    fi
    mv "${out}.new" "$out"
    rm -f "$tmp"
    echo "[extract] ${distro}: ${count} symbols -> ${out}"
done
