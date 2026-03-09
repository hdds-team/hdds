#!/bin/bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

# Regenerate C, C++, and Python type files from IDL using hdds_gen.
#
# Usage: ./regenerate_types.sh
#
# Prerequisites:
#   - hdds_gen built: cd /projects/public/hdds_gen && cargo build --release
#   - Or set HDDSGEN env var to the hddsgen binary path

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SAMPLES_DIR="$(dirname "$SCRIPT_DIR")"
IDL_DIR="$SAMPLES_DIR/idl"

# Find hddsgen binary
HDDSGEN="${HDDSGEN:-}"
if [ -z "$HDDSGEN" ]; then
    # Try common locations
    for path in \
        "$(cd "$SAMPLES_DIR/../.." && pwd)/target/release/hddsgen" \
        "/projects/public/hdds_gen/target/release/hddsgen" \
        "$(command -v hddsgen 2>/dev/null || true)"; do
        if [ -n "$path" ] && [ -x "$path" ]; then
            HDDSGEN="$path"
            break
        fi
    done
fi

if [ -z "$HDDSGEN" ] || [ ! -x "$HDDSGEN" ]; then
    echo "ERROR: hddsgen not found"
    echo "Build it: cd /projects/public/hdds_gen && cargo build --release"
    echo "Or set HDDSGEN=/path/to/hddsgen"
    exit 1
fi

echo "Using hddsgen: $HDDSGEN"
echo "  Version: $($HDDSGEN --version 2>/dev/null || echo 'unknown')"
echo ""

gen() {
    local lang="$1" idl="$2" out="$3"
    $HDDSGEN gen "$lang" "$IDL_DIR/$idl" -o "$out"
}

echo "=== 01_basics (HelloWorld, KeyedData) ==="
for lang in c:c/generated:.h cpp:cpp/generated:.hpp python:python/generated:.py; do
    IFS=: read -r target dir ext <<< "$lang"
    outdir="$SAMPLES_DIR/01_basics/$dir"
    mkdir -p "$outdir"
    gen "$target" "HelloWorld.idl" "$outdir/HelloWorld$ext"
    gen "$target" "KeyedData.idl"  "$outdir/KeyedData$ext"
done

echo ""
echo "=== 03_types (10 type IDLs) ==="
TYPES="Arrays Bits Enums Maps Nested Optional Primitives Sequences Strings Unions"
for lang in c:c/generated:.h cpp:cpp/generated:.hpp python:python/generated:.py; do
    IFS=: read -r target dir ext <<< "$lang"
    outdir="$SAMPLES_DIR/03_types/$dir"
    mkdir -p "$outdir"
    for type in $TYPES; do
        gen "$target" "$type.idl" "$outdir/$type$ext"
    done
done

echo ""
echo "=== Done ==="
echo ""
echo "Generated files:"
echo "  01_basics: c(2) cpp(2) python(2)"
echo "  03_types:  c(10) cpp(10) python(10)"
echo ""
echo "Note: 02_qos, 04-07 C/C++ use symlinks to 01_basics/c/generated"
echo "      and are automatically updated."
