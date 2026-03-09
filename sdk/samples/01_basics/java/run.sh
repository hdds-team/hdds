#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com
#
# Build and run the HDDS Java Hello World sample.
# Requires: Java 22+, HDDS native library (cargo build --release)

set -euo pipefail

# Source SDKMAN if available (manages multiple Java versions)
[ -f "${SDKMAN_DIR:-$HOME/.sdkman}/bin/sdkman-init.sh" ] && \
    source "${SDKMAN_DIR:-$HOME/.sdkman}/bin/sdkman-init.sh"

HDDS_ROOT="${HDDS_ROOT:-$(cd ../../../.. && pwd)}"
LIB_DIR="${HDDS_ROOT}/target/release"

if [ ! -f "${LIB_DIR}/libhdds_c.so" ] && [ ! -f "${LIB_DIR}/libhdds_c.dylib" ]; then
    echo "Error: HDDS native library not found in ${LIB_DIR}"
    echo "Build it first:  cd ${HDDS_ROOT} && cargo build --release"
    exit 1
fi

JAVA_VERSION=$(java -version 2>&1 | head -1 | sed 's/.*"\([0-9]*\)\..*/\1/')
if [ "${JAVA_VERSION}" -lt 22 ] 2>/dev/null; then
    echo "Error: Java 22+ required (found Java ${JAVA_VERSION})"
    exit 1
fi

echo "=== Compiling HelloWorld.java ==="
javac HelloWorld.java

echo "=== Running (mode: ${1:-subscriber}) ==="
java --enable-native-access=ALL-UNNAMED \
     -Djava.library.path="${LIB_DIR}" \
     HelloWorld "$@"
