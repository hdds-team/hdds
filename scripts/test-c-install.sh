#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com
#
# Install the C SDK into a temporary prefix (make install-c) and prove that a
# C program builds and runs against the INSTALLED files only, three ways:
#   1. pkg-config, shared library (-lhdds_c, run with LD_LIBRARY_PATH)
#   2. pkg-config flags + the static archive (runs with no LD_LIBRARY_PATH)
#   3. CMake find_package(hdds <version> REQUIRED COMPONENTS c), with no C++
#      SDK installed
# The program publishes one sample intra-process and takes it back, so a
# link that resolves but a library that does not work also fails.
#
# Missing tools (cc, pkg-config, cmake) are a failure, never a skip.
#
# Usage: scripts/test-c-install.sh        (from anywhere; builds hdds-c if stale)

set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
WORK=$(mktemp -d "${TMPDIR:-/tmp}/hdds-c-install.XXXXXX")
PREFIX="$WORK/prefix"
trap 'rm -rf "$WORK"' EXIT

fail() {
    printf 'test-c-install: FAIL: %s\n' "$*" >&2
    exit 1
}
pass() {
    printf 'test-c-install: ok: %s\n' "$*"
}

for tool in cc pkg-config cmake make awk ldd; do
    command -v "$tool" >/dev/null 2>&1 || fail "required tool not found: $tool"
done

version=$(awk '/^\[workspace\.package\]/{f=1;next} /^\[/{f=0} f && /^version *= */{sub(/^[^"]*"/,""); sub(/".*$/,""); print; exit}' "$ROOT/Cargo.toml")
[[ -n "$version" ]] || fail "could not read the workspace version"

make -C "$ROOT" --no-print-directory install-c PREFIX="$PREFIX" >"$WORK/install.log" 2>&1 ||
    { cat "$WORK/install.log" >&2; fail "make install-c"; }

for f in include/hdds.h lib/libhdds_c.a lib/libhdds_c.so lib/pkgconfig/hdds_c.pc \
    lib/cmake/hdds/hdds-config.cmake lib/cmake/hdds/hdds-config-version.cmake; do
    [[ -f "$PREFIX/$f" ]] || fail "not installed: $f"
done
[[ ! -e "$PREFIX/lib/libhdds_cxx.a" ]] || fail "install-c installed the C++ SDK"
pass "make install-c laid out header, libraries, hdds_c.pc and the CMake config"

export PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig"
pc_version=$(pkg-config --modversion hdds_c)
[[ "$pc_version" == "$version" ]] || fail "hdds_c.pc version $pc_version != workspace $version"
pass "pkg-config --modversion hdds_c == $version"

cat >"$WORK/roundtrip.c" <<'EOF'
#define _POSIX_C_SOURCE 199309L /* nanosleep */
#include <hdds.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

int main(void) {
    struct HddsParticipant *p =
        hdds_participant_create_with_transport("c-install-test", HDDS_TRANSPORT_INTRA_PROCESS);
    if (!p) { fprintf(stderr, "participant\n"); return 1; }
    struct HddsQoS *qos = hdds_qos_reliable();
    struct HddsDataWriter *w = hdds_writer_create_with_qos(p, "c_install_roundtrip", qos);
    struct HddsDataReader *r = hdds_reader_create_with_qos(p, "c_install_roundtrip", qos);
    hdds_qos_destroy(qos);
    if (!w || !r) { fprintf(stderr, "writer/reader\n"); return 1; }

    const char msg[] = "installed";
    if (hdds_writer_write(w, msg, sizeof msg) != HDDS_OK) { fprintf(stderr, "write\n"); return 1; }

    char buf[64];
    size_t len = 0;
    enum HddsError err = HDDS_NOT_FOUND;
    for (int i = 0; i < 200 && err != HDDS_OK; i++) {
        err = hdds_reader_take(r, buf, sizeof buf, &len);
        if (err == HDDS_NOT_FOUND) {
            struct timespec ts = {0, 5 * 1000 * 1000};
            nanosleep(&ts, NULL);
        }
    }
    if (err != HDDS_OK || len != sizeof msg || memcmp(buf, msg, len) != 0) {
        fprintf(stderr, "take: err=%d len=%zu\n", (int)err, len);
        return 1;
    }
    printf("roundtrip ok, hdds %s\n", hdds_version());
    hdds_reader_destroy(r);
    hdds_writer_destroy(w);
    hdds_participant_destroy(p);
    return 0;
}
EOF
CFLAGS_COMMON=(-std=c11 -Wall -Wextra -Werror)

# 1. Shared library through pkg-config.
# shellcheck disable=SC2046
cc "${CFLAGS_COMMON[@]}" -o "$WORK/rt_shared" "$WORK/roundtrip.c" $(pkg-config --cflags --libs hdds_c)
LD_LIBRARY_PATH="$PREFIX/lib" ldd "$WORK/rt_shared" | grep -q "libhdds_c.so => $PREFIX/lib/libhdds_c.so" ||
    fail "shared build does not resolve libhdds_c.so from the prefix"
LD_LIBRARY_PATH="$PREFIX/lib" "$WORK/rt_shared" >"$WORK/shared.out" 2>&1 ||
    { cat "$WORK/shared.out" >&2; fail "shared build did not run"; }
grep -q "roundtrip ok, hdds $version" "$WORK/shared.out" || fail "shared run: $(cat "$WORK/shared.out")"
pass "pkg-config shared link: built, ran, sample round-tripped"

# 2. Static archive, system libraries from Libs.private.
private_libs=$(pkg-config --static --libs-only-l hdds_c | sed 's/-lhdds_c//')
# shellcheck disable=SC2046,SC2086
cc "${CFLAGS_COMMON[@]}" -o "$WORK/rt_static" "$WORK/roundtrip.c" $(pkg-config --cflags hdds_c) \
    "$PREFIX/lib/libhdds_c.a" $private_libs
if ldd "$WORK/rt_static" | grep -q libhdds_c; then
    fail "static build still depends on libhdds_c.so"
fi
env -u LD_LIBRARY_PATH "$WORK/rt_static" >"$WORK/static.out" 2>&1 ||
    { cat "$WORK/static.out" >&2; fail "static build did not run"; }
grep -q "roundtrip ok, hdds $version" "$WORK/static.out" || fail "static run: $(cat "$WORK/static.out")"
pass "static archive + Libs.private: built, ran without LD_LIBRARY_PATH"

# 3. CMake, C component only (no C++ SDK in the prefix).
mkdir -p "$WORK/cmake-src"
cp "$WORK/roundtrip.c" "$WORK/cmake-src/"
cat >"$WORK/cmake-src/CMakeLists.txt" <<EOF
cmake_minimum_required(VERSION 3.16)
project(hdds_c_install_test LANGUAGES C)
find_package(hdds $version REQUIRED COMPONENTS c)
if(TARGET hdds::hdds_cxx)
    message(FATAL_ERROR "COMPONENTS c must not create hdds::hdds_cxx")
endif()
add_executable(rt_cmake roundtrip.c)
set_target_properties(rt_cmake PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON)
target_link_libraries(rt_cmake PRIVATE hdds::hdds_c)
EOF
cmake -S "$WORK/cmake-src" -B "$WORK/cmake-build" -DCMAKE_PREFIX_PATH="$PREFIX" \
    >"$WORK/cmake.log" 2>&1 || { cat "$WORK/cmake.log" >&2; fail "cmake configure (COMPONENTS c)"; }
cmake --build "$WORK/cmake-build" >>"$WORK/cmake.log" 2>&1 ||
    { cat "$WORK/cmake.log" >&2; fail "cmake build"; }
env -u LD_LIBRARY_PATH "$WORK/cmake-build/rt_cmake" >"$WORK/cmake.out" 2>&1 ||
    { cat "$WORK/cmake.out" >&2; fail "cmake build did not run"; }
grep -q "roundtrip ok, hdds $version" "$WORK/cmake.out" || fail "cmake run: $(cat "$WORK/cmake.out")"
pass "CMake find_package(hdds $version REQUIRED COMPONENTS c): built, ran"

# The default (no COMPONENTS) still asks for the C++ SDK, which is absent here.
sed -i "s/find_package(hdds $version REQUIRED COMPONENTS c)/find_package(hdds $version REQUIRED)/" \
    "$WORK/cmake-src/CMakeLists.txt"
if cmake -S "$WORK/cmake-src" -B "$WORK/cmake-build2" -DCMAKE_PREFIX_PATH="$PREFIX" \
    >"$WORK/cmake2.log" 2>&1; then
    fail "find_package(hdds REQUIRED) succeeded without the C++ SDK"
fi
grep -q "Cannot find hdds.hpp" "$WORK/cmake2.log" || { cat "$WORK/cmake2.log" >&2; fail "unexpected cmake error"; }
pass "find_package(hdds REQUIRED) without COMPONENTS still requires the C++ SDK"

echo "test-c-install: PASS"
