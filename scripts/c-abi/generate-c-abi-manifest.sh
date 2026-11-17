#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
HEADER=${1:-"$ROOT/sdk/c/include/hdds.h"}
LIBRARY=${2:-}
ROS2_STUBS="$ROOT/scripts/c-abi/ros2-stubs"

die() {
    printf 'c-abi-manifest: %s\n' "$*" >&2
    exit 1
}

for tool in clang jq nm awk sort; do
    command -v "$tool" >/dev/null 2>&1 || die "required tool not found: $tool"
done

[[ -f "$HEADER" ]] || die "header not found: $HEADER"
[[ -n "$LIBRARY" ]] || die "shared library path is required"
[[ -f "$LIBRARY" ]] || die "shared library not found: $LIBRARY"

emit_ast_surface() {
    local mode=$1
    shift

    clang "$@" -x c -std=c11 -Xclang -ast-dump=json -fsyntax-only "$HEADER" |
        jq -r --arg mode "$mode" '
            .. | objects |
            select(.kind? == "FunctionDecl" and (.name? | startswith("hdds_"))) |
            ["function", $mode, .name, .type.qualType] | @tsv
        '

    clang "$@" -x c -std=c11 -Xclang -ast-dump=json -fsyntax-only "$HEADER" |
        jq -r --arg mode "$mode" '
            .. | objects |
            select(.kind? == "TypedefDecl" and (.name? | startswith("Hdds"))) |
            ["typedef", $mode, .name, .type.qualType] | @tsv
        '

    clang "$@" -x c -std=c11 -Xclang -ast-dump=json -fsyntax-only "$HEADER" |
        jq -r --arg mode "$mode" '
            .. | objects |
            select(.kind? == "EnumDecl" and (.name? | startswith("Hdds"))) |
            .name as $enum |
            .inner[]? |
            select(.kind == "EnumConstantDecl") |
            ([.. | objects | select(.kind? == "ConstantExpr") | .value] | first) as $value |
            if $value == null then
                error("public enum constant lacks an explicit value: " + $enum + "::" + .name)
            else
                ["enum", $mode, $enum, .name, $value] | @tsv
            end
        '
}

emit_record_layouts() {
    local mode=$1
    shift

    clang "$@" -x c -std=c11 -Xclang -fdump-record-layouts-complete -fsyntax-only "$HEADER" 2>&1 |
        awk -v mode="$mode" '
            /^[[:space:]]*[0-9]+ \| struct Hdds[A-Za-z0-9_]+$/ {
                record = $0
                sub(/^.*struct /, "", record)
                active = 1
                print "record\t" mode "\t" record
                next
            }
            active && /^[[:space:]]*[0-9]+ \|/ {
                line = $0
                sub(/^[[:space:]]*/, "", line)
                print "record-field\t" mode "\t" record "\t" line
                next
            }
            active && /\| \[sizeof=/ {
                line = $0
                sub(/^.*\| /, "", line)
                print "record-layout\t" mode "\t" record "\t" line
                active = 0
                next
            }
            /^\*\*\*/ { active = 0 }
        '
}

{
    printf 'target\tall\t%s\n' "$(clang -dumpmachine)"

    emit_ast_surface standalone
    emit_record_layouts standalone

    emit_ast_surface ros2 -DHDDS_WITH_ROS2 -I"$ROS2_STUBS"
    emit_record_layouts ros2 -DHDDS_WITH_ROS2 -I"$ROS2_STUBS"

    # Keep the original baseline modes and also inspect the optional RPC API,
    # both standalone and together with ROS 2. The gate builds all features.
    emit_ast_surface rpc -DHDDS_WITH_RPC
    emit_record_layouts rpc -DHDDS_WITH_RPC
    emit_ast_surface ros2-rpc -DHDDS_WITH_RPC -DHDDS_WITH_ROS2 -I"$ROS2_STUBS"
    emit_record_layouts ros2-rpc -DHDDS_WITH_RPC -DHDDS_WITH_ROS2 -I"$ROS2_STUBS"

    clang -x c -std=c11 -dM -E "$HEADER" |
        awk '$2 ~ /^HDDS_/ && $2 != "HDDS_H" {
            sub(/^#define[[:space:]]+/, "")
            print "macro\tstandalone\t" $0
        }'

    nm -D --defined-only --format=posix "$LIBRARY" |
        awk '$1 ~ /^hdds_/ { print "symbol\tall\t" $1 }'
} | LC_ALL=C sort -u
