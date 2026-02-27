#!/bin/bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

# Generate SDK header from cbindgen output, wrapping RMW functions

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INPUT="$REPO_ROOT/crates/hdds-c/hdds.h"
OUTPUT="$REPO_ROOT/sdk/c/include/hdds.h"

# Copy and wrap RMW-specific functions
awk '
BEGIN { in_rmw = 0 }

# Detect start of RMW function (contains rosidl_message_type_support_t)
/rosidl_message_type_support_t/ && !in_rmw {
    print "#ifdef HDDS_WITH_ROS2"
    in_rmw = 1
}

# Print line
{ print }

# Detect end of function (semicolon at end of line after RMW param)
in_rmw && /;$/ {
    print "#endif /* HDDS_WITH_ROS2 */"
    in_rmw = 0
}
' "$INPUT" > "$OUTPUT"

echo "Generated $OUTPUT"
