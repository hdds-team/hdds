#!/bin/bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

# Generate SDK header from cbindgen output.
# RMW-specific functions are already guarded by cbindgen via
# [defines] "feature = rmw" = "HDDS_WITH_ROS2" in cbindgen.toml.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INPUT="$REPO_ROOT/crates/hdds-c/hdds.h"
OUTPUT="$REPO_ROOT/sdk/c/include/hdds.h"

{
    echo "// SPDX-License-Identifier: Apache-2.0 OR MIT"
    echo "// Copyright (c) 2025-2026 naskel.com"
    echo ""
    cat "$INPUT"
} > "$OUTPUT"

echo "Generated $OUTPUT"
