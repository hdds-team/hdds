#!/bin/bash
# HDDS Wireshark Dissector Installer
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGIN_FILE="$SCRIPT_DIR/hdds_rtps.lua"

# Detect OS and set plugin directory
case "$(uname -s)" in
    Linux*)
        PLUGIN_DIR="$HOME/.local/lib/wireshark/plugins"
        ;;
    Darwin*)
        PLUGIN_DIR="$HOME/Library/Application Support/Wireshark/plugins"
        ;;
    MINGW*|MSYS*|CYGWIN*)
        PLUGIN_DIR="$APPDATA/Wireshark/plugins"
        ;;
    *)
        echo "Unknown OS: $(uname -s)"
        echo "Please copy hdds_rtps.lua manually to your Wireshark plugins directory"
        exit 1
        ;;
esac

echo "HDDS Wireshark Dissector Installer"
echo "==================================="
echo ""
echo "Plugin file: $PLUGIN_FILE"
echo "Target dir:  $PLUGIN_DIR"
echo ""

# Create directory if needed
if [ ! -d "$PLUGIN_DIR" ]; then
    echo "Creating plugin directory..."
    mkdir -p "$PLUGIN_DIR"
fi

# Copy plugin
echo "Installing plugin..."
cp "$PLUGIN_FILE" "$PLUGIN_DIR/"

echo ""
echo "Installation complete!"
echo ""
echo "Next steps:"
echo "  1. Restart Wireshark"
echo "  2. Go to Help -> About Wireshark -> Plugins"
echo "  3. Verify 'hdds' appears in the list"
echo ""
echo "To configure:"
echo "  Edit -> Preferences -> Protocols -> HDDS"
echo ""
