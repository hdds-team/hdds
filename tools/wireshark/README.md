# HDDS Wireshark Dissector

A Lua dissector for enhanced RTPS/DDS packet analysis in Wireshark.

## Features

- **Enhanced RTPS decoding**: All standard submessages (DATA, HEARTBEAT, ACKNACK, GAP, INFO_TS, etc.)
- **HDDS vendor detection**: Highlights HDDS-originated packets
- **CDR2 payload decoding**: Parses serialized data with type information
- **Discovery analysis**: Decodes SPDP/SEDP discovery traffic
- **Inline QoS parsing**: Extracts topic names, type names from DATA submessages

## Installation

### Linux

```bash
mkdir -p ~/.local/lib/wireshark/plugins/
cp hdds_rtps.lua ~/.local/lib/wireshark/plugins/
```

### macOS

```bash
mkdir -p ~/Library/Application\ Support/Wireshark/plugins/
cp hdds_rtps.lua ~/Library/Application\ Support/Wireshark/plugins/
```

### Windows

```cmd
mkdir %APPDATA%\Wireshark\plugins
copy hdds_rtps.lua %APPDATA%\Wireshark\plugins\
```

### Verify Installation

1. Open Wireshark
2. Go to Help → About Wireshark → Plugins
3. Look for "hdds" in the list
4. Check the Lua console (Tools → Lua → Console) for: `[HDDS] RTPS Dissector loaded`

## Configuration

Go to Edit → Preferences → Protocols → HDDS:

| Preference | Description |
|------------|-------------|
| **Types JSON** | Path to types JSON file (for CDR decoding) |
| **Decode CDR** | Enable/disable CDR payload decoding |
| **Show Raw Hex** | Display raw hex alongside decoded data |
| **Verbose** | Show additional debug info in columns |

## Usage

### Capture Filter

To capture only RTPS traffic:

```
udp port 7400-7500
```

### Display Filter

Filter HDDS packets:
```
hdds.vendor == "HDDS"
```

Filter by topic:
```
hdds.topic contains "temperature"
```

Filter DATA submessages:
```
hdds.submsg.kind == "DATA"
```

Filter by sequence number:
```
hdds.seq_num > 100
```

## Type Decoding

To enable full CDR payload decoding, generate a types JSON file:

```bash
# Using hdds_gen (future feature)
hdds_gen --wireshark your_types.idl -o types.ws.json
```

Then set the path in Wireshark preferences:
```
Edit → Preferences → Protocols → HDDS → Types JSON
```

### Types JSON Format

```json
{
  "types": {
    "Temperature": {
      "kind": "struct",
      "fields": [
        { "name": "sensor_id", "type": "string" },
        { "name": "value", "type": "float64" },
        { "name": "unit", "type": "string" }
      ]
    }
  },
  "topics": {
    "sensors/temperature": {
      "type": "Temperature"
    }
  }
}
```

## Protocol Details

### Submessage Types Decoded

| Kind | Name | Fields Decoded |
|------|------|----------------|
| 0x15 | DATA | Reader/Writer IDs, Sequence, Inline QoS, Payload |
| 0x07 | HEARTBEAT | Reader/Writer IDs, First/Last Seq, Count |
| 0x06 | ACKNACK | Reader/Writer IDs, Sequence Set |
| 0x08 | GAP | Gap Start Sequence |
| 0x09 | INFO_TS | Timestamp (seconds.fraction) |

### Vendor IDs Recognized

| ID | Vendor |
|----|--------|
| 0x0101 | RTI Connext |
| 0x0102 | OpenSplice (ADLink) |
| 0x0103 | OpenDDS (OCI) |
| 0x010F | FastDDS (eProsima) |
| 0x0110 | Cyclone DDS |
| 0x0112 | RustDDS |
| 0x01AA | **HDDS** |

### Entity IDs Recognized

| ID | Name |
|----|------|
| 0x000001C1 | PARTICIPANT |
| 0x000100C2 | SPDP_WRITER |
| 0x000100C7 | SPDP_READER |
| 0x000003C2 | SEDP_PUB_WRITER |
| 0x000003C7 | SEDP_PUB_READER |
| 0x000004C2 | SEDP_SUB_WRITER |
| 0x000004C7 | SEDP_SUB_READER |

## Troubleshooting

### Dissector not loading

Check Lua console for errors:
```
Tools → Lua → Console
```

### No HDDS tree in packets

- Verify packets are on ports 7400-7500
- Check that packets have valid RTPS magic ("RTPS")
- Enable the dissector in Analyze → Enabled Protocols

### CDR decoding not working

- Verify types JSON file path is correct
- Check Lua console for parsing errors
- Ensure JSON format matches expected schema

## Development

### Testing Changes

Reload the dissector without restarting Wireshark:
```
Tools → Lua → Evaluate (Ctrl+Shift+L)
```

### Debug Output

Enable verbose logging in preferences, or add to the Lua file:
```lua
print("[HDDS] Debug: " .. message)
```

## License

SPDX-License-Identifier: Apache-2.0 OR MIT

Copyright (c) 2025-2026 naskel.com
