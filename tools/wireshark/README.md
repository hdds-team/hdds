# HDDS Wireshark Dissector

A Lua dissector for enhanced RTPS/DDS packet analysis in Wireshark.

## Features

- **Enhanced RTPS decoding**: All standard submessages (DATA, HEARTBEAT, ACKNACK, GAP, INFO_TS, etc.)
- **HDDS vendor detection**: Highlights HDDS-originated packets
- **Payload encapsulation**: Shows the length and the encapsulation identifier of a DATA payload (the members are not decoded)
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
2. Go to Help -> About Wireshark -> Plugins
3. Look for "hdds" in the list
4. Check the Lua console (Tools -> Lua -> Console) for: `[HDDS] RTPS Dissector loaded`

## Configuration

Go to Edit -> Preferences -> Protocols -> HDDS:

| Preference | Description |
|------------|-------------|
| **Types JSON** | Path to a types JSON file (loaded, but not used: see Type Decoding) |
| **Decode CDR** | Show the encapsulation identifier of each DATA payload |
| **Show Raw Hex** | Show the payload bytes after the encapsulation header as hex |
| **Verbose** | Show additional debug info in columns |

## Usage

### Capture Filter

To capture only the RTPS traffic of domain 0 (a domain uses ports `7400 + 250 x domainId` to
`7649 + 250 x domainId`):

```
udp portrange 7400-7649
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

Decoding a DATA payload into its IDL members is **not implemented**. The
dissector reads the RTPS header and the submessages (kind, flags, length,
entity names, sequence numbers, timestamps) and reports the payload's
encapsulation and length; it does not interpret the payload itself.

The `Types JSON` preference and its loader are present but unused: nothing in
the script reads the parsed registry, so setting the preference changes
nothing. There is no `hddsgen` flag that produces such a file.

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
| 0x011A | **HDDS** |

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
Tools -> Lua -> Console
```

### No HDDS tree in packets

- Verify the packets are UDP datagrams that carry RTPS (the dissector matches the `RTPS` magic at the start of the UDP payload, not a port)
- Check that packets have valid RTPS magic ("RTPS")
- Enable the dissector in Analyze -> Enabled Protocols

### No decoded payload members

Expected: the dissector never decodes the members of a payload (see Type
Decoding). If the payload node is missing, check that **Decode CDR** is on and
that the DATA submessage carries more than 4 bytes of payload.

## Development

### Testing Changes

Reload the dissector without restarting Wireshark:
```
Tools -> Lua -> Evaluate (Ctrl+Shift+L)
```

### Debug Output

Enable verbose logging in preferences, or add to the Lua file:
```lua
print("[HDDS] Debug: " .. message)
```

## License

SPDX-License-Identifier: Apache-2.0 OR MIT

Copyright (c) 2025-2026 naskel.com
