# HDDS Tools

HDDS provides a suite of tools to help you develop, debug, and visualize DDS applications.

## Core SDK Tool

### hdds_gen

**Code Generator** - Generate type support code from IDL files.

```bash
hdds-gen -l rust my_types.idl
```

[Learn more about hdds_gen](../tools/hdds-gen/overview.md)

## Companion Applications

### hdds_viewer

**Network Analyzer** - Capture, decode, and visualize RTPS traffic with ML-powered anomaly detection.

- Live traffic capture and PCAP analysis
- Topology visualization
- 15 AI-powered anomaly detection rules
- 8 themes, 5 languages

[hdds_viewer Documentation](https://viewer.hdds.io/docs)

### hdds_studio

**Visual IDL Editor** - Design data types with a drag-and-drop interface.

- Visual type designer with 9 node types
- IDL import/export with 100% round-trip fidelity
- 60+ real-time validation rules
- Auto-layout with ELK algorithm

[hdds_studio Documentation](https://studio.hdds.io/docs)

## Quick Installation

```bash
# Core SDK tool
cargo install hdds-gen

# Companion applications
cargo install hdds-viewer hdds-studio

# Verify installation
hdds-gen --version
```

## Tool Comparison

| Tool | Purpose | GUI | CLI | Included in SDK |
|------|---------|-----|-----|-----------------|
| hdds_gen | Code generation | No | Yes | Yes |
| hdds_viewer | Network analysis | Yes | Yes | Separate |
| hdds_studio | IDL design | Yes | No | Separate |
