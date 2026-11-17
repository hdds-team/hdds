# HDDS Tools

HDDS provides a suite of tools to help you develop, debug, and visualize DDS applications.

## Core SDK Tool

### hdds_gen

**Code Generator** - Generate type support code from IDL files. The command is
`hddsgen`.

```bash
hddsgen gen rust my_types.idl -o my_types.rs
```

[Learn more about hdds_gen](../tools/hdds-gen/overview.md)

## Companion Applications

### hdds_viewer

**Network Analyzer** - Analyze RTPS/DDS traffic.

- Replay of recorded capture files with CDR2 payload decoding
- Topology visualization
- Timeline and latency views

[hdds_viewer Documentation](https://viewer.hdds.io/docs)

### hdds_studio

**Visual IDL Editor** - Design data types in a graphical editor and export IDL.

[hdds_studio](https://studio.hdds.io)

## Installation

```bash
# IDL code generator (separate repository, installs the `hddsgen` command)
git clone https://git.hdds.io/hdds/hdds_gen.git && cargo install --path hdds_gen

# Verify installation
hddsgen --version
```

hdds_viewer and hdds_studio are not part of this repository and are not
published on crates.io; see their own sites for how to obtain them.

## Tool Overview

| Tool | Purpose | Where it lives |
|------|---------|----------------|
| hdds_gen | IDL code generation (command line) | Separate repository (`hdds_gen`) |
| hdds_viewer | Network analysis | Separate product |
| hdds_studio | IDL design (graphical) | Separate product |
