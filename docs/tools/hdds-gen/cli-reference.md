# hdds_gen CLI Reference

## Global Options

```bash
idl-gen [OPTIONS] <COMMAND>

Options:
  -h, --help     Print help
  -V, --version  Print version (0.2.0)
```

## Commands

### gen - Generate Code

Generate type support code in a target language.

```bash
idl-gen gen [OPTIONS] <LANG> <INPUT>

Arguments:
  <LANG>   Target language: rust, cpp, c, python, typescript, micro, c-micro
  <INPUT>  Input IDL file path (or '-' for stdin)

Options:
  -I, --include <DIR>           Include directory for #include resolution (repeatable)
  -o, --out <FILE>              Output file (stdout if omitted)
  --out-dir <DIR>               Output directory (writes mod.rs for Rust)
  --namespace-cpp <NS>          Wrap C++ in namespace (e.g., "MyApp::Types")
  --c-standard <STD>            C standard: c89, c99 (default), c11
  --example                     Generate full example project
  --build-system <SYS>          Build system: cargo, cmake, make
  --hdds-path <PATH>            Path to hdds crate (default: crates.io)
```

**Examples:**

```bash
# Basic generation
idl-gen gen rust types.idl -o types.rs
idl-gen gen cpp types.idl -o types.hpp

# With includes
idl-gen gen rust -I ./common -I /opt/idl types.idl -o types.rs

# C++ with namespace
idl-gen gen cpp types.idl --namespace-cpp "DDS::Types" -o types.hpp

# Full project with Cargo.toml
idl-gen gen rust types.idl --example --out-dir ./my_project

# Python module
idl-gen gen python types.idl --out-dir ./generated

# TypeScript types + interfaces
idl-gen gen typescript types.idl -o types.ts

# Embedded Rust (no_std)
idl-gen gen micro types.idl --example --out-dir ./embedded

# C with specific standard
idl-gen gen c types.idl -o types.h                      # C99 (default)
idl-gen gen c types.idl --c-standard c89 -o types.h     # ANSI C89
idl-gen gen c types.idl --c-standard c11 -o types.h     # C11
```

### parse - Validate and Inspect

Parse IDL files and optionally display the AST.

```bash
idl-gen parse [OPTIONS] <INPUT>

Arguments:
  <INPUT>  Input IDL file path (or '-' for stdin)

Options:
  -I, --include <DIR>  Include directories
  --pretty             Pretty-print the parsed AST
  --json               Output JSON diagnostics
```

**Examples:**

```bash
# Validate only
idl-gen parse types.idl

# Pretty-print AST
idl-gen parse types.idl --pretty

# JSON output for CI
idl-gen parse types.idl --json
```

### check - Structural Validation

Validate IDL with comprehensive structural checks. Returns non-zero exit code on error.

```bash
idl-gen check [OPTIONS] <INPUT>

Arguments:
  <INPUT>  Input IDL file path (or '-' for stdin)

Options:
  -I, --include <DIR>  Include directories
  --json               Output JSON diagnostics
```

**Validation Checks:**

- Bitset `@bit_bound` constraints
- Non-overlapping bit fields
- Annotation placement rules
- `@autoid` and `@id` uniqueness
- Enum variant duplicates
- Type resolution and FQN validation

**Examples:**

```bash
# CI validation
idl-gen check types.idl --json || exit 1

# Validate with includes
idl-gen check -I ./common types.idl
```

### fmt - Format IDL

Reformat IDL to canonical style.

```bash
idl-gen fmt [OPTIONS] <INPUT>

Arguments:
  <INPUT>  Input IDL file path (or '-' for stdin)

Options:
  -I, --include <DIR>  Include directories
  -o, --out <FILE>     Output file (stdout if omitted)
```

**Examples:**

```bash
# Format to stdout
idl-gen fmt types.idl

# Format in place
idl-gen fmt types.idl -o types.idl

# Check formatting (CI)
idl-gen fmt types.idl | diff - types.idl
```

## Build System Options

When using `--example`, the generated project includes build configuration:

| Language | Default Build System | Alternatives |
|----------|---------------------|--------------|
| rust | cargo | - |
| cpp | cmake | make |
| c | make | cmake |
| python | - | - |
| micro | cargo | - |
| c-micro | make | - |

```bash
# Rust with Cargo (default)
idl-gen gen rust types.idl --example --out-dir ./project

# C++ with CMake (default)
idl-gen gen cpp types.idl --example --out-dir ./project

# C++ with Makefile
idl-gen gen cpp types.idl --example --build-system make --out-dir ./project
```

## C Standard Options

When generating C code, `--c-standard` controls language compatibility:

| Standard | Description | Use Case |
|----------|-------------|----------|
| `c89` | ANSI C (K&R compatible) | Legacy compilers, embedded systems |
| `c99` | C99 (default) | Modern C with inline, `//` comments |
| `c11` | C11 | `_Static_assert`, atomics support |

**Code differences by standard:**

- **C89**: Variables declared at block start, `for(i=0;...)` without inline declaration
- **C99**: Inline variable declarations, `_Bool` type, `//` comments
- **C11**: Native `_Static_assert`, `_Alignas`, atomics

**Generated defines (all standards):**

```c
#define CDR_ALIGN_1 1
#define CDR_ALIGN_2 2
#define CDR_ALIGN_4 4
#define CDR_ALIGN_8 8
#define CDR_SIZE_BOOL 1
#define CDR_SIZE_CHAR 1
#define CDR_SIZE_INT16 2
#define CDR_SIZE_INT32 4
#define CDR_SIZE_INT64 8
#define CDR_SIZE_WCHAR 4
#define CDR_SIZE_FIXED128 16
#define CDR_UNICODE_MAX 0x10FFFFu
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Parse error |
| 2 | Validation error |
| 3 | I/O error |
| 4 | Internal error |

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `IDL_GEN_INCLUDE_PATH` | Default include paths (colon-separated) |

## Piping and Stdin

All commands accept `-` for stdin:

```bash
# Pipe from another command
cat types.idl | idl-gen gen rust - -o types.rs

# Here-doc
idl-gen gen rust - -o types.rs << 'EOF'
struct Point {
    float x;
    float y;
};
EOF
```
