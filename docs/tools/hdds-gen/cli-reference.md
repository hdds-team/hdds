# hdds_gen CLI Reference

## Global Options

```bash
hddsgen [OPTIONS] <COMMAND>

Commands:
  parse  Validate IDL and optionally pretty-print
  gen    Generate code in a target language
  check  Validate only (non-zero on error)
  fmt    Reformat IDL via pretty-printer
  help   Print help of the given subcommand

Options:
  -h, --help     Print help
  -V, --version  Print version (prints `hddsgen 2.0.0` for this release line)
```

## Commands

### gen - Generate Code

Generate type support code in a target language.

```bash
hddsgen gen [OPTIONS] <LANG> <INPUT>

Arguments:
  <LANG>   Target language: cpp, rust, python, c, micro, c-micro, typescript
           (`ts` is accepted as an alias of `typescript`)
  <INPUT>  Input IDL file path (or '-' for stdin)

Options:
  -I, --include <DIR>           Include directory for #include resolution (repeatable)
  -o, --out <FILE>              Output file (stdout if omitted)
      --out-dir <DIR>           Output directory. The file written is mod.rs for
                                rust and micro, otherwise the input's name with the
                                language's extension (Shapes.hpp, Shapes.py,
                                Shapes.h, Shapes.ts). Mutually exclusive with -o
      --namespace-cpp <NS>      Wrap C++ output in a namespace (e.g. "MyApp::Types")
      --example                 Generate an example project (see below)
      --build-system <SYS>      Build system to generate: cargo, cmake, make
      --hdds-path <PATH>        Path to the hdds crate (rust --example) or to the
                                hdds-micro crate (micro --example). Without it the
                                generated Cargo.toml depends on the crates.io
                                release this hddsgen targets
      --c-standard <STD>        C standard: c89, c99 (default), c11
      --fastdds-compat          C++ only: getter/setter methods, so the types work
                                with Fast DDS and HDDS backends
      --serde                   Rust: add serde Serialize/Deserialize derives
      --serde-rename <STYLE>    With --serde: camel, pascal or kebab
      --separate                One output file per included IDL (needs --out-dir)
      --default-extensibility <KIND>
                                Extensibility of a struct, union, enum or bitmask
                                with no extensibility annotation: appendable
                                (default, DDS-XTypes 1.3), final (the hddsgen 1.x
                                layout) or mutable. An enum or bitmask is never
                                mutable
```

Run `hddsgen gen --help` for the exact list and the value set of each option.

When types have no extensibility annotation and `--default-extensibility` is not
given, `gen` prints an `info:` line on stderr naming up to five of them and the
extensibility they were generated with (APPENDABLE).

`gen` stops with exit code 1 and writes nothing when the IDL has validation
errors; validation warnings are printed and generation continues.

**Examples:**

```bash
# Basic generation
hddsgen gen rust types.idl -o types.rs
hddsgen gen cpp types.idl -o types.hpp

# With includes
hddsgen gen rust -I ./common -I /opt/idl types.idl -o types.rs

# C++ with namespace
hddsgen gen cpp types.idl --namespace-cpp "DDS::Types" -o types.hpp

# Example project with Cargo.toml, pointing at your hdds clone
hddsgen gen rust types.idl --example --hdds-path "$PWD/hdds/crates/hdds" --out-dir ./my_project

# Python module (writes Types.py for Types.idl)
hddsgen gen python Types.idl --out-dir ./generated

# Python example: publisher.py, subscriber.py, requirements.txt and the type module
hddsgen gen python types.idl --example --out-dir ./project

# Keep the FINAL layout of hddsgen 1.x for types without an annotation
hddsgen gen cpp types.idl --default-extensibility final -o types.hpp

# TypeScript types and CDR2 functions
hddsgen gen typescript types.idl -o types.ts

# Embedded Rust (no_std)
hddsgen gen micro types.idl --example --out-dir ./embedded

# C with specific standard
hddsgen gen c types.idl -o types.h                      # C99 (default)
hddsgen gen c types.idl --c-standard c89 -o types.h     # ANSI C89
hddsgen gen c types.idl --c-standard c11 -o types.h     # C11

# One header per included IDL file
hddsgen gen cpp -I ./common types.idl --separate --out-dir ./generated
```

### parse - Parse IDL

Parse an IDL file. `parse` checks syntax only (the semantic checks of `check`
do not run) and optionally prints the file back as IDL.

```bash
hddsgen parse [OPTIONS] <INPUT>

Arguments:
  <INPUT>  Input IDL file path (or '-' for stdin)

Options:
  -I, --include <DIR>  Include directories
      --pretty         Print the parsed file as formatted IDL
      --json           Emit a JSON diagnostic ({"ok":true,...} or {"ok":false,"message":...})
```

**Examples:**

```bash
# Syntax check only (prints OK on stderr)
hddsgen parse types.idl

# Print the parsed IDL
hddsgen parse types.idl --pretty

# JSON output for CI
hddsgen parse types.idl --json
```

### check - Semantic Validation

Parse the file, then run the semantic checks. `check` exits non-zero when it
finds any diagnostic, warnings included; `gen` only stops on errors.

```bash
hddsgen check [OPTIONS] <INPUT>

Arguments:
  <INPUT>  Input IDL file path (or '-' for stdin)

Options:
  -I, --include <DIR>  Include directories
      --json           Emit a JSON diagnostic
```

**Examples of what it reports:**

- Unresolved type references and typedef cycles
- Names declared twice in the same scope, including duplicate enumerators
- Duplicate `@id` values within a struct, and conflicting `@final` / `@appendable` / `@mutable`
- `@min` greater than `@max`, `@range` with `min > max`
- `@bit_bound` too small for a bitmask or bitset
- Duplicate union case labels
- Annotations on the wrong kind of declaration (for example `@non_serialized` on a type)
- A `map` with a floating-point key
- A custom annotation used without a declaration, or with missing or unknown parameters

**Examples:**

```bash
# CI validation
hddsgen check types.idl --json || exit 1

# Validate with includes
hddsgen check -I ./common types.idl
```

### fmt - Format IDL

Reformat IDL to canonical style.

```bash
hddsgen fmt [OPTIONS] <INPUT>

Arguments:
  <INPUT>  Input IDL file path (or '-' for stdin)

Options:
  -I, --include <DIR>  Include directories
  -o, --out <FILE>     Output file (stdout if omitted)
```

**Examples:**

```bash
# Format to stdout
hddsgen fmt types.idl

# Format in place
hddsgen fmt types.idl -o types.idl

# Check formatting (CI)
hddsgen fmt types.idl | diff - types.idl
```

## The --example Option

With `--example`, `gen` writes a small project next to the generated types. What
is written depends on the language:

| Language | Files written by `--example` | Build system |
|----------|------------------------------|--------------|
| rust | `Cargo.toml`, the types, `src/bin/publisher.rs`, `src/bin/subscriber.rs` | cargo |
| cpp | `CMakeLists.txt` (or `Makefile`), the header, a publisher and a subscriber | cmake (default) or make |
| c | `Makefile` (or `CMakeLists.txt`), the header, `publisher.c`, `subscriber.c` | make (default) or cmake |
| python | the type module, `publisher.py`, `subscriber.py`, `requirements.txt` | none |
| typescript | `types.ts` only | none |
| micro | `Cargo.toml`, `.cargo/config.toml`, `src/lib.rs`, a sender and a receiver | cargo |
| c-micro | `Makefile`, `include/` headers, a sender and a receiver | make |

`--build-system` selects between cmake and make for cpp and c. It has no effect
on the other languages.

```bash
# C++ with CMake (default)
hddsgen gen cpp types.idl --example --out-dir ./project

# C++ with Makefile
hddsgen gen cpp types.idl --example --build-system make --out-dir ./project
```

The generated Rust `Cargo.toml` depends on `hdds = "1.5.0"` from crates.io unless
you pass `--hdds-path`. The generated C++ `CMakeLists.txt` calls
`find_package(hdds REQUIRED)`: pass `-DCMAKE_PREFIX_PATH=/path/to/hdds/sdk/cmake`
when configuring. The generated Python `requirements.txt` explains that the
HDDS Python SDK is not on PyPI and must be built from `sdk/python`.

## C Standard Options

When generating C code, `--c-standard` controls language compatibility:

| Standard | Description |
|----------|-------------|
| `c89` | ANSI C: the output compiles with `-std=c89 -pedantic-errors` and still includes `<stdint.h>` |
| `c99` | C99 (default) |
| `c11` | C11, adds `_Static_assert` |

The `c-micro` output is always C99.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Input unreadable, parse error, validation error, or output file not writable |
| 2 | Invalid command line: no subcommand, `-o` together with `--out-dir`, or `-o` naming a directory |

The command-line parser itself also exits with 2 on an unknown option or a
missing argument.

## Piping and Stdin

All commands accept `-` for stdin:

```bash
# Pipe from another command
cat types.idl | hddsgen gen rust - -o types.rs

# Here-doc
hddsgen gen rust - -o types.rs << 'EOF'
struct Point {
    float x;
    float y;
};
EOF
```
