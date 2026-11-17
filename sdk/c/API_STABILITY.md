# HDDS C SDK API and ABI stability

This policy applies to the public C SDK starting with HDDS 1.4.0. The installed
surface is the generated `sdk/c/include/hdds.h` header together with the
exported `libhdds_c` symbols.

## Compatibility within one major release

HDDS minor and patch releases keep existing C consumers source-compatible and
binary-compatible:

- exported `hdds_*` symbols are not removed and their signatures do not change;
- public struct layouts, enum values, and callback signatures do not change;
- existing `Hdds*` type names and `HDDS_*` constants are not renamed;
- new functions, opaque handle types, and enum values may be added;
- behavior changes that alter an existing contract are documented in the
  release notes.

A required incompatible change uses a new major version and includes a
migration entry. Deprecation keeps the old symbol available for at least one
minor release when retaining it is technically possible.

The generated header is the source of truth. Documentation examples and local
copies do not override it. Consumers should build against the header shipped by
the same HDDS release as `libhdds_c`.

For the additive dynamic-data and field-map evaluation API, see
[Dynamic data and filter evaluation](DYNAMIC_FILTER.md).

## Identifier naming

C enum constants share the application's global identifier namespace. Public
constants therefore use the `HDDS_` prefix; functions use `hdds_`, and types use
`Hdds`.

Early hand-written header copies used bare log-level constants. They map as
follows:

| Old local name | Public name since 1.4.0 |
|---|---|
| `OFF` | `HDDS_LOG_OFF` |
| `ERROR` | `HDDS_LOG_ERROR` |
| `WARN` | `HDDS_LOG_WARN` |
| `INFO` | `HDDS_LOG_INFO` |
| `DEBUG` | `HDDS_LOG_DEBUG` |
| `TRACE` | `HDDS_LOG_TRACE` |

The bare names are not provided as compatibility macros because identifiers
such as `ERROR`, `INFO`, and `DEBUG` commonly collide with application and
platform headers.

## Verification boundary

`sdk/c/tests/test_api_stability.c` pins the published log-level and error-code
identifiers and numeric values at compile time. The whole-library gate is:

```sh
scripts/c-abi/check-c-abi.sh
```

On its Linux x86-64 reference target, the gate builds the all-feature release
library and compares the generated header plus exported `hdds_*` symbols against
`scripts/c-abi/hdds-c-1.4.0-x86_64-linux.manifest`. The manifest records both
standalone and `HDDS_WITH_ROS2` header modes:

- C function and callback signatures;
- public enum names and numeric values;
- public record field offsets, sizes, and alignments;
- public `Hdds*` typedefs and `HDDS_*` macros;
- dynamic `hdds_*` symbols exported by `libhdds_c.so`.

Existing entries must remain byte-for-byte compatible. Additive declarations
and symbols are accepted, provided every declared function is exported. Do not
regenerate the baseline merely to make a failure green: review the ABI change,
and replace the baseline only for a deliberate new-major contract or when
establishing a baseline for another target ABI.

The optional candidate RPC API and its threading/ownership contract are documented
in [RPC.md](RPC.md). Build the library with `--features rpc` and define
`HDDS_WITH_RPC` in consumers.
