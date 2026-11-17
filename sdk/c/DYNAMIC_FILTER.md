# Dynamic data and filter evaluation

The generated C header exposes runtime type construction, primitive and string
field access, XCDR2 encoding/decoding, and SQL-like evaluation against field maps.
These APIs are included in the default `hdds-c` build. They operate locally;
evaluating a field map does not attach a filter to a DDS reader.

Build and run the C consumer test:

```sh
cargo build --locked -p hdds-c
cmake -S sdk/c -B build/c-sdk -DHDDS_C_LIB_DIR="$PWD/target/debug"
cmake --build build/c-sdk --target test_dynamic_filter
ctest --test-dir build/c-sdk -R '^test_dynamic_filter$' --output-on-failure
```

For a custom `CARGO_TARGET_DIR`, pass its `debug` directory to CMake instead.
The test exercises a CDR roundtrip, descriptor lifetime, type mismatches,
truncated string output, and transactional rejection of invalid parameters.

Use `struct HddsTypeBuilder`, `struct HddsTypeDescriptor`,
`struct HddsDynamicData`, `struct HddsFilter`, and `struct HddsFieldMap` in C.
`hdds_type_builder_build` consumes its builder; never destroy or reuse it
after that call. A dynamic-data handle retains its descriptor independently.
All other owned handles need the corresponding destroy function exactly once.
Mutating operations require exclusive access; do not destroy a handle in use.

The codec writes a little-endian XCDR2 body without a DDS encapsulation
header: the representation a writer created through the C ABI labels its
samples with when its QoS names none, so the encoded bytes go to
`hdds_writer_write` unchanged (create the writer with
`hdds_writer_create_with_extensibility` and the descriptor's extensibility so
its encapsulation identifier names it). A C reader requests XCDR2 alone unless
its QoS asks for XCDR as well (`hdds_qos_set_data_representation`):
`hdds_dynamic_data_decode` reads XCDR2, `hdds_dynamic_data_decode_ex` reads
the body in the representation `hdds_reader_take_ex` reports (XCDR1 or
XCDR2), and a content filter or query condition decodes each sample in its
own representation. Big-endian bodies are refused. A descriptor built here is APPENDABLE: its body starts with a
DHEADER, so an empty descriptor encodes to four bytes (`00 00 00 00`), and an
8-byte member is aligned at four.
Encode writes the required size to `out_len`; query with NULL and capacity zero.
The query returns `HDDS_BUFFER_TOO_SMALL`; allocate the reported size and call
again.

Numeric setters require the declared primitive type. A wrong type or unknown
field returns `HDDS_INVALID_ARGUMENT` without changing the data. String getters
return the required byte count excluding the trailing NUL; allocate that count
plus one. Smaller buffers receive a NUL-terminated byte prefix. Such a prefix
can split a multibyte UTF-8 character. Array and sequence descriptors can be
built, but this C API currently has no element accessors.
Builder kind arguments accept `HDDS_PRIM_*` numeric values and reject unknown
values. Field names must be nonempty and unique. Array lengths must be nonzero
and fit a Rust allocation of `DynamicValue` elements.

Filter parameters are positional (`%0`, `%1`, ...). A NULL array with a nonzero
count, a NULL entry, invalid UTF-8, a missing referenced position or numeric
overflow is rejected. Failed updates preserve all previous parameters. Every
branch is validated, including branches that would short-circuit at evaluation.
A NULL array with count zero succeeds only if the expression references no
parameters. Creating with parameters applies the same checks. Evaluation
returns 1 for a match, 0 for no match, and -1 for an evaluation error (including
a missing parameter).

The expression grammar is DDS 1.4 Annex B `FilterExpression` in full: `AND`,
`OR`, `NOT`, parentheses; `field RelOp value`, `value RelOp field`,
`field RelOp field`, `field [NOT] BETWEEN low AND high`; RelOp `=`, `>`, `>=`,
`<`, `<=`, `<>`, `LIKE` (`%` any sequence, `_` one character); dotted field
names (`pos.x`, looked up as one key of the field map); signed decimal or `0x`
integer literals, float literals with `.` and `e` exponent; single-quoted
strings, chars and enumeration labels (a one-character literal against an
integer field compares by code point); parameters `%0`..`%99`. `!=` and `==`
are accepted as aliases of `<>` and `=`. `hdds_filter_get_expression` returns
the expression exactly as specified at creation (DDS 1.4 2.2.2.3.3.2);
`hdds_filter_get_canonical_expression` returns the parsed expression rendered
as Annex B text (`x <> 1`, upper-case keywords), the only form announced or
sent on the wire. Double-quoted strings, a literal on both sides and a bare
`TRUE` are rejected.
Boolean fields compare with `TRUE`/`FALSE`, with `0`/`1`, or with `'TRUE'`/`'FALSE'`.
`TRUE`/`FALSE` is an extension: Annex B has no boolean literal, so it is refused
inside `BETWEEN` bounds, and the canonical expression keeps it as written. The
canonical text is Annex B in every other respect; an expression using this
extension has no Annex B spelling and a strict foreign parser may reject it.
Use `0`/`1` or `'TRUE'`/`'FALSE'` for a filter that must stay within Annex B.
Integer literals and decimal or hexadecimal integer parameters preserve all
bits over the combined `i64`/`u64` range. Values outside this range are
rejected. Incomplete expressions and trailing tokens are rejected.

## Numeric comparisons (candidate 1.5.0 behavior change)

Comparisons use exact ordering of the represented values. An integer is never
rounded to `f64` before a mixed comparison, so `u64::MAX` is less than the
floating value 18446744073709551616.0, and the integer 9007199254740993 is greater
than the floating value 9007199254740992.0. Float literals and float parameters
are still rounded to binary64 when parsed: use integer syntax for an exact
integer threshold.

There is no implicit epsilon. Two distinct finite floats compare unequal even
when very close; use explicit lower and upper bounds when a tolerance is wanted.
Positive and negative zero compare equal. Infinities follow ordinary numeric
ordering. NaN is unordered: `=` and all four ordered comparisons are false,
while `<>` is true. Consequently `NOT (x > y)` differs from `x <= y` when either
value is NaN. This is a two-valued IEEE comparison policy, not SQL NULL logic.

Numeric parameters support explicit `NaN`, `inf` and `infinity` spellings
(case-insensitive, optionally signed). A finite-looking parameter such as
`1e400` that overflows binary64 is rejected at parameter configuration. Quote a parameter to
treat such a spelling as a string instead.

This corrects earlier core behavior that used an absolute 1e-9 epsilon, rounded
mixed integer comparisons, and returned false for both equality and inequality
with NaN. Applications relying on the old approximate equality must express
their tolerance explicitly. These rules describe HDDS behavior; this test suite
does not certify the full OMG content-subscription profile.

C++ consumers can use this C surface directly:

```cpp
extern "C" {
#include "hdds.h"
}
```

There are no dedicated C++/Python/TypeScript wrapper classes for these APIs yet.
The Python ctypes consumer in `sdk/python/examples/dynamic_filter.py` demonstrates
explicit signatures and cleanup using the SDK's native-library discovery:

```sh
HDDS_LIB_PATH="$PWD/target/debug/libhdds_c.so" PYTHONPATH=sdk/python \
  python3 sdk/python/examples/dynamic_filter.py
```

Read/QueryConditions and content-filtered readers build on this API: they
decode a reader's payload with a type descriptor to evaluate a query or a
filter (`docs/read-query-conditions.md`, `sdk/c/tests/test_conditions.c`).
C RPC is a separate surface (`RPC.md`).

### Checked configuration (candidate 1.5.0 compatibility change)

Previously, missing/overflowing parameters could be accepted and only fail while
evaluating a sample. The C setter now returns HDDS_INVALID_ARGUMENT and retains
the old values; create_with_params returns NULL. Creation without parameters may
still prepare an expression with placeholders, but configure them before use.
Rust ReaderBuilder rejects an evaluator with unbound/overflowing parameters.

Rust callers can use ContentFilter::try_set_parameters and
ContentFilteredTopic::try_set_expression_parameters to receive errors directly.
The existing unit-returning setters keep their signatures, retain previous
values on invalid updates and log a warning. Field-name and operand-type checks
still need sample/schema information; this is parameter validation, not complete
static SQL type checking.
