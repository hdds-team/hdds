# IDL Basic Types

HDDS supports all IDL 4.2 basic types.

## Primitive Types

### Boolean

```idl
boolean flag;
bool enabled;  // alias
```

### Characters

```idl
char c;        // 8-bit character
wchar wc;      // Wide character (UTF-32)
```

### Octet

```idl
octet raw_byte;  // Unsigned 8-bit (mapped to uint8_t)
```

### Void

```idl
void  // Used in operation returns
```

## Integer Types

### Classic Types (IDL 2.x compatible)

```idl
short s;              // 16-bit signed
unsigned short us;    // 16-bit unsigned
long l;               // 32-bit signed
unsigned long ul;     // 32-bit unsigned
long long ll;         // 64-bit signed
unsigned long long ull; // 64-bit unsigned
```

### Fixed-Width Types (IDL 4.x)

```idl
int8_t  i8;   // 8-bit signed
int16_t i16;  // 16-bit signed
int32_t i32;  // 32-bit signed
int64_t i64;  // 64-bit signed

uint8_t  u8;  // 8-bit unsigned
uint16_t u16; // 16-bit unsigned
uint32_t u32; // 32-bit unsigned
uint64_t u64; // 64-bit unsigned
```

### Type Mapping

| IDL Type | Rust | C/C++ | Python |
|----------|------|-------|--------|
| `int8_t` | `i8` | `int8_t` | `int` |
| `int16_t` / `short` | `i16` | `int16_t` | `int` |
| `int32_t` / `long` | `i32` | `int32_t` | `int` |
| `int64_t` / `long long` | `i64` | `int64_t` | `int` |
| `uint8_t` / `octet` | `u8` | `uint8_t` | `int` |
| `uint16_t` | `u16` | `uint16_t` | `int` |
| `uint32_t` | `u32` | `uint32_t` | `int` |
| `uint64_t` | `u64` | `uint64_t` | `int` |

## Floating-Point Types

```idl
float f;        // 32-bit IEEE 754
double d;       // 64-bit IEEE 754
long double ld; // Extended precision (mapped to f64 in Rust)
```

| IDL Type | Rust | C/C++ | Python |
|----------|------|-------|--------|
| `float` | `f32` | `float` | `float` |
| `double` | `f64` | `double` | `float` |
| `long double` | `f64` | `long double` | `float` |

## String Types

### Unbounded Strings

```idl
string name;    // Variable-length string
wstring wname;  // Wide string (UTF-32)
```

### Bounded Strings

```idl
string<64> short_name;   // Max 64 characters
wstring<128> wide_name;  // Max 128 wide characters
```

| IDL Type | Rust | C | Python |
|----------|------|---|--------|
| `string` | `String` | `char*` | `str` |
| `string<N>` | `String` (validated) | `char[N+1]` | `str` |
| `wstring` | `String` | `wchar_t*` | `str` |

## Fixed-Point Decimal

```idl
fixed<10, 3> price;  // 10 digits, 3 after decimal
// Represents values like 1234567.890
```

:::note
Fixed-point types are useful for financial applications where floating-point rounding is unacceptable.
:::

## Constants

```idl
const int32_t MAX_SIZE = 1000;
const double PI = 3.14159265359;
const boolean DEBUG = TRUE;
const string VERSION = "1.0.0";
```

### Constant Expressions

```idl
const int32_t TEN = 5 + 5;
const int32_t SHIFTED = 1 << 3;      // 8
const int32_t HEX = 0xFF00;          // Hex literal
const int32_t OCTAL = 0o755;         // Octal literal
const int32_t MASKED = HEX & 0xFF;   // Bitwise AND
```

**Supported operators:** `+`, `-`, `*`, `/`, `%`, `<<`, `>>`, `&`, `|`, `^`, `&&`, `||`

## Next Steps

- [Structs](../../../tools/hdds-gen/idl-syntax/structs.md) - Composite types
- [Enums](../../../tools/hdds-gen/idl-syntax/enums.md) - Enumeration types
- [Sequences](../../../tools/hdds-gen/idl-syntax/sequences.md) - Collections
