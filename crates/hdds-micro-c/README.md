# HDDS Micro C SDK

C FFI bindings for HDDS Micro - Embedded DDS for microcontrollers.

## Overview

HDDS Micro C SDK provides a simple C API for the HDDS Micro DDS implementation.
It's designed for embedded systems like ESP32, RP2040, STM32, and any Arduino-compatible board.

## Features

- **Pure C API** - No C++ required, works with Arduino, ESP-IDF, bare-metal
- **Small footprint** - < 100 KB Flash, < 50 KB RAM
- **Real RTPS/DDS** - Interoperable with standard DDS implementations
- **Callback-based transport** - Easy integration with any UART/serial
- **Complete CDR encoding** - All primitive types, strings, and bytes
- **Full pub/sub** - Both writer (publisher) and reader (subscriber) APIs

## Quick Start

### Publisher

```c
#include "hdds_micro.h"

// UART callbacks
int32_t my_uart_write(const uint8_t* data, size_t len, void* ctx) {
    return Serial2.write(data, len);
}

int32_t my_uart_read(uint8_t* buf, size_t len, uint32_t timeout, void* ctx) {
    // ... your implementation
}

void setup() {
    // Create transport
    HddsMicroTransport* transport = hdds_micro_transport_create_serial(
        my_uart_write, my_uart_read, 0x42, NULL
    );

    // Create participant
    HddsMicroParticipant* participant = hdds_micro_participant_create(0, transport);

    // Create writer
    HddsMicroWriter* writer = hdds_micro_writer_create(
        participant, "sensor/temperature", NULL
    );

    // Publish data
    uint8_t buf[64];
    int32_t len = hdds_micro_encode_f32(buf, sizeof(buf), 23.5f);
    hdds_micro_write(writer, buf, len);
}
```

### Subscriber

```c
#include "hdds_micro.h"

void setup() {
    // ... transport and participant creation ...

    // Create reader
    HddsMicroReader* reader = hdds_micro_reader_create(
        participant, "sensor/temperature", NULL
    );
}

void loop() {
    uint8_t buf[256];
    size_t len = 0;
    HddsMicroSampleInfo info;

    // Non-blocking read
    HddsMicroError err = hdds_micro_read(reader, buf, sizeof(buf), &len, &info);

    if (err == HDDS_MICRO_ERROR_OK && len > 0) {
        float temperature;
        hdds_micro_decode_f32(buf, len, &temperature);
        printf("Received: %.2f C (seq=%lld)\n", temperature, info.sequence_number);
    }
    // HDDS_MICRO_ERROR_TIMEOUT means no data available - keep polling
}
```

## API Reference

### Transport

```c
// Create serial transport with UART callbacks
HddsMicroTransport* hdds_micro_transport_create_serial(
    UartWriteFn write_fn,
    UartReadFn read_fn,
    uint8_t node_id,
    void* user_data
);

// Create null transport (for testing)
HddsMicroTransport* hdds_micro_transport_create_null(void);

// Destroy transport
void hdds_micro_transport_destroy(HddsMicroTransport* transport);
```

### Participant

```c
// Create participant (takes ownership of transport)
HddsMicroParticipant* hdds_micro_participant_create(
    uint32_t domain_id,
    HddsMicroTransport* transport
);

// Get domain ID
uint32_t hdds_micro_participant_domain_id(const HddsMicroParticipant* p);

// Destroy participant
void hdds_micro_participant_destroy(HddsMicroParticipant* participant);
```

### Writer (Publisher)

```c
// Create writer
HddsMicroWriter* hdds_micro_writer_create(
    HddsMicroParticipant* participant,
    const char* topic_name,
    const HddsMicroQos* qos  // NULL for default
);

// Write data
HddsMicroError hdds_micro_write(
    HddsMicroWriter* writer,
    const uint8_t* data,
    size_t len
);

// Destroy writer
void hdds_micro_writer_destroy(HddsMicroWriter* writer);
```

### Reader (Subscriber)

```c
// Create reader
HddsMicroReader* hdds_micro_reader_create(
    HddsMicroParticipant* participant,
    const char* topic_name,
    const HddsMicroQos* qos  // NULL for default
);

// Read data (non-blocking)
// Returns HDDS_MICRO_ERROR_OK on success, HDDS_MICRO_ERROR_TIMEOUT if no data
HddsMicroError hdds_micro_read(
    HddsMicroReader* reader,
    uint8_t* out_data,
    size_t max_len,
    size_t* out_len,
    HddsMicroSampleInfo* out_info  // NULL to ignore
);

// Take data (alias for read in BEST_EFFORT mode)
HddsMicroError hdds_micro_take(
    HddsMicroReader* reader,
    uint8_t* out_data,
    size_t max_len,
    size_t* out_len,
    HddsMicroSampleInfo* out_info
);

// Get reader topic name
int32_t hdds_micro_reader_topic_name(
    const HddsMicroReader* reader,
    char* out_name,
    size_t max_len
);

// Destroy reader
void hdds_micro_reader_destroy(HddsMicroReader* reader);
```

### Sample Info

```c
typedef struct HddsMicroSampleInfo {
    uint8_t writer_guid_prefix[12];  // Source writer GUID prefix
    uint8_t writer_entity_id[4];     // Source writer entity ID
    int64_t sequence_number;         // Sample sequence number
    uint8_t valid_data;              // 1 if data is valid
} HddsMicroSampleInfo;
```

### CDR Encoding

```c
// Unsigned integers
int32_t hdds_micro_encode_u8(uint8_t* buf, size_t len, uint8_t value);
int32_t hdds_micro_encode_u16(uint8_t* buf, size_t len, uint16_t value);
int32_t hdds_micro_encode_u32(uint8_t* buf, size_t len, uint32_t value);
int32_t hdds_micro_encode_u64(uint8_t* buf, size_t len, uint64_t value);

// Signed integers
int32_t hdds_micro_encode_i8(uint8_t* buf, size_t len, int8_t value);
int32_t hdds_micro_encode_i16(uint8_t* buf, size_t len, int16_t value);
int32_t hdds_micro_encode_i32(uint8_t* buf, size_t len, int32_t value);
int32_t hdds_micro_encode_i64(uint8_t* buf, size_t len, int64_t value);

// Floating point
int32_t hdds_micro_encode_f32(uint8_t* buf, size_t len, float value);
int32_t hdds_micro_encode_f64(uint8_t* buf, size_t len, double value);

// Bool
int32_t hdds_micro_encode_bool(uint8_t* buf, size_t len, bool value);

// String (length-prefixed with null terminator)
int32_t hdds_micro_encode_string(uint8_t* buf, size_t len, const char* str);

// Raw bytes
int32_t hdds_micro_encode_bytes(uint8_t* buf, size_t len, const uint8_t* data, size_t data_len);
```

### CDR Decoding

```c
// Unsigned integers
int32_t hdds_micro_decode_u8(const uint8_t* buf, size_t len, uint8_t* out);
int32_t hdds_micro_decode_u16(const uint8_t* buf, size_t len, uint16_t* out);
int32_t hdds_micro_decode_u32(const uint8_t* buf, size_t len, uint32_t* out);
int32_t hdds_micro_decode_u64(const uint8_t* buf, size_t len, uint64_t* out);

// Signed integers
int32_t hdds_micro_decode_i8(const uint8_t* buf, size_t len, int8_t* out);
int32_t hdds_micro_decode_i16(const uint8_t* buf, size_t len, int16_t* out);
int32_t hdds_micro_decode_i32(const uint8_t* buf, size_t len, int32_t* out);
int32_t hdds_micro_decode_i64(const uint8_t* buf, size_t len, int64_t* out);

// Floating point
int32_t hdds_micro_decode_f32(const uint8_t* buf, size_t len, float* out);
int32_t hdds_micro_decode_f64(const uint8_t* buf, size_t len, double* out);

// Bool
int32_t hdds_micro_decode_bool(const uint8_t* buf, size_t len, bool* out);

// String
int32_t hdds_micro_decode_string(const uint8_t* buf, size_t len, char* out, size_t max_len);

// Raw bytes
int32_t hdds_micro_decode_bytes(const uint8_t* buf, size_t len, uint8_t* out, size_t count);
```

### Utilities

```c
// Get version string
const char* hdds_micro_version(void);

// Get error description
const char* hdds_micro_error_str(HddsMicroError error);
```

## Error Codes

```c
typedef enum HddsMicroError {
    HDDS_MICRO_ERROR_OK = 0,                  // Success
    HDDS_MICRO_ERROR_INVALID_PARAMETER = 1,   // Invalid parameter
    HDDS_MICRO_ERROR_BUFFER_TOO_SMALL = 2,    // Buffer too small
    HDDS_MICRO_ERROR_TRANSPORT_ERROR = 3,     // Transport error
    HDDS_MICRO_ERROR_TIMEOUT = 4,             // No data available
    HDDS_MICRO_ERROR_RESOURCE_EXHAUSTED = 5,  // Resource exhausted
    HDDS_MICRO_ERROR_ENCODING_ERROR = 6,      // Encoding error
    HDDS_MICRO_ERROR_DECODING_ERROR = 7,      // Decoding error
    HDDS_MICRO_ERROR_NOT_INITIALIZED = 8,     // Not initialized
    HDDS_MICRO_ERROR_NULL_POINTER = 9,        // Null pointer
    HDDS_MICRO_ERROR_UNKNOWN = 255,           // Unknown error
} HddsMicroError;
```

## Building

### As static library (for linking)

```bash
cargo build --release -p hdds-micro-c
# Output: target/release/libhdds_micro_c.a
```

### For ESP32 (cross-compile with ESP-IDF)

```bash
# With esp-idf toolchain
cargo build --release -p hdds-micro-c --target xtensa-esp32-espidf --features esp32
```

### For RP2040

```bash
cargo build --release -p hdds-micro-c --target thumbv6m-none-eabi --features rp2040
```

### For STM32

```bash
cargo build --release -p hdds-micro-c --target thumbv7em-none-eabihf --features stm32
```

## Examples

- [hdds_micro_example.ino](examples/arduino/hdds_micro_example.ino) - Simple publisher
- [hdds_micro_pubsub.ino](examples/arduino/hdds_micro_pubsub.ino) - Complete pub/sub example

## Encoding Multiple Fields

To encode a struct with multiple fields:

```c
typedef struct {
    uint32_t sensor_id;
    float    temperature;
    uint64_t timestamp;
} TemperatureMsg;

int32_t encode_temperature(uint8_t* buf, size_t buf_len, const TemperatureMsg* msg) {
    int32_t pos = 0;
    int32_t len;

    // Each encode function returns bytes written, -1 on error
    len = hdds_micro_encode_u32(buf + pos, buf_len - pos, msg->sensor_id);
    if (len < 0) return -1;
    pos += len;

    len = hdds_micro_encode_f32(buf + pos, buf_len - pos, msg->temperature);
    if (len < 0) return -1;
    pos += len;

    len = hdds_micro_encode_u64(buf + pos, buf_len - pos, msg->timestamp);
    if (len < 0) return -1;
    pos += len;

    return pos;  // Total bytes written
}
```

## License

Apache-2.0 OR MIT
