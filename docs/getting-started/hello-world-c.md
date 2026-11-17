# Hello World in C

This tutorial demonstrates using the HDDS C FFI bindings for basic publish-subscribe communication.

**Prerequisites:** a C compiler, `make`, and a stable **Rust toolchain** (install it with
[rustup](https://rustup.rs/)): the C library is built from the HDDS sources with Cargo. See
[Linux installation](installation/linux.md).

:::caution Low-Level API
The C API operates on raw CDR-encoded bytes. For typed data, use `hdds_gen` to generate serialization code, or use the Rust API directly.
:::

:::info Network prerequisites
Discovery uses UDP multicast. If the subscriber receives nothing and nothing
reports an error, discovery is probably not happening (VPN, container,
firewall). For a single-machine test, run both programs with
`HDDS_INTERFACE=lo`. See [Network Prerequisites](https://docs.hdds.io/getting-started/network-prerequisites).
:::

## Step 0: Build the C Library

```bash
git clone https://git.hdds.io/hdds/hdds.git
cd hdds
make sdk-c        # same as: cargo build --release -p hdds-c
```

This produces, inside the HDDS checkout:

| File | What it is |
|------|------------|
| `sdk/c/include/hdds.h` | The public header (use this one) |
| `target/release/libhdds_c.a` | Static library: linked into the program, no `libhdds_c` at run time |
| `target/release/libhdds_c.so` | Shared library (`.dylib` on macOS) |

`crates/hdds-c/hdds.h` is the header as cbindgen generates it during the build;
`sdk/c/include/hdds.h` is the same declarations with a licence header, and is
the copy that gets installed.

**Optional: install** the header, both libraries, a pkg-config file and the CMake
config into a prefix:

```bash
make install-c PREFIX=$HOME/.local     # default PREFIX is /usr/local
```

## Step 1: Project Setup

Create a project directory next to the HDDS checkout:

```bash
mkdir hdds-hello-c
cd hdds-hello-c
```

## Step 2: Create the Publisher

Create `publisher.c`:

```c
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "hdds.h"

int main(void) {
    // Line-buffer stdout so each line shows up at once, even through a pipe or a file
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("Starting publisher...\n");

    // Initialize logging (optional)
    hdds_logging_init(HDDS_LOG_WARN);

    // Create participant with UDP multicast transport. No domain in code:
    // the domain comes from the HDDS_DOMAIN_ID environment variable.
    struct HddsParticipant *participant =
        hdds_participant_create_with_transport("publisher", HDDS_TRANSPORT_UDP_MULTICAST);
    if (participant == NULL) {
        fprintf(stderr, "Failed to create participant\n");
        return 1;
    }
    printf("Participant created: %s, domain %u\n",
           hdds_participant_name(participant), hdds_participant_domain_id(participant));

    // Create QoS profile (reliable, transient-local)
    struct HddsQoS *qos = hdds_qos_reliable();
    hdds_qos_set_transient_local(qos);
    hdds_qos_set_history_depth(qos, 10);

    // Create writer with QoS
    struct HddsDataWriter *writer =
        hdds_writer_create_with_qos(participant, "hello/world", qos);
    if (writer == NULL) {
        fprintf(stderr, "Failed to create writer\n");
        hdds_qos_destroy(qos);
        hdds_participant_destroy(participant);
        return 1;
    }
    printf("Writer created on topic: hello/world\n");

    // QoS no longer needed after writer creation
    hdds_qos_destroy(qos);

    // Wait until a subscriber is matched (10 s at most) before the first write
    printf("Waiting for a subscriber...\n");
    enum HddsError status = hdds_writer_wait_for_matched_readers(writer, 1, 10000);
    if (status != HDDS_OK) {
        fprintf(stderr, "No subscriber matched (error %d): see Network Prerequisites\n", status);
        hdds_writer_destroy(writer);
        hdds_participant_destroy(participant);
        return 1;
    }

    // Publish messages (raw bytes)
    int failed = 0;
    for (int i = 0; i < 10; i++) {
        char message[64];
        int len = snprintf(message, sizeof(message), "Hello #%d from C!", i);

        enum HddsError result = hdds_writer_write(writer, message, len);
        if (result == HDDS_OK) {
            printf("Published: %s\n", message);
        } else {
            fprintf(stderr, "Write failed: %d\n", result);
            failed = 1;
        }

        sleep(1);
    }

    // Cleanup
    printf("Cleaning up...\n");
    hdds_writer_destroy(writer);
    hdds_participant_destroy(participant);
    printf("Done.\n");

    return failed;
}
```

Step 2 waits for a match on purpose: a sample written before the subscriber matched is
not delivered to a VOLATILE reader, so the first writes would depend on discovery timing.

## Step 3: Create the Subscriber

Create `subscriber.c`:

```c
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "hdds.h"

/* Stop after this many samples, or after this long without any sample. */
#define EXPECTED_SAMPLES 10
#define IDLE_TIMEOUT_NS (10LL * 1000 * 1000 * 1000)

int main(void) {
    // Line-buffer stdout so each line shows up at once, even through a pipe or a file
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("Starting subscriber...\n");

    // Initialize logging
    hdds_logging_init(HDDS_LOG_WARN);

    // Create participant with UDP multicast transport. No domain in code:
    // the domain comes from the HDDS_DOMAIN_ID environment variable.
    struct HddsParticipant *participant =
        hdds_participant_create_with_transport("subscriber", HDDS_TRANSPORT_UDP_MULTICAST);
    if (participant == NULL) {
        fprintf(stderr, "Failed to create participant\n");
        return 1;
    }
    printf("Participant created, domain %u\n", hdds_participant_domain_id(participant));

    // Create QoS (must be compatible with writer)
    struct HddsQoS *qos = hdds_qos_reliable();
    hdds_qos_set_history_depth(qos, 100);

    // Create reader with QoS
    struct HddsDataReader *reader =
        hdds_reader_create_with_qos(participant, "hello/world", qos);
    if (reader == NULL) {
        fprintf(stderr, "Failed to create reader\n");
        hdds_qos_destroy(qos);
        hdds_participant_destroy(participant);
        return 1;
    }
    printf("Reader created on topic: hello/world\n");
    hdds_qos_destroy(qos);

    // Set up WaitSet for event-driven reading
    struct HddsWaitSet *waitset = hdds_waitset_create();
    const struct HddsStatusCondition *condition =
        hdds_reader_get_status_condition(reader);
    hdds_waitset_attach_status_condition(waitset, condition);

    printf("Waiting for data...\n");

    // Read loop: stops after EXPECTED_SAMPLES samples or after IDLE_TIMEOUT_NS of silence
    char buffer[256];
    size_t len_read;
    const void *triggered[4];
    size_t triggered_count;
    int received = 0;

    while (received < EXPECTED_SAMPLES) {
        // hdds_waitset_wait returns HDDS_OK with triggered_count == 0 on timeout
        enum HddsError wait_result = hdds_waitset_wait(
            waitset, IDLE_TIMEOUT_NS, triggered, 4, &triggered_count);
        if (wait_result != HDDS_OK || triggered_count == 0) {
            printf("No data for 10 s, exiting\n");
            break;
        }

        // Take all available samples
        while (hdds_reader_take(reader, buffer, sizeof(buffer) - 1, &len_read) == HDDS_OK) {
            buffer[len_read] = '\0';
            printf("Received: %s\n", buffer);
            received++;
        }
    }
    printf("Received %d samples\n", received);

    // Cleanup
    hdds_waitset_detach_condition(waitset, condition);
    hdds_status_condition_release(condition);
    hdds_waitset_destroy(waitset);
    hdds_reader_destroy(reader);
    hdds_participant_destroy(participant);

    return 0;
}
```

## Step 4: Create Makefile

Create `Makefile`. It links the **static** library straight from the HDDS
checkout, so the programs run without any library path setup:

```makefile
# Path to your HDDS checkout
HDDS ?= ../hdds

CC = gcc
CFLAGS = -Wall -Wextra -O2 -I$(HDDS)/sdk/c/include
LDLIBS = $(HDDS)/target/release/libhdds_c.a -lpthread -ldl -lm

all: publisher subscriber

publisher: publisher.c
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

subscriber: subscriber.c
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f publisher subscriber

.PHONY: all clean
```

### Other ways to link

**Shared library.** `-lhdds_c` picks `libhdds_c.so` when it exists, and the
program then needs to find it at run time:

```bash
gcc -I../hdds/sdk/c/include publisher.c -L../hdds/target/release -lhdds_c -o publisher
LD_LIBRARY_PATH=../hdds/target/release ./publisher
```

Without `LD_LIBRARY_PATH` (or an install into a directory the loader knows,
followed by `ldconfig`), the program stops with
`error while loading shared libraries: libhdds_c.so`.

**pkg-config**, after `make install-c PREFIX=$HOME/.local`:

```bash
export PKG_CONFIG_PATH=$HOME/.local/lib/pkgconfig
gcc publisher.c $(pkg-config --cflags --libs hdds_c) -o publisher       # shared
gcc publisher.c $(pkg-config --cflags hdds_c) $HOME/.local/lib/libhdds_c.a -lpthread -ldl -lm -o publisher   # static
```

**CMake**, from the checkout or an install prefix (the C component does not
need the C++ SDK):

```cmake
cmake_minimum_required(VERSION 3.16)
project(hello_c C)
find_package(hdds REQUIRED COMPONENTS c)
add_executable(publisher publisher.c)
target_link_libraries(publisher PRIVATE hdds::hdds_c)   # static libhdds_c.a
```

```bash
cmake -B build -DCMAKE_PREFIX_PATH=/path/to/hdds/sdk/cmake    # or =$HOME/.local
cmake --build build
```

`make test-c-install` in the HDDS checkout builds and runs a program each of
these ways against a temporary install prefix.

## Step 5: Build and Run

Both programs take their DDS domain from the `HDDS_DOMAIN_ID` environment variable
(see [environment variables](../reference/environment-vars.md)). Export the same value in both
terminals (any value from 0 to 232; the examples use 42):

```bash
# Build
make

# Terminal 1 - Start subscriber
export HDDS_DOMAIN_ID=42
./subscriber

# Terminal 2 - Start publisher
export HDDS_DOMAIN_ID=42
./publisher
```

With `HDDS_INTERFACE=lo`, each program also logs one warning line saying that the
loopback interface was chosen explicitly.

The subscriber stops after 10 samples, or after 10 s without any sample. The publisher
waits up to 10 s for a subscriber, then writes 10 samples.

### Expected Output

**Subscriber:**
```
Starting subscriber...
Participant created, domain 42
Reader created on topic: hello/world
Waiting for data...
Received: Hello #0 from C!
Received: Hello #1 from C!
Received: Hello #2 from C!
...
Received: Hello #9 from C!
Received 10 samples
```

**Publisher:**
```
Starting publisher...
Participant created: publisher, domain 42
Writer created on topic: hello/world
Waiting for a subscriber...
Published: Hello #0 from C!
Published: Hello #1 from C!
...
Published: Hello #9 from C!
Cleaning up...
Done.
```

The subscriber prints `No data for 10 s, exiting` instead of `Received 10 samples` when
the publisher stops early or never matched. The publisher prints
`No subscriber matched (error 24): see Network Prerequisites` and exits with status 1 when
no subscriber matched within 10 s.

## C API Reference

### Participant

```c
// Explicit domain (wins over HDDS_DOMAIN_ID); hdds_config_build consumes config
struct HddsParticipantConfig *config = hdds_config_create("my_app");
hdds_config_set_domain_id(config, 42);
hdds_config_set_transport_mode(config, HDDS_TRANSPORT_UDP_MULTICAST);  // or HDDS_TRANSPORT_INTRA_PROCESS
struct HddsParticipant *p = hdds_config_build(config);

// Properties
const char *name = hdds_participant_name(p);
uint32_t domain = hdds_participant_domain_id(p);

// Cleanup
hdds_participant_destroy(p);
```

```c
// No domain in code: HDDS_DOMAIN_ID picks it (see environment variables)
struct HddsParticipant *p = hdds_participant_create_with_transport(
    "my_app",
    HDDS_TRANSPORT_UDP_MULTICAST  // or HDDS_TRANSPORT_INTRA_PROCESS
);
hdds_participant_destroy(p);
```

### Writer

```c
// Create with default QoS
struct HddsDataWriter *w = hdds_writer_create(participant, "topic_name");

// Create with custom QoS
struct HddsDataWriter *w = hdds_writer_create_with_qos(participant, "topic_name", qos);

// Write raw bytes
enum HddsError result = hdds_writer_write(writer, data_ptr, data_len);

// Cleanup
hdds_writer_destroy(w);
```

### Reader

```c
// Create with custom QoS (default QoS: hdds_reader_create(participant, "topic_name"))
struct HddsDataReader *r = hdds_reader_create_with_qos(participant, "topic_name", qos);

// Take data (removes from cache)
char buffer[1024];
size_t len_out;
if (hdds_reader_take(r, buffer, sizeof(buffer), &len_out) == HDDS_OK) {
    printf("Received %zu bytes\n", len_out);
}

// Cleanup
hdds_reader_destroy(r);
```

`hdds_reader_take` returns `HDDS_NOT_FOUND` when no sample is available. When the buffer
is smaller than the next sample, it returns `HDDS_OUT_OF_MEMORY`, writes the required size
to `len_out` and removes nothing: size the buffer from that value and take again.


### QoS

```c
// Create QoS profiles
struct HddsQoS *qos = hdds_qos_default();      // Best effort, volatile
struct HddsQoS *qos = hdds_qos_best_effort();  // Explicit best effort
struct HddsQoS *qos = hdds_qos_reliable();     // Reliable delivery

// Configure QoS
hdds_qos_set_history_depth(qos, 10);
hdds_qos_set_history_keep_all(qos);
hdds_qos_set_transient_local(qos);
hdds_qos_set_volatile(qos);
hdds_qos_set_reliable(qos);
hdds_qos_set_best_effort(qos);
hdds_qos_set_deadline_ns(qos, 100000000);  // 100ms

// Load from XML
struct HddsQoS *qos = hdds_qos_from_xml("/path/to/profile.xml");

// Cleanup
hdds_qos_destroy(qos);
```

### WaitSet

```c
// Create waitset
struct HddsWaitSet *ws = hdds_waitset_create();

// Get reader's status condition
const struct HddsStatusCondition *cond = hdds_reader_get_status_condition(reader);

// Attach condition
hdds_waitset_attach_status_condition(ws, cond);

// Wait for events
const void *triggered[10];
size_t count;
int64_t timeout_ns = 1000000000;  // 1 second
enum HddsError result = hdds_waitset_wait(ws, timeout_ns, triggered, 10, &count);

// Cleanup
hdds_waitset_detach_condition(ws, cond);
hdds_status_condition_release(cond);
hdds_waitset_destroy(ws);
```

### Error Codes

Most functions return an `HddsError`; constructors return `NULL` instead. The table is the
one of the [C API Reference](../api/c.md#error-codes):

| Name | Value | Meaning (hdds.h) |
|------|-------|------------------|
| `HDDS_OK` | 0 | Success |
| `HDDS_INVALID_ARGUMENT` | 1 | Invalid argument provided (null pointer, invalid value) |
| `HDDS_NOT_FOUND` | 2 | Requested resource not found |
| `HDDS_OPERATION_FAILED` | 3 | Generic operation failure |
| `HDDS_OUT_OF_MEMORY` | 4 | Memory allocation failed |
| `HDDS_CONFIG_ERROR` | 10 | Invalid configuration settings |
| `HDDS_INVALID_DOMAIN_ID` | 11 | Invalid domain ID (must be 0-232) |
| `HDDS_INVALID_PARTICIPANT_ID` | 12 | Invalid participant ID (must be 0-119) |
| `HDDS_NO_AVAILABLE_PARTICIPANT_ID` | 13 | No available participant ID (all 120 ports occupied) |
| `HDDS_INVALID_STATE` | 14 | Invalid entity state for requested operation |
| `HDDS_IO_ERROR` | 20 | Generic I/O error |
| `HDDS_TRANSPORT_ERROR` | 21 | UDP transport send/receive failed |
| `HDDS_REGISTRATION_FAILED` | 22 | Topic registration failed |
| `HDDS_WOULD_BLOCK` | 23 | Operation would block but non-blocking mode requested |
| `HDDS_TIMEOUT` | 24 | Operation did not complete before the requested timeout |
| `HDDS_TYPE_MISMATCH` | 30 | Type mismatch between writer and reader |
| `HDDS_SERIALIZATION_ERROR` | 31 | CDR serialization failed |
| `HDDS_BUFFER_TOO_SMALL` | 32 | Buffer too small for encoding |
| `HDDS_ENDIAN_MISMATCH` | 33 | CDR endianness mismatch |
| `HDDS_QOS_INCOMPATIBLE` | 40 | QoS policies are incompatible between endpoints |
| `HDDS_UNSUPPORTED` | 41 | Requested feature or operation is not supported |
| `HDDS_PERMISSION_DENIED` | 50 | Permission denied by access control (DDS Security) |
| `HDDS_AUTHENTICATION_FAILED` | 51 | Authentication failed |

Constructors (`hdds_participant_create`, `hdds_writer_create_with_qos`, ...)
return `NULL` on failure; the reason is written to the HDDS log (enable it with
`hdds_logging_init`), for example an inconsistent QoS such as a history depth
larger than `max_samples_per_instance`.

### Logging

```c
// Initialize with level
hdds_logging_init(HDDS_LOG_INFO);  // HDDS_LOG_OFF, HDDS_LOG_ERROR, HDDS_LOG_WARN, HDDS_LOG_INFO, HDDS_LOG_DEBUG, HDDS_LOG_TRACE

// Or with environment variable (RUST_LOG)
hdds_logging_init_env(HDDS_LOG_INFO);

// Or with filter string
hdds_logging_init_with_filter("hdds=debug");
```

## Using with Typed Data (hdds_gen)

For typed data, use `hdds_gen` to generate C structs and CDR2 serialization functions:

### Step 1: Define IDL

Create `temperature.idl`:

```idl
struct Temperature {
    uint32 sensor_id;
    float  value;
    string unit;
};
```

### Step 2: Generate C Code

```bash
hddsgen gen c temperature.idl -o temperature.h     # hddsgen 2.0 or later
```

`hddsgen gen --help` lists the targets and options. Install hddsgen as shown in
[hdds_gen Installation](../tools/hdds-gen/installation.md).

This generates a header-only file with:
- the C struct `Temperature` (`unit` is a `char *`)
- `temperature_encode_cdr2_le()` and `temperature_decode_cdr2_le_alloc()` (plus
  `temperature_decode_cdr2_le()` for types without strings or sequences)
- `temperature_create_writer()`, the typed DataWriter constructor

`Temperature` has no extensibility annotation, so hddsgen generates it
APPENDABLE (the default since hddsgen 2.0, DDS-XTypes 1.3 7.3.1.2.1.8) and prints
an info line about it. Writers and readers must agree on the extensibility, so
create writers with `temperature_create_writer()`: it labels every sample
APPENDABLE, unlike `hdds_writer_create()`, which always labels FINAL. To get the
layout of hddsgen 1.x, generate with
`--default-extensibility final`, or annotate the type.

For a type with `@key` members (instances, `dispose`, `unregister_instance`), see
[Keyed Types](../api/c.md#keyed-types-key).

### Step 3: Publisher with Generated Code

Create `typed_publisher.c`:

```c
#include <stdio.h>
#include <unistd.h>
#include "temperature.h"
#include "hdds.h"

int main(void) {
    hdds_logging_init(HDDS_LOG_WARN);

    // No domain in code: the domain comes from the HDDS_DOMAIN_ID environment variable
    struct HddsParticipant *participant =
        hdds_participant_create_with_transport("sensor", HDDS_TRANSPORT_UDP_MULTICAST);
    if (participant == NULL) {
        fprintf(stderr, "Failed to create participant\n");
        return 1;
    }

    struct HddsQoS *qos = hdds_qos_reliable();
    hdds_qos_set_history_depth(qos, 10);
    struct HddsDataWriter *writer =
        temperature_create_writer(participant, "sensors/temperature", qos);
    hdds_qos_destroy(qos);
    if (writer == NULL) {
        fprintf(stderr, "Failed to create writer\n");
        hdds_participant_destroy(participant);
        return 1;
    }

    // Wait until a subscriber is matched (10 s at most) before the first write
    enum HddsError status = hdds_writer_wait_for_matched_readers(writer, 1, 10000);
    if (status != HDDS_OK) {
        fprintf(stderr, "No subscriber matched (error %d): see Network Prerequisites\n", status);
        hdds_writer_destroy(writer);
        hdds_participant_destroy(participant);
        return 1;
    }

    int failed = 0;
    for (uint32_t i = 0; i < 10; i++) {
        Temperature temp = {0};
        temp.sensor_id = 42;
        temp.value = 23.5f + (float)i;
        temp.unit = "celsius";

        // Encode to CDR2 bytes: the byte count on success, a negative CDR_* code on failure
        uint8_t buffer[256];
        int encoded_len = temperature_encode_cdr2_le(&temp, buffer, sizeof(buffer));
        if (encoded_len < 0) {
            fprintf(stderr, "Encode failed: %d\n", encoded_len);
            failed = 1;
            break;
        }
        if (hdds_writer_write(writer, buffer, (size_t)encoded_len) != HDDS_OK) {
            fprintf(stderr, "Write failed\n");
            failed = 1;
        } else {
            printf("Published: sensor %u, %.1f %s\n", temp.sensor_id, temp.value, temp.unit);
        }
        sleep(1);
    }

    hdds_writer_destroy(writer);
    hdds_participant_destroy(participant);
    return failed;
}
```

### Step 4: Subscriber with Generated Code

Create `typed_subscriber.c`:

```c
#include <stdio.h>
#include "temperature.h"
#include "hdds.h"

/* Stop after this many samples, or after this long without any sample. */
#define EXPECTED_SAMPLES 10
#define IDLE_TIMEOUT_NS (10LL * 1000 * 1000 * 1000)

int main(void) {
    hdds_logging_init(HDDS_LOG_WARN);

    // No domain in code: the domain comes from the HDDS_DOMAIN_ID environment variable
    struct HddsParticipant *participant =
        hdds_participant_create_with_transport("sensor_display", HDDS_TRANSPORT_UDP_MULTICAST);
    if (participant == NULL) {
        fprintf(stderr, "Failed to create participant\n");
        return 1;
    }

    struct HddsQoS *qos = hdds_qos_reliable();
    hdds_qos_set_history_depth(qos, 100);
    struct HddsDataReader *reader =
        hdds_reader_create_with_type(participant, "sensors/temperature", "Temperature", qos);
    hdds_qos_destroy(qos);
    if (reader == NULL) {
        fprintf(stderr, "Failed to create reader\n");
        hdds_participant_destroy(participant);
        return 1;
    }

    struct HddsWaitSet *waitset = hdds_waitset_create();
    const struct HddsStatusCondition *condition = hdds_reader_get_status_condition(reader);
    hdds_waitset_attach_status_condition(waitset, condition);

    // Storage for the decoded string field: a bump arena over a buffer we own
    static uint8_t storage[256];
    hdds_x2c_arena arena;
    hdds_x2c_arena_init(&arena, storage, sizeof(storage));

    uint8_t buffer[256];
    size_t len_read;
    const void *triggered[4];
    size_t triggered_count;
    int received = 0;

    while (received < EXPECTED_SAMPLES) {
        // hdds_waitset_wait returns HDDS_OK with triggered_count == 0 on timeout
        enum HddsError wait_result = hdds_waitset_wait(
            waitset, IDLE_TIMEOUT_NS, triggered, 4, &triggered_count);
        if (wait_result != HDDS_OK || triggered_count == 0) {
            printf("No data for 10 s, exiting\n");
            break;
        }

        while (hdds_reader_take(reader, buffer, sizeof(buffer), &len_read) == HDDS_OK) {
            arena.used = 0;  // reuse the storage for each sample
            Temperature temp = {0};
            int decoded = temperature_decode_cdr2_le_alloc(
                &temp, buffer, len_read, hdds_x2c_arena_alloc, &arena);
            if (decoded < 0) {
                fprintf(stderr, "Decode failed: %d\n", decoded);
                continue;
            }
            printf("Sensor %u: %.1f %s\n", temp.sensor_id, temp.value, temp.unit);
            received++;
        }
    }
    printf("Received %d samples\n", received);

    hdds_waitset_detach_condition(waitset, condition);
    hdds_status_condition_release(condition);
    hdds_waitset_destroy(waitset);
    hdds_reader_destroy(reader);
    hdds_participant_destroy(participant);
    return 0;
}
```

Build both (`temperature.h` must be in the same directory):

```bash
for p in typed_publisher typed_subscriber; do
    gcc -Wall -Wextra -O2 -I../hdds/sdk/c/include $p.c \
        ../hdds/target/release/libhdds_c.a -lpthread -ldl -lm -o $p
done
```

Run them as in Step 5, with the same `HDDS_DOMAIN_ID` in both terminals.

The subscriber creates its reader with `hdds_reader_create_with_type()` and the type name
`Temperature`, the name the generated writer announces. A reader created with
`hdds_reader_create_with_qos()` announces a placeholder type name instead, and HDDS logs a
warning that the two names differ.

:::tip String fields need an allocator
The generated decoder does not allocate memory on its own. A `string` field
(here `unit`) is stored in memory handed to the decoder: pass an allocator
callback as `temperature_decode_cdr2_le_alloc(..., hdds_x2c_arena_alloc, &arena)`.
`hdds_x2c_arena` is a bump allocator over a buffer you own; reset `arena.used`
to reuse it. Decoding a type with a string field without an allocator
(`temperature_decode_cdr2_le()`) fails with `-CDR_OUT_OF_MEMORY` (-4).
:::

### Return codes of the generated functions

- Encode (`*_encode_cdr2_le`) returns the number of bytes written; decode
  (`*_decode_cdr2_le*`) returns the number of bytes read.
- On failure both return a negative code from the generated header, the
  negated `CDR_*` constant: `-CDR_INVALID_DATA` (-1), `-CDR_UNEXPECTED_EOF` (-2),
  `-CDR_BUFFER_TOO_SMALL` (-3), `-CDR_OUT_OF_MEMORY` (-4).
- Test for `< 0`, not for `== 0`: a positive return is a length, never an error.

## Troubleshooting: the subscriber receives nothing

- **`No data for 10 s, exiting` and `Received 0 samples`?** Nothing arrived, so the subscriber
  gave up after 10 s. Check that the publisher runs with the same `HDDS_DOMAIN_ID` and topic.
  A publisher that never matches a subscriber prints `No subscriber matched (error 24)` and
  exits with status 1. Discovery may be the cause: on one machine, run both programs with
  `HDDS_INTERFACE=lo`. Look for `IP_MULTICAST_IF=... blocked (VPN/tunnel policy?)` in the log.
  On the publisher side, `hdds_writer_matched_reader_count()` tells whether the subscriber was
  found. Full guide: [Network Prerequisites](https://docs.hdds.io/getting-started/network-prerequisites).
- **No output at all when redirected to a file or a pipe?** stdio buffers
  `stdout` when it is not a terminal; the examples above call
  `setvbuf(stdout, NULL, _IOLBF, 0)` for that reason.
- **Same domain and topic?** Set `HDDS_DOMAIN_ID` to the same value in both terminals
  (see [environment variables](../reference/environment-vars.md)). The topic name must be identical too.

## What's Next?

- **[C API Reference](../api/c.md)** - Complete API documentation
- **[hdds_gen CLI](../tools/hdds-gen/cli-reference.md)** - Code generator options
- **[Hello World Rust](hello-world-rust.md)** - Rust version with typed API
