# Hello World in C

This tutorial demonstrates using the HDDS C FFI bindings for basic publish-subscribe communication.

**Prerequisites:** [HDDS C library installed](../getting-started/installation/linux.md)

:::caution Low-Level API
The C API operates on raw CDR-encoded bytes. For typed data, use `hdds_gen` to generate serialization code, or use the Rust API directly.
:::

## Step 1: Project Setup

Create a project directory:

```bash
mkdir hdds-hello-c
cd hdds-hello-c
```

Copy the HDDS header:

```bash
# From HDDS source
cp /path/to/hdds/crates/hdds-c/hdds.h .
```

## Step 2: Create the Publisher

Create `publisher.c`:

```c
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "hdds.h"

int main(void) {
    printf("Starting publisher...\n");

    // Initialize logging (optional)
    hdds_logging_init(INFO);

    // Create participant with UDP multicast transport
    struct HddsParticipant *participant =
        hdds_participant_create_with_transport("publisher", UDP_MULTICAST);
    if (participant == NULL) {
        fprintf(stderr, "Failed to create participant\n");
        return 1;
    }
    printf("Participant created: %s\n", hdds_participant_name(participant));

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

    // Give time for discovery
    printf("Waiting for discovery...\n");
    sleep(2);

    // Publish messages (raw bytes)
    for (int i = 0; i < 10; i++) {
        char message[64];
        int len = snprintf(message, sizeof(message), "Hello #%d from C!", i);

        enum HddsError result = hdds_writer_write(writer, message, len);
        if (result == OK) {
            printf("Published: %s\n", message);
        } else {
            fprintf(stderr, "Write failed: %d\n", result);
        }

        sleep(1);
    }

    // Cleanup
    printf("Cleaning up...\n");
    hdds_writer_destroy(writer);
    hdds_participant_destroy(participant);
    printf("Done.\n");

    return 0;
}
```

## Step 3: Create the Subscriber

Create `subscriber.c`:

```c
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "hdds.h"

int main(void) {
    printf("Starting subscriber...\n");

    // Initialize logging
    hdds_logging_init(INFO);

    // Create participant
    struct HddsParticipant *participant =
        hdds_participant_create_with_transport("subscriber", UDP_MULTICAST);
    if (participant == NULL) {
        fprintf(stderr, "Failed to create participant\n");
        return 1;
    }
    printf("Participant created\n");

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

    // Read loop
    char buffer[256];
    size_t len_read;
    const void *triggered[4];
    size_t triggered_count;

    while (true) {
        // Wait for data (5 second timeout)
        int64_t timeout_ns = 5LL * 1000 * 1000 * 1000;
        enum HddsError wait_result = hdds_waitset_wait(
            waitset, timeout_ns, triggered, 4, &triggered_count);

        if (wait_result == OK && triggered_count > 0) {
            // Take all available samples
            while (hdds_reader_take(reader, buffer, sizeof(buffer) - 1, &len_read) == OK) {
                buffer[len_read] = '\0';
                printf("Received: %s\n", buffer);
            }
        } else {
            printf("No data received (timeout)\n");
        }
    }

    // Cleanup (not reached in this example)
    hdds_waitset_detach_condition(waitset, condition);
    hdds_status_condition_release(condition);
    hdds_waitset_destroy(waitset);
    hdds_reader_destroy(reader);
    hdds_participant_destroy(participant);

    return 0;
}
```

## Step 4: Create Makefile

Create `Makefile`:

```makefile
CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -L/usr/local/lib -lhdds_c -lpthread -ldl -lm

all: publisher subscriber

publisher: publisher.c hdds.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

subscriber: subscriber.c hdds.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f publisher subscriber

.PHONY: all clean
```

## Step 5: Build and Run

```bash
# Build
make

# Terminal 1 - Start subscriber
./subscriber

# Terminal 2 - Start publisher
./publisher
```

### Expected Output

**Subscriber:**
```
Starting subscriber...
Participant created
Reader created on topic: hello/world
Waiting for data...
Received: Hello #0 from C!
Received: Hello #1 from C!
Received: Hello #2 from C!
...
```

**Publisher:**
```
Starting publisher...
Participant created: publisher
Writer created on topic: hello/world
Waiting for discovery...
Published: Hello #0 from C!
Published: Hello #1 from C!
...
Done.
```

## C API Reference

### Participant

```c
// Create with default transport (UDP multicast)
struct HddsParticipant *p = hdds_participant_create("my_app");

// Create with specific transport
struct HddsParticipant *p = hdds_participant_create_with_transport(
    "my_app",
    UDP_MULTICAST  // or INTRA_PROCESS
);

// Properties
const char *name = hdds_participant_name(p);
uint32_t domain = hdds_participant_domain_id(p);

// Cleanup
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
// Create with default QoS
struct HddsDataReader *r = hdds_reader_create(participant, "topic_name");

// Create with custom QoS
struct HddsDataReader *r = hdds_reader_create_with_qos(participant, "topic_name", qos);

// Take data (removes from cache)
char buffer[1024];
size_t len_out;
enum HddsError result = hdds_reader_take(reader, buffer, sizeof(buffer), &len_out);

// Cleanup
hdds_reader_destroy(r);
```

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

```c
typedef enum HddsError {
    OK = 0,
    INVALID_ARGUMENT = 1,
    NOT_FOUND = 2,
    OPERATION_FAILED = 3,
    OUT_OF_MEMORY = 4,
} HddsError;
```

### Logging

```c
// Initialize with level
hdds_logging_init(INFO);  // OFF, ERROR, WARN, INFO, DEBUG, TRACE

// Or with environment variable (RUST_LOG)
hdds_logging_init_env(INFO);

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
idl-gen gen c temperature.idl -o temperature.h
```

This generates a header-only file with:
- C struct definitions
- `temperature_encode_cdr2_le()` - serialize to CDR2 bytes
- `temperature_decode_cdr2_le()` - deserialize from CDR2 bytes

### Step 3: Use Generated Code

```c
#include "temperature.h"
#include "hdds.h"

int main(void) {
    // Create participant and writer...
    struct HddsParticipant *participant =
        hdds_participant_create_with_transport("sensor", UDP_MULTICAST);
    struct HddsDataWriter *writer =
        hdds_writer_create(participant, "sensors/temperature");

    // Create typed data
    Temperature temp = {0};
    temp.sensor_id = 42;
    temp.value = 23.5f;
    temp.unit = "celsius";

    // Encode to CDR2 bytes
    uint8_t buffer[256];
    int encoded_len = temperature_encode_cdr2_le(&temp, buffer, sizeof(buffer));
    if (encoded_len < 0) {
        fprintf(stderr, "Encode failed: %d\n", encoded_len);
        return 1;
    }

    // Write encoded bytes
    hdds_writer_write(writer, buffer, (size_t)encoded_len);

    // ... cleanup
    return 0;
}
```

### Step 4: Decode on Subscriber

```c
#include "temperature.h"
#include "hdds.h"

// In subscriber:
uint8_t buffer[256];
size_t len_read;

if (hdds_reader_take(reader, buffer, sizeof(buffer), &len_read) == OK) {
    Temperature temp = {0};
    // Pre-allocate buffer for string field
    char unit_buf[32];
    temp.unit = unit_buf;

    int decoded = temperature_decode_cdr2_le(&temp, buffer, len_read);
    if (decoded > 0) {
        printf("Sensor %u: %.1f %s\n",
            temp.sensor_id, temp.value, temp.unit);
    }
}
```

:::tip String Fields
For struct fields that are `string`, the decoder does **not** allocate memory. You must pre-allocate the buffer and assign the pointer before calling decode.
:::

## What's Next?

- **[C API Reference](../api/c.md)** - Complete API documentation
- **[hdds_gen CLI](../tools/hdds-gen/cli-reference.md)** - Code generator options
- **[Hello World Rust](../getting-started/hello-world-rust.md)** - Rust version with typed API
