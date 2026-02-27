# C API Reference

HDDS provides C bindings through `hdds-c`, offering a stable ABI for C applications and FFI integration. The API operates on raw CDR-encoded bytes; use `hdds_gen` to generate typed serialization code.

:::info Version 1.0.0
This documents the current v1.0.0 API. The API is FFI-safe and ABI-stable.
:::

## Installation

```bash
# Build from source
git clone https://git.hdds.io/hdds/hdds.git
cd hdds
cargo build --release -p hdds-c

# Install library
sudo cp target/release/libhdds_c.so /usr/local/lib/
sudo cp crates/hdds-c/hdds.h /usr/local/include/
sudo ldconfig
```

## Header

```c
#include "hdds.h"
```

## Error Codes

Error codes are organized by category for easier debugging:

```c
typedef enum HddsError {
    // Generic (0-9)
    HDDS_OK = 0,                      // Success
    HDDS_ERROR = 1,                   // Generic error
    HDDS_INVALID_ARGUMENT = 2,        // Invalid argument passed
    HDDS_NOT_FOUND = 3,               // Resource not found
    HDDS_OUT_OF_MEMORY = 4,           // Memory allocation failed
    HDDS_TIMEOUT = 5,                 // Operation timed out
    HDDS_WOULD_BLOCK = 6,             // Non-blocking operation would block
    HDDS_ALREADY_EXISTS = 7,          // Resource already exists
    HDDS_NOT_INITIALIZED = 8,         // Not initialized
    HDDS_SHUTDOWN = 9,                // System shutting down

    // Configuration (10-19)
    HDDS_INVALID_QOS = 10,            // Invalid QoS configuration
    HDDS_QOS_MISMATCH = 11,           // QoS incompatibility
    HDDS_INVALID_DOMAIN = 12,         // Invalid domain ID
    HDDS_INVALID_TOPIC = 13,          // Invalid topic name
    HDDS_CONFIG_ERROR = 14,           // Configuration file error

    // I/O (20-29)
    HDDS_NETWORK_ERROR = 20,          // Network communication error
    HDDS_BIND_FAILED = 21,            // Socket bind failed
    HDDS_SEND_FAILED = 22,            // Send operation failed
    HDDS_RECEIVE_FAILED = 23,         // Receive operation failed
    HDDS_SERIALIZATION_ERROR = 24,    // Serialization/deserialization failed

    // Type (30-39)
    HDDS_TYPE_MISMATCH = 30,          // Type mismatch between endpoints
    HDDS_TYPE_NOT_REGISTERED = 31,    // Type not registered
    HDDS_INVALID_DATA = 32,           // Invalid data format

    // QoS (40-49)
    HDDS_DEADLINE_MISSED = 40,        // Deadline QoS missed
    HDDS_LIVELINESS_LOST = 41,        // Liveliness QoS lost
    HDDS_SAMPLE_REJECTED = 42,        // Sample rejected (resource limits)
    HDDS_SAMPLE_LOST = 43,            // Sample lost (reliability)
    HDDS_INCONSISTENT_POLICY = 44,    // Inconsistent QoS policies

    // Security (50-59)
    HDDS_PERMISSION_DENIED = 50,      // Access control denied
    HDDS_AUTHENTICATION_FAILED = 51,  // Authentication failed
    HDDS_ENCRYPTION_ERROR = 52,       // Encryption/decryption failed
    HDDS_CERTIFICATE_ERROR = 53,      // Certificate validation failed
    HDDS_SECURITY_NOT_ENABLED = 54,   // Security not enabled
} HddsError;
```

### Error Handling Example

```c
enum HddsError result = hdds_writer_write(writer, data, len);

switch (result) {
    case HDDS_OK:
        // Success
        break;
    case HDDS_PERMISSION_DENIED:
        fprintf(stderr, "Access denied by security policy\n");
        break;
    case HDDS_WOULD_BLOCK:
        fprintf(stderr, "Buffer full, try again later\n");
        break;
    case HDDS_NETWORK_ERROR:
        fprintf(stderr, "Network communication error\n");
        break;
    default:
        fprintf(stderr, "Error: %d\n", result);
        break;
}
```

## Transport Modes

```c
typedef enum HddsTransportMode {
    INTRA_PROCESS = 0,  // No network, same-process only (fastest)
    UDP_MULTICAST = 1,  // Network via UDP multicast (DDS interop)
} HddsTransportMode;
```

## Participant

The entry point to HDDS. All writers and readers are created from a participant.

### Creation

```c
// Create with default transport (UDP multicast)
struct HddsParticipant *participant = hdds_participant_create("my_app");

// Create with specific transport
struct HddsParticipant *participant =
    hdds_participant_create_with_transport("my_app", UDP_MULTICAST);

// Intra-process only (no network)
struct HddsParticipant *participant =
    hdds_participant_create_with_transport("my_app", INTRA_PROCESS);
```

### Properties

```c
// Get participant name
const char *name = hdds_participant_name(participant);

// Get domain ID (default: 0)
uint32_t domain_id = hdds_participant_domain_id(participant);

// Get participant ID (unique within domain)
uint8_t pid = hdds_participant_id(participant);
```

### Cleanup

```c
hdds_participant_destroy(participant);
```

## DataWriter

Writers publish data to a topic. Data is raw bytes (use `hdds_gen` for typed serialization).

### Creation

```c
// Create with default QoS
struct HddsDataWriter *writer = hdds_writer_create(participant, "my/topic");

// Create with custom QoS
struct HddsQoS *qos = hdds_qos_reliable();
hdds_qos_set_transient_local(qos);
hdds_qos_set_history_depth(qos, 10);

struct HddsDataWriter *writer =
    hdds_writer_create_with_qos(participant, "my/topic", qos);

hdds_qos_destroy(qos);  // QoS can be freed after writer creation
```

### Writing Data

```c
// Write raw bytes
const char *message = "Hello, DDS!";
enum HddsError result = hdds_writer_write(writer, message, strlen(message));

if (result != OK) {
    fprintf(stderr, "Write failed: %d\n", result);
}
```

### Properties

```c
// Get topic name
char topic_buf[256];
size_t topic_len;
hdds_writer_topic_name(writer, topic_buf, sizeof(topic_buf), &topic_len);
```

### Cleanup

```c
hdds_writer_destroy(writer);
```

## DataReader

Readers receive data from a topic.

### Creation

```c
// Create with default QoS
struct HddsDataReader *reader = hdds_reader_create(participant, "my/topic");

// Create with custom QoS
struct HddsQoS *qos = hdds_qos_reliable();
hdds_qos_set_history_depth(qos, 100);

struct HddsDataReader *reader =
    hdds_reader_create_with_qos(participant, "my/topic", qos);

hdds_qos_destroy(qos);
```

### Taking Data

```c
// Take single sample (non-blocking)
char buffer[1024];
size_t len_read;

enum HddsError result = hdds_reader_take(reader, buffer, sizeof(buffer), &len_read);

if (result == OK) {
    // Process data (len_read bytes in buffer)
    buffer[len_read] = '\0';  // If treating as string
    printf("Received: %s\n", buffer);
} else if (result == NOT_FOUND) {
    // No data available
}
```

### Properties

```c
// Get topic name
char topic_buf[256];
size_t topic_len;
hdds_reader_topic_name(reader, topic_buf, sizeof(topic_buf), &topic_len);
```

### Cleanup

```c
hdds_reader_destroy(reader);
```

## QoS Configuration

QoS profiles control delivery semantics.

### Creation

```c
// Predefined profiles
struct HddsQoS *qos = hdds_qos_default();      // Best effort, volatile
struct HddsQoS *qos = hdds_qos_best_effort();  // Explicit best effort
struct HddsQoS *qos = hdds_qos_reliable();     // Reliable delivery
struct HddsQoS *qos = hdds_qos_rti_defaults(); // RTI Connext compatibility

// Load from FastDDS XML profile
struct HddsQoS *qos = hdds_qos_from_xml("/path/to/profile.xml");
struct HddsQoS *qos = hdds_qos_load_fastdds_xml("/path/to/fastdds.xml");

// Clone existing QoS
struct HddsQoS *qos2 = hdds_qos_clone(qos);
```

### Reliability

```c
hdds_qos_set_reliable(qos);     // Guaranteed delivery
hdds_qos_set_best_effort(qos);  // Fire and forget

bool reliable = hdds_qos_is_reliable(qos);
```

### Durability

```c
hdds_qos_set_volatile(qos);        // No persistence
hdds_qos_set_transient_local(qos); // Persist for late joiners
hdds_qos_set_persistent(qos);      // Disk persistence

bool transient = hdds_qos_is_transient_local(qos);
```

### History

```c
hdds_qos_set_history_depth(qos, 10);  // KEEP_LAST with depth
hdds_qos_set_history_keep_all(qos);   // KEEP_ALL (unbounded)

uint32_t depth = hdds_qos_get_history_depth(qos);
```

### Deadline & Lifespan

```c
// Deadline: expected update frequency
hdds_qos_set_deadline_ns(qos, 100 * 1000 * 1000);  // 100ms

// Lifespan: how long data remains valid
hdds_qos_set_lifespan_ns(qos, 5 * 1000 * 1000 * 1000);  // 5 seconds

uint64_t deadline = hdds_qos_get_deadline_ns(qos);
uint64_t lifespan = hdds_qos_get_lifespan_ns(qos);
```

### Liveliness

```c
// Automatic liveliness
hdds_qos_set_liveliness_automatic_ns(qos, 1000000000);  // 1 second lease

// Manual by participant
hdds_qos_set_liveliness_manual_participant_ns(qos, 500000000);

// Manual by topic
hdds_qos_set_liveliness_manual_topic_ns(qos, 250000000);

enum HddsLivelinessKind kind = hdds_qos_get_liveliness_kind(qos);
uint64_t lease = hdds_qos_get_liveliness_lease_ns(qos);
```

### Ownership

```c
hdds_qos_set_ownership_shared(qos);             // Multiple writers
hdds_qos_set_ownership_exclusive(qos, 100);     // Single writer, strength=100

bool exclusive = hdds_qos_is_ownership_exclusive(qos);
int32_t strength = hdds_qos_get_ownership_strength(qos);
```

### Partitions

```c
hdds_qos_add_partition(qos, "sensor_data");
hdds_qos_add_partition(qos, "control");
```

### Other Policies

```c
// Time-based filter (throttle high-frequency data)
hdds_qos_set_time_based_filter_ns(qos, 10000000);  // Min 10ms between samples

// Latency budget
hdds_qos_set_latency_budget_ns(qos, 50000000);  // 50ms budget

// Transport priority
hdds_qos_set_transport_priority(qos, 10);

// Resource limits
hdds_qos_set_resource_limits(qos,
    1000,   // max_samples
    100,    // max_instances
    10);    // max_samples_per_instance

// Getters
uint64_t filter = hdds_qos_get_time_based_filter_ns(qos);
uint64_t budget = hdds_qos_get_latency_budget_ns(qos);
int32_t priority = hdds_qos_get_transport_priority(qos);
size_t max_samples = hdds_qos_get_max_samples(qos);
size_t max_instances = hdds_qos_get_max_instances(qos);
size_t max_per_instance = hdds_qos_get_max_samples_per_instance(qos);
```

### Cleanup

```c
hdds_qos_destroy(qos);
```

## WaitSet

Event-driven waiting for data availability.

### Creation

```c
struct HddsWaitSet *waitset = hdds_waitset_create();
```

### Status Conditions

```c
// Get reader's status condition
const struct HddsStatusCondition *condition =
    hdds_reader_get_status_condition(reader);

// Attach to waitset
hdds_waitset_attach_status_condition(waitset, condition);
```

### Guard Conditions

```c
// Create guard condition (for custom signaling)
const struct HddsGuardCondition *guard = hdds_guard_condition_create();

// Attach to waitset
hdds_waitset_attach_guard_condition(waitset, guard);

// Trigger guard condition
hdds_guard_condition_set_trigger(guard, true);
```

### Waiting

```c
const void *triggered[10];
size_t triggered_count;
int64_t timeout_ns = 5LL * 1000 * 1000 * 1000;  // 5 seconds

enum HddsError result = hdds_waitset_wait(
    waitset,
    timeout_ns,
    triggered,
    10,              // max conditions to return
    &triggered_count
);

if (result == OK && triggered_count > 0) {
    // Process triggered conditions
    for (size_t i = 0; i < triggered_count; i++) {
        if (triggered[i] == condition) {
            // Reader has data
            while (hdds_reader_take(reader, buffer, sizeof(buffer), &len) == OK) {
                // Process data
            }
        }
    }
}
```

### Cleanup

```c
hdds_waitset_detach_condition(waitset, condition);
hdds_status_condition_release(condition);
hdds_guard_condition_release(guard);
hdds_waitset_destroy(waitset);
```

## Publisher & Subscriber (Grouping)

Publishers and subscribers group writers/readers with shared QoS policies.

### Publisher

```c
// Create publisher with default QoS
struct HddsPublisher *publisher = hdds_publisher_create(participant);

// Create with custom QoS
struct HddsPublisher *publisher =
    hdds_publisher_create_with_qos(participant, qos);

// Create writer from publisher (inherits publisher QoS)
struct HddsDataWriter *writer =
    hdds_publisher_create_writer(publisher, "my/topic");

// Create writer with custom QoS (overrides publisher defaults)
struct HddsQoS *writer_qos = hdds_qos_reliable();
struct HddsDataWriter *writer =
    hdds_publisher_create_writer_with_qos(publisher, "my/topic", writer_qos);
hdds_qos_destroy(writer_qos);

// Cleanup
hdds_writer_destroy(writer);
hdds_publisher_destroy(publisher);
```

### Subscriber

```c
// Create subscriber with default QoS
struct HddsSubscriber *subscriber = hdds_subscriber_create(participant);

// Create with custom QoS
struct HddsSubscriber *subscriber =
    hdds_subscriber_create_with_qos(participant, qos);

// Create reader from subscriber (inherits subscriber QoS)
struct HddsDataReader *reader =
    hdds_subscriber_create_reader(subscriber, "my/topic");

// Create reader with custom QoS (overrides subscriber defaults)
struct HddsQoS *reader_qos = hdds_qos_reliable();
struct HddsDataReader *reader =
    hdds_subscriber_create_reader_with_qos(subscriber, "my/topic", reader_qos);
hdds_qos_destroy(reader_qos);

// Cleanup
hdds_reader_destroy(reader);
hdds_subscriber_destroy(subscriber);
```

## Logging

```c
// Initialize with level
hdds_logging_init(INFO);  // OFF, ERROR, WARN, INFO, DEBUG, TRACE

// Or use RUST_LOG environment variable with fallback
hdds_logging_init_env(INFO);

// Or with custom filter string
hdds_logging_init_with_filter("hdds=debug,hdds::rtps=trace");
```

Log levels:
```c
typedef enum HddsLogLevel {
    OFF = 0,
    ERROR = 1,
    WARN = 2,
    INFO = 3,
    DEBUG = 4,
    TRACE = 5,
} HddsLogLevel;
```

## Telemetry

Built-in metrics collection and export.

### Initialize

```c
struct HddsMetrics *metrics = hdds_telemetry_init();

// Get existing (if already initialized)
struct HddsMetrics *metrics = hdds_telemetry_get();
```

### Snapshot Metrics

```c
struct HddsMetricsSnapshot snapshot;
hdds_telemetry_snapshot(metrics, &snapshot);

printf("Messages sent: %lu\n", snapshot.MESSAGES_SENT);
printf("Messages received: %lu\n", snapshot.MESSAGES_RECEIVED);
printf("Latency p99: %lu ns\n", snapshot.LATENCY_P99_NS);
```

Available metrics:
```c
typedef struct HddsMetricsSnapshot {
    uint64_t TIMESTAMP_NS;
    uint64_t MESSAGES_SENT;
    uint64_t MESSAGES_RECEIVED;
    uint64_t MESSAGES_DROPPED;
    uint64_t BYTES_SENT;
    uint64_t LATENCY_P50_NS;
    uint64_t LATENCY_P99_NS;
    uint64_t LATENCY_P999_NS;
    uint64_t MERGE_FULL_COUNT;
    uint64_t WOULD_BLOCK_COUNT;
} HddsMetricsSnapshot;
```

### Export Server

Start a server for HDDS Viewer connection:

```c
struct HddsTelemetryExporter *exporter =
    hdds_telemetry_start_exporter("0.0.0.0", 4242);

// ... application runs ...

hdds_telemetry_stop_exporter(exporter);
```

### Cleanup

```c
hdds_telemetry_release(metrics);
```

## Utilities

```c
// Get HDDS version string
const char *version = hdds_version();
printf("HDDS version: %s\n", version);
```

## Using with Typed Data

The C API operates on raw bytes. For typed data, use `hdds_gen` to generate C structs and CDR2 serialization functions:

```bash
idl-gen gen c MyTypes.idl -o my_types.h
```

This generates:
- C struct definitions
- `typename_encode_cdr2_le()` - serialize struct to bytes
- `typename_decode_cdr2_le()` - deserialize bytes to struct

Example usage:

```c
#include "my_types.h"
#include "hdds.h"

// Encode before writing
MyType data = { .id = 42, .value = 3.14f };
uint8_t buffer[256];
int len = mytype_encode_cdr2_le(&data, buffer, sizeof(buffer));
hdds_writer_write(writer, buffer, len);

// Decode after reading
uint8_t read_buf[256];
size_t read_len;
if (hdds_reader_take(reader, read_buf, sizeof(read_buf), &read_len) == OK) {
    MyType decoded = {0};
    mytype_decode_cdr2_le(&decoded, read_buf, read_len);
}
```

## Complete Example

```c
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "hdds.h"

int main(void) {
    // Initialize logging
    hdds_logging_init(INFO);

    // Create participant
    struct HddsParticipant *participant =
        hdds_participant_create_with_transport("example", UDP_MULTICAST);
    if (!participant) {
        fprintf(stderr, "Failed to create participant\n");
        return 1;
    }

    // Create QoS
    struct HddsQoS *qos = hdds_qos_reliable();
    hdds_qos_set_transient_local(qos);
    hdds_qos_set_history_depth(qos, 10);

    // Create writer
    struct HddsDataWriter *writer =
        hdds_writer_create_with_qos(participant, "hello/world", qos);
    hdds_qos_destroy(qos);

    if (!writer) {
        fprintf(stderr, "Failed to create writer\n");
        hdds_participant_destroy(participant);
        return 1;
    }

    // Wait for discovery
    sleep(2);

    // Publish messages
    for (int i = 0; i < 10; i++) {
        char message[64];
        int len = snprintf(message, sizeof(message), "Hello #%d!", i);

        if (hdds_writer_write(writer, message, len) == OK) {
            printf("Published: %s\n", message);
        }
        sleep(1);
    }

    // Cleanup
    hdds_writer_destroy(writer);
    hdds_participant_destroy(participant);

    return 0;
}
```

## Thread Safety

- Participant creation/destruction: NOT thread-safe
- Writer/Reader creation: NOT thread-safe
- `hdds_writer_write()`: Thread-safe (multiple threads can write concurrently)
- `hdds_reader_take()`: NOT thread-safe (use external locking or one reader per thread)
- QoS functions: NOT thread-safe
- WaitSet: NOT thread-safe

## Memory Management

- All `hdds_*_create*` functions allocate memory
- Corresponding `hdds_*_destroy` must be called to free
- `const` return values (like `hdds_participant_name()`) are internal pointers, valid until entity is destroyed
- QoS can be destroyed after entity creation (values are copied)

## Next Steps

- [Hello World C](../getting-started/hello-world-c.md) - Complete tutorial
- [hdds_gen](../tools/hdds-gen/cli-reference.md) - Code generator for typed data
- [Rust API](../api/rust.md) - Native Rust API
