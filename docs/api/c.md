# C API Reference

HDDS provides C bindings through `hdds-c`, offering a stable ABI for C applications and FFI integration. The API operates on raw CDR-encoded bytes; use `hdds_gen` to generate typed serialization code.

:::info Stability contract
This reference follows the generated header shipped by the current tree. The
C SDK API/ABI compatibility policy applies from HDDS 1.4.0; see
[`sdk/c/API_STABILITY.md`](../../sdk/c/API_STABILITY.md).
:::

## Installation

```bash
# Build from source
git clone https://git.hdds.io/hdds/hdds.git
cd hdds
cargo build --release -p hdds-c

# Install library
sudo cp target/release/libhdds_c.so /usr/local/lib/
sudo cp sdk/c/include/hdds.h /usr/local/include/
sudo ldconfig
```

## Header

```c
#include "hdds.h"
```

## Error Codes

Most functions return an `HddsError`. Constructors return `NULL` on failure.

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
        fprintf(stderr, "Would block (non-blocking mode), try again later\n");
        break;
    case HDDS_TRANSPORT_ERROR:
        fprintf(stderr, "Transport error\n");
        break;
    default:
        fprintf(stderr, "Error: %d\n", result);
        break;
}
```

## Transport Modes

```c
typedef enum HddsTransportMode {
    HDDS_TRANSPORT_INTRA_PROCESS = 0,
    HDDS_TRANSPORT_UDP_MULTICAST = 1,
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
    hdds_participant_create_with_transport("my_app", HDDS_TRANSPORT_UDP_MULTICAST);

// Intra-process only (no network)
struct HddsParticipant *participant =
    hdds_participant_create_with_transport("my_app", HDDS_TRANSPORT_INTRA_PROCESS);
```

### Domain ID

The constructors above take no domain. Without a call that sets one, the participant
takes its domain from `HDDS_DOMAIN_ID` (see [environment variables](../reference/environment-vars.md)).
To set the domain in code, use the configuration builder; the domain it sets wins over the variable:

```c
struct HddsParticipantConfig *config = hdds_config_create("my_app");
hdds_config_set_domain_id(config, 42);
hdds_config_set_transport_mode(config, HDDS_TRANSPORT_UDP_MULTICAST);
struct HddsParticipant *participant = hdds_config_build(config);  // consumes config
```

### Properties

```c
// Get participant name
const char *name = hdds_participant_name(participant);

// Domain ID the participant was created on
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

if (result != HDDS_OK) {
    fprintf(stderr, "Write failed: %d\n", result);
}
```

### Matching

Discovery is asynchronous: a writer created a moment ago may have no reader yet.
A VOLATILE writer does not deliver a sample written before a reader matches, so
wait for a match before the first write:

```c
uint32_t matched = 0;
hdds_writer_matched_reader_count(writer, &matched);   // 0 until a reader matched

// Or block for up to 10 s until at least one reader is matched
enum HddsError rc = hdds_writer_wait_for_matched_readers(writer, 1, 10000);
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

enum HddsError result = hdds_reader_take(reader, buffer, sizeof(buffer) - 1, &len_read);

if (result == HDDS_OK) {
    // Process data (len_read bytes in buffer); the spare byte keeps it NUL-terminated
    buffer[len_read] = '\0';  // If treating as string
    printf("Received: %s\n", buffer);
} else if (result == HDDS_NOT_FOUND) {
    // No sample available
}
```

`hdds_reader_take` returns `HDDS_NOT_FOUND` when no sample is available. When the buffer is
smaller than the next sample, it returns `HDDS_OUT_OF_MEMORY`, writes the required size to
`len_read` and removes nothing: size the buffer from that value and take again.

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
struct HddsQoS *qos = hdds_qos_rti_defaults(); // Reliable, Volatile, KeepLast(10) preset

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
hdds_qos_set_persistent(qos);      // PERSISTENT kind (see the durability guide)

bool transient = hdds_qos_is_transient_local(qos);
```

In the core runtime, PERSISTENT keeps its samples in the writer's memory, like
transient-local, and nothing is written to disk. See
[Durability](../guides/qos-policies/durability.md).

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
hdds_qos_set_lifespan_ns(qos, 5ULL * 1000 * 1000 * 1000);  // 5 seconds

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

### Read and Query Conditions

A ReadCondition or QueryCondition belongs to a reader and triggers on the
samples it holds. A QueryCondition evaluates its expression on the payload
decoded with a dynamic type descriptor.

```c
struct HddsReadCondition *rc = hdds_create_read_condition(
    reader, HDDS_SAMPLE_STATE_NOT_READ, HDDS_VIEW_STATE_ANY, HDDS_INSTANCE_STATE_ALIVE);
hdds_waitset_attach_read_condition(waitset, rc);

const char *params[] = { "10" };
struct HddsQueryCondition *qc = hdds_create_query_condition(
    reader, HDDS_SAMPLE_STATE_ANY, HDDS_VIEW_STATE_ANY, HDDS_INSTANCE_STATE_ANY,
    desc, "value > %0", params, 1);
hdds_waitset_attach_query_condition(waitset, qc);

struct HddsSampleInfo info;
while (hdds_reader_take_w_condition(reader, rc, buffer, sizeof(buffer), &len, &info) == HDDS_OK) {
    // one matching sample per call; HDDS_NOT_FOUND when none is left
}
```

Semantics, limits and the ContentFilteredTopic functions:
[read-query-conditions.md](../read-query-conditions.md).

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

if (result == HDDS_OK && triggered_count > 0) {
    // Process triggered conditions
    for (size_t i = 0; i < triggered_count; i++) {
        if (triggered[i] == condition) {
            // Reader has data
            while (hdds_reader_take(reader, buffer, sizeof(buffer), &len) == HDDS_OK) {
                // Process data
            }
        }
    }
}
```

### Cleanup

```c
hdds_waitset_detach_condition(waitset, condition);
hdds_waitset_detach_condition(waitset, rc);
hdds_waitset_detach_condition(waitset, qc);
hdds_status_condition_release(condition);
hdds_guard_condition_release(guard);
hdds_read_condition_delete(rc);
hdds_query_condition_delete(qc);
hdds_waitset_destroy(waitset);
```

## Listeners

A listener calls you back on an event instead of you waiting on a WaitSet.
Fill an `HddsReaderListener` / `HddsWriterListener` and install it; the
struct is copied, so it can live on the stack.

The generated header spells struct fields in SCREAMING_SNAKE_CASE, as for
every struct of `hdds.h`: `ON_DATA_AVAILABLE`, `USER_DATA`,
`status->CURRENT_COUNT`.

```c
static void on_data(const uint8_t *data, size_t len, void *user_data) {
    struct app *app = user_data;          /* passed through untouched */
    /* data is valid only during the call: copy what you keep */
}

static void on_matched(const HddsSubscriptionMatchedStatus *s, void *user_data) {
    printf("matched writers: %u (change %d)\n", s->CURRENT_COUNT, s->CURRENT_COUNT_CHANGE);
}

HddsReaderListener rl = {0};
rl.ON_DATA_AVAILABLE = on_data;
rl.ON_SUBSCRIPTION_MATCHED = on_matched;
rl.USER_DATA = &app;
hdds_reader_set_listener(reader, &rl);   /* HDDS_OK */
...
hdds_reader_clear_listener(reader);      /* waits for running callbacks */
free_app_state(&app);                    /* safe now */
```

| Reader callback | Fires | Writer callback | Fires |
|-----------------|:-----:|-----------------|:-----:|
| `ON_DATA_AVAILABLE` (bytes of the sample) | yes | `ON_SAMPLE_WRITTEN` (bytes, sequence number) | yes |
| `ON_SUBSCRIPTION_MATCHED` | yes | `ON_PUBLICATION_MATCHED` | yes |
| `ON_SAMPLE_REJECTED` | yes | `ON_OFFERED_DEADLINE_MISSED` | yes |
| `ON_DEADLINE_MISSED` | yes | `ON_OFFERED_INCOMPATIBLE_QOS` | yes |
| `ON_INCOMPATIBLE_QOS` | yes | `ON_LIVELINESS_LOST` | yes |
| `ON_LIVELINESS_CHANGED` (alive and not-alive writers) | yes | | |
| `ON_SAMPLE_LOST` | yes, see below | | |

`ON_LIVELINESS_LOST` fires for a writer whose liveliness kind is
MANUAL_BY_PARTICIPANT or MANUAL_BY_TOPIC when it fails to assert within its
lease. `ON_SAMPLE_LOST` fires for samples the reader discards with no other
record, such as the samples of a coherent set that can never be completed.
Matched statuses count every matching endpoint, including one of the same
participant. A match that already exists when the listener is installed does
not raise a callback: read the current state with
`hdds_reader_get_subscription_matched_status` or
`hdds_writer_get_publication_matched_status`.

Threading and safety contract:

- **Threads.** Callbacks run on HDDS threads: the router (UDP), TCP/QUIC or
  control thread for a sample arriving over a transport; **the thread that
  called `hdds_writer_write`, inside that call,** for a sample written by a
  writer of the same participant (or of any participant of the process when
  one of them is `HDDS_TRANSPORT_INTRA_PROCESS`); discovery threads for
  matched and incompatible-QoS events; the thread that refused or lost the
  sample (or a short-lived notification thread of that reader, under a burst)
  for `ON_SAMPLE_REJECTED` / `ON_SAMPLE_LOST`; the writing thread for
  `ON_SAMPLE_WRITTEN` / `ON_OFFERED_DEADLINE_MISSED`; the thread calling a
  take/read for `ON_DEADLINE_MISSED`. Callbacks of one listener can run
  concurrently on different threads.
- **No HDDS lock is held across a callback**: a callback may take/read the
  reader it belongs to (mind that `hdds_reader_take` itself is not thread-safe
  against a concurrent take on the same reader), write, and set or clear
  listeners, including its own.
- **Removal waits.** `hdds_reader_clear_listener`, a replacing
  `hdds_reader_set_listener` and `hdds_reader_destroy` (and the writer
  equivalents) return only once no callback of the previous listener runs on
  another thread; afterwards it is never called again and `USER_DATA` may be
  freed. From inside one of its own callbacks they do not wait for that
  callback. Do not call them while holding a lock one of the callbacks takes,
  and do not let two listeners' callbacks remove each other from two threads
  (each removal would wait for the other).
- **Never destroy a reader or writer from inside its own callback**: the HDDS
  code that called back keeps using it afterwards (`hdds_writer_write` after
  `ON_SAMPLE_WRITTEN`, a take after `ON_DEADLINE_MISSED`). Destroy called
  there removes the listener but leaks the entity instead of freeing it, and
  logs an error. Clearing the listener there is fine.
- **Bindings: `hdds_reader_exchange_listener` / `hdds_writer_exchange_listener`**
  install (or, with a NULL listener, remove) like set/clear and also return
  the `USER_DATA` of the listener they replaced and drained. A binding that
  owns per-listener state frees exactly that state, whatever order concurrent
  installs on one entity reached HDDS in (the C++ and Python SDKs do this).
  Never install a NULL `USER_DATA` through it: it reads as "no listener".
- **NULL callback = not interested.** Its status is not reported to this
  listener; a NULL `ON_SAMPLE_REJECTED` leaves SAMPLE_REJECTED on the
  reader's status condition, where a WaitSet sees it.
- **Never unwind out of a callback** (`longjmp`, a C++ exception): the C++
  SDK catches exceptions in its trampolines for you.
- Status and data pointers are valid only during the callback.

`sdk/c/tests/test_listener.c` exercises all of the above, including a clear
and a destroy racing a running callback under AddressSanitizer.

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
hdds_logging_init(HDDS_LOG_INFO);

// Or use RUST_LOG environment variable with fallback
hdds_logging_init_env(HDDS_LOG_INFO);

// Or with custom filter string
hdds_logging_init_with_filter("hdds=debug,hdds::protocol=trace");
```

Log levels:
```c
typedef enum HddsLogLevel {
    HDDS_LOG_OFF = 0,
    HDDS_LOG_ERROR = 1,
    HDDS_LOG_WARN = 2,
    HDDS_LOG_INFO = 3,
    HDDS_LOG_DEBUG = 4,
    HDDS_LOG_TRACE = 5,
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

printf("Messages sent: %llu\n", (unsigned long long)snapshot.MESSAGES_SENT);
printf("Messages received: %llu\n", (unsigned long long)snapshot.MESSAGES_RECEIVED);
printf("Latency p99: %llu ns\n", (unsigned long long)snapshot.LATENCY_P99_NS);
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

What the counters count (process-wide, all writers and readers, every
transport):

- `MESSAGES_SENT`: one per successful `write` (including writes with no
  matched reader); `BYTES_SENT`: the serialized payload bytes of those writes,
  before RTPS framing, fragmentation or encryption.
- `MESSAGES_RECEIVED`: one per sample deposited in a reader's history, counted
  when the application next accesses the reader (`read`, `take`, ...), so a
  sample still queued in the transport is not counted yet.
- `MESSAGES_DROPPED`: samples discarded after arriving for want of room, or
  refused by a content filter. `MERGE_FULL_COUNT`: a local reader could not take
  a sample for lack of room. `WOULD_BLOCK_COUNT`: a writer operation came back
  `WouldBlock`.

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
hddsgen gen c temperature.idl -o temperature.h     # hddsgen 2.0 or later
```

For `struct Temperature { uint32 sensor_id; float value; string unit; };` this generates, among others:
- the struct `Temperature` (`unit` is a `char *`)
- `temperature_encode_cdr2_le(const Temperature *, uint8_t *dst, size_t len)`: the byte count written, or a negative `CDR_*` code
- `temperature_decode_cdr2_le_alloc(Temperature *, const uint8_t *src, size_t len, hdds_x2c_alloc_fn, void *ctx)`: the byte count read, or a negative `CDR_*` code
- `temperature_decode_cdr2_le(...)`: the same without an allocator; it works for types without strings or sequences only (it returns `-CDR_OUT_OF_MEMORY` otherwise)
- `temperature_create_writer(participant, topic, qos)`: the typed DataWriter constructor. It labels samples APPENDABLE, the extensibility the generated type has. `hdds_writer_create()` labels FINAL.

Example usage:

```c
#include "hdds.h"
#include "temperature.h"

// writer and reader are created as in the examples above
void send_and_receive(struct HddsDataWriter *writer, struct HddsDataReader *reader) {
    // Encode before writing
    Temperature data = { .sensor_id = 42, .value = 23.5f, .unit = "celsius" };
    uint8_t buffer[256];
    int len = temperature_encode_cdr2_le(&data, buffer, sizeof(buffer));
    if (len < 0) {
        /* failed: -CDR_BUFFER_TOO_SMALL, ... */
        return;
    }
    hdds_writer_write(writer, buffer, (size_t)len);

    // Decode after reading. String fields need storage: an arena over a buffer you own.
    static uint8_t storage[256];
    hdds_x2c_arena arena;
    hdds_x2c_arena_init(&arena, storage, sizeof(storage));

    uint8_t read_buf[256];
    size_t read_len;
    if (hdds_reader_take(reader, read_buf, sizeof(read_buf), &read_len) == HDDS_OK) {
        Temperature decoded = {0};
        arena.used = 0;   // reuse the storage for each sample
        int n = temperature_decode_cdr2_le_alloc(&decoded, read_buf, read_len,
                                                 hdds_x2c_arena_alloc, &arena);
        if (n < 0) {
            /* failed: n is a negative CDR_* code */
        }
    }
}
```

`hdds_x2c_arena_alloc` is a bump allocator (no free; set `arena.used = 0` to reuse the
buffer). Any function with the signature `void *(*)(void *ctx, size_t size)` works as
the allocator. The encode and decode functions return a non-negative count on
success and a negative code on failure; a positive return is never an error.

See [Hello World C](../getting-started/hello-world-c.md), section Using with Typed Data,
for complete publisher and subscriber programs.

## Keyed Types (@key)

A type with `@key` members has instances: samples that share a key belong to one
instance, and a writer can dispose or unregister an instance. Declare the key in the
IDL and generate the header as usual:

```idl
struct Temperature {
    @key uint32 sensor_id;
    float  value;
    string unit;
};
```

```bash
hddsgen gen c temperature.idl -o temperature.h     # hddsgen 2.0 or later
```

Include `hdds.h` before the generated header: the header emits the instance functions
only when `hdds.h` was included first. With `@key`, the header adds these functions to
the ones of the previous section:

| Function | Calls (hdds.h) | What it does |
|----------|----------------|--------------|
| `temperature_create_keyed_writer(participant, topic, qos)` | `hdds_writer_create_keyed` | Creates a writer for the keyed type (type name `Temperature`) |
| `temperature_write(writer, &value)` | `hdds_writer_write_keyed` | Writes a sample; the key fields of `value` select the instance |
| `temperature_dispose(writer, &value)` | `hdds_writer_dispose_keyed` | Disposes the instance identified by the key fields of `value` |
| `temperature_unregister_instance(writer, &value)` | `hdds_writer_unregister_instance_keyed` | Unregisters that instance |
| `temperature_register_instance(writer, &value, &handle)` | `hdds_writer_register_instance_keyed` | Registers that instance and returns its handle |
| `temperature_compute_key(&value, hash)` | none | Writes the 16-byte KeyHash (RTPS 2.5 9.6.4.8) and returns 1 for a keyed type |

`hdds_writer_write` fails (`HDDS_OPERATION_FAILED`) on a writer created keyed: write through
`temperature_write`. The write, dispose, unregister and register functions each have a `_w_timestamp` variant
that takes a source timestamp, in nanoseconds since the Unix epoch, as its last argument.

Without `@key`, the header has none of these functions, `temperature_compute_key` returns 0,
and `temperature_create_writer()` is the writer to use.

Writer side, as compiled for this page (`keyed_publisher.c`, with `temperature.h` next to it):

```c
#include <stdio.h>
#include <unistd.h>
#include "hdds.h"        /* include before the generated header: it enables the typed write helpers */
#include "temperature.h"

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
        temperature_create_keyed_writer(participant, "sensors/temperature", qos);
    hdds_qos_destroy(qos);
    if (writer == NULL) {
        fprintf(stderr, "Failed to create writer\n");
        hdds_participant_destroy(participant);
        return 1;
    }

    enum HddsError status = hdds_writer_wait_for_matched_readers(writer, 1, 10000);
    if (status != HDDS_OK) {
        fprintf(stderr, "No subscriber matched (error %d): see Network Prerequisites\n", status);
        hdds_writer_destroy(writer);
        hdds_participant_destroy(participant);
        return 1;
    }

    // Two instances (sensor 1 and sensor 2), alternating
    int failed = 0;
    for (uint32_t i = 0; i < 10; i++) {
        Temperature temp = {0};
        temp.sensor_id = 1 + (i % 2);
        temp.value = 20.0f + (float)i;
        temp.unit = "celsius";

        // Instance identity: the 16-byte KeyHash of the key fields (1 = keyed type)
        uint8_t key_hash[16];
        if (temperature_compute_key(&temp, key_hash) != 1) {
            fprintf(stderr, "Key hash failed\n");
            failed = 1;
            break;
        }

        if (temperature_write(writer, &temp) != HDDS_OK) {
            fprintf(stderr, "Write failed\n");
            failed = 1;
        } else {
            printf("Published: sensor %u, %.1f %s\n", temp.sensor_id, temp.value, temp.unit);
        }
        sleep(1);
    }

    // Instance lifecycle: dispose sensor 1, unregister sensor 2
    Temperature s1 = {0};
    s1.sensor_id = 1;
    s1.unit = "celsius";
    Temperature s2 = {0};
    s2.sensor_id = 2;
    s2.unit = "celsius";
    if (temperature_dispose(writer, &s1) != HDDS_OK) failed = 1;
    if (temperature_unregister_instance(writer, &s2) != HDDS_OK) failed = 1;
    printf("Disposed sensor 1, unregistered sensor 2\n");

    hdds_writer_destroy(writer);
    hdds_participant_destroy(participant);
    return failed;
}
```

```bash
gcc -Wall -Wextra -O2 -I../hdds/sdk/c/include keyed_publisher.c \
    ../hdds/target/release/libhdds_c.a -lpthread -ldl -lm -o keyed_publisher
```

The reader creates its DataReader with the same type name,
`hdds_reader_create_with_type(participant, topic, "Temperature", qos)`, takes the bytes and
decodes them with `temperature_decode_cdr2_le_alloc()` as in the typed example above.

## Complete Example

```c
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "hdds.h"

int main(void) {
    // Initialize logging
    hdds_logging_init(HDDS_LOG_INFO);

    // Create participant
    struct HddsParticipant *participant =
        hdds_participant_create_with_transport("example", HDDS_TRANSPORT_UDP_MULTICAST);
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

    // Wait until a subscriber is matched (10 s at most) before the first write
    if (hdds_writer_wait_for_matched_readers(writer, 1, 10000) != HDDS_OK) {
        fprintf(stderr, "No subscriber matched after 10 s\n");
        hdds_writer_destroy(writer);
        hdds_participant_destroy(participant);
        return 1;
    }

    // Publish messages
    for (int i = 0; i < 10; i++) {
        char message[64];
        int len = snprintf(message, sizeof(message), "Hello #%d!", i);

        if (hdds_writer_write(writer, message, len) == HDDS_OK) {
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
- `hdds_writer_write()`: one writing thread per writer at a time (the writer feeds single-producer reader rings); use one writer per thread or serialize the calls with a lock
- `hdds_reader_take()`: NOT thread-safe (use external locking or one reader per thread)
- QoS functions: NOT thread-safe
- WaitSet: NOT thread-safe
- Listener install / clear: thread-safe; see [Listeners](#listeners) for the callback threads

## Memory Management

- All `hdds_*_create*` functions allocate memory
- Corresponding `hdds_*_destroy` must be called to free
- `const` return values (like `hdds_participant_name()`) are internal pointers, valid until entity is destroyed
- QoS can be destroyed after entity creation (values are copied)

## Next Steps

- [Hello World C](../getting-started/hello-world-c.md) - Complete tutorial
- [hdds_gen](../tools/hdds-gen/cli-reference.md) - Code generator for typed data
- [Rust API](../api/rust.md) - Native Rust API
