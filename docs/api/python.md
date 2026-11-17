# Python API Reference

HDDS provides Python bindings through the `hdds` package, offering a Pythonic API with context managers and fluent QoS configuration.

:::info Version
The SDK carries the workspace version (`hdds.__version__` equals the root
`Cargo.toml` version; `scripts/test-sdk.sh` Layer 1 fails when they diverge).
The API operates on raw bytes; use `hdds_gen` to generate typed serialization code.
:::

## Installation

The package is pure Python (`ctypes` bindings, wheel tag `py3-none-any`)
and loads the `hdds-c` shared library at first use. It is installed from
this repository; it is not published on PyPI.

```bash
# 1. Native library (default features; never --all-features, the rmw
#    feature links ROS 2 symbols)
cd /path/to/hdds
cargo build --release -p hdds-c        # -> target/release/libhdds_c.so

# 2. Wheel, built offline with the host's setuptools (>= 77)
cd sdk/python
python3 -m pip wheel --no-build-isolation --no-deps --no-index -w dist .

# 3. Install and point the loader at the library
python3 -m venv ~/.venvs/hdds
~/.venvs/hdds/bin/python -m pip install --no-index dist/hdds-*-py3-none-any.whl
export HDDS_LIB_PATH=/path/to/hdds/target/release
~/.venvs/hdds/bin/python -c "import hdds; print(hdds.library_path(), hdds.version())"
```

Library discovery order (`HDDS_LIB_PATH` strict override, then a library
bundled in the installed package under `hdds/_lib/` if the wheel ships one,
then `<repo>/target/{release,debug}` for source checkouts, then
`/usr/local/lib`, `/usr/lib`, then the system dynamic linker) and the
fail-closed `ImportError` are documented in
[`sdk/python/README.md`](https://git.hdds.io/hdds/hdds/src/branch/master/sdk/python/README.md),
verbatim from `hdds/_native.py`. Proof: `scripts/test-sdk.sh --python`
(source-tree pytest, offline wheel build, bare-venv install, installed
smoke, fail-closed import).

## Quick Start

```python
import hdds

# Initialize logging
hdds.logging.init(hdds.LogLevel.INFO)

# Create participant with context manager
with hdds.Participant("my_app") as p:
    # Fluent QoS builder
    qos = hdds.QoS.reliable().transient_local().history_depth(10)

    # Create writer
    writer = p.create_writer("hello/world", qos=qos)

    # Publish raw bytes
    writer.write(b"Hello, DDS!")
```

## Participant

Entry point for all DDS operations.

### Creation

```python
from hdds import Participant

# Basic creation (domain from HDDS_DOMAIN_ID, else 0)
participant = Participant("my_app")

# With domain ID
participant = Participant("my_app", domain_id=42)

# With discovery disabled (intra-process only)
participant = Participant("my_app", enable_discovery=False)
```

Without `domain_id` (or with `None`) the domain is `HDDS_DOMAIN_ID` if set, else 0
(see [Environment variables](../reference/environment-vars.md)). An explicit
`domain_id` always wins. A malformed `HDDS_DOMAIN_ID` (for example `abc` or `300`)
makes `Participant(...)` raise `RuntimeError`.

### Context Manager

```python
# Recommended: auto-cleanup with context manager
with Participant("my_app") as p:
    writer = p.create_writer("topic")
    writer.write(b"data")
# Participant and all entities automatically closed
```

### Properties

```python
name: str = participant.name          # Participant name
domain_id: int = participant.domain_id  # Domain ID
pid: int = participant.participant_id   # Unique ID within domain
```

### Creating Writers/Readers

```python
# Create writer
writer = participant.create_writer("topic")
writer = participant.create_writer("topic", qos=hdds.QoS.reliable())

# Create reader
reader = participant.create_reader("topic")
reader = participant.create_reader("topic", qos=hdds.QoS.reliable())
```

### Cleanup

```python
# Explicit cleanup (if not using context manager)
participant.close()
```

## QoS Configuration

Fluent builder API for Quality of Service.

### Factory Methods

```python
from hdds import QoS

# Predefined profiles
qos = QoS.default()       # BestEffort, Volatile
qos = QoS.reliable()      # Reliable delivery
qos = QoS.best_effort()   # Fire and forget
qos = QoS.rti_defaults()  # Reliable, Volatile, KeepLast(10) preset

# Load from XML file
qos = QoS.from_file("fastdds_profile.xml")

# Clone existing QoS
qos2 = qos.clone()
```

### Fluent Builder

All methods return `self` for chaining:

```python
qos = QoS.reliable() \
    .transient_local() \
    .history_depth(100) \
    .deadline_ms(100) \
    .deadline_secs(1) \
    .lifespan_ms(5000) \
    .lifespan_secs(5) \
    .liveliness_automatic(lease_secs=1.0) \
    .liveliness_manual_participant(lease_secs=0.5) \
    .liveliness_manual_topic(lease_secs=0.25) \
    .ownership_shared() \
    .ownership_exclusive(strength=100) \
    .partition("sensors") \
    .time_based_filter_ms(10) \
    .latency_budget_ms(50) \
    .transport_priority(10) \
    .resource_limits(
        max_samples=1000,
        max_instances=100,
        max_samples_per_instance=10
    )
```

### Durability

```python
qos.volatile()         # No persistence (default)
qos.transient_local()  # Persist for late joiners
```

### Inspection

```python
qos.is_reliable()                # bool
qos.is_transient_local()         # bool
qos.is_ownership_exclusive()     # bool
qos.get_history_depth()          # int
qos.get_deadline_ns()            # int, nanoseconds; a huge sentinel value (the default) = infinite
qos.get_lifespan_ns()            # int, nanoseconds; a huge sentinel value (the default) = infinite
qos.get_ownership_strength()     # int
qos.get_liveliness_kind()        # LivelinessKind
qos.get_liveliness_lease_ns()    # int
qos.get_transport_priority()     # int

# String representation
print(qos)  # QoS(reliable, transient_local, depth=100)
```

### Enums

The QoS enums live in `hdds.qos`, not in the top-level `hdds` package:

```python
from hdds.qos import Reliability, Durability, LivelinessKind, OwnershipKind

LivelinessKind.AUTOMATIC              # 0
LivelinessKind.MANUAL_BY_PARTICIPANT  # 1
LivelinessKind.MANUAL_BY_TOPIC        # 2
```

`Reliability` (`BEST_EFFORT`, `RELIABLE`), `Durability` (`VOLATILE`,
`TRANSIENT_LOCAL`) and `OwnershipKind` (`SHARED`, `EXCLUSIVE`) are `Enum`
classes with `auto()` values.

## DataWriter

Writers publish data to a topic.

### Creation

```python
# Create with default QoS
writer = participant.create_writer("topic")

# Create with custom QoS
qos = QoS.reliable().transient_local()
writer = participant.create_writer("topic", qos=qos)
```

### Writing Data

```python
# Write raw bytes
writer.write(b"Hello, DDS!")

# Write from bytearray
data = bytearray([1, 2, 3, 4])
writer.write(bytes(data))
```

:::caution Bytes Only
The `write()` method accepts only `bytes`. For typed data, serialize first using `hdds_gen`-generated code.
:::

### Typed Writers

Pass the generated class as the second positional argument. A class generated by
`hdds_gen` 2.0 or later carries its extensibility, and the writer labels every
sample with it. `extensibility="final"`, `"appendable"` or `"mutable"` sets it
explicitly, for a writer without a generated class:

```python
writer = participant.create_writer("topic", Temperature, qos=qos)
writer = participant.create_writer("topic", extensibility="appendable", qos=qos)
```

### Instance Lifecycle

For a keyed type generated by `hddsgen` 2.0 or later, the writer can register,
dispose and unregister an instance. `dispose()` and `unregister_instance()`
take the instance (the key fields identify it); `register_instance()` returns
the 16-byte instance handle without sending a sample. Each has a `*_w_timestamp`
variant taking a source timestamp in nanoseconds since the Unix epoch.

```python
handle: bytes = writer.register_instance(sample)
writer.write_typed(sample)
writer.dispose(sample)
writer.unregister_instance(sample)
```

### Waiting for Readers

Samples written before a reader is matched are not delivered to a VOLATILE
reader, so wait for the match before the first write:

```python
# True once min_count readers are matched, False on timeout (in seconds)
if not writer.wait_for_readers(min_count=1, timeout=10.0):
    print("no subscriber found")

# Number of readers matched right now
n: int = writer.matched_reader_count()
```

### Properties

```python
topic_name: str = writer.topic_name
qos: QoS = writer.qos
```

## DataReader

Readers receive data from a topic.

### Creation

```python
# Create with default QoS
reader = participant.create_reader("topic")

# Create with custom QoS
qos = QoS.reliable().history_depth(100)
reader = participant.create_reader("topic", qos=qos)
```

### Taking Data

```python
# Take one sample (non-blocking)
data: bytes | None = reader.take()
if data is not None:
    print(f"Received {len(data)} bytes")

# Take with custom buffer size
data = reader.take(buffer_size=1024)

# Polling loop
while running:
    data = reader.take()
    if data:
        process(data)
    time.sleep(0.001)  # 1ms
```

### Status Condition

```python
# Get status condition for WaitSet integration
condition = reader.get_status_condition()
```

### Properties

```python
topic_name: str = reader.topic_name
qos: QoS = reader.qos
```

## WaitSet

Event-driven waiting for data availability.

### Basic Usage

```python
from hdds import WaitSet

# Create waitset
waitset = WaitSet()

# Create reader and attach it
reader = participant.create_reader("topic")
waitset.attach_reader(reader)

# Wait loop
while running:
    triggered = waitset.wait(timeout=1.0)
    if triggered:
        while (data := reader.take()) is not None:
            process(data)

# Cleanup
waitset.detach_reader(reader)
```

### Guard Conditions

```python
from hdds import GuardCondition

# Create guard condition for custom signaling
guard = GuardCondition()
waitset.attach_guard(guard)

# Trigger from another thread
import threading

def trigger_later():
    time.sleep(1.0)
    guard.trigger()

threading.Thread(target=trigger_later).start()

# Wait will return when guard is triggered
waitset.wait()

# Cleanup
waitset.detach_guard(guard)
```

### Infinite Wait

```python
waitset.wait()  # Blocks until condition triggered
```

## Listeners

Override the methods you need on `hdds.ReaderListener` / `hdds.WriterListener`
and install the listener; only the overridden methods are installed.

```python
import hdds

class SensorListener(hdds.ReaderListener):
    def on_data_available(self, data: bytes):
        print(f"received {len(data)} bytes")

    def on_subscription_matched(self, status):
        print(f"matched writers: {status.current_count} ({status.current_count_change:+d})")

reader.set_listener(SensorListener())
# ...
reader.clear_listener()   # returns once no callback runs on another thread

class Acks(hdds.WriterListener):
    def on_publication_matched(self, status):
        print(f"matched readers: {status.current_count}")

    def on_sample_written(self, data: bytes, sequence_number: int):
        pass

writer.set_listener(Acks())
```

| Reader method | Fires | Writer method | Fires |
|---------------|:-----:|---------------|:-----:|
| `on_data_available(data)` | yes | `on_sample_written(data, sequence_number)` | yes |
| `on_subscription_matched(status)` | yes | `on_publication_matched(status)` | yes |
| `on_sample_rejected(status)` | yes | `on_offered_deadline_missed(instance_handle)` | yes |
| `on_deadline_missed(status)` | yes | `on_offered_incompatible_qos(policy_id, policy_name)` | yes |
| `on_incompatible_qos(status)` | yes | `on_liveliness_lost(status)` | yes (MANUAL_BY_* liveliness only) |
| `on_liveliness_changed(status)` | yes | | |
| `on_sample_lost(status)` | never called | | |

`on_sample_lost` is accepted but never called: the core does not raise the
SAMPLE_LOST status. A reader and a writer of the same participant match each
other and report it like remote endpoints.

Threading:

- Callbacks run on HDDS threads (router / discovery threads, or the thread
  calling `writer.write()` for a reader of the same participant, inside that
  call), with the GIL acquired for the duration of the callback.
- An exception raised in a callback is logged on the `hdds.listener` logger
  and swallowed; it never propagates into HDDS.
- `clear_listener()`, a replacing `set_listener()` and closing the
  participant wait for callbacks running on other threads (the GIL is
  released meanwhile). A callback may `take()`, write, or clear its own
  listener.
- `set_listener()` / `clear_listener()` may race on one entity from several
  threads: the last install to reach the library stays installed.
- Do not close the participant from inside one of its entities' callbacks:
  the library leaks the entity rather than free it under the code that
  called back.
- Status objects and `data` are copies, safe to keep.
- Installed listeners are removed at interpreter exit.

## Logging

```python
import hdds

# Initialize with level
hdds.logging.init(hdds.LogLevel.INFO)

# hdds.LogLevel is a plain class of int constants, not an Enum:
# OFF = 0, ERROR = 1, WARN = 2, INFO = 3, DEBUG = 4, TRACE = 5
```

`hdds.logging.init()` can run once per process: a second call raises `HddsException`.

## Telemetry

Built-in metrics collection.

### Initialize

```python
import hdds

# Initialize global metrics
metrics = hdds.telemetry.init()

# Get existing (if already initialized)
metrics = hdds.telemetry.get()  # Returns None if not initialized
```

### Snapshot

```python
snapshot = metrics.snapshot()

print(f"Messages sent: {snapshot.messages_sent}")
print(f"Messages received: {snapshot.messages_received}")
print(f"Messages dropped: {snapshot.messages_dropped}")
print(f"Bytes sent: {snapshot.bytes_sent}")
print(f"Latency P50: {snapshot.latency_p50_ms:.2f}ms")
print(f"Latency P99: {snapshot.latency_p99_ms:.2f}ms")
print(f"Latency P99.9: {snapshot.latency_p999_ms:.2f}ms")
```

MetricsSnapshot fields:
```python
@dataclass
class MetricsSnapshot:
    timestamp_ns: int
    messages_sent: int
    messages_received: int
    messages_dropped: int
    bytes_sent: int
    latency_p50_ns: int
    latency_p99_ns: int
    latency_p999_ns: int
    merge_full_count: int
    would_block_count: int

    # Convenience properties
    @property
    def latency_p50_ms(self) -> float: ...
    @property
    def latency_p99_ms(self) -> float: ...
    @property
    def latency_p999_ms(self) -> float: ...
```

What the counters count (process-wide, all writers and readers, every
transport):

- `messages_sent`: one per successful `write` (including writes with no
  matched reader); `bytes_sent`: the serialized payload bytes of those writes,
  before RTPS framing, fragmentation or encryption.
- `messages_received`: one per sample deposited in a reader's history, counted
  when the application next accesses the reader (`read`, `take`, ...), so a
  sample still queued in the transport is not counted yet.
- `messages_dropped`: samples discarded after arriving for want of room, or
  refused by a content filter. `merge_full_count`: a local reader could not take
  a sample for lack of room. `would_block_count`: a writer operation came back
  `WouldBlock`.

### Exporter (HDDS Viewer)

```python
# Start telemetry server for HDDS Viewer
exporter = hdds.telemetry.start_exporter("127.0.0.1", 4242)

# ... application runs ...

exporter.stop()
```

### Manual Latency Recording

```python
import time

start_ns = time.time_ns()
# ... operation ...
end_ns = time.time_ns()

metrics.record_latency(start_ns, end_ns)
```

## Error Handling

```python
from hdds import HddsException, HddsError

try:
    writer.write(b"data")
except HddsException as e:
    print(f"HDDS error: {e}")

# Error codes: hdds.HddsError is a plain class of int constants (the values of
# the C HddsError enum in hdds.h). Meanings as in the C error table:
HddsError.OK                 # 0   Success
HddsError.INVALID_ARGUMENT   # 1   Invalid argument provided (null pointer, invalid value)
HddsError.NOT_FOUND          # 2   Requested resource not found
HddsError.OPERATION_FAILED   # 3   Generic operation failure
HddsError.OUT_OF_MEMORY      # 4   Memory allocation failed
HddsError.INVALID_STATE      # 14  Invalid entity state for requested operation
HddsError.TIMEOUT            # 24  Operation did not complete before the requested timeout
HddsError.UNSUPPORTED        # 41  Requested feature or operation is not supported
```

## Complete Example

Run it on any domain (`HDDS_DOMAIN_ID`, default 0). The publisher and the
subscriber are two threads of one participant, so the samples do not cross the network:

```python
#!/usr/bin/env python3
"""HDDS Python SDK example: basic pub/sub in one process.

The publisher and the subscriber are two threads sharing one participant, so the
samples do not cross the network. The writer is TRANSIENT_LOCAL, so a reader created
late still receives the samples already written.
"""

import threading
import time
import hdds

def publisher(participant: hdds.Participant):
    """Publish ten messages, one per second."""
    qos = hdds.QoS.reliable().transient_local().history_depth(10)
    writer = participant.create_writer("hello/world", qos=qos)

    for i in range(10):
        message = f"Hello #{i}".encode()
        writer.write(message)
        print(f"Published: {message.decode()}", flush=True)
        time.sleep(1.0)

def subscriber(participant: hdds.Participant):
    """Print messages until ten have arrived, or until 5 s pass without one."""
    qos = hdds.QoS.reliable().history_depth(100)
    reader = participant.create_reader("hello/world", qos=qos)

    received = 0
    with hdds.WaitSet() as waitset:
        waitset.attach_reader(reader)
        while received < 10:
            if not waitset.wait(timeout=5.0):
                break
            while (data := reader.take()) is not None:
                print(f"Received: {data.decode()}", flush=True)
                received += 1
    print(f"Subscriber received {received} messages", flush=True)

def main():
    hdds.logging.init(hdds.LogLevel.WARN)
    metrics = hdds.telemetry.init()

    with hdds.Participant("example") as participant:
        sub_thread = threading.Thread(target=subscriber, args=(participant,))
        sub_thread.start()

        # Give the subscriber time to create its reader
        time.sleep(0.5)

        publisher(participant)
        sub_thread.join()

        snap = metrics.snapshot()
        print("\nMetrics:")
        print(f"  Messages sent: {snap.messages_sent}")
        print(f"  Messages received: {snap.messages_received}")

if __name__ == "__main__":
    main()
```

Expected output of one run (domain 217). The two threads share the console, so
a `Published` and a `Received` line for the same message can swap places:

```
Published: Hello #0
Received: Hello #0
...
Published: Hello #9
Received: Hello #9
Subscriber received 10 messages

Metrics:
  Messages sent: 10
  Messages received: 10
```

## Using with Typed Data

The Python SDK writes and reads bytes, and `write_typed()` / `take_typed()` do the
CDR2 encoding for generated types. Generate the type with `hdds_gen`:

```bash
hddsgen gen python temperature.idl -o temperature.py    # hddsgen 2.0 or later
```

For `struct Temperature { @key unsigned long sensor_id; float value; unsigned long long timestamp; };`
the generated `@dataclass Temperature` has the fields `sensor_id`, `value` and
`timestamp`, and the methods `encode_cdr2_le()` / `decode_cdr2_le()`.

```python
import hdds
from temperature import Temperature

with hdds.Participant("sensor") as p:    # domain from HDDS_DOMAIN_ID
    qos = hdds.QoS.reliable().history_depth(10)
    writer = p.create_writer("sensors/temp", Temperature, qos=qos)
    reader = p.create_reader("sensors/temp", qos=qos, msg_type=Temperature)

    # Publish typed data (CDR2-encoded by write_typed)
    writer.write_typed(Temperature(sensor_id=1, value=23.5, timestamp=0))

    # Receive typed data
    if (sample := reader.take_typed(Temperature)) is not None:
        print(f"Sensor {sample.sensor_id}: {sample.value}")
```

Without generated code, `writer.write(bytes)` and `reader.take()` (which returns
`bytes` or `None`) move the payload as is; the payload must then be the CDR
encoding the other side expects.

## Thread Safety

- `GuardCondition.trigger()` can be called from any thread.
- Listener callbacks run on HDDS threads: see [Listeners](#listeners).
- The SDK documents no other thread-safety guarantee. Use each QoS object,
  participant, reader, writer and WaitSet from one thread at a time, or
  serialize access yourself.

## Module Structure

```
hdds/
|-- __init__.py      # Main exports
|-- participant.py   # Participant class
|-- qos.py           # QoS class and enums
|-- entities.py      # DataWriter, DataReader
|-- waitset.py       # WaitSet, GuardCondition
|-- listener.py      # ReaderListener, WriterListener, status types
|-- conditions.py    # ReadCondition, QueryCondition, ContentFilteredTopic (see Limitations)
|-- logging.py       # Logging utilities
|-- telemetry.py     # Metrics collection
`-- _native.py       # FFI bindings (internal)
```

## Limitations

| Feature | Status |
|---------|--------|
| Async API (`async`/`await`) | Not available |
| Instance state and SampleInfo on the reader | Not available: `take()` returns the payload bytes only (the writer side has `dispose()`, `unregister_instance()` and `register_instance()`, see [Instance Lifecycle](#instance-lifecycle)) |
| Typed API (without hdds_gen) | Not available |
| Content-filtered topics, read and query conditions | Not available: `hdds/conditions.py` is not exported by the package, and `Participant` has no method to create a content-filtered topic and `WaitSet` none to attach a read or query condition |

## Next Steps

- [Hello World Python](../getting-started/hello-world-python.md) - Complete tutorial
- [hdds_gen](../tools/hdds-gen/cli-reference.md) - Code generator for typed data
- [C++ API](../api/cpp.md) - C++ SDK
- [Rust API](../api/rust.md) - Native Rust API
