# Python API Reference

HDDS provides Python bindings through the `hdds` package, offering a Pythonic API with context managers and fluent QoS configuration.

:::info Version 1.0.0
This documents the current v1.0.0 SDK. The API operates on raw bytes; use `hdds_gen` to generate typed serialization code.
:::

## Installation

```bash
# From source
cd /path/to/hdds/sdk/python
pip install maturin
maturin develop  # Development install
maturin build    # Build wheel

# Or with pip (once published)
pip install hdds
```

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

# Basic creation (domain 0)
participant = Participant("my_app")

# With domain ID
participant = Participant("my_app", domain_id=42)

# With discovery disabled (intra-process only)
participant = Participant("my_app", enable_discovery=False)
```

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
qos = QoS.rti_defaults()  # RTI Connext compatible

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
qos.is_reliable() -> bool
qos.is_transient_local() -> bool
qos.is_ownership_exclusive() -> bool
qos.get_history_depth() -> int
qos.get_deadline_ns() -> int      # 0 = infinite
qos.get_lifespan_ns() -> int      # 0 = infinite
qos.get_ownership_strength() -> int
qos.get_liveliness_kind() -> LivelinessKind
qos.get_liveliness_lease_ns() -> int
qos.get_transport_priority() -> int

# String representation
print(qos)  # QoS(reliable, transient_local, depth=100)
```

### Enums

```python
from hdds import Reliability, Durability, LivelinessKind, OwnershipKind

class LivelinessKind(Enum):
    AUTOMATIC = 0
    MANUAL_BY_PARTICIPANT = 1
    MANUAL_BY_TOPIC = 2
```

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

# Create reader and attach condition
reader = participant.create_reader("topic")
condition = reader.get_status_condition()
waitset.attach(condition)

# Wait loop
while running:
    triggered = waitset.wait(timeout_secs=1.0)
    if triggered:
        while (data := reader.take()) is not None:
            process(data)

# Cleanup
waitset.detach(condition)
```

### Guard Conditions

```python
from hdds import GuardCondition

# Create guard condition for custom signaling
guard = GuardCondition()
waitset.attach(guard)

# Trigger from another thread
import threading

def trigger_later():
    time.sleep(1.0)
    guard.trigger()

threading.Thread(target=trigger_later).start()

# Wait will return when guard is triggered
waitset.wait()

# Cleanup
waitset.detach(guard)
```

### Infinite Wait

```python
waitset.wait()  # Blocks until condition triggered
```

## Logging

```python
import hdds

# Initialize with level
hdds.logging.init(hdds.LogLevel.INFO)

# Available log levels
class LogLevel(Enum):
    OFF = 0
    ERROR = 1
    WARN = 2
    INFO = 3
    DEBUG = 4
    TRACE = 5
```

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

# Error codes
class HddsError(Enum):
    OK = 0
    INVALID_ARGUMENT = 1
    NOT_FOUND = 2
    OPERATION_FAILED = 3
    OUT_OF_MEMORY = 4
```

## Complete Example

```python
#!/usr/bin/env python3
"""HDDS Python SDK example: Basic pub/sub."""

import time
import threading
import hdds

def publisher(participant: hdds.Participant):
    """Publish messages every second."""
    qos = hdds.QoS.reliable().transient_local().history_depth(10)
    writer = participant.create_writer("hello/world", qos=qos)

    for i in range(10):
        message = f"Hello #{i}".encode()
        writer.write(message)
        print(f"Published: {message.decode()}")
        time.sleep(1.0)

def subscriber(participant: hdds.Participant):
    """Subscribe and print messages."""
    qos = hdds.QoS.reliable().history_depth(100)
    reader = participant.create_reader("hello/world", qos=qos)

    waitset = hdds.WaitSet()
    condition = reader.get_status_condition()
    waitset.attach(condition)

    received = 0
    while received < 10:
        if waitset.wait(timeout_secs=5.0):
            while (data := reader.take()) is not None:
                print(f"Received: {data.decode()}")
                received += 1

    waitset.detach(condition)

def main():
    # Initialize logging
    hdds.logging.init(hdds.LogLevel.INFO)

    # Initialize telemetry
    metrics = hdds.telemetry.init()

    with hdds.Participant("example") as participant:
        # Start subscriber thread
        sub_thread = threading.Thread(
            target=subscriber, args=(participant,))
        sub_thread.start()

        # Give subscriber time to initialize
        time.sleep(0.5)

        # Run publisher in main thread
        publisher(participant)

        # Wait for subscriber
        sub_thread.join()

        # Print metrics
        snap = metrics.snapshot()
        print(f"\nMetrics:")
        print(f"  Messages sent: {snap.messages_sent}")
        print(f"  Messages received: {snap.messages_received}")

if __name__ == "__main__":
    main()
```

## Using with Typed Data

The Python SDK operates on raw bytes. For typed data, use `hdds_gen` to generate Python serialization code:

```bash
idl-gen gen python Temperature.idl -o temperature.py
```

```python
# temperature.py (generated)
from dataclasses import dataclass

@dataclass
class Temperature:
    sensor_id: int
    value: float
    unit: str

def temperature_encode_cdr2_le(t: Temperature) -> bytes:
    ...

def temperature_decode_cdr2_le(data: bytes) -> Temperature:
    ...
```

Usage:
```python
from temperature import Temperature, temperature_encode_cdr2_le, temperature_decode_cdr2_le
import hdds

with hdds.Participant("sensor") as p:
    writer = p.create_writer("sensors/temp")
    reader = p.create_reader("sensors/temp")

    # Publish typed data
    temp = Temperature(sensor_id=1, value=23.5, unit="celsius")
    writer.write(temperature_encode_cdr2_le(temp))

    # Receive typed data
    if (data := reader.take()) is not None:
        temp = temperature_decode_cdr2_le(data)
        print(f"Sensor {temp.sensor_id}: {temp.value} {temp.unit}")
```

## Thread Safety

- Participant creation/close: NOT thread-safe
- Writer/Reader creation: NOT thread-safe
- `writer.write()`: Thread-safe
- `reader.take()`: NOT thread-safe (use one reader per thread)
- QoS methods: NOT thread-safe
- WaitSet: NOT thread-safe

## Module Structure

```
hdds/
├── __init__.py      # Main exports
├── participant.py   # Participant class
├── qos.py           # QoS class and enums
├── entities.py      # DataWriter, DataReader
├── waitset.py       # WaitSet, GuardCondition
├── logging.py       # Logging utilities
├── telemetry.py     # Metrics collection
└── _native.py       # FFI bindings (internal)
```

## Not Yet Implemented (v1.0.0)

| Feature | Status |
|---------|--------|
| Async API (`async`/`await`) | Not implemented |
| DataWriterListener / DataReaderListener | Not implemented |
| Instance management (dispose, unregister) | Not implemented |
| SampleInfo with metadata | Not implemented |
| Typed API (without hdds_gen) | Not implemented |
| Content-filtered topics | Not implemented |

## Next Steps

- [Hello World Python](../getting-started/hello-world-python.md) - Complete tutorial
- [hdds_gen](../tools/hdds-gen/cli-reference.md) - Code generator for typed data
- [C++ API](../api/cpp.md) - C++ SDK
- [Rust API](../api/rust.md) - Native Rust API
