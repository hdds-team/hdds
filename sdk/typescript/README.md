# @hdds/client - HDDS TypeScript SDK

Native FFI bindings to the HDDS DDS implementation for Node.js.

Provides direct access to DDS topics via the hdds-c shared library using
[koffi](https://koffi.dev/) (zero-dependency FFI for Node.js). No WebSocket
bridge required -- your application communicates directly over UDP multicast
using the RTPS protocol.

## Requirements

- **Node.js** >= 18
- **hdds-c** shared library built from the HDDS repository

## Installation

```bash
npm install @hdds/client
```

## Building hdds-c

Before using the SDK, build the native shared library:

```bash
# From the HDDS repository root
cargo build --release -p hdds-c

# The library will be at:
#   Linux:  target/release/libhdds_c.so
#   macOS:  target/release/libhdds_c.dylib
#   Windows: target/release/hdds_c.dll
```

If the library is not in the default search paths, set the environment variable:

```bash
export HDDS_LIB_PATH=/path/to/directory/containing/libhdds_c.so
```

## Quick Start

```typescript
import { Participant, QoS, WaitSet, TransportMode } from '@hdds/client';

// Create a participant
const participant = Participant.create('my_app');

// Create writer and reader with QoS
const qos = QoS.reliable().transientLocal().historyDepth(10);
const writer = participant.createWriter('temperature', qos);
const reader = participant.createReader('temperature', qos.clone());

// Write data (raw bytes)
writer.write(Buffer.from(JSON.stringify({ value: 23.5, unit: 'C' })));

// Or use the JSON convenience method
writer.writeJson({ value: 23.5, unit: 'C' });

// Read data (non-blocking)
const data = reader.take();
if (data !== null) {
  const msg = JSON.parse(data.toString('utf-8'));
  console.log(msg.value, msg.unit);
}

// Or use the JSON convenience method
const msg = reader.takeJson<{ value: number; unit: string }>();

// Use WaitSet for blocking reads
const waitset = new WaitSet();
waitset.attachReader(reader);

if (waitset.wait(5.0)) {  // 5 second timeout
  const sample = reader.take();
  // process sample...
}

// Clean up
waitset.dispose();
qos.dispose();
participant.dispose();  // Also disposes all writers/readers
```

## API Reference

### Participant

Entry point for DDS communication.

```typescript
// UDP multicast (default -- for network DDS)
const p = Participant.create('my_app');

// Intra-process only (no network, fastest for same-process)
const p = Participant.create('my_app', {
  transport: TransportMode.INTRA_PROCESS,
});

// Properties
p.name;           // string
p.domainId;       // number
p.participantId;  // number

// Create endpoints
p.createWriter<T>(topicName, qos?);
p.createReader<T>(topicName, qos?);

// Clean up (destroys all writers/readers)
p.dispose();
```

### DataWriter

Publish data to a DDS topic.

```typescript
const writer = participant.createWriter('topic', QoS.reliable());

// Write raw bytes
writer.write(Buffer.from('hello'));
writer.write(new Uint8Array([1, 2, 3]));

// Write JSON
writer.writeJson({ key: 'value' });

writer.dispose();
```

### DataReader

Subscribe to data on a DDS topic.

```typescript
const reader = participant.createReader('topic');

// Non-blocking take (returns null if no data)
const data: Buffer | null = reader.take();
const json: MyType | null = reader.takeJson<MyType>();

// Get status condition for WaitSet
const cond = reader.getStatusCondition();

reader.dispose();
```

### QoS

Quality of Service configuration with fluent builder API.

```typescript
// Factory methods
QoS.createDefault();    // BestEffort, Volatile
QoS.reliable();         // Reliable delivery
QoS.bestEffort();       // Fire-and-forget
QoS.rtiDefaults();      // RTI Connext compatible
QoS.fromXml('profile.xml');        // Load from XML (requires qos-loaders)
QoS.fromFastDdsXml('profile.xml'); // FastDDS XML (requires qos-loaders)

// Fluent builder
const qos = QoS.reliable()
  .transientLocal()
  .historyDepth(10)
  .deadlineMs(500)
  .partition('sensor_data')
  .livelinessAutomatic(5.0);

// Inspection
qos.isReliable();        // boolean
qos.isTransientLocal();  // boolean
qos.getHistoryDepth();   // number

// Clone and dispose
const copy = qos.clone();
qos.dispose();
```

### WaitSet

Block until data arrives on one or more readers.

```typescript
const waitset = new WaitSet();
waitset.attachReader(reader1);
waitset.attachReader(reader2);

// Block up to 5 seconds
if (waitset.wait(5.0)) {
  // At least one reader has data
  const d1 = reader1.take();
  const d2 = reader2.take();
}

// Non-blocking poll
const hasData = waitset.wait(0);

// Block indefinitely
waitset.wait();

waitset.dispose();
```

### GuardCondition

Manually-triggered condition for signaling across threads.

```typescript
const guard = new GuardCondition();
waitset.attachGuard(guard);

// From another context:
guard.trigger();

// Reset
guard.reset();
guard.dispose();
```

### Logging

```typescript
import { initLogging, initLoggingEnv, initLoggingWithFilter, LogLevel } from '@hdds/client';

initLogging(LogLevel.INFO);
initLoggingEnv(LogLevel.WARN);              // Uses RUST_LOG if set
initLoggingWithFilter('hdds=debug,info');
```

### Version

```typescript
import { version } from '@hdds/client';
console.log(version());  // e.g., "1.0.5"
```

## Error Handling

All operations throw `HddsError` on failure:

```typescript
import { HddsError, HddsErrorCode } from '@hdds/client';

try {
  const p = Participant.create('test');
} catch (e) {
  if (e instanceof HddsError) {
    console.error(`HDDS error [${e.code}]: ${e.message}`);
    if (e.code === HddsErrorCode.NO_AVAILABLE_PARTICIPANT_ID) {
      // All 120 participant slots are in use
    }
  }
}
```

## Transport Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| `UDP_MULTICAST` | Standard DDS network transport | Cross-process, cross-machine |
| `INTRA_PROCESS` | No network, shared memory | Same-process, testing, benchmarks |

## Architecture

```
Node.js Application
      |
      | @hdds/client (koffi FFI)
      |
      v
+----------------+
|   libhdds_c    |  Native shared library
+----------------+
      |
      | UDP Multicast / RTPS
      |
      v
+----------------+
|  DDS Domain    |  Other DDS peers (any vendor)
+----------------+
```

The SDK loads the hdds-c shared library at runtime via koffi and calls
the C functions directly. No intermediate bridge process is needed.

## Compatibility

- Interoperates with any OMG DDS implementation (FastDDS, CycloneDDS, RTI Connext)
- ROS2 compatible (via ROS2 DDS middleware)
- Node.js only (koffi requires native access; for browser use, see the WebSocket bridge)

## License

Apache-2.0 OR MIT
