# 12_typescript - DDS from TypeScript/JavaScript

WebSocket-based DDS access from the browser or Node.js via the hdds-ws bridge.

## Architecture

```
Browser/Node.js          hdds-ws bridge           DDS Domain
  (TypeScript)    ──WS──►  (Rust native)   ──UDP/RTPS──►  DDS Peers
  @hdds/client            localhost:9090                   (any impl)
```

The `@hdds/client` SDK communicates with `hdds-ws` over WebSocket using JSON
messages. The bridge handles DDS/RTPS serialization and UDP multicast natively.

## Prerequisites

1. **hdds-ws bridge** must be running:
   ```bash
   cargo run --release -p hdds-ws -- --port 9090
   # or: hdds-ws --port 9090
   ```

2. **Node.js >= 18** with TypeScript:
   ```bash
   cd sdk/typescript && npm install
   ```

## Samples

| File | Description |
|------|-------------|
| `hello_world.ts` | Basic pub/sub — publish 5 messages to "hello_world" topic |
| `publisher.ts`   | Sensor data publisher with configurable topic and interval |
| `subscriber.ts`  | Generic topic listener with auto-reconnection |
| `qos_example.ts` | QoS profiles: best_effort vs reliable, history depth |

These are symlinks to `sdk/typescript/samples/` — the canonical source.

## Running

```bash
cd sdk/typescript

# Hello World
npx ts-node samples/hello_world.ts

# Publish sensor data at 1 Hz
npx ts-node samples/publisher.ts temperature 1000

# Subscribe to any topic
npx ts-node samples/subscriber.ts temperature

# QoS demonstration
npx ts-node samples/qos_example.ts
```

## Compatibility

- Works with any DDS implementation (FastDDS, CycloneDDS, RTI Connext)
- ROS2 compatible via DDS middleware layer
- Browser and Node.js supported

## License

Apache-2.0 OR MIT
