# hdds-ws - WebSocket Bridge for DDS

Connect web browsers to DDS topics in real-time using WebSocket.

`hdds-ws` is a lightweight bridge that allows JavaScript/TypeScript applications
to subscribe and publish to DDS topics through a simple JSON-based WebSocket protocol.

## Features

- **Real-time subscriptions** - Subscribe to DDS topics and receive live data
- **Publish from browser** - Send messages to DDS topics from web clients
- **Topic discovery** - List available topics in the DDS domain
- **QoS support** - Configure reliability and history depth
- **Multi-client** - Broadcast data to multiple WebSocket connections
- **ROS2 compatible** - Automatic detection of ROS2 string message format
- **Embedded demo** - Built-in web UI for testing subscriptions

## Installation

### From source

```bash
cd tools/hdds-ws
cargo build --release
# Binary at: target/release/hdds-ws
```

### Using cargo

```bash
cargo install --path tools/hdds-ws
```

## Usage

### Start the bridge

```bash
# Default: port 9090, domain 0
hdds-ws

# Custom port and domain
hdds-ws --port 8080 --domain 42

# Full options
hdds-ws --port 9090 --bind 0.0.0.0 --domain 0 --name my-bridge --log-level debug
```

### CLI Options

| Option | Default | Description |
|--------|---------|-------------|
| `-p, --port` | `9090` | WebSocket server port |
| `-b, --bind` | `0.0.0.0` | Bind address |
| `-d, --domain` | `0` | DDS Domain ID |
| `--name` | `hdds-ws-bridge` | DDS Participant name |
| `--log-level` | `info` | Log level (trace, debug, info, warn, error) |
| `--max-clients` | `100` | Maximum concurrent WebSocket connections |

### Endpoints

| Endpoint | Description |
|----------|-------------|
| `ws://host:port/ws` | WebSocket connection |
| `http://host:port/` | Demo web page |
| `http://host:port/health` | Health check (JSON) |

## WebSocket Protocol

All messages are JSON-encoded. The protocol uses a `type` field to identify message kinds.

### Client → Server Messages

#### Subscribe to a topic

```json
{
  "type": "subscribe",
  "topic": "temperature",
  "qos": {
    "reliability": "reliable",
    "history_depth": 10
  }
}
```

`qos` is optional. Supported values:
- `reliability`: `"reliable"` or `"best_effort"`
- `history_depth`: number (for reliable mode)

#### Unsubscribe from a topic

```json
{
  "type": "unsubscribe",
  "topic": "temperature"
}
```

#### Publish to a topic

```json
{
  "type": "publish",
  "topic": "commands",
  "data": {"action": "start", "value": 42}
}
```

For ROS2 `std_msgs/String` format, use:

```json
{
  "type": "publish",
  "topic": "chatter",
  "data": {"data": "Hello from browser!"}
}
```

#### List available topics

```json
{"type": "list_topics"}
```

#### Ping (keepalive)

```json
{"type": "ping", "id": 12345}
```

### Server → Client Messages

#### Welcome (sent on connection)

```json
{
  "type": "welcome",
  "version": "0.1.0",
  "domain": 0
}
```

#### Subscription confirmed

```json
{
  "type": "subscribed",
  "topic": "temperature",
  "subscription_id": "sub_abc123"
}
```

#### Unsubscription confirmed

```json
{
  "type": "unsubscribed",
  "topic": "temperature"
}
```

#### Data received

```json
{
  "type": "data",
  "topic": "temperature",
  "subscription_id": "sub_abc123",
  "sample": {"value": 23.5, "unit": "celsius"},
  "info": {
    "source_timestamp_ms": 1704567890123,
    "reception_timestamp_ms": 1704567890150,
    "sequence": 42,
    "writer_guid": "01.02.03.04..."
  }
}
```

#### Publish confirmed

```json
{
  "type": "published",
  "topic": "commands",
  "sequence": 1
}
```

#### Topics list

```json
{
  "type": "topics",
  "topics": [
    {"name": "temperature", "type_name": "SensorData", "subscribers": 2, "publishers": 1},
    {"name": "commands", "type_name": "Command", "subscribers": 0, "publishers": 3}
  ]
}
```

#### Pong response

```json
{"type": "pong", "id": 12345}
```

#### Error

```json
{
  "type": "error",
  "code": "TOPIC_NOT_FOUND",
  "message": "Topic 'xyz' does not exist",
  "topic": "xyz"
}
```

Error codes: `INVALID_MESSAGE`, `TOPIC_NOT_FOUND`, `ALREADY_SUBSCRIBED`, `NOT_SUBSCRIBED`, `PUBLISH_FAILED`, `INTERNAL_ERROR`, `RATE_LIMITED`

## JavaScript Client Example

### Basic usage

```javascript
const ws = new WebSocket('ws://localhost:9090/ws');

ws.onopen = () => {
  console.log('Connected to HDDS bridge');

  // Subscribe to a topic
  ws.send(JSON.stringify({
    type: 'subscribe',
    topic: 'temperature'
  }));
};

ws.onmessage = (event) => {
  const msg = JSON.parse(event.data);

  switch (msg.type) {
    case 'welcome':
      console.log(`Connected to domain ${msg.domain}`);
      break;
    case 'data':
      console.log(`[${msg.topic}] ${JSON.stringify(msg.sample)}`);
      break;
    case 'error':
      console.error(`Error: ${msg.message}`);
      break;
  }
};

// Publish a message
function publish(topic, data) {
  ws.send(JSON.stringify({ type: 'publish', topic, data }));
}
```

### TypeScript with reconnection

```typescript
interface WsMessage {
  type: string;
  topic?: string;
  sample?: unknown;
  info?: SampleInfo;
  error?: string;
}

interface SampleInfo {
  source_timestamp_ms?: number;
  reception_timestamp_ms?: number;
  sequence?: number;
  writer_guid?: string;
}

class DdsClient {
  private ws: WebSocket | null = null;
  private subscriptions = new Map<string, (data: unknown) => void>();

  constructor(private url: string) {
    this.connect();
  }

  private connect() {
    this.ws = new WebSocket(this.url);

    this.ws.onopen = () => {
      // Re-subscribe to all topics
      for (const topic of this.subscriptions.keys()) {
        this.ws?.send(JSON.stringify({ type: 'subscribe', topic }));
      }
    };

    this.ws.onmessage = (event) => {
      const msg: WsMessage = JSON.parse(event.data);
      if (msg.type === 'data' && msg.topic) {
        const handler = this.subscriptions.get(msg.topic);
        handler?.(msg.sample);
      }
    };

    this.ws.onclose = () => {
      setTimeout(() => this.connect(), 3000);
    };
  }

  subscribe<T>(topic: string, handler: (data: T) => void) {
    this.subscriptions.set(topic, handler as (data: unknown) => void);
    this.ws?.send(JSON.stringify({ type: 'subscribe', topic }));
  }

  publish(topic: string, data: unknown) {
    this.ws?.send(JSON.stringify({ type: 'publish', topic, data }));
  }
}

// Usage
const client = new DdsClient('ws://localhost:9090/ws');

client.subscribe<{value: number}>('temperature', (data) => {
  console.log(`Temperature: ${data.value}`);
});
```

## Integration with hdds_gen TypeScript types

Generate TypeScript types from your IDL:

```bash
idl-gen gen typescript sensors.idl -o types.ts
```

Use generated types with hdds-ws:

```typescript
import { SensorReading, encodeSensorReading, decodeSensorReading } from './types';

// Subscribe with type safety
client.subscribe<SensorReading>('sensors/temperature', (reading) => {
  console.log(`Sensor ${reading.sensor_id}: ${reading.value} at ${reading.timestamp}`);
});

// Publish typed data
const reading: SensorReading = {
  sensor_id: 'temp-001',
  type: SensorType.TEMPERATURE,
  value: 23.5,
  timestamp: BigInt(Date.now()),
  tags: ['indoor', 'lab']
};

client.publish('sensors/temperature', reading);
```

## Health Check

```bash
curl http://localhost:9090/health
```

Response:

```json
{
  "status": "ok",
  "version": "0.1.0",
  "domain": 0,
  "clients": 3,
  "max_clients": 100
}
```

## Architecture

```
Browser/Node.js  ──WebSocket──►  hdds-ws  ──DDS/RTPS──►  Other DDS Participants
     │                              │
     │  JSON messages               │  CDR2 encoding
     │                              │
     └──────────────────────────────┘
```

The bridge:
1. Creates a DDS DomainParticipant on startup
2. Manages RawDataReader/RawDataWriter for each subscribed/published topic
3. Converts between JSON (WebSocket) and CDR2 (DDS wire format)
4. Broadcasts received DDS samples to all subscribed WebSocket clients

## Deployment

### Docker

```dockerfile
FROM rust:1.75-slim as builder
WORKDIR /app
COPY . .
RUN cargo build --release -p hdds-ws

FROM debian:bookworm-slim
COPY --from=builder /app/target/release/hdds-ws /usr/local/bin/
EXPOSE 9090
CMD ["hdds-ws", "--bind", "0.0.0.0"]
```

### Reverse proxy (nginx)

```nginx
location /dds/ {
    proxy_pass http://localhost:9090/;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_read_timeout 86400;
}
```

### With TLS (using external termination)

For production, terminate TLS at a reverse proxy (nginx, caddy, etc.) and proxy to hdds-ws over localhost.

## Interoperability

hdds-ws works with any DDS/RTPS implementation:
- Other HDDS participants (Rust, Python, C++, C)
- ROS2 nodes (via rmw_hdds or any ROS2 DDS middleware)
- FastDDS, CycloneDDS, RTI Connext, OpenDDS

The bridge uses raw CDR2 encoding, so it can communicate with any topic regardless of type. For best results, use types generated by `idl-gen`.

## License

Apache-2.0 OR MIT
