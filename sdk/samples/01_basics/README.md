# 01_basics - Basic HDDS Samples

This directory contains basic HDDS samples demonstrating core pub/sub functionality.

## Samples

| Sample | Description |
|--------|-------------|
| `hello_world` | Simple pub/sub with a HelloWorld message type |
| `multi_participant` | Multiple participants in same process (coming soon) |
| `multi_topic` | Publishing/subscribing to multiple topics (coming soon) |
| `instance_keys` | Using keyed instances for data management (coming soon) |

## Running the Samples

### Prerequisites

Build HDDS first:
```bash
cd /path/to/hdds
cargo build --release
```

### Python

```bash
cd python

# Terminal 1 - Subscriber
python hello_world.py

# Terminal 2 - Publisher
python hello_world.py pub
```

### C

```bash
cd c
cmake -B build
cmake --build build

# Terminal 1 - Subscriber
./build/hello_world

# Terminal 2 - Publisher
./build/hello_world pub
```

### C++

```bash
cd cpp
cmake -B build
cmake --build build

# Terminal 1 - Subscriber
./build/hello_world

# Terminal 2 - Publisher
./build/hello_world pub
```

### Rust

```bash
cd rust

# Terminal 1 - Subscriber
cargo run --bin hello_world

# Terminal 2 - Publisher
cargo run --bin hello_world -- pub
```

## Expected Output

### Publisher
```
Creating participant...
Creating writer...
Publishing messages...
  Published: Hello from HDDS! (count=0)
  Published: Hello from HDDS! (count=1)
  ...
  Published: Hello from HDDS! (count=9)
Done publishing.
Cleanup complete.
```

### Subscriber
```
Creating participant...
Creating reader...
Waiting for messages (Ctrl+C to exit)...
  Received: Hello from HDDS! (count=0)
  Received: Hello from HDDS! (count=1)
  ...
  Received: Hello from HDDS! (count=9)
Done receiving.
Cleanup complete.
```

## Key Concepts

1. **Participant**: The entry point for DDS communication. Creates topics, writers, and readers.

2. **DataWriter**: Publishes data samples to a topic.

3. **DataReader**: Subscribes to and receives data samples from a topic.

4. **WaitSet**: Efficient mechanism for waiting on multiple conditions (e.g., data available).

5. **Serialization**: Messages are serialized to CDR (Common Data Representation) format for wire transfer.
