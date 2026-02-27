# Hello World in Python

Python is the fastest way to get started with HDDS. This tutorial takes about 5 minutes.

**Time:** ~5 minutes
**Prerequisites:** [HDDS Python package installed](../getting-started/installation/linux.md)

## Step 1: Install HDDS

```bash
pip install hdds
```

## Step 2: Define the Data Type

Create `temperature.py`:

```python
from dataclasses import dataclass
from hdds import Topic, Key

@dataclass
class Temperature(Topic):
    """Temperature reading from a sensor."""

    sensor_id: Key[str]  # Instance key
    value: float         # Temperature in Celsius
    timestamp: int       # Unix timestamp in ms
```

:::tip Python Type Hints
HDDS uses Python type hints to generate the DDS type. The `Key[str]` annotation marks `sensor_id` as the instance key.
:::

## Step 3: Create the Publisher

Create `publisher.py`:

```python
#!/usr/bin/env python3
import time
import hdds
from temperature import Temperature

def main():
    print("Starting temperature publisher...")

    # 1. Create DomainParticipant
    participant = hdds.DomainParticipant(domain_id=0)
    print("Joined domain 0")

    # 2. Create Topic
    topic = participant.create_topic("temperature/room1", Temperature)
    print("Created topic: temperature/room1")

    # 3. Create Publisher and DataWriter
    publisher = participant.create_publisher()
    writer = publisher.create_writer(topic)
    print("DataWriter created, waiting for subscribers...")

    # 4. Wait for subscribers
    writer.wait_for_subscribers(count=1, timeout=30.0)
    print("Subscriber connected!")

    # 5. Publish temperature readings
    for i in range(10):
        temp = Temperature(
            sensor_id="sensor-001",
            value=22.0 + (i * 0.5),
            timestamp=int(time.time() * 1000)
        )

        writer.write(temp)
        print(f"Published: sensor={temp.sensor_id}, temp={temp.value:.1f}°C")

        time.sleep(1)

    print("Publisher finished")

if __name__ == "__main__":
    main()
```

## Step 4: Create the Subscriber

Create `subscriber.py`:

```python
#!/usr/bin/env python3
import hdds
from temperature import Temperature

def main():
    print("Starting temperature subscriber...")

    # 1. Create DomainParticipant
    participant = hdds.DomainParticipant(domain_id=0)
    print("Joined domain 0")

    # 2. Create Topic
    topic = participant.create_topic("temperature/room1", Temperature)
    print("Created topic: temperature/room1")

    # 3. Create Subscriber and DataReader
    subscriber = participant.create_subscriber()
    reader = subscriber.create_reader(topic)
    print("DataReader created, waiting for data...")

    # 4. Read samples in a loop
    while True:
        if reader.wait_for_data(timeout=5.0):
            # Take all available samples
            for sample in reader.take():
                print(
                    f"Received: sensor={sample.sensor_id}, "
                    f"temp={sample.value:.1f}°C, "
                    f"time={sample.timestamp}"
                )
        else:
            print("No data received in 5 seconds, waiting...")

if __name__ == "__main__":
    main()
```

## Step 5: Run

Open two terminals:

```bash
# Terminal 1
python subscriber.py

# Terminal 2
python publisher.py
```

## Using Async/Await

HDDS supports Python's async/await for non-blocking I/O:

```python
#!/usr/bin/env python3
import asyncio
import hdds
from temperature import Temperature

async def main():
    participant = hdds.DomainParticipant(domain_id=0)
    topic = participant.create_topic("temperature/room1", Temperature)
    reader = participant.create_subscriber().create_reader(topic)

    async for sample in reader:
        print(f"Received: {sample.sensor_id} = {sample.value}°C")

if __name__ == "__main__":
    asyncio.run(main())
```

## Using Callbacks

Event-driven style with callbacks:

```python
import hdds
from temperature import Temperature

def on_data(reader):
    for sample in reader.take():
        print(f"Received: {sample.value}°C")

participant = hdds.DomainParticipant(0)
topic = participant.create_topic("temperature/room1", Temperature)
reader = participant.create_subscriber().create_reader(topic)

reader.on_data_available(on_data)

# Keep running
hdds.spin()
```

## QoS Configuration

```python
from hdds import QoS, Reliability, Durability, History

# Reliable with history
qos = QoS(
    reliability=Reliability.RELIABLE,
    durability=Durability.TRANSIENT_LOCAL,
    history=History.keep_last(10)
)

writer = publisher.create_writer(topic, qos=qos)
```

## Complex Types

HDDS supports complex Python types:

```python
from dataclasses import dataclass
from typing import List, Optional
from hdds import Topic, Key

@dataclass
class SensorReading(Topic):
    sensor_id: Key[str]
    values: List[float]           # Sequence
    location: Optional[str]       # Optional field
    metadata: dict[str, str]      # Map

@dataclass
class Point:
    x: float
    y: float
    z: float

@dataclass
class Pose(Topic):
    robot_id: Key[str]
    position: Point              # Nested struct
    orientation: List[float]     # Quaternion
```

## Integration with NumPy

```python
import numpy as np
from hdds import Topic, Key
from dataclasses import dataclass

@dataclass
class LidarScan(Topic):
    sensor_id: Key[str]
    ranges: np.ndarray    # Will be serialized as sequence<float>
    intensities: np.ndarray

# Write numpy arrays directly
scan = LidarScan(
    sensor_id="lidar-001",
    ranges=np.random.rand(360) * 10,
    intensities=np.random.rand(360)
)
writer.write(scan)
```

## What's Next?

- **[QoS Policies](../guides/qos-policies/overview.md)** - Fine-tune data distribution
- **[Python API Reference](../api/python.md)** - Complete Python documentation
- **[Examples](../examples.md)** - More complex examples
