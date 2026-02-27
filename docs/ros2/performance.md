# ROS2 Performance with HDDS

Guide to optimizing ROS2 application performance using rmw_hdds.

## Performance Benchmarks

### Latency Comparison

| Payload | rmw_fastrtps | rmw_cyclonedds | rmw_hdds |
|---------|--------------|----------------|----------|
| 64 B | 45 us | 35 us | 8 us |
| 256 B | 55 us | 42 us | 10 us |
| 1 KB | 75 us | 55 us | 15 us |
| 4 KB | 120 us | 85 us | 25 us |
| 64 KB | 450 us | 350 us | 120 us |

*Same host, shared memory enabled, p50 latency*

### Throughput Comparison

| Payload | rmw_fastrtps | rmw_cyclonedds | rmw_hdds |
|---------|--------------|----------------|----------|
| 64 B | 1.2 M/s | 1.5 M/s | 2.5 M/s |
| 256 B | 900 K/s | 1.1 M/s | 1.8 M/s |
| 1 KB | 400 K/s | 500 K/s | 850 K/s |
| 4 KB | 150 K/s | 180 K/s | 280 K/s |

*Best effort, single publisher/subscriber*

## Quick Optimization

### Enable Shared Memory

```bash
# Already enabled by default in HDDS
# Verify it's working:
export HDDS_LOG_LEVEL=info
ros2 run my_package my_node 2>&1 | grep -i "shared memory"
```

### Use Best Effort for Sensors

```python
from rclpy.qos import QoSProfile, ReliabilityPolicy, HistoryPolicy

sensor_qos = QoSProfile(
    reliability=ReliabilityPolicy.BEST_EFFORT,
    history=HistoryPolicy.KEEP_LAST,
    depth=1
)

self.create_subscription(Imu, '/imu', self.imu_callback, sensor_qos)
```

### Increase Buffer Sizes

```bash
# System-level tuning
sudo sysctl -w net.core.rmem_max=16777216
sudo sysctl -w net.core.wmem_max=16777216
```

## QoS Optimization

### Sensor Data (High Rate)

```python
from rclpy.qos import QoSProfile, ReliabilityPolicy, HistoryPolicy, DurabilityPolicy

# Optimal for IMU, LIDAR, camera at high rates
sensor_qos = QoSProfile(
    reliability=ReliabilityPolicy.BEST_EFFORT,
    durability=DurabilityPolicy.VOLATILE,
    history=HistoryPolicy.KEEP_LAST,
    depth=1
)
```

### Commands (Must Arrive)

```python
# Optimal for cmd_vel, control commands
command_qos = QoSProfile(
    reliability=ReliabilityPolicy.RELIABLE,
    durability=DurabilityPolicy.VOLATILE,
    history=HistoryPolicy.KEEP_LAST,
    depth=10
)
```

### State (Late Joiners Need)

```python
# Optimal for robot_state, map data
state_qos = QoSProfile(
    reliability=ReliabilityPolicy.RELIABLE,
    durability=DurabilityPolicy.TRANSIENT_LOCAL,
    history=HistoryPolicy.KEEP_LAST,
    depth=1
)
```

### Services

```python
# ROS2 service QoS (fixed)
# HDDS automatically optimizes service communication
```

## Transport Optimization

### Same-Host Communication

```xml
<!-- hdds_config.xml -->
<hdds>
    <transport>
        <shared_memory enabled="true" prefer="true">
            <segment_size_mb>256</segment_size_mb>
        </shared_memory>
    </transport>
</hdds>
```

### Network Communication

```xml
<hdds>
    <transport>
        <udp enabled="true">
            <send_buffer_size>16777216</send_buffer_size>
            <receive_buffer_size>16777216</receive_buffer_size>
        </udp>
        <shared_memory enabled="false"/>
    </transport>
</hdds>
```

### Multi-Robot Fleet

```xml
<hdds>
    <transport>
        <udp>
            <multicast enabled="false"/>
        </udp>
    </transport>
    <discovery>
        <static_peers>
            <peer>${BASE_STATION}:7400</peer>
        </static_peers>
    </discovery>
</hdds>
```

## Node Optimization

### Callback Executor

```python
import rclpy
from rclpy.executors import MultiThreadedExecutor

def main():
    rclpy.init()

    node1 = MyNode1()
    node2 = MyNode2()

    # Multi-threaded for parallel callbacks
    executor = MultiThreadedExecutor(num_threads=4)
    executor.add_node(node1)
    executor.add_node(node2)

    executor.spin()
```

### Timer Optimization

```python
# Use wall timer for control loops
self.create_wall_timer(0.01, self.control_callback)  # 100 Hz

# Avoid creating many small timers
# Instead, use single timer with state machine
```

### Subscription Callback

```python
def fast_callback(self, msg):
    # Do minimal work in callback
    # Offload heavy processing to separate thread
    self.process_queue.put(msg)

def slow_processing(self):
    while True:
        msg = self.process_queue.get()
        self.heavy_computation(msg)
```

## Message Optimization

### Use Fixed-Size Messages

```python
# Prefer fixed-size arrays
from std_msgs.msg import Float32MultiArray
# vs variable-length sequences

# Better: Create custom message with fixed arrays
# my_msgs/msg/FixedSensorData.msg
# float32[16] values
```

### Avoid Large Messages

```python
# Split large data into chunks
class ImageChunker:
    def __init__(self, node, chunk_size=65536):
        self.pub = node.create_publisher(Chunk, 'image_chunks', 10)
        self.chunk_size = chunk_size

    def publish_image(self, image_data):
        for i in range(0, len(image_data), self.chunk_size):
            chunk = Chunk()
            chunk.sequence = i // self.chunk_size
            chunk.data = image_data[i:i+self.chunk_size]
            self.pub.publish(chunk)
```

### Zero-Copy Transfer

```cpp
// C++ only: Use loaned messages
auto msg = pub_->borrow_loaned_message();
msg.get().data = sensor_value;
pub_->publish(std::move(msg));
```

## Launch File Optimization

### CPU Affinity

```python
from launch import LaunchDescription
from launch_ros.actions import Node

def generate_launch_description():
    return LaunchDescription([
        Node(
            package='my_package',
            executable='critical_node',
            # Pin to specific CPU cores
            prefix='taskset -c 0,1',
            parameters=[{'use_intra_process_comms': True}]
        ),
    ])
```

### Intra-Process Communication

```python
Node(
    package='image_proc',
    executable='debayer_node',
    parameters=[{'use_intra_process_comms': True}],
    # Nodes in same process share memory directly
)
```

### Composable Nodes

```python
from launch_ros.actions import ComposableNodeContainer
from launch_ros.descriptions import ComposableNode

container = ComposableNodeContainer(
    name='sensor_container',
    namespace='',
    package='rclcpp_components',
    executable='component_container_mt',
    composable_node_descriptions=[
        ComposableNode(
            package='sensor_driver',
            plugin='SensorDriver',
        ),
        ComposableNode(
            package='sensor_filter',
            plugin='SensorFilter',
        ),
    ],
)
```

## System Tuning

### Linux Kernel Parameters

```bash
# /etc/sysctl.d/90-ros2-hdds.conf

# Network buffers
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 4194304
net.core.wmem_default = 4194304
net.core.netdev_max_backlog = 100000

# Shared memory
kernel.shmmax = 268435456
kernel.shmall = 65536

# Apply
sudo sysctl -p /etc/sysctl.d/90-ros2-hdds.conf
```

### Real-Time Priority

```bash
# /etc/security/limits.d/ros2.conf
@ros2 - rtprio 99
@ros2 - nice -20
@ros2 - memlock unlimited

# Add user to ros2 group
sudo groupadd ros2
sudo usermod -aG ros2 $USER

# In launch file
prefix='chrt -f 50'
```

### CPU Governor

```bash
# Set to performance mode
sudo cpupower frequency-set -g performance

# Or per-core
for cpu in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
    echo performance | sudo tee $cpu
done
```

## Profiling

### ROS2 Tracing

```bash
# Install
sudo apt install ros-$ROS_DISTRO-tracetools-launch

# Trace
ros2 launch tracetools_launch example.launch.py

# Analyze
babeltrace /path/to/trace | grep -E "callback|publish"
```

### HDDS Statistics

```bash
# Enable statistics
export HDDS_STATS_ENABLE=1

# Run node
ros2 run my_package my_node

# View stats
ros2 topic echo /hdds/statistics
```

### Latency Measurement

```python
import time
from rclpy.clock import Clock

class LatencyNode(Node):
    def __init__(self):
        super().__init__('latency_node')
        self.pub = self.create_publisher(Stamped, 'ping', 10)
        self.sub = self.create_subscription(Stamped, 'pong', self.pong_cb, 10)
        self.latencies = []

    def ping(self):
        msg = Stamped()
        msg.header.stamp = self.get_clock().now().to_msg()
        self.pub.publish(msg)

    def pong_cb(self, msg):
        now = self.get_clock().now()
        sent = Time.from_msg(msg.header.stamp)
        latency = (now - sent).nanoseconds / 1e6  # ms
        self.latencies.append(latency)
```

## Performance Checklist

### Configuration

- [ ] Enable shared memory for same-host nodes
- [ ] Use appropriate QoS for each topic type
- [ ] Configure adequate buffer sizes
- [ ] Tune discovery for deployment topology

### Code

- [ ] Use composable nodes where possible
- [ ] Enable intra-process communication
- [ ] Avoid work in callbacks (queue to separate thread)
- [ ] Use fixed-size message types

### System

- [ ] Set kernel parameters for networking/memory
- [ ] Configure CPU governor to performance
- [ ] Set real-time priorities for critical nodes
- [ ] Pin CPU affinity for determinism

### Deployment

- [ ] Disable logging in production
- [ ] Use release builds
- [ ] Profile before/after optimization
- [ ] Monitor resource usage

## Common Performance Issues

| Issue | Symptom | Solution |
|-------|---------|----------|
| High latency | Delayed messages | Enable SHM, reduce history |
| Dropped messages | Missing data | Increase history depth |
| High CPU | Spinning | Use WaitSet, fix spin rate |
| Memory growth | OOM | Limit history, check leaks |
| Slow discovery | Late matching | Configure initial peers |

## Next Steps

- [rmw_hdds Configuration](../ros2/rmw-hdds/configuration.md) - Detailed settings
- [Latency Tuning](../guides/performance/tuning-latency.md) - Advanced latency optimization
- [Throughput Tuning](../guides/performance/tuning-throughput.md) - Maximize bandwidth
