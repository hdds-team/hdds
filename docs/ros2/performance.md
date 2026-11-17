# ROS2 Performance with HDDS

Guide to optimizing ROS2 application performance using rmw_hdds.

## Published Figures

Apex.AI `performance_test` through the ROS 2 plugin, `rclcpp-single-threaded-executor`,
Array1k, 1000 msg/s, 10 s per run, one publisher and one subscriber in the same process,
ROS 2 Humble in a container, on an 88-core x86_64 host. Ten rounds, built from a clean clone
of this release. Reproduce with `rmw_hdds/scripts/bench_rmw.sh --quick`, ten times.

| RMW | mean | median of the per-run maxima | worst sample |
|---|---|---|---|
| `rmw_hdds` | 11.4 us | 598 us | 1064 us |
| `rmw_cyclonedds_cpp` | 99.6 us | 298 us | 619 us |
| `rmw_fastrtps_cpp` | 121.3 us | 355 us | 572 us |

That is the WHOLE run of each round, startup included. Excluding the first two seconds, which is
where HDDS puts its spikes, the same ten rounds give:

| RMW | mean | median of the per-run maxima | worst sample |
|---|---|---|---|
| `rmw_hdds` | 11.4 us | 85 us | 413 us |
| `rmw_cyclonedds_cpp` | 100.0 us | 278 us | 619 us |
| `rmw_fastrtps_cpp` | 121.5 us | 312 us | 572 us |

Both windows are stated because they say different things; `bench_rmw.sh` prints both for every
run. The mean moves by at most 0.4 us between them (`rmw_hdds` 11.4 then 11.4, `rmw_cyclonedds_cpp` 99.6 then 100.0, `rmw_fastrtps_cpp` 121.3 then 121.5): 8.7x to 8.8x lower than `rmw_cyclonedds_cpp` and 10.6x to 10.7x lower than `rmw_fastrtps_cpp` (the ratios of the means in the two tables). The tail is not: in steady state HDDS has the smallest maxima of the
three, and over the whole run it has the largest, because for `rmw_hdds` the worst second of the
round is the FIRST or the SECOND in ten rounds out of ten, while for Cyclone DDS the worst second
lands anywhere. So HDDS pays a startup transient that the peers do not show in that shape, and that
transient is tracked as an open item rather than hidden here.

Delivery: 89940 of 89940 samples on all three, no loss anywhere. Ten rounds out of ten produced a
measurement; none failed. `rmw_cyclonedds_cpp` and `rmw_fastrtps_cpp` ran with their default
configuration, in the same run as `rmw_hdds`, on the same host and with the same harness: no peer
was tuned, and none was handicapped.

`bench_rmw.sh` does not pin its inputs: the container image is pulled by tag, the Rust toolchain
is installed at run time and `performance_test` is cloned from its default branch, so a later run
may use different tool versions than these ten. These figures are the RMW layer on one machine and one message size, not a certification: a
different host, executor or message size gives different numbers, so run the script rather than
quote these. The HDDS core figures, each with its regime, are in
[Benchmarks](../guides/performance/benchmarks.md); they do not include the RMW layer.

## Quick Optimization

### Shared Memory

HDDS offers a shared-memory transport to co-located endpoints by default
(`ShmPolicy::Prefer`). It carries a sample only when every one of these holds,
and otherwise the pairing uses UDP:

- both endpoints are `BestEffort` (a `Reliable` endpoint never gets a
  shared-memory leg, which rules out most ROS 2 topics);
- the peer advertises the capability and co-location is provable;
- the platform is Linux.

So it will not engage for a typical ROS 2 node, and a measurement should not
be attributed to shared memory without checking that the conditions hold. See
[System Limits](../reference/limits.md#shared-memory-transport) for the
details. In `rmw_hdds`, `HDDS_SHM_DISABLE` is parsed but not applied.

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
# ROS2 service QoS is fixed by the ROS 2 service profile
```

## Transport Optimization

### Network Communication

Raise the kernel socket buffer limits (see System Tuning below); the HDDS
engine also reads `HDDS_RCVBUF_BYTES` and `HDDS_SNDBUF_BYTES` to request
larger buffers on its UDP sockets.

### Multi-Robot Fleet

Turn multicast discovery off and list the peers by their metatraffic unicast
port:

```bash
export HDDS_MULTICAST_DISABLE=true
export HDDS_DISCOVERY_PEERS=${BASE_STATION}:7410
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

- [ ] Check whether the shared-memory conditions hold for same-host nodes
- [ ] Use appropriate QoS for each topic type
- [ ] Configure adequate buffer sizes
- [ ] Tune discovery for deployment topology

### Code

- [ ] Use composable nodes where possible
- [ ] Enable intra-process communication
- [ ] Avoid work in callbacks (queue to separate thread)
- [ ] Use fixed-size message types

### System

- [ ] Set kernel parameters for networking
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
| High latency | Delayed messages | Use BestEffort where acceptable, reduce history |
| Dropped messages | Missing data | Increase history depth |
| High CPU | Spinning | Use WaitSet, fix spin rate |
| Memory growth | OOM | Limit history, check leaks |
| Slow discovery | Late matching | Configure `HDDS_DISCOVERY_PEERS` |

## Next Steps

- [rmw_hdds Configuration](../ros2/rmw-hdds/configuration.md) - Detailed settings
- [Latency Tuning](../guides/performance/tuning-latency.md) - Advanced latency optimization
- [Throughput Tuning](../guides/performance/tuning-throughput.md) - Maximize bandwidth
