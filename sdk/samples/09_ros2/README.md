# 09_ros2 - ROS2 Integration Samples

This directory contains samples demonstrating **ROS2-compatible communication** using HDDS directly at the DDS layer.

## Samples

| Sample | Description |
|--------|-------------|
| `string_talker_listener` | ROS2-style talker/listener pattern with Int32 messages |
| `pose_publisher` | Publishing geometry_msgs/Pose for robot localization |

## ROS2 and DDS

ROS2 is built on top of DDS. When you use `rclcpp` or `rclpy`, you're actually using DDS underneath:

```
ROS2 Node (rclcpp)
        │
        ▼
   rmw_hdds (RMW layer)
        │
        ▼
   HDDS (DDS layer)
        │
        ▼
  RTPS Wire Protocol
```

HDDS can communicate directly with ROS2 nodes by matching:
- Topic naming convention (`rt/<topic>` prefix)
- Message type layout (compatible CDR encoding)
- Domain ID (default: 0, configurable via `ROS_DOMAIN_ID`)

## Topic Naming Convention

ROS2 maps topic names to DDS with prefixes:

| ROS2 Topic | DDS Topic |
|------------|-----------|
| `/chatter` | `rt/chatter` |
| `/cmd_vel` | `rt/cmd_vel` |
| `/robot_pose` | `rt/robot_pose` |

The `rt/` prefix stands for "ROS Topic".

## Running the Samples

### Prerequisites

- HDDS built and installed
- (Optional) ROS2 installation for cross-communication testing

### Rust

#### Talker/Listener

```bash
cd rust

# Terminal 1 - Listener (subscriber)
cargo run --bin string_talker_listener

# Terminal 2 - Talker (publisher)
cargo run --bin string_talker_listener -- talk

# Alternative: ROS2 nodes
# ros2 run demo_nodes_cpp talker
# ros2 run demo_nodes_cpp listener
```

#### Pose Publisher

```bash
# Terminal 1 - Subscriber
cargo run --bin pose_publisher

# Terminal 2 - Publisher (robot simulation)
cargo run --bin pose_publisher -- pub

# Visualize in RViz (if ROS2 installed):
# ros2 topic echo /robot_pose geometry_msgs/msg/Pose
```

## Expected Output

### Talker
```
============================================================
HDDS ROS2 Talker/Listener Sample
Topic: rt/counter (ROS2: /counter)
Type: std_msgs/msg/Int32 equivalent
============================================================

Node Configuration:
  Participant: ros2_demo
  Domain ID: 0 (matches ROS2 default)

  [Talker] Publishing: 0
  [Talker] Publishing: 1
  ...
```

### Listener
```
Subscribed to topic: rt/counter (ROS2: /counter)
Waiting for messages...

  [Listener] I heard: 0
  [Listener] I heard: 1
  ...
```

## Message Types

Samples use ROS2-compatible message structures:

### Int32 (std_msgs/msg/Int32)
```idl
struct Int32 {
    long data;
};
```

### Pose (geometry_msgs/msg/Pose)
```idl
struct Point {
    double x, y, z;
};

struct Quaternion {
    double x, y, z, w;
};

struct Pose {
    Point position;
    Quaternion orientation;
};
```

## Key Concepts

1. **Topic Prefixes**: ROS2 uses `rt/` for topics, `rq/`/`rr/` for services

2. **QoS Profiles**: ROS2 defaults to RELIABLE; match for compatibility

3. **Domain ID**: Set via `ROS_DOMAIN_ID` env var (default: 0)

4. **Type Support**: Message types must match ROS2 IDL definitions

## Integration with rmw_hdds

For full ROS2 integration, use the `rmw_hdds` RMW implementation:

```bash
export RMW_IMPLEMENTATION=rmw_hdds
ros2 run demo_nodes_cpp talker
```

See `/docs/ros2/` for complete RMW integration documentation.
