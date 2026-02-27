# 10_usecases - Real-World Use Case Samples

This directory contains samples demonstrating **production use cases** for HDDS in robotics and IoT applications.

## Samples

| Sample | Description |
|--------|-------------|
| `robot_telemetry` | Robot fleet monitoring and diagnostics |
| `sensor_network` | Distributed IoT sensor data collection |

## Use Case 1: Robot Telemetry

Fleet management and monitoring for autonomous robots:

```
┌─────────────┐  ┌─────────────┐  ┌─────────────┐
│   Robot 1   │  │   Robot 2   │  │   Robot N   │
│ (Simulator) │  │ (Simulator) │  │ (Simulator) │
└──────┬──────┘  └──────┬──────┘  └──────┬──────┘
       │                │                │
       └────────────────┼────────────────┘
                        │ Topic: robot/state
                        ▼
               ┌────────────────┐
               │    Monitor     │
               │  (Dashboard)   │
               └────────────────┘
```

### Message: RobotState

```idl
struct RobotState {
    unsigned long robot_id;         // Unique robot identifier
    unsigned long long timestamp_ns;// Nanosecond timestamp
    float position_x, y, z;         // Position in meters
    float orientation_w, x, y, z;   // Quaternion orientation
    float battery_percent;          // Battery level (0-100)
    octet status;                   // 0=IDLE, 1=MOVING, 2=CHARGING
};
```

### Running

```bash
cd rust

# Terminal 1 - Monitor dashboard
cargo run --bin robot_telemetry

# Terminal 2 - Robot simulator
cargo run --bin robot_telemetry -- sim
```

## Use Case 2: IoT Sensor Network

Distributed environmental monitoring with multiple sensors:

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Sensor 1   │     │  Sensor 2   │     │  Sensor N   │
│ (Publisher) │     │ (Publisher) │     │ (Publisher) │
└──────┬──────┘     └──────┬──────┘     └──────┬──────┘
       │                   │                   │
       └───────────────────┼───────────────────┘
                           │ Topic: sensors/readings
                           ▼
                  ┌────────────────┐
                  │   Collector    │
                  │  (Subscriber)  │
                  └────────────────┘
                           │
                  ┌────────┴────────┐
                  ▼                 ▼
             Dashboard        Time-Series DB
```

### Message: SensorReading

```idl
struct SensorReading {
    unsigned long sensor_id;      // Unique sensor ID
    unsigned long long timestamp; // Nanosecond timestamp
    float temperature;            // Temperature in Celsius
    float humidity;               // Relative humidity %
    float pressure;               // Atmospheric pressure hPa
    float battery_voltage;        // Battery voltage
    octet signal_strength;        // RSSI (0-100)
};
```

### Running

```bash
cd rust

# Terminal 1 - Data collector
cargo run --bin sensor_network

# Terminal 2 - Sensor simulator (ID: 1)
cargo run --bin sensor_network -- sensor 1

# Terminal 3 - Another sensor (ID: 2)
cargo run --bin sensor_network -- sensor 2
```

## QoS Recommendations

| Use Case | QoS | Rationale |
|----------|-----|-----------|
| Robot state (critical) | RELIABLE | Every state update matters |
| Sensor stream | BEST_EFFORT | High frequency, occasional loss OK |
| Alarms/Alerts | RELIABLE + TRANSIENT_LOCAL | Must not miss, late joiners get last |
| Commands | RELIABLE | Commands must be delivered |

## Expected Output

### Robot Telemetry - Monitor
```
============================================================
HDDS Robot Telemetry System
Topic: robot/state
Use Case: Fleet monitoring and diagnostics
============================================================

   Robot          X          Y  Battery     Status
--------------------------------------------------
       1       3.00       0.00    99.5%     MOVING
       1       2.94       0.59    99.0%     MOVING
  ...
  LOW BATTERY WARNING: Robot #1
```

### Sensor Network - Collector
```
============================================================
HDDS IoT Sensor Network
Topic: sensors/readings
Use Case: Distributed environmental monitoring
============================================================

Sensor Temp(C) Hum(%)  Press(hPa) Bat(V) RSSI
-----------------------------------------------------
     1    22.5   45.3     1013.2   3.29   82
     2    23.0   44.8     1013.1   3.28   78
  ...
  HIGH TEMP: Sensor #1
```

## Key Concepts

1. **Multi-Publisher Pattern**: Multiple sources publishing to same topic

2. **Centralized Monitoring**: Single collector aggregates all data

3. **Anomaly Detection**: Real-time threshold checking and alerts

4. **QoS Selection**: Match QoS to data criticality and frequency

5. **Timestamps**: Nanosecond precision for latency measurement

## Production Considerations

- **Persistence**: Add TRANSIENT_LOCAL for late-joiner support
- **Partitions**: Use DDS partitions to segment data by location/type
- **Security**: Enable DDS Security for authentication/encryption
- **Scaling**: Use content filters to reduce subscriber load
