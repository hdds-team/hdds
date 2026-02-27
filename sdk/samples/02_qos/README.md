# HDDS Samples: 02_qos

Quality of Service (QoS) samples demonstrating HDDS QoS policies.

## Samples

| Sample | Description | Key QoS |
|--------|-------------|---------|
| `reliable_delivery` | Guaranteed delivery with NACK retransmission | `RELIABLE` |
| `best_effort` | Fire-and-forget, lowest latency | `BEST_EFFORT` |
| `transient_local` | Late-joiner support with historical data | `TRANSIENT_LOCAL` |
| `deadline_monitor` | Monitor data update rate violations | `DEADLINE` |
| `liveliness_auto` | System heartbeats for presence detection | `LIVELINESS(AUTO)` |
| `liveliness_manual` | App-level heartbeat assertion | `LIVELINESS(MANUAL)` |
| `partition_filter` | Logical data filtering by namespace | `PARTITION` |
| `ownership_exclusive` | Strength-based writer arbitration | `OWNERSHIP(EXCLUSIVE)` |
| `history_keep_last` | Retain N most recent samples | `HISTORY(KEEP_LAST)` |
| `lifespan` | Auto-expire stale samples after TTL | `LIFESPAN` |
| `latency_budget` | Hint acceptable delivery delay | `LATENCY_BUDGET` |
| `time_based_filter` | Throttle reader delivery rate | `TIME_BASED_FILTER` |
| `transport_priority` | DSCP-based network prioritization | `TRANSPORT_PRIORITY` |
| `resource_limits` | Bound memory with max samples/instances | `RESOURCE_LIMITS` |

## Building

### C
```bash
cd c && mkdir build && cd build
cmake .. && make
```

### C++
```bash
cd cpp && mkdir build && cd build
cmake .. && make
```

### Python
```bash
# No build required - run directly
python reliable_delivery.py pub
python reliable_delivery.py
```

### Rust
```bash
cd rust
cargo build --release
```

## Running the Samples

Each sample has a publisher and subscriber mode:

```bash
# Terminal 1: Start subscriber
./reliable_delivery

# Terminal 2: Start publisher
./reliable_delivery pub
```

### Sample-specific options

#### deadline_monitor
```bash
./deadline_monitor        # Subscriber - monitors for deadline violations
./deadline_monitor pub    # Publisher - meets deadlines (300ms interval)
./deadline_monitor slow   # Publisher - misses deadlines (800ms interval)
```

#### partition_filter
```bash
./partition_filter            # Subscriber in partition "A"
./partition_filter pub        # Publisher in partition "A" (matches)
./partition_filter pub B      # Publisher in partition "B" (no match)
./partition_filter sub B      # Subscriber in partition "B"
```

#### ownership_exclusive
```bash
./ownership_exclusive             # Subscriber
./ownership_exclusive pub 100     # Publisher with strength 100
./ownership_exclusive pub 200     # Publisher with strength 200 (wins)
```

#### history_keep_last
```bash
./history_keep_last        # Subscriber with depth=3 (default)
./history_keep_last pub    # Publisher (burst of 10 messages)
./history_keep_last sub 5  # Subscriber with depth=5
```

#### lifespan
```bash
./lifespan pub    # Publisher (samples with 2s lifespan)
./lifespan        # Subscriber (late-start sees expired samples discarded)
```

#### latency_budget
```bash
./latency_budget pub    # Publisher (50ms latency budget hint)
./latency_budget        # Subscriber (reports delivery latency)
```

#### time_based_filter
```bash
./time_based_filter pub    # Publisher (10ms interval burst)
./time_based_filter        # Subscriber (500ms minimum separation filter)
```

#### transport_priority
```bash
./transport_priority pub      # Publisher (DSCP priority 46 = EF)
./transport_priority          # Subscriber
./transport_priority pub 10   # Publisher with custom priority
```

#### resource_limits
```bash
./resource_limits pub    # Publisher (burst of 20 samples)
./resource_limits        # Subscriber (max_samples=10 limit)
```

## QoS Concepts

### Reliability
- **RELIABLE**: Guaranteed delivery via NACK-based retransmission
- **BEST_EFFORT**: Fire-and-forget, lowest latency

### Durability
- **VOLATILE**: No caching (default)
- **TRANSIENT_LOCAL**: Publisher caches data for late-joining subscribers

### Deadline
- Monitors expected data update rate
- Triggers notification if data not received within period

### Liveliness
- **AUTOMATIC**: System sends heartbeats automatically
- **MANUAL_BY_PARTICIPANT**: App must explicitly assert liveliness

### Partition
- Logical filtering by namespace
- Writers and readers only communicate when partitions match

### Ownership
- **SHARED**: Multiple writers can publish (default)
- **EXCLUSIVE**: Only highest-strength writer publishes

### History
- **KEEP_LAST(N)**: Retain N most recent samples per instance
- **KEEP_ALL**: Retain all samples (unbounded)

### Lifespan
- Automatically expires samples older than the configured duration
- Expired samples are discarded by the reader, even if already in cache

### Latency Budget
- Advisory hint for acceptable delivery delay
- Middleware may batch or optimize delivery within the budget

### Time-Based Filter
- Sets minimum separation between delivered samples on the reader side
- Samples arriving faster than the filter interval are dropped

### Transport Priority
- Maps to DSCP values for network-level QoS prioritization
- Requires OS/network support for actual traffic shaping

### Resource Limits
- Bounds memory usage with `max_samples`, `max_instances`, `max_samples_per_instance`
- Writes are rejected when limits are reached

## Language Support

All samples are available in:
- C (C11)
- C++ (C++17)
- Python 3
- Rust (2021 edition)
