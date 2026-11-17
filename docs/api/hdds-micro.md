# HDDS Micro - Embedded DDS

HDDS Micro is a **no_std** DDS implementation for resource-constrained microcontrollers.

:::info Version and footprint
The crate carries the workspace version (`hdds_micro::VERSION`).

Measured footprint of the core: **10467 bytes of `.text`, 0 data, 0 bss** for
`thumbv7em-none-eabihf` (Cortex-M4F) in release with no default features. Reproduce it
with `crates/hdds-micro/scripts/footprint.sh`, which builds the crate and reads the
objects of the produced rlib with `llvm-size`.

This is the library's compiled code size, not a linked firmware image: a final link
applies garbage collection and an application pulls only the subset it calls. No
firmware size is published.
:::

HDDS Micro speaks to HDDS participants. It is not a general-purpose RTPS stack
and does not claim interoperability with other vendors' implementations (see
[Interoperability](#interoperability)).

## Design Constraints

| Constraint | Design target |
|------------|---------------|
| Flash | < 100 KB |
| RAM | < 50 KB |
| Heap | 0 (no allocations in core) |
| std | Optional, no_std by default |

## Transports and Targets

The crate is hardware-independent: a transport is a type that implements the
[`Transport`](#transport-trait) trait, and the radio drivers take the SPI, GPIO
and UART access they need through small traits that your board support code
implements. The transports in the crate:

| Transport | Module | Hardware access you provide |
|-----------|--------|-----------------------------|
| UDP (WiFi, Ethernet, host) | `transport::udp` | a `UdpSocket` implementation; `StdUdpSocket` is provided with the `std` feature |
| LoRa | `transport::lora` | SX1276/78 over SPI (`SpiDevice`, `DioPin`) |
| NRF24L01 | `transport::nrf24` | SPI (`SpiDevice`) and the CE pin (`CePin`) |
| CC1101 | `transport::cc1101` | SPI (`SpiDevice`), optional GDO pin (`GdoPin`) |
| HC-12 | `transport::hc12` | UART (`Uart`) and the SET pin (`SetPin`) |
| Mesh | `transport::mesh` | wraps any other transport (`MeshTransport`) |

The `crates/hdds-micro/esp32-example` directory of the repository is an ESP32
project (ESP-IDF, WiFi UDP) built on the crate, with an HC-12 test program. The
crate contains no board-specific code for RP2040 or STM32: implement the
traits above for your HAL.

## Installation

Depend on the crate from a checkout of the repository; this page documents that
version of the API.

```toml
# Cargo.toml
[dependencies]
hdds-micro = { path = "../hdds/crates/hdds-micro" }

# On a host, with std (StdUdpSocket, the gateway module)
hdds-micro = { path = "../hdds/crates/hdds-micro", features = ["std"] }
```

### Available Features

`default = []`: the crate is `no_std` without any feature.

| Feature | Description |
|---------|-------------|
| `std` | Enable the standard library: `StdUdpSocket`, the `gateway` module, `std::error::Error` for `Error` |
| `alloc` | Link the `alloc` crate |
| `heapless` | Enable `CdrDecoder::decode_string` (decodes into a `heapless::String`); pulls the `heapless` 0.8 dependency |
| `esp32`, `rp2040`, `stm32`, `wifi`, `lora` | Reserved markers: they enable no code today. Every transport module compiles without them |

## Core API

### MicroParticipant

The entry point for HDDS Micro applications.

```rust
use hdds_micro::core::MicroParticipant;
use hdds_micro::transport::udp::{StdUdpSocket, WifiUdpTransport};

// Create the transport: a UDP socket bound to local port 7400
// (StdUdpSocket needs the `std` feature; on a board, use your own UdpSocket)
let mut transport = WifiUdpTransport::new(StdUdpSocket::new(), 7400)?;
transport.enable_multicast([239, 255, 0, 1])?;

// Create the participant. `instance` must differ on every boot (a hardware
// random number, a boot counter): it is part of the GUID prefix.
let instance: u32 = 1;
let mut participant = MicroParticipant::with_instance(0, transport, instance)?;

// Get GUID prefix
let guid_prefix = participant.guid_prefix();
let domain_id = participant.domain_id();
```

`MicroParticipant::new(domain_id, transport)` is deprecated: it is
`with_instance(domain_id, transport, 0)`, and the GUID prefix then repeats
across reboots.

**Key properties:**
- Single-threaded (no async, no locks)
- BEST_EFFORT QoS only
- No discovery and no topic matching: the writer is given its destination
  locator, and the DATA it sends carries no topic name. A reader takes every
  DATA whose reader id is unknown or its own, so keep topics apart by
  destination (address and port)

### MicroWriter

Publishes data samples to a topic.

```rust
use hdds_micro::core::MicroWriter;
use hdds_micro::cdr::CdrEncoder;
use hdds_micro::rtps::Locator;

// Allocate entity ID
let writer_id = participant.allocate_entity_id(true); // true = writer

// Create destination locator (multicast)
let dest_locator = Locator::udpv4([239, 255, 0, 1], 7400);

// Create writer
let mut writer = MicroWriter::new(
    participant.guid_prefix(),
    writer_id,
    "Temperature",        // topic name (max 63 chars)
    dest_locator,
)?;

// Encode and write sample
let mut buf = [0u8; 256];
let mut encoder = CdrEncoder::new(&mut buf);
encoder.encode_f32(23.5)?;           // temperature value
encoder.encode_i64(1234567890)?;     // timestamp
let payload = encoder.finish();

writer.write(payload, participant.transport_mut())?;
```

### MicroReader

Receives data samples from a topic.

```rust
use hdds_micro::core::{MicroReader, Sample};
use hdds_micro::cdr::CdrDecoder;

// Allocate entity ID
let reader_id = participant.allocate_entity_id(false); // false = reader

// Create reader
let mut reader = MicroReader::new(
    participant.guid_prefix(),
    reader_id,
    "Temperature",
)?;

// Read samples (non-blocking)
loop {
    if let Some(sample) = reader.read(participant.transport_mut())? {
        // Decode payload: decoder() refuses a body that is not XCDR1
        // little endian, the encoding CdrDecoder reads
        let mut decoder = sample.decoder()?;
        let temperature: f32 = decoder.decode_f32()?;
        let timestamp: i64 = decoder.decode_i64()?;

        // Process sample
        println!("Temp: {} at {}", temperature, timestamp);
    }

    // Sleep/yield in embedded environment
}
```

`Sample` also carries `writer_guid`, `sequence_number`, `representation` (the
payload representation identifier) and `payload` (the body, without the
4-octet serialized payload header). `read()` returns `Ok(None)` when nothing is
queued. `reader.read_next()` returns a `Next` value (`Sample`, `Skipped` or
`Empty`) so that a loop can tell a skipped frame (malformed, addressed to
another reader, or larger than the receive buffer) from an empty queue, and keep
draining.

## CDR Encoding

HDDS Micro includes a lightweight encoder/decoder for classic CDR (XCDR1, little endian) with no heap allocations. `MicroWriter` sends the body behind a `CDR_LE` serialized payload header, and `Sample::decoder()` refuses a body in any other encoding.

### Supported Types

| Type | Encode | Decode |
|------|--------|--------|
| `u8`, `i8` | `encode_u8()` | `decode_u8()` |
| `u16`, `i16` | `encode_u16()` | `decode_u16()` |
| `u32`, `i32` | `encode_u32()` | `decode_u32()` |
| `u64`, `i64` | `encode_u64()` | `decode_u64()` |
| `f32` | `encode_f32()` | `decode_f32()` |
| `f64` | `encode_f64()` | `decode_f64()` |
| `bool` | `encode_bool()` | `decode_bool()` |
| `&str` | `encode_string()` | `decode_string_borrowed()`, `decode_string::<N>()` (`heapless` feature) |
| `&[u8]` | `encode_bytes()` (raw bytes, no length prefix) | `decode_bytes(count)` |
| Sequence length | `encode_seq_len()` | `decode_seq_len()` |

### CdrEncoder

```rust
use hdds_micro::cdr::CdrEncoder;

let mut buf = [0u8; 256];
let mut encoder = CdrEncoder::new(&mut buf);

// Encode primitive types
encoder.encode_u32(42)?;
encoder.encode_f32(3.14)?;
encoder.encode_string("hello")?;

// Get encoded bytes
let bytes = encoder.finish();
```

### CdrDecoder

```rust
use hdds_micro::cdr::CdrDecoder;

let mut decoder = CdrDecoder::new(received_bytes);

let id: u32 = decoder.decode_u32()?;
let value: f32 = decoder.decode_f32()?;
let name = decoder.decode_string_borrowed()?; // zero-copy
```

### Generated Types

`hddsgen` generates the encode and decode code for an IDL struct:

```bash
hddsgen gen micro temperature.idl -o temperature.rs
```

```rust
let sample = Temperature { sensor_id: 1, value: 23.5, timestamp: 0 };

let mut buf = [0u8; 64];
let mut encoder = CdrEncoder::new(&mut buf);
sample.encode(&mut encoder)?;
let payload = encoder.finish();

let mut decoder = CdrDecoder::new(payload);
let back = Temperature::decode(&mut decoder)?;
```

`hddsgen` is installed from the generator repository
(`git clone https://git.hdds.io/hdds/hdds_gen.git`, then
`cargo install --path hdds_gen`); the `hddsgen` release on crates.io stops at
1.0.12. See the [hddsgen CLI reference](../tools/hdds-gen/cli-reference.md).

### Limitations

- No sequences (unbounded arrays) - use fixed arrays
- No optional fields - all fields required
- Little-endian only (native for most embedded targets)
- Classic CDR (XCDR1) only: a body labelled XCDR2 is refused by
  `Sample::decoder()`. A full HDDS writer that offers XCDR2 must be set to
  offer XCDR1 to reach this crate

## Transport Implementations

### WiFi UDP Transport

UDP over any network interface that gives you a socket. `WifiUdpTransport` wraps
anything that implements the `UdpSocket` trait (`bind`, `join_multicast`,
`send_to`, `recv_from`, `try_recv_from`, `local_port`, `local_ip`).

```rust
use hdds_micro::transport::udp::{StdUdpSocket, WifiUdpTransport};

// Standard UDP socket (host, `std` feature), bound to local port 7400
let mut transport = WifiUdpTransport::new(StdUdpSocket::new(), 7400)?;

// Optional: join a multicast group
transport.enable_multicast([239, 255, 0, 1])?;
```

On a board, implement `UdpSocket` over the platform's socket API and pass it to
`WifiUdpTransport::new(socket, port)`.

### LoRa Transport (SX1276/78)

Long-range, low-bandwidth communication.

```rust
use hdds_micro::transport::lora::{
    Bandwidth, CodingRate, LoRaConfig, LoRaTransport, SpreadingFactor,
};

// Configure LoRa
let config = LoRaConfig {
    frequency_mhz: 868.0,        // EU band
    spreading_factor: SpreadingFactor::Sf7,
    bandwidth: Bandwidth::Bw125,
    coding_rate: CodingRate::Cr4_5,
    tx_power_dbm: 14,
    rx_timeout_ms: 5000,
    preamble_length: 8,
    crc_enabled: true,
};

// Or start from a preset: LoRaConfig::eu868(LoRaProfile::Balanced),
// LoRaConfig::us915(...), LoRaConfig::from_profile(profile, frequency_mhz)

// Create transport: `spi` implements lora::SpiDevice, `dio0_pin` lora::DioPin
let mut transport = LoRaTransport::new(spi, dio0_pin, config, node_id)?;

let rssi: i16 = transport.rssi()?;
let snr: i8 = transport.snr()?;
```

**LoRa features:**
- Packet fragmentation for messages > 255 bytes
- RSSI/SNR monitoring
- Configurable spreading factor (SF7-SF12)
- Presets (`LoRaProfile::Fast`, `Balanced`, `LongRange`) and
  `LoRaConfig::time_on_air_ms()`

### NRF24L01 Transport

High-speed, short-range 2.4 GHz radio.

```rust
use hdds_micro::transport::nrf24::{
    Nrf24Channel, Nrf24Config, Nrf24DataRate, Nrf24Power, Nrf24Transport,
};

let config = Nrf24Config {
    channel: Nrf24Channel(76),
    data_rate: Nrf24DataRate::Rate1Mbps,
    power: Nrf24Power::Max,
    ..Default::default()
};

// `spi` implements nrf24::SpiDevice, `ce_pin` nrf24::CePin
let transport = Nrf24Transport::new(spi, ce_pin, config);
```

**NRF24 features:**
- Data rates: 250kbps, 1Mbps, 2Mbps
- 126 channels (0-125)
- Auto-acknowledgment and retransmit
- Payload size: 1-32 bytes (`transport::nrf24::MAX_PAYLOAD_SIZE`), so a
  datagram larger than 32 bytes is refused with `InvalidParameter`

### CC1101 and HC-12

Sub-GHz radio transports for 433MHz/868MHz bands.

```rust
use hdds_micro::transport::cc1101::{Cc1101Config, Cc1101Transport};
use hdds_micro::transport::hc12::{Hc12Config, Hc12Transport};

// CC1101: `spi` implements cc1101::SpiDevice. Payload limit: 61 bytes.
let cc = Cc1101Transport::new(spi, Cc1101Config::default());
// Presets: Cc1101Config::long_range(), Cc1101Config::high_speed()
// With a GDO pin: Cc1101Transport::with_gdo(spi, gdo0, config)

// HC-12: `uart` implements hc12::Uart, `set_pin` hc12::SetPin
let hc = Hc12Transport::new(uart, set_pin, node_id);
// Or with a configuration: Hc12Transport::with_config(uart, set_pin, node_id, Hc12Config::default())
```

The HC-12 module carries at most 58 bytes per packet (`transport::hc12::HC12_MAX_PACKET`).

### Mesh Transport

Multi-hop flooding mesh over any underlying transport. `MeshTransport` wraps a
transport and adds a mesh header, a TTL, duplicate suppression and relaying; it
does not implement `Transport` itself: use its own send and receive methods.

```rust
use hdds_micro::transport::mesh::{MeshConfig, MeshTransport};

// 8 neighbor slots, 16 entries in the seen-message cache
let mut mesh: MeshTransport<_, 8, 16> =
    MeshTransport::new(radio_transport, 1 /* node id */, MeshConfig::relay_node());

mesh.send_mesh(b"hello")?;        // flood
mesh.send_to(2, b"hello")?;       // addressed to node 2

let mut buf = [0u8; 128];
if let Some((src_node, len)) = mesh.recv_mesh(&mut buf)? {
    let payload = &buf[..len];    // a message for this node; others are relayed
}
```

`MeshConfig::endpoint()` disables relaying, `MeshConfig::default()` has
`default_ttl = 3`; the maximum TTL is `transport::mesh::MAX_TTL` (7).

## Transport Trait

Custom transports can implement the `Transport` trait:

```rust
use hdds_micro::transport::Transport;
use hdds_micro::rtps::Locator;
use hdds_micro::error::Result;

pub trait Transport {
    fn init(&mut self) -> Result<()>;
    fn send(&mut self, data: &[u8], dest: &Locator) -> Result<usize>;
    fn recv(&mut self, buf: &mut [u8]) -> Result<(usize, Locator)>;
    fn try_recv(&mut self, buf: &mut [u8]) -> Result<(usize, Locator)>;
    fn local_locator(&self) -> Locator;
    fn mtu(&self) -> usize;
    fn shutdown(&mut self) -> Result<()>;

    // Optional: RSSI for radio transports
    fn last_rssi(&self) -> Option<i16> { None }
}
```

`try_recv` returns `Err(Error::ResourceExhausted)` when no packet is queued;
`MicroReader::read()` turns that into `Ok(None)`.

## Error Handling

```rust
use hdds_micro::error::{Error, Result};

match writer.write(payload, transport) {
    Ok(()) => { /* success */ }
    Err(Error::BufferTooSmall) => { /* payload too large */ }
    Err(Error::TransportError) => { /* network error */ }
    Err(Error::Timeout) => { /* operation timed out */ }
    Err(e) => { /* other error */ }
}
```

### Error Types

| Error | Description |
|-------|-------------|
| `BufferTooSmall` | Buffer insufficient for operation |
| `InvalidHeader` | Invalid RTPS header |
| `InvalidSubmessage` | Invalid submessage format |
| `EncodingError` | CDR encoding failed |
| `DecodingError` | CDR decoding failed |
| `TransportError` | Network/radio error |
| `NotInitialized` | Participant not initialized |
| `EntityNotFound` | Entity not found |
| `InvalidParameter` | Invalid parameter value |
| `ResourceExhausted` | History full or no data available |
| `Timeout` | Operation timed out |
| `InvalidData` | Invalid or corrupted data |
| `InvalidEncoding` | Invalid encoding (for example an unknown enum discriminator) |

## Complete Example

A publisher and a subscriber in one process, over the loopback interface (the
`std` feature, `StdUdpSocket`). The subscriber listens on UDP port 17401 and the
publisher sends its DATA to that address.

```rust
use hdds_micro::cdr::CdrEncoder;
use hdds_micro::core::{MicroParticipant, MicroReader, MicroWriter};
use hdds_micro::rtps::Locator;
use hdds_micro::transport::udp::{StdUdpSocket, WifiUdpTransport};
use hdds_micro::Result;

fn main() -> Result<()> {
    // Subscriber: UDP port 17401
    let rx_transport = WifiUdpTransport::new(StdUdpSocket::new(), 17401)?;
    let mut rx = MicroParticipant::with_instance(0, rx_transport, 1)?;
    let reader_id = rx.allocate_entity_id(false);
    let mut reader = MicroReader::new(rx.guid_prefix(), reader_id, "Temperature")?;

    // Publisher: any free port, sends to the subscriber's address
    let tx_transport = WifiUdpTransport::new(StdUdpSocket::new(), 0)?;
    let mut tx = MicroParticipant::with_instance(0, tx_transport, 2)?;
    let writer_id = tx.allocate_entity_id(true);
    let dest = Locator::udpv4([127, 0, 0, 1], 17401);
    let mut writer = MicroWriter::new(tx.guid_prefix(), writer_id, "Temperature", dest)?;

    // Publish one sample: sensor_id, value, timestamp
    let mut buf = [0u8; 64];
    let mut encoder = CdrEncoder::new(&mut buf);
    encoder.encode_u32(42)?;
    encoder.encode_f32(23.5)?;
    encoder.encode_u64(1_234_567_890)?;
    writer.write(encoder.finish(), tx.transport_mut())?;

    // Poll the reader until the sample arrives
    for _ in 0..50 {
        if let Some(sample) = reader.read(rx.transport_mut())? {
            let mut decoder = sample.decoder()?;
            let sensor_id = decoder.decode_u32()?;
            let value = decoder.decode_f32()?;
            let timestamp = decoder.decode_u64()?;
            println!("sensor {sensor_id}: {value} at {timestamp}");
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    eprintln!("no sample received");
    Ok(())
}
```

Output: `sensor 42: 23.5 at 1234567890`.

The repository carries the same pattern as a two-process program
(`crates/hdds-micro/examples/temperature_pubsub.rs`, run with
`cargo run --example temperature_pubsub --features std -- sub` and `-- pub`) and
an ESP32 project that runs it over WiFi with ESP-IDF
(`crates/hdds-micro/esp32-example`).

## Interoperability

HDDS Micro speaks to HDDS participants. It sends and receives RTPS 2.5 DATA
submessages with classic CDR bodies (XCDR1, little endian), and it runs no
discovery: the writer is given its destination and the reader takes the DATA
addressed to it.

- **Scope**: HDDS participants. The crate does not claim conformance against
  other vendors' stacks.
- **Wire format**: RTPS 2.5 header and DATA submessage, `CDR_LE` serialized
  payload header, little-endian submessage bodies.
- **A sample the crate cannot read is refused**, never delivered partially
  decoded (for example a body labelled XCDR2, or a big-endian peer's DATA).
- **HDDS side**: a full HDDS writer that offers XCDR2 must have its
  `data_representation` set to XCDR1 for this crate to decode its samples.

## QoS Support

HDDS Micro implements **BEST_EFFORT QoS only**:

| Policy | Support |
|--------|---------|
| Reliability | BEST_EFFORT only |
| Durability | VOLATILE only |
| History | No history cache |
| Deadline | Not supported |
| Liveliness | Not supported |

For reliable delivery, use HDDS (full) on more capable hardware.

## Constants

```rust
// Maximum packet size
pub const MAX_PACKET_SIZE: usize = 1024;

// Maximum number of samples in a history cache (a constant; nothing in the
// crate uses it, since there is no history cache)
pub const MAX_HISTORY_DEPTH: usize = 16;

// Crate version string
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
```

## Next Steps

- [Rust API](../api/rust.md) - Full HDDS API reference
- [Interoperability](../interop/index.md) - Cross-vendor communication
- [Hello World Rust](../getting-started/hello-world-rust.md) - Getting started tutorial
