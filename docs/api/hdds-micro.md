# HDDS Micro - Embedded DDS

HDDS Micro is a **no_std** DDS implementation for resource-constrained microcontrollers.

:::info Version 1.0.0
Sub-megabyte footprint (~600 KB static binary), verified on ESP32, Raspberry Pi Zero, and ARM Cortex-M platforms.
:::

## Design Constraints

| Constraint | Target | Actual |
|------------|--------|--------|
| Flash | < 100 KB | ~60-80 KB |
| RAM | < 50 KB | ~30-40 KB |
| Heap | 0 | 0 (no allocations in core) |
| std | Optional | no_std by default |

## Supported Platforms

| Platform | Architecture | Transport | Tested |
|----------|--------------|-----------|--------|
| ESP32-WROOM-32 | Xtensa | WiFi UDP | 10/10 samples |
| ESP32-WROVER-E | Xtensa | WiFi UDP | 25/25 samples |
| ESP32 + HC-12 | Xtensa | 433MHz Radio | 18/18 samples |
| Raspberry Pi Zero 2 W | aarch64 | WiFi UDP | 10/10 samples |
| Raspberry Pi Zero v1 | armv6 | WiFi UDP | 10/10 samples |
| Linux PC | x86_64 | WiFi UDP | 10/10 samples |
| RP2040 | ARM Cortex-M0+ | WiFi (Pico W) | Supported |
| STM32 | ARM Cortex-M | Serial/CAN | Supported |

## Installation

```toml
# Cargo.toml
[dependencies]
hdds-micro = "1.0"

# Platform-specific features
hdds-micro = { version = "1.0", features = ["esp32", "wifi"] }
hdds-micro = { version = "1.0", features = ["rp2040", "wifi"] }
hdds-micro = { version = "1.0", features = ["stm32", "lora"] }
```

### Available Features

| Feature | Description |
|---------|-------------|
| `esp32` | ESP32 platform support |
| `rp2040` | RP2040 (Raspberry Pi Pico) support |
| `stm32` | STM32 platform support |
| `wifi` | WiFi UDP transport |
| `lora` | LoRa radio transport (SX1276/78) |
| `alloc` | Enable heap allocations |
| `std` | Enable standard library |

## Core API

### MicroParticipant

The entry point for HDDS Micro applications.

```rust
use hdds_micro::core::MicroParticipant;
use hdds_micro::transport::udp::WifiUdpTransport;

// Create transport
let transport = WifiUdpTransport::new("192.168.1.100", 7400)?;

// Create participant
let mut participant = MicroParticipant::new(0, transport)?;

// Get GUID prefix
let guid_prefix = participant.guid_prefix();
let domain_id = participant.domain_id();
```

**Key properties:**
- Single-threaded (no async, no locks)
- Fixed number of readers/writers
- BEST_EFFORT QoS only

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
        // Decode payload
        let mut decoder = CdrDecoder::new(sample.payload);
        let temperature: f32 = decoder.decode_f32()?;
        let timestamp: i64 = decoder.decode_i64()?;

        // Process sample
        println!("Temp: {} at {}", temperature, timestamp);
    }

    // Sleep/yield in embedded environment
}
```

## CDR Encoding

HDDS Micro includes a lightweight CDR2 encoder/decoder with no heap allocations.

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
| `&str` | `encode_string()` | `decode_string_borrowed()` |
| `&[u8]` | `encode_bytes()` | `decode_bytes()` |

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

let mut decoder = CdrDecoder::new(&received_bytes);

let id: u32 = decoder.decode_u32()?;
let value: f32 = decoder.decode_f32()?;
let name = decoder.decode_string_borrowed()?; // zero-copy
```

### Limitations

- No sequences (unbounded arrays) - use fixed arrays
- No optional fields - all fields required
- Little-endian only (native for most embedded targets)

## Transport Implementations

### WiFi UDP Transport

For ESP32, RP2040W, and Linux platforms.

```rust
use hdds_micro::transport::udp::{StdUdpSocket, WifiUdpTransport};

// Standard UDP socket (Linux/std)
let socket = StdUdpSocket::bind("0.0.0.0:7400")?;
let transport = WifiUdpTransport::new(socket)?;

// ESP32 with esp-idf-svc (see ESP32 example below)
```

### LoRa Transport (SX1276/78)

Long-range, low-bandwidth communication.

```rust
use hdds_micro::transport::lora::{LoRaTransport, LoRaConfig, SpreadingFactor};

// Configure LoRa
let config = LoRaConfig {
    frequency_mhz: 868.0,        // EU band
    spreading_factor: SpreadingFactor::SF7,
    bandwidth: Bandwidth::Bw125kHz,
    coding_rate: CodingRate::Cr45,
    tx_power_dbm: 14,
    rx_timeout_ms: 5000,
};

// Create transport (SPI + DIO0 pin)
let transport = LoRaTransport::new(spi, dio0_pin, config, node_id)?;
```

**LoRa features:**
- Packet fragmentation for messages > 255 bytes
- RSSI/SNR monitoring
- Configurable spreading factor (SF7-SF12)

### NRF24L01 Transport

High-speed, short-range 2.4 GHz radio.

```rust
use hdds_micro::transport::nrf24::{Nrf24Transport, Nrf24Config, Nrf24DataRate};

let config = Nrf24Config {
    channel: Nrf24Channel(76),
    data_rate: Nrf24DataRate::Rate1Mbps,
    power: Nrf24Power::Max,
    ..Default::default()
};

let transport = Nrf24Transport::new(spi, ce_pin, config);
```

**NRF24 features:**
- Data rates: 250kbps, 1Mbps, 2Mbps
- 126 channels
- Auto-acknowledgment and retransmit
- Payload size: 1-32 bytes

### CC1101 and HC-12

Sub-GHz radio transports for 433MHz/868MHz bands.

```rust
use hdds_micro::transport::cc1101::{Cc1101Transport, Cc1101Config};
use hdds_micro::transport::hc12::Hc12Transport;
```

### Mesh Transport

Multi-hop mesh networking over any underlying radio.

```rust
use hdds_micro::transport::mesh::{MeshTransport, MeshConfig};

let config = MeshConfig {
    max_hops: 3,
    node_id: 1,
    ..Default::default()
};

let mesh = MeshTransport::new(radio_transport, config)?;
```

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

## Complete ESP32 Example

```rust
#![no_std]
#![no_main]

use esp_idf_svc::wifi::{BlockingWifi, EspWifi};
use esp_idf_svc::hal::peripherals::Peripherals;
use hdds_micro::cdr::CdrEncoder;
use hdds_micro::rtps::{RtpsHeader, VendorId, ProtocolVersion};
use hdds_micro::rtps::submessages::Data;

#[no_mangle]
fn main() {
    // Initialize ESP32 peripherals
    let peripherals = Peripherals::take().unwrap();

    // Connect to WiFi
    let wifi = BlockingWifi::wrap(
        EspWifi::new(peripherals.modem, sysloop.clone(), None).unwrap(),
        sysloop,
    ).unwrap();

    wifi.connect().unwrap();
    wifi.wait_netif_up().unwrap();

    // Create UDP socket
    let socket = UdpSocket::bind("0.0.0.0:7400").unwrap();

    // Build RTPS packet
    let mut packet = [0u8; 256];

    // RTPS Header (20 bytes)
    let header = RtpsHeader::new(
        ProtocolVersion::RTPS_2_5,
        VendorId::HDDS,
        guid_prefix,
    );
    let header_len = header.encode(&mut packet).unwrap();

    // DATA submessage
    let data = Data::new(entity_id_reader, entity_id_writer, seq_num);
    let data_len = data.encode_header(&mut packet[header_len..]).unwrap();

    // CDR payload
    let mut encoder = CdrEncoder::new(&mut packet[header_len + data_len..]);
    encoder.encode_f32(25.5).unwrap();  // temperature
    let payload = encoder.finish();

    // Send to multicast
    let dest = "239.255.0.1:7400";
    socket.send_to(&packet[..header_len + data_len + payload.len()], dest).unwrap();
}
```

## Interoperability

HDDS Micro uses standard RTPS 2.5 protocol and CDR2 encoding:

- **Interoperates with**: HDDS (full), FastDDS, RTI Connext, CycloneDDS
- **Wire format**: CDR2 little-endian
- **Discovery**: Simplified SPDP (no SEDP for minimal footprint)

Cross-architecture verified:
- aarch64 (Pi Zero 2) ↔ armv6 (Pi Zero v1) ↔ Xtensa (ESP32)

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

// Maximum history depth (compile-time configurable)
pub const MAX_HISTORY_DEPTH: usize = 16;
```

## Next Steps

- [Rust API](../api/rust.md) - Full HDDS API reference
- [Interoperability](../interop.md) - Cross-vendor communication
- [Hello World Rust](../getting-started/hello-world-rust.md) - Getting started tutorial
