// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! HDDS Micro ESP32 WiFi Example - Real RTPS
//!
//! Temperature publisher/subscriber on ESP32 over WiFi using hdds-micro RTPS.

use esp_idf_svc::eventloop::EspSystemEventLoop;
use esp_idf_svc::hal::prelude::Peripherals;
use esp_idf_svc::nvs::EspDefaultNvsPartition;
use esp_idf_svc::wifi::{BlockingWifi, ClientConfiguration, Configuration, EspWifi};
use log::*;
use std::net::UdpSocket;
use std::time::Duration;

// Use real hdds-micro RTPS
use hdds_micro::cdr::{CdrDecoder, CdrEncoder};
use hdds_micro::rtps::submessages::Data;
use hdds_micro::rtps::{EntityId, GuidPrefix, ProtocolVersion, RtpsHeader, SequenceNumber, VendorId};

// WiFi credentials - update these for your network
const WIFI_SSID: &str = "YOUR_WIFI_SSID";
const WIFI_PASS: &str = "YOUR_WIFI_PASSWORD";

// Mode: "pub" or "sub"
const MODE: &str = "pub";

// Destination IP for publisher (PC running receiver)
const DEST_IP: &str = "192.0.2.100"; // Update to your PC's IP on same network
const DEST_PORT: u16 = 7777;

/// Temperature data
#[derive(Debug, Clone)]
struct Temperature {
    sensor_id: u32,
    value: f32,
    timestamp: u64,
}

impl Temperature {
    fn encode(&self, enc: &mut CdrEncoder) -> Result<(), hdds_micro::Error> {
        enc.encode_u32(self.sensor_id)?;
        enc.encode_f32(self.value)?;
        enc.encode_u64(self.timestamp)?;
        Ok(())
    }

    fn decode(dec: &mut CdrDecoder) -> Result<Self, hdds_micro::Error> {
        Ok(Self {
            sensor_id: dec.decode_u32()?,
            value: dec.decode_f32()?,
            timestamp: dec.decode_u64()?,
        })
    }
}

fn main() -> anyhow::Result<()> {
    esp_idf_svc::sys::link_patches();
    esp_idf_svc::log::EspLogger::initialize_default();

    info!("========================================");
    info!("  HDDS Micro ESP32 - RTPS Temperature");
    info!("========================================");
    info!("Mode: {}", MODE);

    // Initialize peripherals
    let peripherals = Peripherals::take()?;
    let sys_loop = EspSystemEventLoop::take()?;
    let nvs = EspDefaultNvsPartition::take()?;

    // Initialize WiFi
    info!("Connecting to WiFi: {}", WIFI_SSID);
    let mut wifi = BlockingWifi::wrap(
        EspWifi::new(peripherals.modem, sys_loop.clone(), Some(nvs))?,
        sys_loop,
    )?;

    wifi.set_configuration(&Configuration::Client(ClientConfiguration {
        ssid: WIFI_SSID.try_into().unwrap(),
        password: WIFI_PASS.try_into().unwrap(),
        ..Default::default()
    }))?;

    wifi.start()?;
    wifi.connect()?;
    wifi.wait_netif_up()?;

    let ip_info = wifi.wifi().sta_netif().get_ip_info()?;
    info!("WiFi connected!");
    info!("  IP: {}", ip_info.ip);

    // Run based on mode
    match MODE {
        "pub" => run_publisher()?,
        "sub" => run_subscriber()?,
        _ => error!("Invalid MODE"),
    }

    loop {
        std::thread::sleep(Duration::from_secs(1));
    }
}

fn run_publisher() -> anyhow::Result<()> {
    info!("Starting RTPS Publisher...");

    let socket = UdpSocket::bind("0.0.0.0:0")?;
    let dest = format!("{}:{}", DEST_IP, DEST_PORT);
    info!("Sending to: {}", dest);

    // GUID prefix: the HDDS vendor id first (RTPS 2.5 9.3.1.5), then a
    // marker for this example, then the hardware random number generator so
    // that the prefix differs from one boot to the next.
    // SAFETY: esp_random has no precondition; it reads the RNG register.
    let boot = unsafe { esp_idf_svc::sys::esp_random() }.to_be_bytes();
    let guid_prefix = GuidPrefix::new([
        0x01, 0x1A, // HDDS vendor id
        0xE5, 0x32, 0x00, 0x01, // ESP32 example marker
        0x00, 0x00, boot[0], boot[1], boot[2], boot[3],
    ]);
    let writer_id = EntityId::new([0x00, 0x00, 0x01, 0x02]); // User DataWriter

    let mut seq: u32 = 0;
    loop {
        seq += 1;
        let temp_value = 20.0 + (seq as f32 * 0.1) % 10.0;
        let temp = Temperature {
            sensor_id: 0xE532,
            value: temp_value,
            timestamp: seq as u64 * 1000,
        };

        // Build RTPS packet
        let mut packet = [0u8; 256];
        let mut offset = 0;

        // 1. RTPS Header (20 bytes)
        let header = RtpsHeader::new(ProtocolVersion::RTPS_2_5, VendorId::HDDS, guid_prefix);
        offset += header.encode(&mut packet[offset..]).expect("Encode header failed");

        // 2. DATA submessage header (24 bytes)
        let sn = SequenceNumber::new(seq as i64);
        let data = Data::new(EntityId::UNKNOWN, writer_id, sn);
        let data_header_len = data.encode_header(&mut packet[offset..]).expect("Encode DATA failed");

        // 3. CDR payload
        let payload_offset = offset + data_header_len;
        let mut cdr_buf = [0u8; 64];
        let cdr_bytes = {
            let mut enc = CdrEncoder::new(&mut cdr_buf);
            temp.encode(&mut enc).expect("Encode CDR failed");
            enc.finish()
        };
        // SerializedPayloadHeader (RTPS 2.5 10.2): CDR_LE, the encoder
        // writes XCDR1 little endian; the body follows it.
        let cdr_len = cdr_bytes.len();
        packet[payload_offset..payload_offset + 2]
            .copy_from_slice(&hdds_micro::cdr::CDR_LE.to_be_bytes());
        let body_offset = payload_offset + hdds_micro::cdr::ENCAPSULATION_HEADER_SIZE;
        packet[body_offset..body_offset + cdr_len].copy_from_slice(cdr_bytes);
        let serialized_len = hdds_micro::cdr::ENCAPSULATION_HEADER_SIZE + cdr_len;

        // Update DATA octets_to_next (20 fixed + serialized payload)
        let octets_to_next = (20 + serialized_len) as u16;
        packet[offset + 2] = (octets_to_next & 0xff) as u8;
        packet[offset + 3] = ((octets_to_next >> 8) & 0xff) as u8;

        let total_len = payload_offset + serialized_len;
        socket.send_to(&packet[..total_len], &dest)?;

        info!("[TX] Sample {}: temp={:.1}C ({} bytes RTPS)", seq, temp_value, total_len);

        std::thread::sleep(Duration::from_secs(1));

        if seq >= 20 {
            info!("Done - 20 samples sent!");
            break;
        }
    }

    Ok(())
}

fn run_subscriber() -> anyhow::Result<()> {
    info!("Starting RTPS Subscriber on port {}...", DEST_PORT);

    let socket = UdpSocket::bind(format!("0.0.0.0:{}", DEST_PORT))?;
    socket.set_read_timeout(Some(Duration::from_millis(100)))?;

    let mut count = 0u32;
    let mut buf = [0u8; 512];

    loop {
        match socket.recv_from(&mut buf) {
            Ok((len, src)) => {
                if len < 20 {
                    continue;
                }

                // 1. Parse RTPS header
                let header = match RtpsHeader::decode(&buf[0..20]) {
                    Ok(h) => h,
                    Err(e) => {
                        warn!("[RX] Invalid RTPS header: {:?}", e);
                        continue;
                    }
                };

                // 2. Parse DATA submessage
                if len < 44 {
                    continue;
                }

                let (data, payload_offset) = match Data::decode(&buf[20..len]) {
                    Ok(d) => d,
                    Err(e) => {
                        warn!("[RX] Invalid DATA: {:?}", e);
                        continue;
                    }
                };

                // 3. Decode CDR payload: the SerializedPayloadHeader first
                // (RTPS 2.5 10.2); only an XCDR1 little-endian body is read
                // with CdrDecoder.
                let payload_start = 20 + payload_offset;
                let body_start = payload_start + hdds_micro::cdr::ENCAPSULATION_HEADER_SIZE;
                if body_start > len {
                    continue;
                }
                let representation =
                    u16::from_be_bytes([buf[payload_start], buf[payload_start + 1]]);
                if !hdds_micro::cdr::representation_is_xcdr1_le(representation) {
                    warn!("[RX] Not XCDR1 little endian: {:#06x}", representation);
                    continue;
                }

                let mut dec = CdrDecoder::new(&buf[body_start..len]);
                match Temperature::decode(&mut dec) {
                    Ok(temp) => {
                        count += 1;
                        info!(
                            "[RX] Sample {} from {}: temp={:.1}C (RTPS seq={})",
                            count,
                            src,
                            temp.value,
                            data.writer_sn.value()
                        );
                        info!("     GUID: {:?}", header.guid_prefix);
                    }
                    Err(e) => {
                        warn!("[RX] CDR decode error: {:?}", e);
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => warn!("Error: {}", e),
        }

        if count >= 20 {
            info!("Done - 20 samples received!");
            break;
        }
    }

    Ok(())
}
