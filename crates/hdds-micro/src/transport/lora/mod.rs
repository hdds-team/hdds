// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! LoRa transport for long-range, low-bandwidth communication
//!
//! Supports SX1276/SX1278 LoRa transceivers via SPI interface.
//!
//! ## Features
//!
//! - Platform-agnostic SPI abstraction
//! - Configurable spreading factor (SF7-SF12)
//! - Packet fragmentation for RTPS messages > 255 bytes
//! - RSSI/SNR monitoring

mod config;
mod fragment;
mod sx127x;

pub use config::{Bandwidth, CodingRate, LoRaConfig, LoRaProfile, SpreadingFactor};
pub use fragment::{FragmentAssembler, FragmentHeader};
pub use sx127x::{DioPin, SpiDevice, Sx127x};

use crate::error::{Error, Result};
use crate::rtps::Locator;
use crate::transport::Transport;

/// Maximum LoRa packet size (hardware limit)
pub const LORA_MAX_PACKET: usize = 255;

/// LoRa transport
///
/// Implements Transport trait for LoRa communication.
pub struct LoRaTransport<SPI: SpiDevice, DIO0: DioPin> {
    /// SX127x radio driver
    radio: Sx127x<SPI, DIO0>,

    /// Configuration
    config: LoRaConfig,

    /// Fragment assembler for incoming packets
    assembler: FragmentAssembler,

    /// TX sequence number
    tx_seq: u8,

    /// Local "address" (node ID for routing)
    node_id: u8,
}

impl<SPI: SpiDevice, DIO0: DioPin> LoRaTransport<SPI, DIO0> {
    /// Create a new LoRa transport
    ///
    /// # Arguments
    ///
    /// * `spi` - SPI device for communication with SX127x
    /// * `dio0` - DIO0 pin for TX/RX done interrupts
    /// * `config` - LoRa configuration
    /// * `node_id` - Unique node identifier (0-255)
    pub fn new(spi: SPI, dio0: DIO0, config: LoRaConfig, node_id: u8) -> Result<Self> {
        let mut radio = Sx127x::new(spi, dio0);

        // Initialize radio
        radio.reset()?;
        radio.set_mode_sleep()?;
        radio.set_lora_mode()?;

        // Apply configuration
        radio.set_frequency(config.frequency_mhz)?;
        radio.set_spreading_factor(config.spreading_factor)?;
        radio.set_bandwidth(config.bandwidth)?;
        radio.set_coding_rate(config.coding_rate)?;
        radio.set_tx_power(config.tx_power_dbm)?;

        // Set to standby
        radio.set_mode_standby()?;

        Ok(Self {
            radio,
            config,
            assembler: FragmentAssembler::new(),
            tx_seq: 0,
            node_id,
        })
    }

    /// Get current RSSI (Received Signal Strength Indicator)
    pub fn rssi(&mut self) -> Result<i16> {
        self.radio.read_rssi()
    }

    /// Get SNR (Signal-to-Noise Ratio) of last received packet
    pub fn snr(&mut self) -> Result<i8> {
        self.radio.read_snr()
    }

    /// Get node ID
    pub const fn node_id(&self) -> u8 {
        self.node_id
    }

    /// Send raw packet (no fragmentation)
    fn send_raw(&mut self, data: &[u8]) -> Result<usize> {
        if data.len() > LORA_MAX_PACKET {
            return Err(Error::BufferTooSmall);
        }

        self.radio.send(data)?;
        Ok(data.len())
    }

    /// Receive raw packet (blocking with timeout)
    fn recv_raw(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.radio.recv(buf, self.config.rx_timeout_ms)
    }

    /// Next TX sequence number
    fn next_seq(&mut self) -> u8 {
        let seq = self.tx_seq;
        self.tx_seq = self.tx_seq.wrapping_add(1);
        seq
    }
}

impl<SPI: SpiDevice, DIO0: DioPin> Transport for LoRaTransport<SPI, DIO0> {
    fn init(&mut self) -> Result<()> {
        // Already initialized in new()
        self.radio.set_mode_standby()
    }

    fn send(&mut self, data: &[u8], _dest: &Locator) -> Result<usize> {
        // LoRa is broadcast - dest is ignored (use node_id for addressing)

        if data.len() <= LORA_MAX_PACKET - FragmentHeader::SIZE {
            // Single packet - no fragmentation needed
            let mut buf = [0u8; LORA_MAX_PACKET];
            let header = FragmentHeader::single(self.node_id, self.next_seq());
            let header_len = header.encode(&mut buf)?;
            buf[header_len..header_len + data.len()].copy_from_slice(data);

            self.send_raw(&buf[..header_len + data.len()])
        } else {
            // Fragment into multiple packets
            let max_payload = LORA_MAX_PACKET - FragmentHeader::SIZE;
            let num_fragments = data.len().div_ceil(max_payload);

            if num_fragments > 255 {
                return Err(Error::BufferTooSmall);
            }

            let msg_seq = self.next_seq();
            let mut total_sent = 0;

            for (i, chunk) in data.chunks(max_payload).enumerate() {
                let mut buf = [0u8; LORA_MAX_PACKET];
                let header =
                    FragmentHeader::fragment(self.node_id, msg_seq, i as u8, num_fragments as u8);
                let header_len = header.encode(&mut buf)?;
                buf[header_len..header_len + chunk.len()].copy_from_slice(chunk);

                self.send_raw(&buf[..header_len + chunk.len()])?;
                total_sent += chunk.len();
            }

            Ok(total_sent)
        }
    }

    fn recv(&mut self, buf: &mut [u8]) -> Result<(usize, Locator)> {
        let mut rx_buf = [0u8; LORA_MAX_PACKET];

        loop {
            let len = self.recv_raw(&mut rx_buf)?;

            if len < FragmentHeader::SIZE {
                continue; // Too short, skip
            }

            let header = FragmentHeader::decode(&rx_buf[..len])?;
            let payload = &rx_buf[FragmentHeader::SIZE..len];

            if header.is_single() {
                // Single packet - return directly
                if payload.len() > buf.len() {
                    return Err(Error::BufferTooSmall);
                }
                buf[..payload.len()].copy_from_slice(payload);

                // Create pseudo-locator from node_id
                let locator = Locator::udpv4([0, 0, 0, header.src_node], 0);
                return Ok((payload.len(), locator));
            }

            // Fragment - add to assembler
            if let Some(complete) = self.assembler.add_fragment(&header, payload)? {
                if complete.len() > buf.len() {
                    return Err(Error::BufferTooSmall);
                }
                buf[..complete.len()].copy_from_slice(complete);

                let locator = Locator::udpv4([0, 0, 0, header.src_node], 0);
                return Ok((complete.len(), locator));
            }
            // Not complete yet, continue receiving
        }
    }

    fn try_recv(&mut self, buf: &mut [u8]) -> Result<(usize, Locator)> {
        // Check if radio has received data
        if !self.radio.is_rx_done()? {
            return Err(Error::ResourceExhausted);
        }

        self.recv(buf)
    }

    fn local_locator(&self) -> Locator {
        // Use node_id as pseudo-address
        Locator::udpv4([0, 0, 0, self.node_id], 0)
    }

    fn mtu(&self) -> usize {
        // With fragmentation, we can handle larger packets
        // But single-packet MTU is limited
        LORA_MAX_PACKET - FragmentHeader::SIZE
    }

    fn shutdown(&mut self) -> Result<()> {
        self.radio.set_mode_sleep()
    }
}
