// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! HC-12 433MHz Serial Radio Transport
//!
//! The HC-12 is a "plug & play" wireless serial module operating at 433 MHz.
//! It provides transparent UART-to-radio bridging - data written to TX appears
//! on the remote RX, like a wireless serial cable.
//!
//! ## Features
//!
//! - **Dead simple**: Just UART TX/RX, no radio protocol to manage
//! - **Good range**: 600m - 1km depending on antenna
//! - **Decent speed**: 5 kbps default, up to 15 kbps
//! - **Cheap**: ~3EUR per module
//!
//! ## Wiring (ESP32 example)
//!
//! | HC-12 Pin | ESP32      |
//! |-----------|------------|
//! | VCC       | 3.3V       |
//! | GND       | GND        |
//! | TX        | GPIO 16 RX |
//! | RX        | GPIO 17 TX |
//! | SET       | GPIO 4     |
//!
//! ## AT Command Configuration
//!
//! To configure the HC-12, pull SET pin LOW, wait 40ms, send AT commands:
//! - `AT+B9600` - Set baud rate
//! - `AT+C001` - Set channel (001-127)
//! - `AT+FU3` - Set mode (FU1-FU4, FU3 is default)
//! - `AT+P8` - Set power (1-8, 8 is max 100mW)

mod config;
mod framing;

pub use config::{Hc12Channel, Hc12Config, Hc12Mode, Hc12Power};
pub use framing::{FrameDecoder, FrameEncoder, FRAME_OVERHEAD};

use crate::error::{Error, Result};
use crate::rtps::Locator;
use crate::transport::Transport;

/// Maximum HC-12 packet size (module buffer limit)
pub const HC12_MAX_PACKET: usize = 58;

/// UART abstraction for HC-12 communication
///
/// Platform implementations (ESP32, RP2040, STM32) provide this trait.
pub trait Uart {
    /// Write bytes to UART TX
    fn write(&mut self, data: &[u8]) -> Result<usize>;

    /// Read bytes from UART RX (blocking with timeout)
    fn read(&mut self, buf: &mut [u8], timeout_ms: u32) -> Result<usize>;

    /// Read bytes from UART RX (non-blocking)
    fn try_read(&mut self, buf: &mut [u8]) -> Result<usize>;

    /// Flush TX buffer
    fn flush(&mut self) -> Result<()>;

    /// Check if data is available to read
    fn available(&self) -> usize;
}

/// GPIO pin abstraction for SET pin control
pub trait SetPin {
    /// Set pin high (normal operation)
    fn set_high(&mut self);

    /// Set pin low (AT command mode)
    fn set_low(&mut self);
}

/// HC-12 433MHz Transport
///
/// Implements Transport trait using HC-12 serial radio modules.
/// Provides transparent wireless serial communication.
pub struct Hc12Transport<U: Uart, S: SetPin> {
    /// UART interface
    uart: U,

    /// SET pin for AT command mode
    set_pin: S,

    /// Configuration
    config: Hc12Config,

    /// Frame encoder for outgoing packets
    encoder: FrameEncoder,

    /// Frame decoder for incoming packets
    decoder: FrameDecoder,

    /// Local node ID (used for addressing)
    node_id: u8,

    /// RX timeout in milliseconds
    rx_timeout_ms: u32,
}

impl<U: Uart, S: SetPin> Hc12Transport<U, S> {
    /// Create a new HC-12 transport
    ///
    /// # Arguments
    ///
    /// * `uart` - UART interface for communication
    /// * `set_pin` - SET pin for AT command configuration
    /// * `node_id` - Unique node identifier (0-255)
    pub fn new(uart: U, set_pin: S, node_id: u8) -> Self {
        Self {
            uart,
            set_pin,
            config: Hc12Config::default(),
            encoder: FrameEncoder::new(),
            decoder: FrameDecoder::new(),
            node_id,
            rx_timeout_ms: 1000,
        }
    }

    /// Create with custom configuration
    pub fn with_config(uart: U, set_pin: S, node_id: u8, config: Hc12Config) -> Self {
        let rx_timeout = config.rx_timeout_ms;
        Self {
            uart,
            set_pin,
            config,
            encoder: FrameEncoder::new(),
            decoder: FrameDecoder::new(),
            node_id,
            rx_timeout_ms: rx_timeout,
        }
    }

    /// Enter AT command mode
    ///
    /// Pull SET pin LOW, wait for module to enter command mode.
    fn enter_at_mode(&mut self) -> Result<()> {
        self.set_pin.set_low();
        // Module needs 40ms to enter AT mode
        // Platform code should provide delay
        Ok(())
    }

    /// Exit AT command mode
    fn exit_at_mode(&mut self) {
        self.set_pin.set_high();
        // Module needs 80ms to return to normal mode
    }

    /// Send AT command and read response
    fn send_at_command(&mut self, cmd: &[u8], response: &mut [u8]) -> Result<usize> {
        self.uart.write(cmd)?;
        self.uart.flush()?;

        // Wait for response (typical 40-100ms)
        self.uart.read(response, 200)
    }

    /// Configure the HC-12 module using AT commands
    ///
    /// Applies the current configuration to the module.
    /// Call this after creating the transport to set channel, power, etc.
    pub fn configure(&mut self) -> Result<()> {
        self.enter_at_mode()?;

        let mut response = [0u8; 32];

        // Test connection
        let len = self.send_at_command(b"AT\r\n", &mut response)?;
        if len < 2 || &response[..2] != b"OK" {
            self.exit_at_mode();
            return Err(Error::TransportError);
        }

        // Set channel
        let channel_cmd = self.config.channel.at_command();
        self.send_at_command(&channel_cmd, &mut response)?;

        // Set transmission mode
        let mode_cmd = self.config.mode.at_command();
        self.send_at_command(&mode_cmd, &mut response)?;

        // Set power level
        let power_cmd = self.config.power.at_command();
        self.send_at_command(&power_cmd, &mut response)?;

        self.exit_at_mode();

        Ok(())
    }

    /// Get module version info
    pub fn get_version(&mut self) -> Result<[u8; 32]> {
        self.enter_at_mode()?;

        let mut response = [0u8; 32];
        let len = self.send_at_command(b"AT+V\r\n", &mut response)?;

        self.exit_at_mode();

        if len == 0 {
            return Err(Error::TransportError);
        }

        Ok(response)
    }

    /// Get current configuration
    pub const fn config(&self) -> &Hc12Config {
        &self.config
    }

    /// Get node ID
    pub const fn node_id(&self) -> u8 {
        self.node_id
    }

    /// Set RX timeout
    pub fn set_rx_timeout(&mut self, timeout_ms: u32) {
        self.rx_timeout_ms = timeout_ms;
    }
}

impl<U: Uart, S: SetPin> Transport for Hc12Transport<U, S> {
    fn init(&mut self) -> Result<()> {
        // Ensure we're in normal mode
        self.exit_at_mode();
        Ok(())
    }

    fn send(&mut self, data: &[u8], _dest: &Locator) -> Result<usize> {
        // HC-12 is broadcast - dest is ignored

        // Frame the packet with header and checksum
        let mut frame_buf = [0u8; HC12_MAX_PACKET + FRAME_OVERHEAD];
        let frame_len = self.encoder.encode(self.node_id, data, &mut frame_buf)?;

        // Send over UART
        let sent = self.uart.write(&frame_buf[..frame_len])?;
        self.uart.flush()?;

        if sent != frame_len {
            return Err(Error::TransportError);
        }

        Ok(data.len())
    }

    fn recv(&mut self, buf: &mut [u8]) -> Result<(usize, Locator)> {
        let mut rx_buf = [0u8; HC12_MAX_PACKET + FRAME_OVERHEAD];

        loop {
            // Read available data
            let len = self.uart.read(&mut rx_buf, self.rx_timeout_ms)?;

            if len == 0 {
                return Err(Error::Timeout);
            }

            // Feed to decoder
            for &byte in &rx_buf[..len] {
                if let Some((src_node, payload)) = self.decoder.feed(byte)? {
                    if payload.len() > buf.len() {
                        return Err(Error::BufferTooSmall);
                    }

                    buf[..payload.len()].copy_from_slice(payload);

                    // Create pseudo-locator from source node ID
                    let locator = Locator::udpv4([0, 0, 0, src_node], 0);
                    return Ok((payload.len(), locator));
                }
            }
        }
    }

    fn try_recv(&mut self, buf: &mut [u8]) -> Result<(usize, Locator)> {
        // Check if data available
        if self.uart.available() == 0 {
            return Err(Error::ResourceExhausted);
        }

        let mut rx_buf = [0u8; HC12_MAX_PACKET + FRAME_OVERHEAD];

        // Read available data (non-blocking)
        let len = self.uart.try_read(&mut rx_buf)?;

        if len == 0 {
            return Err(Error::ResourceExhausted);
        }

        // Feed to decoder
        for &byte in &rx_buf[..len] {
            if let Some((src_node, payload)) = self.decoder.feed(byte)? {
                if payload.len() > buf.len() {
                    return Err(Error::BufferTooSmall);
                }

                buf[..payload.len()].copy_from_slice(payload);

                let locator = Locator::udpv4([0, 0, 0, src_node], 0);
                return Ok((payload.len(), locator));
            }
        }

        Err(Error::ResourceExhausted)
    }

    fn local_locator(&self) -> Locator {
        // Use node_id as pseudo-address
        Locator::udpv4([0, 0, 0, self.node_id], 0)
    }

    fn mtu(&self) -> usize {
        // Max payload after framing overhead
        HC12_MAX_PACKET - FRAME_OVERHEAD
    }

    fn shutdown(&mut self) -> Result<()> {
        // Nothing special needed
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mock UART for testing
    struct MockUart {
        tx_buf: [u8; 256],
        tx_len: usize,
        rx_buf: [u8; 256],
        rx_len: usize,
        rx_pos: usize,
    }

    impl MockUart {
        fn new() -> Self {
            Self {
                tx_buf: [0u8; 256],
                tx_len: 0,
                rx_buf: [0u8; 256],
                rx_len: 0,
                rx_pos: 0,
            }
        }
    }

    impl Uart for MockUart {
        fn write(&mut self, data: &[u8]) -> Result<usize> {
            let len = data.len().min(256 - self.tx_len);
            self.tx_buf[self.tx_len..self.tx_len + len].copy_from_slice(&data[..len]);
            self.tx_len += len;
            Ok(len)
        }

        fn read(&mut self, buf: &mut [u8], _timeout_ms: u32) -> Result<usize> {
            let available = self.rx_len - self.rx_pos;
            let len = buf.len().min(available);
            buf[..len].copy_from_slice(&self.rx_buf[self.rx_pos..self.rx_pos + len]);
            self.rx_pos += len;
            Ok(len)
        }

        fn try_read(&mut self, buf: &mut [u8]) -> Result<usize> {
            self.read(buf, 0)
        }

        fn flush(&mut self) -> Result<()> {
            Ok(())
        }

        fn available(&self) -> usize {
            self.rx_len - self.rx_pos
        }
    }

    /// Mock SET pin
    struct MockSetPin {
        is_high: bool,
    }

    impl MockSetPin {
        fn new() -> Self {
            Self { is_high: true }
        }
    }

    impl SetPin for MockSetPin {
        fn set_high(&mut self) {
            self.is_high = true;
        }

        fn set_low(&mut self) {
            self.is_high = false;
        }
    }

    #[test]
    fn test_hc12_creation() {
        let uart = MockUart::new();
        let set_pin = MockSetPin::new();
        let transport = Hc12Transport::new(uart, set_pin, 42);

        assert_eq!(transport.node_id(), 42);
    }

    #[test]
    fn test_hc12_local_locator() {
        let uart = MockUart::new();
        let set_pin = MockSetPin::new();
        let transport = Hc12Transport::new(uart, set_pin, 123);

        let locator = transport.local_locator();
        assert_eq!(locator.address[15], 123);
    }

    #[test]
    fn test_hc12_mtu() {
        let uart = MockUart::new();
        let set_pin = MockSetPin::new();
        let transport = Hc12Transport::new(uart, set_pin, 1);

        // MTU should be packet size minus framing overhead
        assert!(transport.mtu() > 0);
        assert!(transport.mtu() < HC12_MAX_PACKET);
    }

    #[test]
    fn test_hc12_send() {
        let uart = MockUart::new();
        let set_pin = MockSetPin::new();
        let mut transport = Hc12Transport::new(uart, set_pin, 1);

        let data = b"Hello";
        let dest = Locator::udpv4([0, 0, 0, 2], 0);

        let result = transport.send(data, &dest);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), data.len());
    }

    #[test]
    fn test_hc12_try_recv_no_data() {
        let uart = MockUart::new();
        let set_pin = MockSetPin::new();
        let mut transport = Hc12Transport::new(uart, set_pin, 1);

        let mut buf = [0u8; 64];
        let result = transport.try_recv(&mut buf);

        assert_eq!(result, Err(Error::ResourceExhausted));
    }
}
