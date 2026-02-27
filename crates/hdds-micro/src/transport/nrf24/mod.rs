// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! NRF24L01/NRF24L01+ 2.4GHz Radio Transport
//!
//! High-speed, low-latency radio for short-range communication.
//!
//! ## Features
//!
//! - 2.4 GHz ISM band (2400-2525 MHz)
//! - Data rates: 250kbps, 1Mbps, 2Mbps
//! - 126 channels
//! - Auto-acknowledgment and retransmit
//! - Up to 6 data pipes (multipoint)
//! - Payload size: 1-32 bytes
//!
//! ## Hardware Connection (SPI)
//!
//! ```text
//! NRF24L01    MCU
//! ---------   ---
//! VCC    ---- 3.3V (NOT 5V!)
//! GND    ---- GND
//! CE     ---- GPIO (Chip Enable)
//! CSN    ---- SPI CS
//! SCK    ---- SPI CLK
//! MOSI   ---- SPI MOSI
//! MISO   ---- SPI MISO
//! IRQ    ---- GPIO (optional)
//! ```

mod config;
mod registers;

pub use config::{
    Nrf24AddressWidth, Nrf24Channel, Nrf24Config, Nrf24CrcMode, Nrf24DataRate, Nrf24Power,
};
pub use registers::Register;

use crate::error::{Error, Result};
use crate::rtps::Locator;
use crate::transport::Transport;

/// Maximum payload size
pub const MAX_PAYLOAD_SIZE: usize = 32;

/// Default address (5 bytes)
pub const DEFAULT_ADDRESS: [u8; 5] = [0xE7, 0xE7, 0xE7, 0xE7, 0xE7];

/// SPI device trait for NRF24L01
pub trait SpiDevice {
    /// Transfer data (write and read simultaneously)
    fn transfer(&mut self, data: &mut [u8]) -> Result<()>;
}

/// Chip Enable pin trait
pub trait CePin {
    /// Set CE pin high
    fn set_high(&mut self);
    /// Set CE pin low
    fn set_low(&mut self);
}

/// NRF24L01 radio driver
pub struct Nrf24<SPI: SpiDevice, CE: CePin> {
    /// SPI device
    spi: SPI,
    /// Chip Enable pin
    ce: CE,
    /// Configuration
    config: Nrf24Config,
    /// TX address (for sending)
    tx_address: [u8; 5],
    /// RX address pipe 0 (for receiving and auto-ack)
    rx_address: [u8; 5],
    /// Current mode
    mode: Nrf24Mode,
    /// Last received RSSI approximation (based on retries)
    last_rssi: Option<i16>,
}

/// Operating mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Nrf24Mode {
    /// Power down mode
    #[default]
    PowerDown,
    /// Standby mode
    Standby,
    /// RX mode
    Rx,
    /// TX mode
    Tx,
}

impl<SPI: SpiDevice, CE: CePin> Nrf24<SPI, CE> {
    /// Create a new NRF24L01 driver
    pub fn new(spi: SPI, ce: CE, config: Nrf24Config) -> Self {
        Self {
            spi,
            ce,
            config,
            tx_address: DEFAULT_ADDRESS,
            rx_address: DEFAULT_ADDRESS,
            mode: Nrf24Mode::PowerDown,
            last_rssi: None,
        }
    }

    /// Initialize the radio
    pub fn init(&mut self) -> Result<()> {
        // Power down first
        self.ce.set_low();

        // Wait for power on reset (100ms max, we do small delay via dummy reads)
        for _ in 0..10 {
            let _ = self.read_register(Register::CONFIG);
        }

        // Flush FIFOs
        self.flush_tx()?;
        self.flush_rx()?;

        // Clear status flags
        self.write_register(Register::STATUS, 0x70)?;

        // Set address width
        self.write_register(Register::SETUP_AW, self.config.address_width.to_register())?;

        // Set channel
        self.write_register(Register::RF_CH, self.config.channel.0)?;

        // Set data rate and power
        let rf_setup = self.config.data_rate.to_register() | self.config.power.to_register();
        self.write_register(Register::RF_SETUP, rf_setup)?;

        // Set auto-retransmit (delay and count)
        let setup_retr = (self.config.retry_delay << 4) | (self.config.retry_count & 0x0F);
        self.write_register(Register::SETUP_RETR, setup_retr)?;

        // Enable auto-ack on pipe 0
        self.write_register(Register::EN_AA, 0x01)?;

        // Enable RX pipe 0
        self.write_register(Register::EN_RXADDR, 0x01)?;

        // Set payload size for pipe 0
        self.write_register(Register::RX_PW_P0, MAX_PAYLOAD_SIZE as u8)?;

        // Configure: CRC, power up, PRX mode
        let config_reg = self.config.crc.to_register() | 0x02; // PWR_UP
        self.write_register(Register::CONFIG, config_reg)?;

        // Set addresses
        self.set_tx_address(&self.tx_address.clone())?;
        self.set_rx_address(0, &self.rx_address.clone())?;

        self.mode = Nrf24Mode::Standby;
        Ok(())
    }

    /// Set TX address
    pub fn set_tx_address(&mut self, address: &[u8; 5]) -> Result<()> {
        self.tx_address = *address;
        self.write_register_multi(Register::TX_ADDR, address)?;
        // Also set RX_ADDR_P0 for auto-ack
        self.write_register_multi(Register::RX_ADDR_P0, address)?;
        Ok(())
    }

    /// Set RX address for a pipe
    pub fn set_rx_address(&mut self, pipe: u8, address: &[u8; 5]) -> Result<()> {
        if pipe > 5 {
            return Err(Error::InvalidParameter);
        }

        if pipe == 0 {
            self.rx_address = *address;
            self.write_register_multi(Register::RX_ADDR_P0, address)?;
        } else if pipe == 1 {
            self.write_register_multi(Register::RX_ADDR_P1, address)?;
        } else {
            // Pipes 2-5 only use 1 byte (LSB), rest from P1
            let reg = match pipe {
                2 => Register::RX_ADDR_P2,
                3 => Register::RX_ADDR_P3,
                4 => Register::RX_ADDR_P4,
                5 => Register::RX_ADDR_P5,
                _ => unreachable!(),
            };
            self.write_register(reg, address[0])?;
        }

        Ok(())
    }

    /// Enter RX mode
    pub fn start_listening(&mut self) -> Result<()> {
        // Set PRIM_RX bit
        let config = self.read_register(Register::CONFIG)?;
        self.write_register(Register::CONFIG, config | 0x03)?; // PWR_UP + PRIM_RX

        // Clear status
        self.write_register(Register::STATUS, 0x70)?;

        // Flush RX FIFO
        self.flush_rx()?;

        // Set CE high to enter RX mode
        self.ce.set_high();

        self.mode = Nrf24Mode::Rx;
        Ok(())
    }

    /// Exit RX mode
    pub fn stop_listening(&mut self) -> Result<()> {
        self.ce.set_low();

        // Clear PRIM_RX bit
        let config = self.read_register(Register::CONFIG)?;
        self.write_register(Register::CONFIG, config & !0x01)?;

        self.mode = Nrf24Mode::Standby;
        Ok(())
    }

    /// Check if data is available
    pub fn data_available(&mut self) -> Result<bool> {
        let status = self.read_register(Register::STATUS)?;
        let rx_empty = self.read_register(Register::FIFO_STATUS)? & 0x01;

        Ok((status & 0x40) != 0 || rx_empty == 0)
    }

    /// Read received data
    pub fn read_payload(&mut self, buf: &mut [u8]) -> Result<usize> {
        if buf.len() < MAX_PAYLOAD_SIZE {
            return Err(Error::BufferTooSmall);
        }

        // Read payload
        let mut cmd = [0u8; 33];
        cmd[0] = 0x61; // R_RX_PAYLOAD
        self.spi.transfer(&mut cmd)?;
        buf[..MAX_PAYLOAD_SIZE].copy_from_slice(&cmd[1..33]);

        // Clear RX_DR flag
        self.write_register(Register::STATUS, 0x40)?;

        Ok(MAX_PAYLOAD_SIZE)
    }

    /// Send data
    pub fn send_payload(&mut self, data: &[u8]) -> Result<bool> {
        if data.len() > MAX_PAYLOAD_SIZE {
            return Err(Error::InvalidParameter);
        }

        // Stop listening if in RX mode
        if self.mode == Nrf24Mode::Rx {
            self.stop_listening()?;
        }

        // Flush TX FIFO
        self.flush_tx()?;

        // Write payload
        let mut cmd = [0u8; 33];
        cmd[0] = 0xA0; // W_TX_PAYLOAD
        cmd[1..1 + data.len()].copy_from_slice(data);
        // Pad with zeros if needed
        self.spi.transfer(&mut cmd)?;

        // Pulse CE to transmit
        self.ce.set_high();
        // Short delay (minimum 10us)
        for _ in 0..100 {
            core::hint::spin_loop();
        }
        self.ce.set_low();

        // Wait for TX complete or max retries
        let mut attempts = 0;
        loop {
            let status = self.read_register(Register::STATUS)?;

            if (status & 0x20) != 0 {
                // TX_DS - Data sent
                self.write_register(Register::STATUS, 0x20)?;

                // Estimate RSSI based on retry count
                let observe = self.read_register(Register::OBSERVE_TX)?;
                let retries = observe & 0x0F;
                self.last_rssi = Some(-50 - (retries as i16 * 5));

                return Ok(true);
            }

            if (status & 0x10) != 0 {
                // MAX_RT - Max retries
                self.write_register(Register::STATUS, 0x10)?;
                self.flush_tx()?;
                self.last_rssi = Some(-100);
                return Ok(false);
            }

            attempts += 1;
            if attempts > 1000 {
                self.flush_tx()?;
                return Err(Error::Timeout);
            }
        }
    }

    /// Flush TX FIFO
    pub fn flush_tx(&mut self) -> Result<()> {
        let mut cmd = [0xE1u8];
        self.spi.transfer(&mut cmd)?;
        Ok(())
    }

    /// Flush RX FIFO
    pub fn flush_rx(&mut self) -> Result<()> {
        let mut cmd = [0xE2u8];
        self.spi.transfer(&mut cmd)?;
        Ok(())
    }

    /// Power down the radio
    pub fn power_down(&mut self) -> Result<()> {
        self.ce.set_low();
        let config = self.read_register(Register::CONFIG)?;
        self.write_register(Register::CONFIG, config & !0x02)?;
        self.mode = Nrf24Mode::PowerDown;
        Ok(())
    }

    /// Read a register
    fn read_register(&mut self, reg: Register) -> Result<u8> {
        let mut buf = [reg as u8, 0];
        self.spi.transfer(&mut buf)?;
        Ok(buf[1])
    }

    /// Write a register
    fn write_register(&mut self, reg: Register, value: u8) -> Result<()> {
        let mut buf = [0x20 | (reg as u8), value];
        self.spi.transfer(&mut buf)?;
        Ok(())
    }

    /// Write multiple bytes to a register
    fn write_register_multi(&mut self, reg: Register, data: &[u8]) -> Result<()> {
        let mut buf = [0u8; 6];
        buf[0] = 0x20 | (reg as u8);
        let len = data.len().min(5);
        buf[1..1 + len].copy_from_slice(&data[..len]);
        self.spi.transfer(&mut buf[..1 + len])?;
        Ok(())
    }

    /// Get current mode
    pub fn mode(&self) -> Nrf24Mode {
        self.mode
    }

    /// Get configuration
    pub fn config(&self) -> &Nrf24Config {
        &self.config
    }

    /// Get last RSSI estimate
    pub fn last_rssi(&self) -> Option<i16> {
        self.last_rssi
    }
}

/// NRF24L01 Transport wrapper
pub struct Nrf24Transport<SPI: SpiDevice, CE: CePin> {
    /// Radio driver
    radio: Nrf24<SPI, CE>,
    /// Local locator (node ID encoded)
    local_locator: Locator,
    /// Receive buffer (reserved for buffered RX)
    #[allow(dead_code)]
    rx_buf: [u8; MAX_PAYLOAD_SIZE],
    /// Pending RX data length (reserved for buffered RX)
    #[allow(dead_code)]
    rx_len: usize,
}

impl<SPI: SpiDevice, CE: CePin> Nrf24Transport<SPI, CE> {
    /// Create a new NRF24 transport
    pub fn new(spi: SPI, ce: CE, config: Nrf24Config) -> Self {
        Self {
            radio: Nrf24::new(spi, ce, config),
            local_locator: Locator::udpv4([0, 0, 0, 1], 2400), // 2.4GHz marker
            rx_buf: [0u8; MAX_PAYLOAD_SIZE],
            rx_len: 0,
        }
    }

    /// Get mutable reference to radio
    pub fn radio_mut(&mut self) -> &mut Nrf24<SPI, CE> {
        &mut self.radio
    }

    /// Get reference to radio
    pub fn radio(&self) -> &Nrf24<SPI, CE> {
        &self.radio
    }
}

impl<SPI: SpiDevice, CE: CePin> Transport for Nrf24Transport<SPI, CE> {
    fn init(&mut self) -> Result<()> {
        self.radio.init()?;
        self.radio.start_listening()?;
        Ok(())
    }

    fn send(&mut self, data: &[u8], _dest: &Locator) -> Result<usize> {
        if data.len() > MAX_PAYLOAD_SIZE {
            return Err(Error::InvalidParameter);
        }

        // Pad to 32 bytes
        let mut payload = [0u8; MAX_PAYLOAD_SIZE];
        payload[..data.len()].copy_from_slice(data);

        let success = self.radio.send_payload(&payload)?;

        // Resume listening
        self.radio.start_listening()?;

        if success {
            Ok(data.len())
        } else {
            Err(Error::TransportError)
        }
    }

    fn recv(&mut self, buf: &mut [u8]) -> Result<(usize, Locator)> {
        loop {
            if self.radio.data_available()? {
                let len = self.radio.read_payload(buf)?;
                return Ok((len, self.local_locator));
            }
        }
    }

    fn try_recv(&mut self, buf: &mut [u8]) -> Result<(usize, Locator)> {
        if self.radio.data_available()? {
            let len = self.radio.read_payload(buf)?;
            Ok((len, self.local_locator))
        } else {
            Err(Error::ResourceExhausted)
        }
    }

    fn local_locator(&self) -> Locator {
        self.local_locator
    }

    fn mtu(&self) -> usize {
        MAX_PAYLOAD_SIZE
    }

    fn last_rssi(&self) -> Option<i16> {
        self.radio.last_rssi()
    }

    fn shutdown(&mut self) -> Result<()> {
        self.radio.power_down()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mock SPI
    struct MockSpi {
        registers: [u8; 32],
    }

    impl MockSpi {
        fn new() -> Self {
            Self { registers: [0; 32] }
        }
    }

    impl SpiDevice for MockSpi {
        fn transfer(&mut self, data: &mut [u8]) -> Result<()> {
            if data.is_empty() {
                return Ok(());
            }

            let cmd = data[0];

            if cmd < 0x20 {
                // Read register
                let reg = cmd as usize;
                if reg < 32 && data.len() > 1 {
                    data[1] = self.registers[reg];
                }
            } else if cmd < 0x40 {
                // Write register
                let reg = (cmd & 0x1F) as usize;
                if reg < 32 && data.len() > 1 {
                    self.registers[reg] = data[1];
                }
            }
            // Other commands: flush, payloads, etc - just accept

            Ok(())
        }
    }

    // Mock CE pin
    struct MockCe {
        high: bool,
    }

    impl MockCe {
        fn new() -> Self {
            Self { high: false }
        }
    }

    impl CePin for MockCe {
        fn set_high(&mut self) {
            self.high = true;
        }

        fn set_low(&mut self) {
            self.high = false;
        }
    }

    #[test]
    fn test_nrf24_creation() {
        let spi = MockSpi::new();
        let ce = MockCe::new();
        let config = Nrf24Config::default();

        let radio = Nrf24::new(spi, ce, config);
        assert_eq!(radio.mode(), Nrf24Mode::PowerDown);
    }

    #[test]
    fn test_nrf24_init() {
        let spi = MockSpi::new();
        let ce = MockCe::new();
        let config = Nrf24Config::default();

        let mut radio = Nrf24::new(spi, ce, config);
        radio.init().unwrap();

        assert_eq!(radio.mode(), Nrf24Mode::Standby);
    }

    #[test]
    fn test_nrf24_transport_creation() {
        let spi = MockSpi::new();
        let ce = MockCe::new();
        let config = Nrf24Config::default();

        let transport = Nrf24Transport::new(spi, ce, config);
        assert_eq!(transport.mtu(), MAX_PAYLOAD_SIZE);
    }

    #[test]
    fn test_nrf24_config_defaults() {
        let config = Nrf24Config::default();
        assert_eq!(config.channel.0, 76);
        assert_eq!(config.data_rate, Nrf24DataRate::Rate1Mbps);
        assert_eq!(config.power, Nrf24Power::Max);
    }

    #[test]
    fn test_nrf24_mode_transitions() {
        let spi = MockSpi::new();
        let ce = MockCe::new();
        let config = Nrf24Config::default();

        let mut radio = Nrf24::new(spi, ce, config);

        assert_eq!(radio.mode(), Nrf24Mode::PowerDown);

        radio.init().unwrap();
        assert_eq!(radio.mode(), Nrf24Mode::Standby);

        radio.start_listening().unwrap();
        assert_eq!(radio.mode(), Nrf24Mode::Rx);

        radio.stop_listening().unwrap();
        assert_eq!(radio.mode(), Nrf24Mode::Standby);

        radio.power_down().unwrap();
        assert_eq!(radio.mode(), Nrf24Mode::PowerDown);
    }
}
