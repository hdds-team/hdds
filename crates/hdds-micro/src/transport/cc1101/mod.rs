// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! CC1101 Sub-GHz Radio Transport
//!
//! Multi-band radio transceiver supporting 315/433/868/915 MHz bands.
//!
//! ## Features
//!
//! - Frequency bands: 300-348, 387-464, 779-928 MHz
//! - Data rates: 1.2 - 500 kbps
//! - Modulation: OOK, 2-FSK, 4-FSK, GFSK, MSK
//! - TX power: -30 to +12 dBm
//! - RX sensitivity: -116 dBm @ 1.2 kbps
//! - 64-byte TX/RX FIFOs
//! - Hardware CRC, preamble, sync word
//! - Wake-on-radio support
//!
//! ## Hardware Connection (SPI)
//!
//! ```text
//! CC1101      MCU
//! ---------   ---
//! VCC    ---- 3.3V
//! GND    ---- GND
//! CSN    ---- SPI CS
//! SCK    ---- SPI CLK
//! MOSI   ---- SPI MOSI (SI)
//! MISO   ---- SPI MISO (SO)
//! GDO0   ---- GPIO (optional, TX/RX status)
//! GDO2   ---- GPIO (optional, carrier sense)
//! ```

mod config;
mod registers;

pub use config::{
    Cc1101Band, Cc1101Config, Cc1101DataRate, Cc1101Modulation, Cc1101Power, Cc1101SyncMode,
};
pub use registers::Register;

use crate::error::{Error, Result};
use crate::rtps::Locator;
use crate::transport::Transport;

/// Maximum FIFO size
pub const FIFO_SIZE: usize = 64;

/// Maximum payload size (FIFO - 2 bytes for length and status)
pub const MAX_PAYLOAD_SIZE: usize = 61;

/// SPI device trait for CC1101
pub trait SpiDevice {
    /// Transfer data (write and read simultaneously)
    fn transfer(&mut self, data: &mut [u8]) -> Result<()>;
}

/// GDO pin trait (optional interrupt/status pin)
pub trait GdoPin {
    /// Read pin state
    fn is_high(&self) -> bool;
}

/// Dummy GDO pin (when not using interrupts)
pub struct NoGdo;

impl GdoPin for NoGdo {
    fn is_high(&self) -> bool {
        false
    }
}

/// CC1101 state machine states
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Cc1101State {
    /// Idle state
    #[default]
    Idle,
    /// Receiving
    Rx,
    /// Transmitting
    Tx,
    /// Frequency synthesizer calibration
    FsTxOn,
    /// Frequency synthesizer calibration
    FsRxOn,
    /// Crystal oscillator running
    Calibrate,
    /// PLL settling
    Settling,
    /// RX FIFO overflow
    RxOverflow,
    /// TX FIFO underflow
    TxUnderflow,
}

impl Cc1101State {
    /// Parse from status byte
    fn from_status(status: u8) -> Self {
        match (status >> 4) & 0x07 {
            0 => Self::Idle,
            1 => Self::Rx,
            2 => Self::Tx,
            3 => Self::FsTxOn,
            4 => Self::FsRxOn,
            5 => Self::Calibrate,
            6 => Self::Settling,
            7 => Self::RxOverflow,
            _ => Self::Idle,
        }
    }
}

/// CC1101 radio driver
pub struct Cc1101<SPI: SpiDevice, GDO: GdoPin = NoGdo> {
    /// SPI device
    spi: SPI,
    /// GDO0 pin (optional, reserved for interrupt-driven RX)
    #[allow(dead_code)]
    gdo0: GDO,
    /// Configuration
    config: Cc1101Config,
    /// Last RSSI reading
    last_rssi: Option<i16>,
    /// Last LQI reading
    last_lqi: u8,
}

impl<SPI: SpiDevice> Cc1101<SPI, NoGdo> {
    /// Create a new CC1101 driver without GDO pin
    pub fn new(spi: SPI, config: Cc1101Config) -> Self {
        Self::with_gdo(spi, NoGdo, config)
    }
}

impl<SPI: SpiDevice, GDO: GdoPin> Cc1101<SPI, GDO> {
    /// Create a new CC1101 driver with GDO pin
    pub fn with_gdo(spi: SPI, gdo0: GDO, config: Cc1101Config) -> Self {
        Self {
            spi,
            gdo0,
            config,
            last_rssi: None,
            last_lqi: 0,
        }
    }

    /// Reset the radio
    pub fn reset(&mut self) -> Result<()> {
        // Strobe SRES
        self.strobe(registers::Strobe::SRES)?;

        // Wait for reset (use dummy reads as delay)
        for _ in 0..100 {
            let _ = self.read_status();
        }

        Ok(())
    }

    /// Initialize the radio
    pub fn init(&mut self) -> Result<()> {
        // Reset first
        self.reset()?;

        // Configure radio registers based on config
        self.configure()?;

        // Calibrate
        self.strobe(registers::Strobe::SCAL)?;

        // Enter idle
        self.strobe(registers::Strobe::SIDLE)?;

        Ok(())
    }

    /// Configure radio with current config
    fn configure(&mut self) -> Result<()> {
        // Get frequency registers for band
        let (freq2, freq1, freq0) = self.config.band.freq_registers();

        // IOCFG2: GDO2 output config (carrier sense)
        self.write_register(Register::IOCFG2, 0x09)?;

        // IOCFG0: GDO0 output config (RX/TX status)
        self.write_register(Register::IOCFG0, 0x06)?;

        // FIFOTHR: FIFO thresholds
        self.write_register(Register::FIFOTHR, 0x47)?;

        // SYNC1/SYNC0: Sync word
        self.write_register(Register::SYNC1, 0xD3)?;
        self.write_register(Register::SYNC0, 0x91)?;

        // PKTLEN: Packet length
        self.write_register(Register::PKTLEN, MAX_PAYLOAD_SIZE as u8)?;

        // PKTCTRL1: Packet automation (CRC autoflush, append status)
        self.write_register(Register::PKTCTRL1, 0x04)?;

        // PKTCTRL0: Packet format (variable length, CRC enabled)
        self.write_register(Register::PKTCTRL0, 0x05)?;

        // ADDR: Device address (for filtering)
        self.write_register(Register::ADDR, 0x00)?;

        // CHANNR: Channel number
        self.write_register(Register::CHANNR, 0x00)?;

        // FSCTRL1: Frequency synthesizer control
        self.write_register(Register::FSCTRL1, 0x06)?;

        // FREQ2/1/0: Frequency control
        self.write_register(Register::FREQ2, freq2)?;
        self.write_register(Register::FREQ1, freq1)?;
        self.write_register(Register::FREQ0, freq0)?;

        // MDMCFG4/3/2/1/0: Modem configuration
        let (mdmcfg4, mdmcfg3) = self.config.data_rate.modem_registers();
        let mdmcfg2 = self.config.modulation.register() | self.config.sync_mode.register();

        self.write_register(Register::MDMCFG4, mdmcfg4)?;
        self.write_register(Register::MDMCFG3, mdmcfg3)?;
        self.write_register(Register::MDMCFG2, mdmcfg2)?;
        self.write_register(Register::MDMCFG1, 0x22)?; // 4 preamble bytes
        self.write_register(Register::MDMCFG0, 0xF8)?; // Channel spacing

        // DEVIATN: Deviation
        self.write_register(Register::DEVIATN, 0x34)?;

        // MCSM2/1/0: Main radio control state machine
        self.write_register(Register::MCSM2, 0x07)?;
        self.write_register(Register::MCSM1, 0x30)?; // CCA, stay in RX
        self.write_register(Register::MCSM0, 0x18)?; // Auto calibrate

        // FOCCFG: Frequency offset compensation
        self.write_register(Register::FOCCFG, 0x16)?;

        // BSCFG: Bit synchronization
        self.write_register(Register::BSCFG, 0x6C)?;

        // AGCCTRL2/1/0: AGC control
        self.write_register(Register::AGCCTRL2, 0x43)?;
        self.write_register(Register::AGCCTRL1, 0x40)?;
        self.write_register(Register::AGCCTRL0, 0x91)?;

        // FREND1/0: Front end config
        self.write_register(Register::FREND1, 0x56)?;
        self.write_register(Register::FREND0, self.config.power.register())?;

        // FSCAL3/2/1/0: Frequency synthesizer calibration
        self.write_register(Register::FSCAL3, 0xE9)?;
        self.write_register(Register::FSCAL2, 0x2A)?;
        self.write_register(Register::FSCAL1, 0x00)?;
        self.write_register(Register::FSCAL0, 0x1F)?;

        // TEST2/1/0: Test registers
        self.write_register(Register::TEST2, 0x81)?;
        self.write_register(Register::TEST1, 0x35)?;
        self.write_register(Register::TEST0, 0x09)?;

        Ok(())
    }

    /// Enter RX mode
    pub fn start_rx(&mut self) -> Result<()> {
        // Flush RX FIFO
        self.strobe(registers::Strobe::SFRX)?;
        // Enter RX
        self.strobe(registers::Strobe::SRX)?;
        Ok(())
    }

    /// Enter idle mode
    pub fn idle(&mut self) -> Result<()> {
        self.strobe(registers::Strobe::SIDLE)?;
        Ok(())
    }

    /// Check if packet is available
    pub fn packet_available(&mut self) -> Result<bool> {
        let rxbytes = self.read_register(Register::RXBYTES)?;
        let num_bytes = rxbytes & 0x7F;
        let overflow = (rxbytes & 0x80) != 0;

        if overflow {
            // Flush on overflow
            self.strobe(registers::Strobe::SFRX)?;
            self.start_rx()?;
            return Ok(false);
        }

        Ok(num_bytes > 0)
    }

    /// Read received packet
    pub fn read_packet(&mut self, buf: &mut [u8]) -> Result<usize> {
        // Read length byte
        let len = self.read_register(Register::FIFO)? as usize;

        if len == 0 || len > MAX_PAYLOAD_SIZE {
            self.strobe(registers::Strobe::SFRX)?;
            return Err(Error::InvalidData);
        }

        if len > buf.len() {
            self.strobe(registers::Strobe::SFRX)?;
            return Err(Error::BufferTooSmall);
        }

        // Read payload
        self.read_burst(Register::FIFO, &mut buf[..len])?;

        // Read status bytes (RSSI, LQI)
        let rssi_raw = self.read_register(Register::FIFO)?;
        let lqi_crc = self.read_register(Register::FIFO)?;

        // Convert RSSI
        self.last_rssi = Some(Self::convert_rssi(rssi_raw));
        self.last_lqi = lqi_crc & 0x7F;

        // Check CRC
        if (lqi_crc & 0x80) == 0 {
            return Err(Error::InvalidData);
        }

        Ok(len)
    }

    /// Send packet
    pub fn send_packet(&mut self, data: &[u8]) -> Result<()> {
        if data.len() > MAX_PAYLOAD_SIZE {
            return Err(Error::InvalidParameter);
        }

        // Enter idle
        self.strobe(registers::Strobe::SIDLE)?;

        // Flush TX FIFO
        self.strobe(registers::Strobe::SFTX)?;

        // Write length byte
        self.write_register(Register::FIFO, data.len() as u8)?;

        // Write payload
        self.write_burst(Register::FIFO, data)?;

        // Enter TX
        self.strobe(registers::Strobe::STX)?;

        // Wait for TX complete
        let mut attempts = 0;
        loop {
            let state = self.get_state()?;
            if state == Cc1101State::Idle {
                break;
            }
            if state == Cc1101State::TxUnderflow {
                self.strobe(registers::Strobe::SFTX)?;
                return Err(Error::TransportError);
            }
            attempts += 1;
            if attempts > 10000 {
                self.strobe(registers::Strobe::SIDLE)?;
                return Err(Error::Timeout);
            }
        }

        Ok(())
    }

    /// Get current state
    pub fn get_state(&mut self) -> Result<Cc1101State> {
        let status = self.read_status()?;
        Ok(Cc1101State::from_status(status))
    }

    /// Convert raw RSSI to dBm
    fn convert_rssi(raw: u8) -> i16 {
        let rssi = raw as i16;
        if rssi >= 128 {
            (rssi - 256) / 2 - 74
        } else {
            rssi / 2 - 74
        }
    }

    /// Get last RSSI
    pub fn last_rssi(&self) -> Option<i16> {
        self.last_rssi
    }

    /// Get last LQI (Link Quality Indicator)
    pub fn last_lqi(&self) -> u8 {
        self.last_lqi
    }

    /// Change frequency band
    pub fn set_band(&mut self, band: Cc1101Band) -> Result<()> {
        self.config.band = band;

        let (freq2, freq1, freq0) = band.freq_registers();

        self.strobe(registers::Strobe::SIDLE)?;
        self.write_register(Register::FREQ2, freq2)?;
        self.write_register(Register::FREQ1, freq1)?;
        self.write_register(Register::FREQ0, freq0)?;
        self.strobe(registers::Strobe::SCAL)?;

        Ok(())
    }

    /// Set channel
    pub fn set_channel(&mut self, channel: u8) -> Result<()> {
        self.strobe(registers::Strobe::SIDLE)?;
        self.write_register(Register::CHANNR, channel)?;
        Ok(())
    }

    /// Power down
    pub fn power_down(&mut self) -> Result<()> {
        self.strobe(registers::Strobe::SPWD)?;
        Ok(())
    }

    // --- SPI operations ---

    /// Send strobe command
    fn strobe(&mut self, strobe: registers::Strobe) -> Result<u8> {
        let mut buf = [strobe as u8];
        self.spi.transfer(&mut buf)?;
        Ok(buf[0])
    }

    /// Read status byte
    fn read_status(&mut self) -> Result<u8> {
        self.strobe(registers::Strobe::SNOP)
    }

    /// Read register
    fn read_register(&mut self, reg: Register) -> Result<u8> {
        let mut buf = [reg as u8 | 0x80, 0];
        self.spi.transfer(&mut buf)?;
        Ok(buf[1])
    }

    /// Write register
    fn write_register(&mut self, reg: Register, value: u8) -> Result<()> {
        let mut buf = [reg as u8, value];
        self.spi.transfer(&mut buf)?;
        Ok(())
    }

    /// Read burst
    fn read_burst(&mut self, reg: Register, buf: &mut [u8]) -> Result<()> {
        if buf.is_empty() {
            return Ok(());
        }

        // Burst read: address | 0xC0
        let mut cmd = [reg as u8 | 0xC0];
        self.spi.transfer(&mut cmd)?;

        for byte in buf.iter_mut() {
            let mut b = [0u8];
            self.spi.transfer(&mut b)?;
            *byte = b[0];
        }

        Ok(())
    }

    /// Write burst
    fn write_burst(&mut self, reg: Register, data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }

        // Burst write: address | 0x40
        let mut cmd = [reg as u8 | 0x40];
        self.spi.transfer(&mut cmd)?;

        for &byte in data {
            let mut b = [byte];
            self.spi.transfer(&mut b)?;
        }

        Ok(())
    }

    /// Get configuration
    pub fn config(&self) -> &Cc1101Config {
        &self.config
    }
}

/// CC1101 Transport wrapper
pub struct Cc1101Transport<SPI: SpiDevice, GDO: GdoPin = NoGdo> {
    /// Radio driver
    radio: Cc1101<SPI, GDO>,
    /// Local locator
    local_locator: Locator,
}

impl<SPI: SpiDevice> Cc1101Transport<SPI, NoGdo> {
    /// Create a new CC1101 transport
    pub fn new(spi: SPI, config: Cc1101Config) -> Self {
        let freq_marker = config.band.frequency_mhz();
        Self {
            radio: Cc1101::new(spi, config),
            local_locator: Locator::udpv4([0, 0, 0, 1], freq_marker),
        }
    }
}

impl<SPI: SpiDevice, GDO: GdoPin> Cc1101Transport<SPI, GDO> {
    /// Create with GDO pin
    pub fn with_gdo(spi: SPI, gdo0: GDO, config: Cc1101Config) -> Self {
        let freq_marker = config.band.frequency_mhz();
        Self {
            radio: Cc1101::with_gdo(spi, gdo0, config),
            local_locator: Locator::udpv4([0, 0, 0, 1], freq_marker),
        }
    }

    /// Get radio reference
    pub fn radio(&self) -> &Cc1101<SPI, GDO> {
        &self.radio
    }

    /// Get mutable radio reference
    pub fn radio_mut(&mut self) -> &mut Cc1101<SPI, GDO> {
        &mut self.radio
    }
}

impl<SPI: SpiDevice, GDO: GdoPin> Transport for Cc1101Transport<SPI, GDO> {
    fn init(&mut self) -> Result<()> {
        self.radio.init()?;
        self.radio.start_rx()?;
        Ok(())
    }

    fn send(&mut self, data: &[u8], _dest: &Locator) -> Result<usize> {
        self.radio.send_packet(data)?;
        self.radio.start_rx()?;
        Ok(data.len())
    }

    fn recv(&mut self, buf: &mut [u8]) -> Result<(usize, Locator)> {
        loop {
            if self.radio.packet_available()? {
                let len = self.radio.read_packet(buf)?;
                return Ok((len, self.local_locator));
            }
        }
    }

    fn try_recv(&mut self, buf: &mut [u8]) -> Result<(usize, Locator)> {
        if self.radio.packet_available()? {
            let len = self.radio.read_packet(buf)?;
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
        registers: [u8; 64],
    }

    impl MockSpi {
        fn new() -> Self {
            Self { registers: [0; 64] }
        }
    }

    impl SpiDevice for MockSpi {
        fn transfer(&mut self, data: &mut [u8]) -> Result<()> {
            if data.is_empty() {
                return Ok(());
            }

            let cmd = data[0];

            // Strobe commands (0x30-0x3F)
            if (0x30..=0x3F).contains(&cmd) {
                data[0] = 0x00; // Return idle status
                return Ok(());
            }

            // Read (0x80-0xBF)
            if (0x80..0xC0).contains(&cmd) {
                let reg = (cmd & 0x3F) as usize;
                if reg < 64 && data.len() > 1 {
                    data[1] = self.registers[reg];
                }
                return Ok(());
            }

            // Write (0x00-0x3F, excluding strobes)
            if cmd < 0x30 {
                let reg = cmd as usize;
                if reg < 64 && data.len() > 1 {
                    self.registers[reg] = data[1];
                }
                return Ok(());
            }

            Ok(())
        }
    }

    #[test]
    fn test_cc1101_creation() {
        let spi = MockSpi::new();
        let config = Cc1101Config::default();

        let radio = Cc1101::new(spi, config);
        assert!(radio.last_rssi().is_none());
    }

    #[test]
    fn test_cc1101_init() {
        let spi = MockSpi::new();
        let config = Cc1101Config::default();

        let mut radio = Cc1101::new(spi, config);
        radio.init().unwrap();
    }

    #[test]
    fn test_cc1101_transport_creation() {
        let spi = MockSpi::new();
        let config = Cc1101Config::default();

        let transport = Cc1101Transport::new(spi, config);
        assert_eq!(transport.mtu(), MAX_PAYLOAD_SIZE);
    }

    #[test]
    fn test_cc1101_config_defaults() {
        let config = Cc1101Config::default();
        assert_eq!(config.band, Cc1101Band::Band433);
        assert_eq!(config.data_rate, Cc1101DataRate::Rate38k4);
        assert_eq!(config.power, Cc1101Power::Plus10dBm);
    }

    #[test]
    fn test_cc1101_rssi_conversion() {
        // Strong signal
        assert_eq!(Cc1101::<MockSpi>::convert_rssi(200), -102);

        // Weak signal
        assert_eq!(Cc1101::<MockSpi>::convert_rssi(100), -24);
    }

    #[test]
    fn test_cc1101_state_parsing() {
        assert_eq!(Cc1101State::from_status(0x00), Cc1101State::Idle);
        assert_eq!(Cc1101State::from_status(0x10), Cc1101State::Rx);
        assert_eq!(Cc1101State::from_status(0x20), Cc1101State::Tx);
    }

    #[test]
    fn test_cc1101_bands() {
        assert_eq!(Cc1101Band::Band315.frequency_mhz(), 315);
        assert_eq!(Cc1101Band::Band433.frequency_mhz(), 433);
        assert_eq!(Cc1101Band::Band868.frequency_mhz(), 868);
        assert_eq!(Cc1101Band::Band915.frequency_mhz(), 915);
    }
}
