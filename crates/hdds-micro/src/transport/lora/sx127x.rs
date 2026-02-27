// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! SX1276/SX1278 LoRa transceiver driver
//!
//! Platform-agnostic driver using embedded-hal style traits.
//! Supports basic LoRa operations: TX, RX, configuration.

use super::config::{Bandwidth, CodingRate, SpreadingFactor};
use crate::error::{Error, Result};

/// SPI device abstraction
///
/// Platform implementations (ESP32, RP2040, STM32) provide this trait.
pub trait SpiDevice {
    /// Transfer data (full-duplex SPI)
    ///
    /// Writes `tx` bytes while simultaneously reading into `rx`.
    /// Both slices must have the same length.
    fn transfer(&mut self, tx: &[u8], rx: &mut [u8]) -> Result<()>;

    /// Write bytes (ignoring read data)
    fn write(&mut self, data: &[u8]) -> Result<()>;

    /// Read bytes (writing zeros)
    fn read(&mut self, buf: &mut [u8]) -> Result<()>;
}

/// Digital I/O pin abstraction
///
/// Used for DIO0 interrupt pin (TX Done / RX Done).
pub trait DioPin {
    /// Check if pin is high
    fn is_high(&self) -> bool;

    /// Check if pin is low
    fn is_low(&self) -> bool {
        !self.is_high()
    }
}

// SX127x Register addresses
#[allow(dead_code)]
mod regs {
    pub const REG_FIFO: u8 = 0x00;
    pub const REG_OP_MODE: u8 = 0x01;
    pub const REG_FRF_MSB: u8 = 0x06;
    pub const REG_FRF_MID: u8 = 0x07;
    pub const REG_FRF_LSB: u8 = 0x08;
    pub const REG_PA_CONFIG: u8 = 0x09;
    pub const REG_LNA: u8 = 0x0C; // Used for LNA gain configuration
    pub const REG_FIFO_ADDR_PTR: u8 = 0x0D;
    pub const REG_FIFO_TX_BASE_ADDR: u8 = 0x0E;
    pub const REG_FIFO_RX_BASE_ADDR: u8 = 0x0F;
    pub const REG_FIFO_RX_CURRENT_ADDR: u8 = 0x10;
    pub const REG_IRQ_FLAGS_MASK: u8 = 0x11; // Used to mask IRQ sources
    pub const REG_IRQ_FLAGS: u8 = 0x12;
    pub const REG_RX_NB_BYTES: u8 = 0x13;
    pub const REG_PKT_SNR_VALUE: u8 = 0x19;
    pub const REG_PKT_RSSI_VALUE: u8 = 0x1A; // Used for packet RSSI
    pub const REG_RSSI_VALUE: u8 = 0x1B;
    pub const REG_MODEM_CONFIG_1: u8 = 0x1D;
    pub const REG_MODEM_CONFIG_2: u8 = 0x1E;
    pub const REG_PREAMBLE_MSB: u8 = 0x20;
    pub const REG_PREAMBLE_LSB: u8 = 0x21;
    pub const REG_PAYLOAD_LENGTH: u8 = 0x22;
    pub const REG_MODEM_CONFIG_3: u8 = 0x26;
    pub const REG_DETECTION_OPTIMIZE: u8 = 0x31;
    pub const REG_DETECTION_THRESHOLD: u8 = 0x37;
    pub const REG_SYNC_WORD: u8 = 0x39;
    pub const REG_DIO_MAPPING_1: u8 = 0x40;
    pub const REG_VERSION: u8 = 0x42;
    pub const REG_PA_DAC: u8 = 0x4D;
}

// Operating modes
#[allow(dead_code)]
mod modes {
    pub const MODE_SLEEP: u8 = 0x00;
    pub const MODE_STANDBY: u8 = 0x01;
    pub const MODE_TX: u8 = 0x03;
    pub const MODE_RX_CONTINUOUS: u8 = 0x05; // For continuous receive mode
    pub const MODE_RX_SINGLE: u8 = 0x06;
    pub const MODE_LORA: u8 = 0x80;
}

// IRQ flags
#[allow(dead_code)]
mod irq {
    pub const IRQ_TX_DONE: u8 = 0x08;
    pub const IRQ_RX_DONE: u8 = 0x40;
    pub const IRQ_VALID_HEADER: u8 = 0x10; // Used for header validation
    pub const IRQ_CRC_ERROR: u8 = 0x20;
    pub const IRQ_RX_TIMEOUT: u8 = 0x80;
}

/// SX1276/SX1278 LoRa transceiver driver
pub struct Sx127x<SPI: SpiDevice, DIO0: DioPin> {
    spi: SPI,
    #[allow(dead_code)]
    dio0: DIO0, // Used for interrupt-driven TX/RX
    /// Current operating mode
    mode: u8,
    /// Frequency offset correction (in Hz, for crystal calibration)
    freq_offset: i32,
}

impl<SPI: SpiDevice, DIO0: DioPin> Sx127x<SPI, DIO0> {
    /// Create a new SX127x driver
    ///
    /// # Arguments
    ///
    /// * `spi` - SPI device for communication
    /// * `dio0` - DIO0 pin for TX/RX done interrupts
    pub fn new(spi: SPI, dio0: DIO0) -> Self {
        Self {
            spi,
            dio0,
            mode: modes::MODE_SLEEP,
            freq_offset: 0,
        }
    }

    /// Reset the radio (software reset via register)
    ///
    /// Note: Hardware reset via RST pin should be done by platform code.
    pub fn reset(&mut self) -> Result<()> {
        // Set sleep mode
        self.set_mode_sleep()?;

        // Verify chip version
        let version = self.read_register(regs::REG_VERSION)?;
        if version != 0x12 {
            return Err(Error::InvalidParameter);
        }

        Ok(())
    }

    /// Set sleep mode (lowest power)
    pub fn set_mode_sleep(&mut self) -> Result<()> {
        self.write_register(regs::REG_OP_MODE, modes::MODE_LORA | modes::MODE_SLEEP)?;
        self.mode = modes::MODE_SLEEP;
        Ok(())
    }

    /// Set standby mode
    pub fn set_mode_standby(&mut self) -> Result<()> {
        self.write_register(regs::REG_OP_MODE, modes::MODE_LORA | modes::MODE_STANDBY)?;
        self.mode = modes::MODE_STANDBY;
        Ok(())
    }

    /// Enable LoRa mode (must be in sleep mode first)
    pub fn set_lora_mode(&mut self) -> Result<()> {
        self.write_register(regs::REG_OP_MODE, modes::MODE_LORA | modes::MODE_SLEEP)?;
        Ok(())
    }

    /// Set carrier frequency
    ///
    /// # Arguments
    ///
    /// * `center_mhz` - Frequency in MHz (e.g., 868.0 or 915.0)
    pub fn set_frequency(&mut self, center_mhz: f32) -> Result<()> {
        // F_RF = (frf * 32MHz) / 2^19
        // frf = F_RF * 2^19 / 32MHz
        let rf_hz = (center_mhz * 1_000_000.0) as i64 + self.freq_offset as i64;
        let frf = ((rf_hz as u64) << 19) / 32_000_000;

        self.write_register(regs::REG_FRF_MSB, ((frf >> 16) & 0xFF) as u8)?;
        self.write_register(regs::REG_FRF_MID, ((frf >> 8) & 0xFF) as u8)?;
        self.write_register(regs::REG_FRF_LSB, (frf & 0xFF) as u8)?;

        Ok(())
    }

    /// Set spreading factor
    pub fn set_spreading_factor(&mut self, sf: SpreadingFactor) -> Result<()> {
        let sf_val = sf.value();

        // Read current config
        let mut config2 = self.read_register(regs::REG_MODEM_CONFIG_2)?;

        // Clear SF bits [7:4] and set new value
        config2 = (config2 & 0x0F) | (sf_val << 4);
        self.write_register(regs::REG_MODEM_CONFIG_2, config2)?;

        // Set detection optimize and threshold for SF
        if sf_val == 6 {
            // SF6 requires special settings
            self.write_register(regs::REG_DETECTION_OPTIMIZE, 0xC5)?;
            self.write_register(regs::REG_DETECTION_THRESHOLD, 0x0C)?;
        } else {
            self.write_register(regs::REG_DETECTION_OPTIMIZE, 0xC3)?;
            self.write_register(regs::REG_DETECTION_THRESHOLD, 0x0A)?;
        }

        // Enable LowDataRateOptimize for SF11/SF12
        let mut config3 = self.read_register(regs::REG_MODEM_CONFIG_3)?;
        if sf_val >= 11 {
            config3 |= 0x08; // Enable LDRO
        } else {
            config3 &= !0x08; // Disable LDRO
        }
        self.write_register(regs::REG_MODEM_CONFIG_3, config3)?;

        Ok(())
    }

    /// Set bandwidth
    pub fn set_bandwidth(&mut self, bw: Bandwidth) -> Result<()> {
        let mut config1 = self.read_register(regs::REG_MODEM_CONFIG_1)?;

        // Clear BW bits [7:4] and set new value
        config1 = (config1 & 0x0F) | (bw.value() << 4);
        self.write_register(regs::REG_MODEM_CONFIG_1, config1)?;

        Ok(())
    }

    /// Set coding rate
    pub fn set_coding_rate(&mut self, cr: CodingRate) -> Result<()> {
        let mut config1 = self.read_register(regs::REG_MODEM_CONFIG_1)?;

        // Clear CR bits [3:1] and set new value
        config1 = (config1 & 0xF1) | (cr.value() << 1);
        self.write_register(regs::REG_MODEM_CONFIG_1, config1)?;

        Ok(())
    }

    /// Set TX power
    ///
    /// # Arguments
    ///
    /// * `power_dbm` - Power level in dBm (2-20)
    pub fn set_tx_power(&mut self, power_dbm: i8) -> Result<()> {
        // Clamp power to valid range
        let power = power_dbm.clamp(2, 20);

        if power > 17 {
            // Use PA_BOOST with high power settings
            self.write_register(regs::REG_PA_DAC, 0x87)?; // Enable +20dBm
            self.write_register(regs::REG_PA_CONFIG, 0x80 | ((power - 5) as u8))?;
        } else {
            self.write_register(regs::REG_PA_DAC, 0x84)?; // Default
            self.write_register(regs::REG_PA_CONFIG, 0x80 | ((power - 2) as u8))?;
        }

        Ok(())
    }

    /// Set preamble length
    pub fn set_preamble_length(&mut self, length: u16) -> Result<()> {
        self.write_register(regs::REG_PREAMBLE_MSB, (length >> 8) as u8)?;
        self.write_register(regs::REG_PREAMBLE_LSB, (length & 0xFF) as u8)?;
        Ok(())
    }

    /// Enable/disable CRC
    pub fn set_crc_enabled(&mut self, enabled: bool) -> Result<()> {
        let mut config2 = self.read_register(regs::REG_MODEM_CONFIG_2)?;
        if enabled {
            config2 |= 0x04; // RxPayloadCrcOn
        } else {
            config2 &= !0x04;
        }
        self.write_register(regs::REG_MODEM_CONFIG_2, config2)?;
        Ok(())
    }

    /// Set sync word (0x12 for private networks, 0x34 for LoRaWAN)
    pub fn set_sync_word(&mut self, sync_word: u8) -> Result<()> {
        self.write_register(regs::REG_SYNC_WORD, sync_word)?;
        Ok(())
    }

    /// Send a packet
    ///
    /// # Arguments
    ///
    /// * `data` - Packet data (max 255 bytes)
    ///
    /// Blocks until transmission is complete (DIO0 goes high).
    pub fn send(&mut self, data: &[u8]) -> Result<()> {
        if data.len() > 255 {
            return Err(Error::BufferTooSmall);
        }

        // Set standby mode first
        self.set_mode_standby()?;

        // Configure DIO0 for TxDone
        self.write_register(regs::REG_DIO_MAPPING_1, 0x40)?;

        // Set FIFO TX base address
        self.write_register(regs::REG_FIFO_TX_BASE_ADDR, 0x00)?;
        self.write_register(regs::REG_FIFO_ADDR_PTR, 0x00)?;

        // Write payload to FIFO
        for &byte in data {
            self.write_register(regs::REG_FIFO, byte)?;
        }

        // Set payload length
        self.write_register(regs::REG_PAYLOAD_LENGTH, data.len() as u8)?;

        // Clear IRQ flags
        self.write_register(regs::REG_IRQ_FLAGS, 0xFF)?;

        // Start transmission
        self.write_register(regs::REG_OP_MODE, modes::MODE_LORA | modes::MODE_TX)?;

        // Wait for TxDone (poll DIO0 or IRQ register)
        loop {
            let irq = self.read_register(regs::REG_IRQ_FLAGS)?;
            if irq & irq::IRQ_TX_DONE != 0 {
                break;
            }
            // In real embedded code, would add timeout here
        }

        // Clear TxDone flag
        self.write_register(regs::REG_IRQ_FLAGS, irq::IRQ_TX_DONE)?;

        // Return to standby
        self.set_mode_standby()?;

        Ok(())
    }

    /// Receive a packet (blocking with timeout)
    ///
    /// # Arguments
    ///
    /// * `buf` - Buffer to receive into
    /// * `timeout_ms` - Timeout in milliseconds
    ///
    /// # Returns
    ///
    /// Number of bytes received
    pub fn recv(&mut self, buf: &mut [u8], timeout_ms: u32) -> Result<usize> {
        // Set standby mode first
        self.set_mode_standby()?;

        // Configure DIO0 for RxDone
        self.write_register(regs::REG_DIO_MAPPING_1, 0x00)?;

        // Set FIFO RX base address
        self.write_register(regs::REG_FIFO_RX_BASE_ADDR, 0x00)?;
        self.write_register(regs::REG_FIFO_ADDR_PTR, 0x00)?;

        // Clear IRQ flags
        self.write_register(regs::REG_IRQ_FLAGS, 0xFF)?;

        // Start receiving (single mode with timeout, or continuous)
        self.write_register(regs::REG_OP_MODE, modes::MODE_LORA | modes::MODE_RX_SINGLE)?;

        // Simple timeout loop (in real embedded, use hardware timer)
        let mut elapsed = 0u32;
        let poll_interval = 1; // 1ms per iteration (approximate)

        loop {
            let irq = self.read_register(regs::REG_IRQ_FLAGS)?;

            if irq & irq::IRQ_RX_DONE != 0 {
                // Check for CRC error
                if irq & irq::IRQ_CRC_ERROR != 0 {
                    self.write_register(
                        regs::REG_IRQ_FLAGS,
                        irq::IRQ_CRC_ERROR | irq::IRQ_RX_DONE,
                    )?;
                    return Err(Error::InvalidData);
                }

                // Read payload length
                let len = self.read_register(regs::REG_RX_NB_BYTES)? as usize;
                if len > buf.len() {
                    return Err(Error::BufferTooSmall);
                }

                // Set FIFO address to packet start
                let fifo_addr = self.read_register(regs::REG_FIFO_RX_CURRENT_ADDR)?;
                self.write_register(regs::REG_FIFO_ADDR_PTR, fifo_addr)?;

                // Read payload from FIFO
                for byte in buf.iter_mut().take(len) {
                    *byte = self.read_register(regs::REG_FIFO)?;
                }

                // Clear IRQ flags
                self.write_register(regs::REG_IRQ_FLAGS, irq::IRQ_RX_DONE)?;

                // Return to standby
                self.set_mode_standby()?;

                return Ok(len);
            }

            if irq & irq::IRQ_RX_TIMEOUT != 0 {
                self.write_register(regs::REG_IRQ_FLAGS, irq::IRQ_RX_TIMEOUT)?;
                self.set_mode_standby()?;
                return Err(Error::Timeout);
            }

            elapsed += poll_interval;
            if elapsed >= timeout_ms {
                self.set_mode_standby()?;
                return Err(Error::Timeout);
            }

            // Small delay would go here in real implementation
        }
    }

    /// Check if RX is complete (for non-blocking receive)
    pub fn is_rx_done(&mut self) -> Result<bool> {
        let irq = self.read_register(regs::REG_IRQ_FLAGS)?;
        Ok(irq & irq::IRQ_RX_DONE != 0)
    }

    /// Read current RSSI value (in dBm)
    pub fn read_rssi(&mut self) -> Result<i16> {
        let raw = self.read_register(regs::REG_RSSI_VALUE)?;
        // RSSI = -157 + raw (for LF band)
        // RSSI = -164 + raw (for HF band, >862MHz)
        Ok(-164 + raw as i16)
    }

    /// Read packet SNR (in dB, scaled by 4)
    pub fn read_snr(&mut self) -> Result<i8> {
        let raw = self.read_register(regs::REG_PKT_SNR_VALUE)?;
        // SNR is signed, divide by 4 for actual dB
        Ok((raw as i8) / 4)
    }

    /// Set frequency offset for crystal calibration
    pub fn set_frequency_offset(&mut self, offset_hz: i32) {
        self.freq_offset = offset_hz;
    }

    // ---- Low-level register access ----

    /// Read a register
    fn read_register(&mut self, addr: u8) -> Result<u8> {
        let tx = [addr & 0x7F, 0x00]; // Read: MSB = 0
        let mut rx = [0u8; 2];
        self.spi.transfer(&tx, &mut rx)?;
        Ok(rx[1])
    }

    /// Write a register
    fn write_register(&mut self, addr: u8, value: u8) -> Result<()> {
        let tx = [addr | 0x80, value]; // Write: MSB = 1
        self.spi.write(&tx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mock SPI device for testing
    struct MockSpi {
        registers: [u8; 256],
    }

    impl MockSpi {
        fn new() -> Self {
            let mut registers = [0u8; 256];
            // Set version register to valid value
            registers[regs::REG_VERSION as usize] = 0x12;
            Self { registers }
        }
    }

    impl SpiDevice for MockSpi {
        fn transfer(&mut self, tx: &[u8], rx: &mut [u8]) -> Result<()> {
            if tx.len() != rx.len() || tx.is_empty() {
                return Err(Error::InvalidParameter);
            }

            let addr = tx[0] & 0x7F;

            if tx[0] & 0x80 == 0 {
                // Read operation
                rx[0] = 0;
                if tx.len() > 1 {
                    rx[1] = self.registers[addr as usize];
                }
            } else {
                // Write operation
                if tx.len() > 1 {
                    self.registers[addr as usize] = tx[1];
                }
            }

            Ok(())
        }

        fn write(&mut self, data: &[u8]) -> Result<()> {
            if data.len() >= 2 {
                let addr = data[0] & 0x7F;
                self.registers[addr as usize] = data[1];
            }
            Ok(())
        }

        fn read(&mut self, buf: &mut [u8]) -> Result<()> {
            for byte in buf.iter_mut() {
                *byte = 0;
            }
            Ok(())
        }
    }

    /// Mock DIO pin
    struct MockDio {
        high: bool,
    }

    impl MockDio {
        fn new() -> Self {
            Self { high: false }
        }
    }

    impl DioPin for MockDio {
        fn is_high(&self) -> bool {
            self.high
        }
    }

    #[test]
    fn test_sx127x_creation() {
        let spi = MockSpi::new();
        let dio = MockDio::new();
        let _radio = Sx127x::new(spi, dio);
    }

    #[test]
    fn test_sx127x_reset() {
        let spi = MockSpi::new();
        let dio = MockDio::new();
        let mut radio = Sx127x::new(spi, dio);

        assert!(radio.reset().is_ok());
    }

    #[test]
    fn test_sx127x_mode_changes() {
        let spi = MockSpi::new();
        let dio = MockDio::new();
        let mut radio = Sx127x::new(spi, dio);

        radio.reset().unwrap();

        assert!(radio.set_mode_standby().is_ok());
        assert_eq!(radio.mode, modes::MODE_STANDBY);

        assert!(radio.set_mode_sleep().is_ok());
        assert_eq!(radio.mode, modes::MODE_SLEEP);
    }

    #[test]
    fn test_sx127x_configuration() {
        let spi = MockSpi::new();
        let dio = MockDio::new();
        let mut radio = Sx127x::new(spi, dio);

        radio.reset().unwrap();

        assert!(radio.set_frequency(868.0).is_ok());
        assert!(radio.set_spreading_factor(SpreadingFactor::Sf9).is_ok());
        assert!(radio.set_bandwidth(Bandwidth::Bw125).is_ok());
        assert!(radio.set_coding_rate(CodingRate::Cr4_5).is_ok());
        assert!(radio.set_tx_power(14).is_ok());
        assert!(radio.set_preamble_length(8).is_ok());
        assert!(radio.set_crc_enabled(true).is_ok());
        assert!(radio.set_sync_word(0x12).is_ok());
    }

    #[test]
    fn test_rssi_calculation() {
        let spi = MockSpi::new();
        let dio = MockDio::new();
        let mut radio = Sx127x::new(spi, dio);

        // Mock register will return 0, so RSSI = -164
        let rssi = radio.read_rssi().unwrap();
        assert_eq!(rssi, -164);
    }
}
