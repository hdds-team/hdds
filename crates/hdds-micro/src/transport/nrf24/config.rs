// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! NRF24L01 configuration types

/// Data rate
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Nrf24DataRate {
    /// 250 kbps (NRF24L01+ only, longest range)
    Rate250Kbps,
    /// 1 Mbps (default, good balance)
    #[default]
    Rate1Mbps,
    /// 2 Mbps (shortest range, lowest latency)
    Rate2Mbps,
}

impl Nrf24DataRate {
    /// Convert to RF_SETUP register bits
    pub fn to_register(self) -> u8 {
        match self {
            Self::Rate250Kbps => 0x20, // RF_DR_LOW = 1
            Self::Rate1Mbps => 0x00,   // RF_DR = 0
            Self::Rate2Mbps => 0x08,   // RF_DR_HIGH = 1
        }
    }

    /// Get data rate in kbps
    pub fn kbps(self) -> u16 {
        match self {
            Self::Rate250Kbps => 250,
            Self::Rate1Mbps => 1000,
            Self::Rate2Mbps => 2000,
        }
    }
}

/// TX power level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Nrf24Power {
    /// -18 dBm (minimum)
    Min,
    /// -12 dBm
    Low,
    /// -6 dBm
    Medium,
    /// 0 dBm (maximum)
    #[default]
    Max,
}

impl Nrf24Power {
    /// Convert to RF_SETUP register bits
    pub fn to_register(self) -> u8 {
        match self {
            Self::Min => 0x00,    // -18 dBm
            Self::Low => 0x02,    // -12 dBm
            Self::Medium => 0x04, // -6 dBm
            Self::Max => 0x06,    // 0 dBm
        }
    }

    /// Get power in dBm
    pub fn dbm(self) -> i8 {
        match self {
            Self::Min => -18,
            Self::Low => -12,
            Self::Medium => -6,
            Self::Max => 0,
        }
    }
}

/// CRC mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Nrf24CrcMode {
    /// CRC disabled
    Disabled,
    /// 1-byte CRC
    Crc1Byte,
    /// 2-byte CRC (default, recommended)
    #[default]
    Crc2Bytes,
}

impl Nrf24CrcMode {
    /// Convert to CONFIG register bits
    pub fn to_register(self) -> u8 {
        match self {
            Self::Disabled => 0x00,
            Self::Crc1Byte => 0x08,  // EN_CRC
            Self::Crc2Bytes => 0x0C, // EN_CRC + CRCO
        }
    }
}

/// Address width
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Nrf24AddressWidth {
    /// 3 bytes
    Width3,
    /// 4 bytes
    Width4,
    /// 5 bytes (default, recommended)
    #[default]
    Width5,
}

impl Nrf24AddressWidth {
    /// Convert to SETUP_AW register value
    pub fn to_register(self) -> u8 {
        match self {
            Self::Width3 => 0x01,
            Self::Width4 => 0x02,
            Self::Width5 => 0x03,
        }
    }

    /// Get width in bytes
    pub fn bytes(self) -> u8 {
        match self {
            Self::Width3 => 3,
            Self::Width4 => 4,
            Self::Width5 => 5,
        }
    }
}

/// RF channel (0-125, frequency = 2400 + channel MHz)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Nrf24Channel(pub u8);

impl Nrf24Channel {
    /// Create a new channel
    ///
    /// Valid range: 0-125 (2400-2525 MHz)
    pub fn new(channel: u8) -> Option<Self> {
        if channel <= 125 {
            Some(Self(channel))
        } else {
            None
        }
    }

    /// Get frequency in MHz
    pub fn frequency_mhz(self) -> u16 {
        2400 + self.0 as u16
    }
}

impl Default for Nrf24Channel {
    fn default() -> Self {
        Self(76) // 2476 MHz, common default
    }
}

/// NRF24L01 configuration
#[derive(Debug, Clone)]
pub struct Nrf24Config {
    /// RF channel
    pub channel: Nrf24Channel,
    /// Data rate
    pub data_rate: Nrf24DataRate,
    /// TX power
    pub power: Nrf24Power,
    /// CRC mode
    pub crc: Nrf24CrcMode,
    /// Address width
    pub address_width: Nrf24AddressWidth,
    /// Auto-retransmit delay (0-15, delay = 250 + 250*n us)
    pub retry_delay: u8,
    /// Auto-retransmit count (0-15, 0 = disabled)
    pub retry_count: u8,
}

impl Default for Nrf24Config {
    fn default() -> Self {
        Self {
            channel: Nrf24Channel::default(),
            data_rate: Nrf24DataRate::default(),
            power: Nrf24Power::default(),
            crc: Nrf24CrcMode::default(),
            address_width: Nrf24AddressWidth::default(),
            retry_delay: 5,  // 1500 us
            retry_count: 15, // Max retries
        }
    }
}

impl Nrf24Config {
    /// Create configuration for high-speed, short-range
    pub fn high_speed() -> Self {
        Self {
            data_rate: Nrf24DataRate::Rate2Mbps,
            power: Nrf24Power::Max,
            retry_delay: 1, // 500 us
            retry_count: 5,
            ..Default::default()
        }
    }

    /// Create configuration for long-range (NRF24L01+ only)
    pub fn long_range() -> Self {
        Self {
            data_rate: Nrf24DataRate::Rate250Kbps,
            power: Nrf24Power::Max,
            retry_delay: 15, // 4000 us
            retry_count: 15,
            ..Default::default()
        }
    }

    /// Create configuration for low power
    pub fn low_power() -> Self {
        Self {
            data_rate: Nrf24DataRate::Rate250Kbps,
            power: Nrf24Power::Min,
            retry_delay: 5,
            retry_count: 3,
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_rate() {
        assert_eq!(Nrf24DataRate::Rate250Kbps.kbps(), 250);
        assert_eq!(Nrf24DataRate::Rate1Mbps.kbps(), 1000);
        assert_eq!(Nrf24DataRate::Rate2Mbps.kbps(), 2000);
    }

    #[test]
    fn test_data_rate_register() {
        assert_eq!(Nrf24DataRate::Rate250Kbps.to_register(), 0x20);
        assert_eq!(Nrf24DataRate::Rate1Mbps.to_register(), 0x00);
        assert_eq!(Nrf24DataRate::Rate2Mbps.to_register(), 0x08);
    }

    #[test]
    fn test_power() {
        assert_eq!(Nrf24Power::Min.dbm(), -18);
        assert_eq!(Nrf24Power::Low.dbm(), -12);
        assert_eq!(Nrf24Power::Medium.dbm(), -6);
        assert_eq!(Nrf24Power::Max.dbm(), 0);
    }

    #[test]
    fn test_power_register() {
        assert_eq!(Nrf24Power::Min.to_register(), 0x00);
        assert_eq!(Nrf24Power::Low.to_register(), 0x02);
        assert_eq!(Nrf24Power::Medium.to_register(), 0x04);
        assert_eq!(Nrf24Power::Max.to_register(), 0x06);
    }

    #[test]
    fn test_crc_register() {
        assert_eq!(Nrf24CrcMode::Disabled.to_register(), 0x00);
        assert_eq!(Nrf24CrcMode::Crc1Byte.to_register(), 0x08);
        assert_eq!(Nrf24CrcMode::Crc2Bytes.to_register(), 0x0C);
    }

    #[test]
    fn test_address_width() {
        assert_eq!(Nrf24AddressWidth::Width3.bytes(), 3);
        assert_eq!(Nrf24AddressWidth::Width4.bytes(), 4);
        assert_eq!(Nrf24AddressWidth::Width5.bytes(), 5);
    }

    #[test]
    fn test_channel() {
        let ch = Nrf24Channel::new(76).unwrap();
        assert_eq!(ch.frequency_mhz(), 2476);

        let ch0 = Nrf24Channel::new(0).unwrap();
        assert_eq!(ch0.frequency_mhz(), 2400);

        let ch125 = Nrf24Channel::new(125).unwrap();
        assert_eq!(ch125.frequency_mhz(), 2525);

        // Invalid channel
        assert!(Nrf24Channel::new(126).is_none());
    }

    #[test]
    fn test_config_presets() {
        let hs = Nrf24Config::high_speed();
        assert_eq!(hs.data_rate, Nrf24DataRate::Rate2Mbps);

        let lr = Nrf24Config::long_range();
        assert_eq!(lr.data_rate, Nrf24DataRate::Rate250Kbps);
        assert_eq!(lr.power, Nrf24Power::Max);

        let lp = Nrf24Config::low_power();
        assert_eq!(lp.power, Nrf24Power::Min);
    }

    #[test]
    fn test_default_config() {
        let config = Nrf24Config::default();
        assert_eq!(config.channel.0, 76);
        assert_eq!(config.data_rate, Nrf24DataRate::Rate1Mbps);
        assert_eq!(config.power, Nrf24Power::Max);
        assert_eq!(config.crc, Nrf24CrcMode::Crc2Bytes);
        assert_eq!(config.address_width, Nrf24AddressWidth::Width5);
    }
}
