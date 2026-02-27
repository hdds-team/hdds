// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! CC1101 configuration types

/// Frequency band
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Cc1101Band {
    /// 315 MHz band
    Band315,
    /// 433 MHz band (default, most common)
    #[default]
    Band433,
    /// 868 MHz band (Europe)
    Band868,
    /// 915 MHz band (Americas)
    Band915,
}

impl Cc1101Band {
    /// Get frequency in MHz
    pub fn frequency_mhz(self) -> u16 {
        match self {
            Self::Band315 => 315,
            Self::Band433 => 433,
            Self::Band868 => 868,
            Self::Band915 => 915,
        }
    }

    /// Get FREQ2/FREQ1/FREQ0 register values
    /// Based on 26 MHz crystal
    pub fn freq_registers(self) -> (u8, u8, u8) {
        match self {
            // 315 MHz: 0x0C1D89
            Self::Band315 => (0x0C, 0x1D, 0x89),
            // 433.92 MHz: 0x10B13B
            Self::Band433 => (0x10, 0xB1, 0x3B),
            // 868.3 MHz: 0x216276
            Self::Band868 => (0x21, 0x62, 0x76),
            // 915 MHz: 0x23313B
            Self::Band915 => (0x23, 0x31, 0x3B),
        }
    }
}

/// Data rate
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Cc1101DataRate {
    /// 1.2 kbps (longest range)
    Rate1k2,
    /// 2.4 kbps
    Rate2k4,
    /// 10 kbps
    Rate10k,
    /// 38.4 kbps (default, good balance)
    #[default]
    Rate38k4,
    /// 76.8 kbps
    Rate76k8,
    /// 100 kbps
    Rate100k,
    /// 250 kbps (shortest range)
    Rate250k,
}

impl Cc1101DataRate {
    /// Get data rate in bps
    pub fn bps(self) -> u32 {
        match self {
            Self::Rate1k2 => 1200,
            Self::Rate2k4 => 2400,
            Self::Rate10k => 10000,
            Self::Rate38k4 => 38400,
            Self::Rate76k8 => 76800,
            Self::Rate100k => 100_000,
            Self::Rate250k => 250_000,
        }
    }

    /// Get MDMCFG4 and MDMCFG3 register values
    pub fn modem_registers(self) -> (u8, u8) {
        match self {
            // 1.2 kbps
            Self::Rate1k2 => (0xF5, 0x83),
            // 2.4 kbps
            Self::Rate2k4 => (0xF6, 0x83),
            // 10 kbps
            Self::Rate10k => (0xC8, 0x93),
            // 38.4 kbps
            Self::Rate38k4 => (0xCA, 0x83),
            // 76.8 kbps
            Self::Rate76k8 => (0x7B, 0x83),
            // 100 kbps
            Self::Rate100k => (0x5B, 0xF8),
            // 250 kbps
            Self::Rate250k => (0x3D, 0x3B),
        }
    }
}

/// TX power level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Cc1101Power {
    /// -30 dBm (minimum)
    Minus30dBm,
    /// -20 dBm
    Minus20dBm,
    /// -15 dBm
    Minus15dBm,
    /// -10 dBm
    Minus10dBm,
    /// 0 dBm
    Zero,
    /// +5 dBm
    Plus5dBm,
    /// +7 dBm
    Plus7dBm,
    /// +10 dBm (default, max for most modules)
    #[default]
    Plus10dBm,
}

impl Cc1101Power {
    /// Get power in dBm
    pub fn dbm(self) -> i8 {
        match self {
            Self::Minus30dBm => -30,
            Self::Minus20dBm => -20,
            Self::Minus15dBm => -15,
            Self::Minus10dBm => -10,
            Self::Zero => 0,
            Self::Plus5dBm => 5,
            Self::Plus7dBm => 7,
            Self::Plus10dBm => 10,
        }
    }

    /// Get FREND0 register value (PA table index)
    /// These values are for 433 MHz, may need adjustment for other bands
    pub fn register(self) -> u8 {
        match self {
            Self::Minus30dBm => 0x00,
            Self::Minus20dBm => 0x01,
            Self::Minus15dBm => 0x02,
            Self::Minus10dBm => 0x03,
            Self::Zero => 0x04,
            Self::Plus5dBm => 0x05,
            Self::Plus7dBm => 0x06,
            Self::Plus10dBm => 0x07,
        }
    }
}

/// Modulation scheme
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Cc1101Modulation {
    /// 2-FSK (default)
    #[default]
    Fsk2,
    /// GFSK (Gaussian FSK)
    Gfsk,
    /// ASK/OOK (On-Off Keying)
    Ask,
    /// 4-FSK
    Fsk4,
    /// MSK (Minimum Shift Keying)
    Msk,
}

impl Cc1101Modulation {
    /// Get MDMCFG2 register bits (MOD_FORMAT)
    pub fn register(self) -> u8 {
        match self {
            Self::Fsk2 => 0x00,
            Self::Gfsk => 0x10,
            Self::Ask => 0x30,
            Self::Fsk4 => 0x40,
            Self::Msk => 0x70,
        }
    }
}

/// Sync word mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Cc1101SyncMode {
    /// No sync word
    None,
    /// 15/16 sync word bits
    Bits15of16,
    /// 16/16 sync word bits (default)
    #[default]
    Bits16of16,
    /// 30/32 sync word bits
    Bits30of32,
    /// Carrier sense
    CarrierSense,
    /// 15/16 + carrier sense
    Bits15of16Cs,
    /// 16/16 + carrier sense
    Bits16of16Cs,
    /// 30/32 + carrier sense
    Bits30of32Cs,
}

impl Cc1101SyncMode {
    /// Get MDMCFG2 register bits (SYNC_MODE)
    pub fn register(self) -> u8 {
        match self {
            Self::None => 0x00,
            Self::Bits15of16 => 0x01,
            Self::Bits16of16 => 0x02,
            Self::Bits30of32 => 0x03,
            Self::CarrierSense => 0x04,
            Self::Bits15of16Cs => 0x05,
            Self::Bits16of16Cs => 0x06,
            Self::Bits30of32Cs => 0x07,
        }
    }
}

/// CC1101 configuration
#[derive(Debug, Clone, Default)]
pub struct Cc1101Config {
    /// Frequency band
    pub band: Cc1101Band,
    /// Data rate
    pub data_rate: Cc1101DataRate,
    /// TX power
    pub power: Cc1101Power,
    /// Modulation
    pub modulation: Cc1101Modulation,
    /// Sync word mode
    pub sync_mode: Cc1101SyncMode,
}

impl Cc1101Config {
    /// Configuration for long range (1.2 kbps)
    pub fn long_range() -> Self {
        Self {
            data_rate: Cc1101DataRate::Rate1k2,
            power: Cc1101Power::Plus10dBm,
            ..Default::default()
        }
    }

    /// Configuration for high speed (250 kbps)
    pub fn high_speed() -> Self {
        Self {
            data_rate: Cc1101DataRate::Rate250k,
            power: Cc1101Power::Plus10dBm,
            ..Default::default()
        }
    }

    /// Configuration for low power
    pub fn low_power() -> Self {
        Self {
            data_rate: Cc1101DataRate::Rate1k2,
            power: Cc1101Power::Minus10dBm,
            ..Default::default()
        }
    }

    /// Configuration for 868 MHz (Europe)
    pub fn europe_868() -> Self {
        Self {
            band: Cc1101Band::Band868,
            ..Default::default()
        }
    }

    /// Configuration for 915 MHz (Americas)
    pub fn americas_915() -> Self {
        Self {
            band: Cc1101Band::Band915,
            ..Default::default()
        }
    }

    /// Configuration for 315 MHz
    pub fn band_315() -> Self {
        Self {
            band: Cc1101Band::Band315,
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_band_frequency() {
        assert_eq!(Cc1101Band::Band315.frequency_mhz(), 315);
        assert_eq!(Cc1101Band::Band433.frequency_mhz(), 433);
        assert_eq!(Cc1101Band::Band868.frequency_mhz(), 868);
        assert_eq!(Cc1101Band::Band915.frequency_mhz(), 915);
    }

    #[test]
    fn test_band_registers() {
        let (f2, f1, f0) = Cc1101Band::Band433.freq_registers();
        assert_eq!(f2, 0x10);
        assert_eq!(f1, 0xB1);
        assert_eq!(f0, 0x3B);
    }

    #[test]
    fn test_data_rate_bps() {
        assert_eq!(Cc1101DataRate::Rate1k2.bps(), 1200);
        assert_eq!(Cc1101DataRate::Rate38k4.bps(), 38400);
        assert_eq!(Cc1101DataRate::Rate250k.bps(), 250_000);
    }

    #[test]
    fn test_power_dbm() {
        assert_eq!(Cc1101Power::Minus30dBm.dbm(), -30);
        assert_eq!(Cc1101Power::Zero.dbm(), 0);
        assert_eq!(Cc1101Power::Plus10dBm.dbm(), 10);
    }

    #[test]
    fn test_modulation_register() {
        assert_eq!(Cc1101Modulation::Fsk2.register(), 0x00);
        assert_eq!(Cc1101Modulation::Gfsk.register(), 0x10);
        assert_eq!(Cc1101Modulation::Ask.register(), 0x30);
    }

    #[test]
    fn test_sync_mode_register() {
        assert_eq!(Cc1101SyncMode::None.register(), 0x00);
        assert_eq!(Cc1101SyncMode::Bits16of16.register(), 0x02);
    }

    #[test]
    fn test_config_presets() {
        let lr = Cc1101Config::long_range();
        assert_eq!(lr.data_rate, Cc1101DataRate::Rate1k2);

        let hs = Cc1101Config::high_speed();
        assert_eq!(hs.data_rate, Cc1101DataRate::Rate250k);

        let eu = Cc1101Config::europe_868();
        assert_eq!(eu.band, Cc1101Band::Band868);

        let us = Cc1101Config::americas_915();
        assert_eq!(us.band, Cc1101Band::Band915);
    }

    #[test]
    fn test_default_config() {
        let config = Cc1101Config::default();
        assert_eq!(config.band, Cc1101Band::Band433);
        assert_eq!(config.data_rate, Cc1101DataRate::Rate38k4);
        assert_eq!(config.power, Cc1101Power::Plus10dBm);
        assert_eq!(config.modulation, Cc1101Modulation::Fsk2);
        assert_eq!(config.sync_mode, Cc1101SyncMode::Bits16of16);
    }
}
