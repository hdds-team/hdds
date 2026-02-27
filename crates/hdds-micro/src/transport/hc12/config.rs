// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! HC-12 configuration and AT commands

/// HC-12 transmission mode
///
/// Different modes trade off between speed and range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Hc12Mode {
    /// FU1: Moderate power saving, 5 kbps, moderate range
    Fu1,
    /// FU2: Power saving mode, lower speed
    Fu2,
    /// FU3: Default mode, balanced (recommended)
    #[default]
    Fu3,
    /// FU4: Long range mode, 1.2 kbps, maximum range
    Fu4,
}

impl Hc12Mode {
    /// Get AT command for this mode
    pub fn at_command(self) -> [u8; 8] {
        match self {
            Self::Fu1 => *b"AT+FU1\r\n",
            Self::Fu2 => *b"AT+FU2\r\n",
            Self::Fu3 => *b"AT+FU3\r\n",
            Self::Fu4 => *b"AT+FU4\r\n",
        }
    }

    /// Approximate data rate in bits per second
    pub const fn approx_bitrate(self) -> u32 {
        match self {
            Self::Fu1 => 5000,
            Self::Fu2 => 2400,
            Self::Fu3 => 5000,
            Self::Fu4 => 1200,
        }
    }

    /// Approximate range in meters (line of sight)
    pub const fn approx_range_m(self) -> u32 {
        match self {
            Self::Fu1 => 600,
            Self::Fu2 => 800,
            Self::Fu3 => 600,
            Self::Fu4 => 1000,
        }
    }
}

/// HC-12 channel (001-127)
///
/// Each channel is 400kHz apart.
/// Channel 001 = 433.4 MHz, Channel 127 = 473.0 MHz
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hc12Channel(u8);

impl Hc12Channel {
    /// Create a new channel (1-127)
    pub const fn new(channel: u8) -> Option<Self> {
        if channel >= 1 && channel <= 127 {
            Some(Self(channel))
        } else {
            None
        }
    }

    /// Get channel number
    pub const fn value(self) -> u8 {
        self.0
    }

    /// Get frequency in MHz for this channel
    pub fn frequency_mhz(self) -> f32 {
        433.4 + (self.0 as f32 - 1.0) * 0.4
    }

    /// Get AT command for this channel
    pub fn at_command(self) -> [u8; 10] {
        let mut cmd = *b"AT+C000\r\n\0";
        cmd[4] = b'0' + (self.0 / 100);
        cmd[5] = b'0' + ((self.0 / 10) % 10);
        cmd[6] = b'0' + (self.0 % 10);
        // Remove null terminator, return 9 bytes
        let mut result = [0u8; 10];
        result[..9].copy_from_slice(&cmd[..9]);
        result
    }
}

impl Default for Hc12Channel {
    fn default() -> Self {
        Self(1) // Channel 001 = 433.4 MHz
    }
}

/// HC-12 TX power level (1-8)
///
/// Higher power = longer range but more current draw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hc12Power(u8);

impl Hc12Power {
    /// Create a new power level (1-8)
    pub const fn new(level: u8) -> Option<Self> {
        if level >= 1 && level <= 8 {
            Some(Self(level))
        } else {
            None
        }
    }

    /// Get power level
    pub const fn value(self) -> u8 {
        self.0
    }

    /// Get approximate TX power in dBm
    pub const fn approx_dbm(self) -> i8 {
        match self.0 {
            1 => -1,
            2 => 2,
            3 => 5,
            4 => 8,
            5 => 11,
            6 => 14,
            7 => 17,
            8 => 20, // 100mW
            _ => 0,
        }
    }

    /// Get approximate current draw in mA (TX mode)
    pub const fn approx_current_ma(self) -> u16 {
        match self.0 {
            1 => 15,
            2 => 18,
            3 => 23,
            4 => 30,
            5 => 40,
            6 => 55,
            7 => 75,
            8 => 100,
            _ => 0,
        }
    }

    /// Get AT command for this power level
    pub fn at_command(self) -> [u8; 7] {
        let mut cmd = *b"AT+P0\r\n";
        cmd[4] = b'0' + self.0;
        cmd
    }

    /// Maximum power (100mW, 20 dBm)
    pub const fn max() -> Self {
        Self(8)
    }

    /// Minimum power (-1 dBm)
    pub const fn min() -> Self {
        Self(1)
    }
}

impl Default for Hc12Power {
    fn default() -> Self {
        Self(8) // Max power by default
    }
}

/// HC-12 baud rate
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Hc12BaudRate {
    /// 1200 bps
    B1200,
    /// 2400 bps
    B2400,
    /// 4800 bps
    B4800,
    /// 9600 bps (default)
    #[default]
    B9600,
    /// 19200 bps
    B19200,
    /// 38400 bps
    B38400,
    /// 57600 bps
    B57600,
    /// 115200 bps
    B115200,
}

impl Hc12BaudRate {
    /// Get AT command for this baud rate
    pub fn at_command(self) -> [u8; 12] {
        match self {
            Self::B1200 => *b"AT+B1200\r\n\0\0",
            Self::B2400 => *b"AT+B2400\r\n\0\0",
            Self::B4800 => *b"AT+B4800\r\n\0\0",
            Self::B9600 => *b"AT+B9600\r\n\0\0",
            Self::B19200 => *b"AT+B19200\r\n\0",
            Self::B38400 => *b"AT+B38400\r\n\0",
            Self::B57600 => *b"AT+B57600\r\n\0",
            Self::B115200 => *b"AT+B115200\r\n",
        }
    }

    /// Get baud rate value
    pub const fn value(self) -> u32 {
        match self {
            Self::B1200 => 1200,
            Self::B2400 => 2400,
            Self::B4800 => 4800,
            Self::B9600 => 9600,
            Self::B19200 => 19200,
            Self::B38400 => 38400,
            Self::B57600 => 57600,
            Self::B115200 => 115_200,
        }
    }
}

/// Complete HC-12 configuration
#[derive(Debug, Clone)]
pub struct Hc12Config {
    /// Channel (1-127)
    pub channel: Hc12Channel,

    /// Transmission mode
    pub mode: Hc12Mode,

    /// TX power level
    pub power: Hc12Power,

    /// UART baud rate
    pub baud_rate: Hc12BaudRate,

    /// RX timeout in milliseconds
    pub rx_timeout_ms: u32,
}

impl Hc12Config {
    /// Create default configuration
    pub const fn new() -> Self {
        Self {
            channel: Hc12Channel(1),
            mode: Hc12Mode::Fu3,
            power: Hc12Power(8),
            baud_rate: Hc12BaudRate::B9600,
            rx_timeout_ms: 1000,
        }
    }

    /// Fast mode configuration
    ///
    /// Higher speed, shorter range, suitable for close-range communication.
    pub const fn fast() -> Self {
        Self {
            channel: Hc12Channel(1),
            mode: Hc12Mode::Fu3,
            power: Hc12Power(4),
            baud_rate: Hc12BaudRate::B9600,
            rx_timeout_ms: 500,
        }
    }

    /// Long range configuration
    ///
    /// Maximum range, lower speed.
    pub const fn long_range() -> Self {
        Self {
            channel: Hc12Channel(1),
            mode: Hc12Mode::Fu4,
            power: Hc12Power(8),
            baud_rate: Hc12BaudRate::B9600,
            rx_timeout_ms: 2000,
        }
    }

    /// Low power configuration
    ///
    /// Reduced power consumption, shorter range.
    pub const fn low_power() -> Self {
        Self {
            channel: Hc12Channel(1),
            mode: Hc12Mode::Fu2,
            power: Hc12Power(2),
            baud_rate: Hc12BaudRate::B9600,
            rx_timeout_ms: 1000,
        }
    }

    /// Get approximate data rate in bps
    pub const fn approx_bitrate(&self) -> u32 {
        self.mode.approx_bitrate()
    }

    /// Get approximate range in meters
    pub const fn approx_range_m(&self) -> u32 {
        self.mode.approx_range_m()
    }
}

impl Default for Hc12Config {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_valid() {
        assert!(Hc12Channel::new(1).is_some());
        assert!(Hc12Channel::new(127).is_some());
        assert!(Hc12Channel::new(64).is_some());
    }

    #[test]
    fn test_channel_invalid() {
        assert!(Hc12Channel::new(0).is_none());
        assert!(Hc12Channel::new(128).is_none());
        assert!(Hc12Channel::new(255).is_none());
    }

    #[test]
    fn test_channel_frequency() {
        let ch1 = Hc12Channel::new(1).unwrap();
        assert!((ch1.frequency_mhz() - 433.4).abs() < 0.01);

        let ch127 = Hc12Channel::new(127).unwrap();
        assert!((ch127.frequency_mhz() - 483.8).abs() < 0.1);
    }

    #[test]
    fn test_power_levels() {
        let p1 = Hc12Power::new(1).unwrap();
        assert_eq!(p1.approx_dbm(), -1);

        let p8 = Hc12Power::new(8).unwrap();
        assert_eq!(p8.approx_dbm(), 20);
    }

    #[test]
    fn test_power_invalid() {
        assert!(Hc12Power::new(0).is_none());
        assert!(Hc12Power::new(9).is_none());
    }

    #[test]
    fn test_mode_bitrate() {
        assert_eq!(Hc12Mode::Fu3.approx_bitrate(), 5000);
        assert_eq!(Hc12Mode::Fu4.approx_bitrate(), 1200);
    }

    #[test]
    fn test_config_profiles() {
        let fast = Hc12Config::fast();
        assert_eq!(fast.mode, Hc12Mode::Fu3);

        let long = Hc12Config::long_range();
        assert_eq!(long.mode, Hc12Mode::Fu4);
        assert_eq!(long.power, Hc12Power(8));

        let low = Hc12Config::low_power();
        assert_eq!(low.mode, Hc12Mode::Fu2);
        assert_eq!(low.power, Hc12Power(2));
    }

    #[test]
    fn test_channel_at_command() {
        let ch1 = Hc12Channel::new(1).unwrap();
        let cmd = ch1.at_command();
        assert_eq!(&cmd[..7], b"AT+C001");

        let ch127 = Hc12Channel::new(127).unwrap();
        let cmd = ch127.at_command();
        assert_eq!(&cmd[..7], b"AT+C127");
    }

    #[test]
    fn test_power_at_command() {
        let p5 = Hc12Power::new(5).unwrap();
        let cmd = p5.at_command();
        assert_eq!(&cmd[..5], b"AT+P5");
    }

    #[test]
    fn test_mode_at_command() {
        let cmd = Hc12Mode::Fu3.at_command();
        assert_eq!(&cmd[..6], b"AT+FU3");
    }

    #[test]
    fn test_baud_rate_at_command() {
        let cmd = Hc12BaudRate::B9600.at_command();
        assert_eq!(&cmd[..8], b"AT+B9600");
    }
}
