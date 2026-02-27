// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! LoRa configuration

/// Spreading Factor (SF7-SF12)
///
/// Higher SF = longer range but slower data rate
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[derive(Default)]
pub enum SpreadingFactor {
    /// SF7: Fastest, shortest range (~11 kbps @ 250kHz BW)
    Sf7 = 7,
    /// SF8: (~6.25 kbps @ 250kHz BW)
    Sf8 = 8,
    /// SF9: (~3.5 kbps @ 125kHz BW)
    #[default]
    Sf9 = 9,
    /// SF10: (~2 kbps @ 125kHz BW)
    Sf10 = 10,
    /// SF11: (~1 kbps @ 125kHz BW)
    Sf11 = 11,
    /// SF12: Slowest, longest range (~300 bps @ 125kHz BW)
    Sf12 = 12,
}

impl SpreadingFactor {
    /// Get register value
    pub const fn value(self) -> u8 {
        self as u8
    }

    /// Approximate data rate in bits per second (at 125kHz BW, CR 4/5)
    pub const fn approx_bitrate(self) -> u32 {
        match self {
            Self::Sf7 => 5470,
            Self::Sf8 => 3125,
            Self::Sf9 => 1760,
            Self::Sf10 => 980,
            Self::Sf11 => 440,
            Self::Sf12 => 250,
        }
    }
}

/// Bandwidth
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[derive(Default)]
pub enum Bandwidth {
    /// 7.8 kHz
    Bw7_8 = 0,
    /// 10.4 kHz
    Bw10_4 = 1,
    /// 15.6 kHz
    Bw15_6 = 2,
    /// 20.8 kHz
    Bw20_8 = 3,
    /// 31.25 kHz
    Bw31_25 = 4,
    /// 41.7 kHz
    Bw41_7 = 5,
    /// 62.5 kHz
    Bw62_5 = 6,
    /// 125 kHz (most common)
    #[default]
    Bw125 = 7,
    /// 250 kHz
    Bw250 = 8,
    /// 500 kHz
    Bw500 = 9,
}

impl Bandwidth {
    /// Get register value
    pub const fn value(self) -> u8 {
        self as u8
    }

    /// Get bandwidth in Hz
    pub const fn hz(self) -> u32 {
        match self {
            Self::Bw7_8 => 7_800,
            Self::Bw10_4 => 10_400,
            Self::Bw15_6 => 15_600,
            Self::Bw20_8 => 20_800,
            Self::Bw31_25 => 31_250,
            Self::Bw41_7 => 41_700,
            Self::Bw62_5 => 62_500,
            Self::Bw125 => 125_000,
            Self::Bw250 => 250_000,
            Self::Bw500 => 500_000,
        }
    }
}

/// Coding Rate (error correction)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[derive(Default)]
pub enum CodingRate {
    /// 4/5 - least overhead
    #[default]
    Cr4_5 = 1,
    /// 4/6
    Cr4_6 = 2,
    /// 4/7
    Cr4_7 = 3,
    /// 4/8 - most error correction
    Cr4_8 = 4,
}

impl CodingRate {
    /// Get register value
    pub const fn value(self) -> u8 {
        self as u8
    }
}

/// LoRa configuration
#[derive(Debug, Clone)]
pub struct LoRaConfig {
    /// Center frequency in MHz (e.g., 868.0 for EU, 915.0 for US)
    pub frequency_mhz: f32,

    /// Spreading factor
    pub spreading_factor: SpreadingFactor,

    /// Bandwidth
    pub bandwidth: Bandwidth,

    /// Coding rate
    pub coding_rate: CodingRate,

    /// TX power in dBm (2-20, hardware dependent)
    pub tx_power_dbm: i8,

    /// RX timeout in milliseconds
    pub rx_timeout_ms: u32,

    /// Preamble length (symbols)
    pub preamble_length: u16,

    /// Enable CRC
    pub crc_enabled: bool,
}

impl LoRaConfig {
    /// Create configuration from profile
    pub fn from_profile(profile: LoRaProfile, frequency_mhz: f32) -> Self {
        match profile {
            LoRaProfile::Fast => Self {
                frequency_mhz,
                spreading_factor: SpreadingFactor::Sf7,
                bandwidth: Bandwidth::Bw250,
                coding_rate: CodingRate::Cr4_5,
                tx_power_dbm: 14,
                rx_timeout_ms: 1000,
                preamble_length: 8,
                crc_enabled: true,
            },
            LoRaProfile::Balanced => Self {
                frequency_mhz,
                spreading_factor: SpreadingFactor::Sf9,
                bandwidth: Bandwidth::Bw125,
                coding_rate: CodingRate::Cr4_5,
                tx_power_dbm: 14,
                rx_timeout_ms: 3000,
                preamble_length: 8,
                crc_enabled: true,
            },
            LoRaProfile::LongRange => Self {
                frequency_mhz,
                spreading_factor: SpreadingFactor::Sf12,
                bandwidth: Bandwidth::Bw125,
                coding_rate: CodingRate::Cr4_8,
                tx_power_dbm: 20,
                rx_timeout_ms: 10000,
                preamble_length: 12,
                crc_enabled: true,
            },
        }
    }

    /// EU 868 MHz band (863-870 MHz)
    pub fn eu868(profile: LoRaProfile) -> Self {
        Self::from_profile(profile, 868.0)
    }

    /// US 915 MHz band (902-928 MHz)
    pub fn us915(profile: LoRaProfile) -> Self {
        Self::from_profile(profile, 915.0)
    }

    /// Calculate time on air for a packet (in milliseconds)
    ///
    /// Based on Semtech LoRa modem designer's guide formulas.
    pub fn time_on_air_ms(&self, payload_bytes: usize) -> u32 {
        let sf = self.spreading_factor.value() as u32;
        let bw = self.bandwidth.hz();
        let cr = self.coding_rate.value() as u32;
        let preamble = self.preamble_length as u32;
        let payload = payload_bytes as u32;

        // Symbol duration in microseconds = 2^SF * 1_000_000 / BW
        // Example: SF9, 125kHz -> 512 * 1_000_000 / 125_000 = 4096 us
        let t_sym_us = ((1u64 << sf) * 1_000_000) / (bw as u64);

        // Preamble duration in microseconds
        // n_preamble = preamble_length + 4.25 symbols (using 4 for integer math)
        let t_preamble_us = (preamble + 4) * t_sym_us as u32;

        // Payload symbols calculation (from LoRa modem spec)
        // DE = 1 if LowDataRateOptimize is enabled (SF >= 11)
        let de = if sf >= 11 { 1u32 } else { 0 };

        // Header is enabled (H = 0 means header enabled, adding 20 bits)
        // CRC is enabled (adds 16 bits)
        let header_bits = 20u32; // header overhead

        // Simplified payload symbol calculation
        // n_payload = 8 + max(ceil((8*PL - 4*SF + 28 + 16) / (4*(SF - 2*DE))) * (CR + 4), 0)
        let numerator = (8 * payload + header_bits + 16).saturating_sub(4 * sf);
        let denominator = 4 * (sf.saturating_sub(2 * de));

        let n_payload = if denominator > 0 && numerator > 0 {
            let ceil_div = numerator.div_ceil(denominator);
            8 + ceil_div * (cr + 4)
        } else {
            8
        };

        let t_payload_us = n_payload as u64 * t_sym_us;

        // Total time in milliseconds
        ((t_preamble_us as u64 + t_payload_us) / 1000) as u32
    }
}

impl Default for LoRaConfig {
    fn default() -> Self {
        Self::eu868(LoRaProfile::Balanced)
    }
}

/// Pre-defined LoRa profiles
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoRaProfile {
    /// Fast: SF7, 250kHz - ~11 kbps, short range
    Fast,
    /// Balanced: SF9, 125kHz - ~3 kbps, medium range
    Balanced,
    /// Long Range: SF12, 125kHz - ~300 bps, maximum range
    LongRange,
}

impl LoRaProfile {
    /// Get approximate data rate in bps
    pub const fn approx_bitrate(self) -> u32 {
        match self {
            Self::Fast => 11000,
            Self::Balanced => 3000,
            Self::LongRange => 300,
        }
    }

    /// Get approximate range in meters (outdoor, line of sight)
    pub const fn approx_range_m(self) -> u32 {
        match self {
            Self::Fast => 2000,
            Self::Balanced => 5000,
            Self::LongRange => 15000,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spreading_factor_values() {
        assert_eq!(SpreadingFactor::Sf7.value(), 7);
        assert_eq!(SpreadingFactor::Sf12.value(), 12);
    }

    #[test]
    fn test_bandwidth_hz() {
        assert_eq!(Bandwidth::Bw125.hz(), 125_000);
        assert_eq!(Bandwidth::Bw250.hz(), 250_000);
    }

    #[test]
    fn test_profile_configs() {
        let fast = LoRaConfig::from_profile(LoRaProfile::Fast, 868.0);
        assert_eq!(fast.spreading_factor, SpreadingFactor::Sf7);
        assert_eq!(fast.bandwidth, Bandwidth::Bw250);

        let long = LoRaConfig::from_profile(LoRaProfile::LongRange, 915.0);
        assert_eq!(long.spreading_factor, SpreadingFactor::Sf12);
        assert_eq!(long.tx_power_dbm, 20);
    }

    #[test]
    fn test_time_on_air() {
        let config = LoRaConfig::eu868(LoRaProfile::Balanced);
        let toa = config.time_on_air_ms(50);

        // SF9, 125kHz, 50 bytes: expected ~200-400ms range
        // Symbol time = 512 * 1_000_000 / 125_000 = 4096 us
        // Preamble (8+4) * 4096 = 49152 us = 49 ms
        // Payload symbols ~= 8 + ceil((400+36-36)/28)*5 = 8 + 72 = 80 symbols
        // Payload time = 80 * 4096 = 327680 us = 327 ms
        // Total ~= 376 ms
        assert!(
            toa > 100 && toa < 600,
            "ToA was {} ms, expected 100-600",
            toa
        );
    }
}
