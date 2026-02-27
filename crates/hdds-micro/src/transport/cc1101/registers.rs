// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! CC1101 register definitions
#![allow(dead_code)]

/// CC1101 configuration registers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[allow(non_camel_case_types)]
pub enum Register {
    /// GDO2 output pin configuration
    IOCFG2 = 0x00,
    /// GDO1 output pin configuration
    IOCFG1 = 0x01,
    /// GDO0 output pin configuration
    IOCFG0 = 0x02,
    /// RX FIFO and TX FIFO thresholds
    FIFOTHR = 0x03,
    /// Sync word, high byte
    SYNC1 = 0x04,
    /// Sync word, low byte
    SYNC0 = 0x05,
    /// Packet length
    PKTLEN = 0x06,
    /// Packet automation control
    PKTCTRL1 = 0x07,
    /// Packet automation control
    PKTCTRL0 = 0x08,
    /// Device address
    ADDR = 0x09,
    /// Channel number
    CHANNR = 0x0A,
    /// Frequency synthesizer control
    FSCTRL1 = 0x0B,
    /// Frequency synthesizer control
    FSCTRL0 = 0x0C,
    /// Frequency control word, high byte
    FREQ2 = 0x0D,
    /// Frequency control word, middle byte
    FREQ1 = 0x0E,
    /// Frequency control word, low byte
    FREQ0 = 0x0F,
    /// Modem configuration
    MDMCFG4 = 0x10,
    /// Modem configuration
    MDMCFG3 = 0x11,
    /// Modem configuration
    MDMCFG2 = 0x12,
    /// Modem configuration
    MDMCFG1 = 0x13,
    /// Modem configuration
    MDMCFG0 = 0x14,
    /// Modem deviation setting
    DEVIATN = 0x15,
    /// Main radio control state machine configuration
    MCSM2 = 0x16,
    /// Main radio control state machine configuration
    MCSM1 = 0x17,
    /// Main radio control state machine configuration
    MCSM0 = 0x18,
    /// Frequency offset compensation configuration
    FOCCFG = 0x19,
    /// Bit synchronization configuration
    BSCFG = 0x1A,
    /// AGC control
    AGCCTRL2 = 0x1B,
    /// AGC control
    AGCCTRL1 = 0x1C,
    /// AGC control
    AGCCTRL0 = 0x1D,
    /// Wake on radio control
    WOREVT1 = 0x1E,
    /// Wake on radio control
    WOREVT0 = 0x1F,
    /// Wake on radio control
    WORCTRL = 0x20,
    /// Front end RX configuration
    FREND1 = 0x21,
    /// Front end TX configuration
    FREND0 = 0x22,
    /// Frequency synthesizer calibration
    FSCAL3 = 0x23,
    /// Frequency synthesizer calibration
    FSCAL2 = 0x24,
    /// Frequency synthesizer calibration
    FSCAL1 = 0x25,
    /// Frequency synthesizer calibration
    FSCAL0 = 0x26,
    /// RC oscillator configuration
    RCCTRL1 = 0x27,
    /// RC oscillator configuration
    RCCTRL0 = 0x28,
    /// Frequency synthesizer calibration control
    FSTEST = 0x29,
    /// Production test
    PTEST = 0x2A,
    /// AGC test
    AGCTEST = 0x2B,
    /// Various test settings
    TEST2 = 0x2C,
    /// Various test settings
    TEST1 = 0x2D,
    /// Various test settings
    TEST0 = 0x2E,

    // Status registers (read-only, burst access)
    /// Part number
    PARTNUM = 0x30,
    /// Version number
    VERSION = 0x31,
    /// Frequency offset estimate
    FREQEST = 0x32,
    /// Link quality indicator
    LQI = 0x33,
    /// RSSI value
    RSSI = 0x34,
    /// Control state machine state
    MARCSTATE = 0x35,
    /// High byte of WOR timer
    WORTIME1 = 0x36,
    /// Low byte of WOR timer
    WORTIME0 = 0x37,
    /// Current packet status
    PKTSTATUS = 0x38,
    /// Current VCO VC_DAC value
    VCO_VC_DAC = 0x39,
    /// TX FIFO underflow and number of bytes
    TXBYTES = 0x3A,
    /// RX FIFO overflow and number of bytes
    RXBYTES = 0x3B,
    /// Last RC oscillator calibration result
    RCCTRL1_STATUS = 0x3C,
    /// Last RC oscillator calibration result
    RCCTRL0_STATUS = 0x3D,

    // FIFO access
    /// TX/RX FIFO (write for TX, read for RX)
    FIFO = 0x3F,

    // PA table
    /// Power amplifier table
    PATABLE = 0x3E,
}

/// Command strobes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[allow(non_camel_case_types, clippy::upper_case_acronyms)]
pub enum Strobe {
    /// Reset chip
    SRES = 0x30,
    /// Enable and calibrate frequency synthesizer
    SFSTXON = 0x31,
    /// Turn off crystal oscillator
    SXOFF = 0x32,
    /// Calibrate frequency synthesizer and turn it off
    SCAL = 0x33,
    /// Enable RX
    SRX = 0x34,
    /// Enable TX
    STX = 0x35,
    /// Exit RX/TX, turn off frequency synthesizer
    SIDLE = 0x36,
    /// Start automatic RX polling sequence (Wake-on-Radio)
    SWOR = 0x38,
    /// Enter power down mode when CSn goes high
    SPWD = 0x39,
    /// Flush the RX FIFO buffer
    SFRX = 0x3A,
    /// Flush the TX FIFO buffer
    SFTX = 0x3B,
    /// Reset real time clock to Event1 value
    SWORRST = 0x3C,
    /// No operation (returns status byte)
    SNOP = 0x3D,
}

/// MARCSTATE values (Main Radio Control State)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[allow(non_camel_case_types, clippy::upper_case_acronyms)]
pub enum MarcState {
    /// Sleep
    SLEEP = 0x00,
    /// Idle
    IDLE = 0x01,
    /// XOFF
    XOFF = 0x02,
    /// MANCAL
    MANCAL = 0x03,
    /// FS_WAKEUP
    FS_WAKEUP = 0x06,
    /// FS_CALIBRATE
    FS_CALIBRATE = 0x08,
    /// SETTLING
    SETTLING = 0x09,
    /// RX
    RX = 0x0D,
    /// RX_END
    RX_END = 0x0E,
    /// RXFIFO_OVERFLOW
    RXFIFO_OVERFLOW = 0x11,
    /// FSTXON
    FSTXON = 0x12,
    /// TX
    TX = 0x13,
    /// TX_END
    TX_END = 0x14,
    /// TXFIFO_UNDERFLOW
    TXFIFO_UNDERFLOW = 0x16,
}

/// GDO pin modes (for IOCFG0/1/2)
pub mod gdo_cfg {
    /// RX FIFO threshold or end of packet
    pub const RX_FIFO_THRESHOLD: u8 = 0x00;
    /// RX FIFO threshold or EOP
    pub const RX_FIFO_EOP: u8 = 0x01;
    /// TX FIFO threshold
    pub const TX_FIFO_THRESHOLD: u8 = 0x02;
    /// TX FIFO full
    pub const TX_FIFO_FULL: u8 = 0x03;
    /// RX FIFO overflow
    pub const RX_OVERFLOW: u8 = 0x04;
    /// TX FIFO underflow
    pub const TX_UNDERFLOW: u8 = 0x05;
    /// Sync word sent/received
    pub const SYNC_WORD: u8 = 0x06;
    /// Packet received with CRC OK
    pub const PKT_CRC_OK: u8 = 0x07;
    /// Preamble quality reached
    pub const PQT_REACHED: u8 = 0x08;
    /// Clear channel assessment
    pub const CCA: u8 = 0x09;
    /// Lock detector output
    pub const PLL_LOCK: u8 = 0x0A;
    /// Serial clock
    pub const SERIAL_CLOCK: u8 = 0x0B;
    /// Synchronous serial data output
    pub const SERIAL_DATA_SYNC: u8 = 0x0C;
    /// Asynchronous serial data output
    pub const SERIAL_DATA_ASYNC: u8 = 0x0D;
    /// Carrier sense
    pub const CARRIER_SENSE: u8 = 0x0E;
    /// RSSI valid
    pub const RSSI_VALID: u8 = 0x0F;
    /// High impedance (3-state)
    pub const HI_Z: u8 = 0x2E;
    /// CLK_XOSC/1
    pub const CLK_XOSC_1: u8 = 0x30;
    /// CLK_XOSC/1.5
    pub const CLK_XOSC_1_5: u8 = 0x31;
    /// CLK_XOSC/2
    pub const CLK_XOSC_2: u8 = 0x32;
    /// CLK_XOSC/3
    pub const CLK_XOSC_3: u8 = 0x33;
    /// CLK_XOSC/4
    pub const CLK_XOSC_4: u8 = 0x34;
    /// CLK_XOSC/6
    pub const CLK_XOSC_6: u8 = 0x35;
    /// CLK_XOSC/8
    pub const CLK_XOSC_8: u8 = 0x36;
    /// CLK_XOSC/12
    pub const CLK_XOSC_12: u8 = 0x37;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_values() {
        assert_eq!(Register::IOCFG2 as u8, 0x00);
        assert_eq!(Register::FREQ2 as u8, 0x0D);
        assert_eq!(Register::PKTLEN as u8, 0x06);
        assert_eq!(Register::RXBYTES as u8, 0x3B);
    }

    #[test]
    fn test_strobe_values() {
        assert_eq!(Strobe::SRES as u8, 0x30);
        assert_eq!(Strobe::SRX as u8, 0x34);
        assert_eq!(Strobe::STX as u8, 0x35);
        assert_eq!(Strobe::SIDLE as u8, 0x36);
        assert_eq!(Strobe::SNOP as u8, 0x3D);
    }

    #[test]
    fn test_marc_state_values() {
        assert_eq!(MarcState::IDLE as u8, 0x01);
        assert_eq!(MarcState::RX as u8, 0x0D);
        assert_eq!(MarcState::TX as u8, 0x13);
    }
}
