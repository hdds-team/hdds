// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! NRF24L01 register definitions
#![allow(dead_code)]

/// NRF24L01 registers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[allow(non_camel_case_types)]
pub enum Register {
    /// Configuration register
    CONFIG = 0x00,
    /// Enable auto-acknowledgment
    EN_AA = 0x01,
    /// Enable RX addresses
    EN_RXADDR = 0x02,
    /// Setup address width
    SETUP_AW = 0x03,
    /// Setup automatic retransmission
    SETUP_RETR = 0x04,
    /// RF channel
    RF_CH = 0x05,
    /// RF setup register
    RF_SETUP = 0x06,
    /// Status register
    STATUS = 0x07,
    /// Transmit observe register
    OBSERVE_TX = 0x08,
    /// Received power detector
    RPD = 0x09,
    /// RX address pipe 0
    RX_ADDR_P0 = 0x0A,
    /// RX address pipe 1
    RX_ADDR_P1 = 0x0B,
    /// RX address pipe 2
    RX_ADDR_P2 = 0x0C,
    /// RX address pipe 3
    RX_ADDR_P3 = 0x0D,
    /// RX address pipe 4
    RX_ADDR_P4 = 0x0E,
    /// RX address pipe 5
    RX_ADDR_P5 = 0x0F,
    /// TX address
    TX_ADDR = 0x10,
    /// RX payload width pipe 0
    RX_PW_P0 = 0x11,
    /// RX payload width pipe 1
    RX_PW_P1 = 0x12,
    /// RX payload width pipe 2
    RX_PW_P2 = 0x13,
    /// RX payload width pipe 3
    RX_PW_P3 = 0x14,
    /// RX payload width pipe 4
    RX_PW_P4 = 0x15,
    /// RX payload width pipe 5
    RX_PW_P5 = 0x16,
    /// FIFO status
    FIFO_STATUS = 0x17,
    /// Dynamic payload length
    DYNPD = 0x1C,
    /// Feature register
    FEATURE = 0x1D,
}

/// CONFIG register bits
pub mod config {
    /// RX/TX control (1 = PRX, 0 = PTX)
    pub const PRIM_RX: u8 = 0x01;
    /// Power up
    pub const PWR_UP: u8 = 0x02;
    /// CRC encoding scheme (0 = 1 byte, 1 = 2 bytes)
    pub const CRCO: u8 = 0x04;
    /// Enable CRC
    pub const EN_CRC: u8 = 0x08;
    /// Mask interrupt: MAX_RT
    pub const MASK_MAX_RT: u8 = 0x10;
    /// Mask interrupt: TX_DS
    pub const MASK_TX_DS: u8 = 0x20;
    /// Mask interrupt: RX_DR
    pub const MASK_RX_DR: u8 = 0x40;
}

/// STATUS register bits
pub mod status {
    /// TX FIFO full flag
    pub const TX_FULL: u8 = 0x01;
    /// RX FIFO pipe number (bits 1-3)
    pub const RX_P_NO_MASK: u8 = 0x0E;
    /// Max retransmits interrupt
    pub const MAX_RT: u8 = 0x10;
    /// Data sent interrupt
    pub const TX_DS: u8 = 0x20;
    /// Data received interrupt
    pub const RX_DR: u8 = 0x40;
}

/// FIFO_STATUS register bits
pub mod fifo_status {
    /// RX FIFO empty
    pub const RX_EMPTY: u8 = 0x01;
    /// RX FIFO full
    pub const RX_FULL: u8 = 0x02;
    /// TX FIFO empty
    pub const TX_EMPTY: u8 = 0x10;
    /// TX FIFO full
    pub const TX_FULL: u8 = 0x20;
    /// TX FIFO reuse
    pub const TX_REUSE: u8 = 0x40;
}

/// SPI commands
pub mod commands {
    /// Read register
    pub const R_REGISTER: u8 = 0x00;
    /// Write register
    pub const W_REGISTER: u8 = 0x20;
    /// Read RX payload
    pub const R_RX_PAYLOAD: u8 = 0x61;
    /// Write TX payload
    pub const W_TX_PAYLOAD: u8 = 0xA0;
    /// Flush TX FIFO
    pub const FLUSH_TX: u8 = 0xE1;
    /// Flush RX FIFO
    pub const FLUSH_RX: u8 = 0xE2;
    /// Reuse TX payload
    pub const REUSE_TX_PL: u8 = 0xE3;
    /// Read RX payload width
    pub const R_RX_PL_WID: u8 = 0x60;
    /// Write ACK payload
    pub const W_ACK_PAYLOAD: u8 = 0xA8;
    /// Write TX payload (no ACK)
    pub const W_TX_PAYLOAD_NOACK: u8 = 0xB0;
    /// NOP (read STATUS)
    pub const NOP: u8 = 0xFF;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_values() {
        assert_eq!(Register::CONFIG as u8, 0x00);
        assert_eq!(Register::STATUS as u8, 0x07);
        assert_eq!(Register::RF_CH as u8, 0x05);
        assert_eq!(Register::TX_ADDR as u8, 0x10);
    }

    #[test]
    fn test_status_bits() {
        assert_eq!(status::RX_DR, 0x40);
        assert_eq!(status::TX_DS, 0x20);
        assert_eq!(status::MAX_RT, 0x10);
    }

    #[test]
    fn test_config_bits() {
        assert_eq!(config::PWR_UP, 0x02);
        assert_eq!(config::PRIM_RX, 0x01);
        assert_eq!(config::EN_CRC, 0x08);
    }
}
