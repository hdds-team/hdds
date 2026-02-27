// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Binary protocol definitions for Admin API.
//!
//! Defines command and status codes for the TCP protocol.

/// Binary protocol commands handled by the admin API server.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(clippy::enum_variant_names)]
pub enum Command {
    GetMesh = 0x01,
    GetTopics = 0x02,
    GetMetrics = 0x03,
    GetHealth = 0x04,
    GetWriters = 0x05,
    GetReaders = 0x06,
}

impl Command {
    pub(crate) fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x01 => Some(Command::GetMesh),
            0x02 => Some(Command::GetTopics),
            0x03 => Some(Command::GetMetrics),
            0x04 => Some(Command::GetHealth),
            0x05 => Some(Command::GetWriters),
            0x06 => Some(Command::GetReaders),
            _ => None,
        }
    }
}

/// Response status codes returned to clients.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Status {
    Ok = 0x00,
    InvalidCommand = 0x01,
    InternalError = 0x02,
}

impl Status {
    pub(crate) const fn to_byte(self) -> u8 {
        match self {
            Status::Ok => 0x00,
            Status::InvalidCommand => 0x01,
            Status::InternalError => 0x02,
        }
    }
}
