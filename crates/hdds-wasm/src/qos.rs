// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

// HDDS WASM SDK - QoS subset for WASM

/// Reliability QoS policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[derive(Default)]
pub enum WasmReliability {
    /// Best-effort delivery: no retransmissions.
    #[default]
    BestEffort,
    /// Reliable delivery: retransmit on loss.
    Reliable,
}


/// Durability QoS policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[derive(Default)]
pub enum WasmDurability {
    /// Volatile: no persistence, only live data.
    #[default]
    Volatile,
    /// Transient-local: keep last N samples for late joiners.
    TransientLocal,
}


/// QoS subset supported by the WASM SDK.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmQos {
    /// Reliability policy.
    pub reliability: WasmReliability,
    /// Durability policy.
    pub durability: WasmDurability,
    /// History depth (number of samples to keep).
    pub history_depth: u32,
}

impl Default for WasmQos {
    fn default() -> Self {
        Self {
            reliability: WasmReliability::default(),
            durability: WasmDurability::default(),
            history_depth: 1,
        }
    }
}

impl WasmQos {
    /// Create a reliable QoS profile.
    pub fn reliable() -> Self {
        Self {
            reliability: WasmReliability::Reliable,
            durability: WasmDurability::Volatile,
            history_depth: 1,
        }
    }

    /// Create a reliable + transient-local QoS profile with given depth.
    pub fn reliable_transient_local(depth: u32) -> Self {
        Self {
            reliability: WasmReliability::Reliable,
            durability: WasmDurability::TransientLocal,
            history_depth: depth,
        }
    }

    /// Encode QoS to bytes for wire transmission (6 bytes).
    /// Format: reliability(u8) + durability(u8) + history_depth(u32 LE)
    pub fn encode(&self) -> [u8; 6] {
        let mut buf = [0u8; 6];
        buf[0] = match self.reliability {
            WasmReliability::BestEffort => 0,
            WasmReliability::Reliable => 1,
        };
        buf[1] = match self.durability {
            WasmDurability::Volatile => 0,
            WasmDurability::TransientLocal => 1,
        };
        buf[2..6].copy_from_slice(&self.history_depth.to_le_bytes());
        buf
    }

    /// Decode QoS from bytes.
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 6 {
            return None;
        }
        let reliability = match data[0] {
            0 => WasmReliability::BestEffort,
            1 => WasmReliability::Reliable,
            _ => return None,
        };
        let durability = match data[1] {
            0 => WasmDurability::Volatile,
            1 => WasmDurability::TransientLocal,
            _ => return None,
        };
        let history_depth =
            u32::from_le_bytes([data[2], data[3], data[4], data[5]]);
        Some(Self {
            reliability,
            durability,
            history_depth,
        })
    }
}
