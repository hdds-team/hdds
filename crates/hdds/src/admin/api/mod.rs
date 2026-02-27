// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! TCP-based Admin API server implementation.
//!
//!
//! Exposes mesh state via a lightweight binary protocol for debugging tools.

mod builder;
mod format;
mod locks;
mod protocol;
mod server;
mod time;

pub use protocol::{Command, Status};
pub use server::AdminApi;

#[cfg(test)]
mod tests;
