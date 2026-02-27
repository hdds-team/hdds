// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! X.509 certificate-based authentication.
//!
//! Provides the DDS Security PKI-DH authentication plugin backed by X.509
//! certificates. Real cryptographic validation is gated behind the `security`
//! cargo feature; without it we fall back to deterministic test-only behavior
//! suitable for unit testing.

mod cert;
mod crypto;
mod plugin;

pub use plugin::X509AuthenticationPlugin;

#[cfg(test)]
mod tests;
