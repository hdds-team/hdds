// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Authentication implementation
//!
//! This module implements the Authentication plugin for DDS Security v1.1.
//!
//! # Components
//!
//! - `x509`: X.509 certificate validation
//! - `handshake`: Challenge-Response authentication handshake
//! - `identity_token`: Wire format for identity tokens

pub mod handshake;
pub mod identity_token;
pub mod x509;

pub use handshake::HandshakeFsm;
pub use identity_token::IdentityToken;
pub use x509::X509Validator;
