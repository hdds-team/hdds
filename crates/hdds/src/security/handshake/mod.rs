// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! PKI-DH 3-message authentication handshake (DDS Security v1.1 sec. 9.3.4).
//!
//! Implements the Participant-Authentication state machine driven by tokens
//! exchanged over the Participant-Stateless-Message builtin channel
//! (entity IDs 0xFF0202C3/0xFF0202C4, gap #2).
//!
//! Message flow per sec. 9.3.4.2:
//!
//! ```text
//! Initiator                              Responder
//!    | ---AuthRequest (req)-----------> |
//!    | <-----------(reply) AuthReply--- |
//!    | ---AuthFinal (final)-----------> |
//!    |                                  |
//!    ECDH shared_secret derived         ECDH shared_secret derived
//! ```
//!
//! Role assignment: the participant whose GUID is lexicographically LOWER
//! initiates (DDS Security v1.1 Sec.9.3.4).

mod machine;
mod pdata;
#[cfg(feature = "security")]
mod pss;
mod state;
pub(crate) mod tokens;

pub use machine::{HandshakeAction, HandshakeMachine};
pub use state::{HandshakeRole, HandshakeState, SharedSecret};
pub use tokens::{parse_token, AuthFinalToken, AuthReplyToken, AuthRequestToken, TokenKind};

#[cfg(test)]
mod tests;
