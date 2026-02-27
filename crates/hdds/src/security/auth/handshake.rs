// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Challenge-Response Authentication Handshake
//!
//! Implements the handshake FSM for mutual authentication between DDS participants.
//!
//! # Protocol
//!
//! ```text
//! Initiator                              Responder
//!    |                                      |
//!    |------- 1. CHALLENGE_REQUEST -------->|
//!    |                                      | (verify cert)
//!    |<------ 2. CHALLENGE_RESPONSE --------|
//!    | (verify cert + signature)            |
//!    |------- 3. FINAL_MESSAGE ------------>|
//!    |                                      | (verify signature)
//!    |<------ 4. SUCCESS -------------------|
//!    |                                      |
//! ```
//!
//! # OMG DDS Security v1.1 Sec.8.3.3 (Handshake Protocol)

#[cfg(feature = "security")]
use crate::security::SecurityError;

#[cfg(feature = "security")]
use ring::rand::{SecureRandom, SystemRandom};

/// Handshake FSM for Challenge-Response authentication
#[cfg(feature = "security")]
pub struct HandshakeFsm {
    /// Current state of the handshake
    state: HandshakeState,
    /// Local nonce (crypto-secure random)
    local_nonce: Option<[u8; 32]>,
    /// Remote nonce (received from peer)
    remote_nonce: Option<[u8; 32]>,
    /// Random number generator
    rng: SystemRandom,
}

#[cfg(feature = "security")]
#[derive(Debug, Clone, PartialEq)]
enum HandshakeState {
    /// Initial state - no handshake started
    Init,
    /// Challenge sent, waiting for response
    ChallengeSent,
    /// Challenge received, sent response
    ChallengeReceived,
    /// Handshake completed successfully
    Completed,
    /// Handshake failed
    Failed(String),
}

#[cfg(feature = "security")]
impl Default for HandshakeFsm {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "security")]
impl HandshakeFsm {
    /// Create a new handshake FSM
    pub fn new() -> Self {
        Self {
            state: HandshakeState::Init,
            local_nonce: None,
            remote_nonce: None,
            rng: SystemRandom::new(),
        }
    }

    /// Begin handshake as initiator
    ///
    /// # Returns
    ///
    /// * `Ok(challenge_message)` - Handshake message to send to responder
    pub fn begin_handshake(&mut self) -> Result<Vec<u8>, SecurityError> {
        if self.state != HandshakeState::Init {
            return Err(SecurityError::AuthenticationFailed(
                "Handshake already in progress".to_string(),
            ));
        }

        // Generate crypto-secure random nonce
        let mut nonce = [0u8; 32];
        self.rng
            .fill(&mut nonce)
            .map_err(|_| SecurityError::AuthenticationFailed("RNG failed".to_string()))?;

        self.local_nonce = Some(nonce);
        self.state = HandshakeState::ChallengeSent;

        // Build challenge message
        // Format: [message_type(1) | nonce(32)]
        let mut message = Vec::with_capacity(33);
        message.push(HandshakeMessageType::ChallengeRequest.to_byte());
        message.extend_from_slice(&nonce);

        Ok(message)
    }

    /// Process handshake message from remote peer
    ///
    /// # Arguments
    ///
    /// * `message` - Handshake message received from peer
    ///
    /// # Returns
    ///
    /// * `Ok(Some(response))` - Response message to send back
    /// * `Ok(None)` - Handshake completed, no response needed
    /// * `Err(SecurityError)` - Handshake failed
    pub fn process_message(&mut self, message: &[u8]) -> Result<Option<Vec<u8>>, SecurityError> {
        if message.is_empty() {
            return Err(SecurityError::AuthenticationFailed(
                "Empty handshake message".to_string(),
            ));
        }

        let msg_type = HandshakeMessageType::from_u8(message[0])?;

        match msg_type {
            HandshakeMessageType::ChallengeRequest => self.handle_challenge_request(&message[1..]),
            HandshakeMessageType::ChallengeResponse => {
                self.handle_challenge_response(&message[1..])
            }
            HandshakeMessageType::FinalMessage => self.handle_final_message(&message[1..]),
        }
    }

    /// Handle challenge request (as responder)
    fn handle_challenge_request(
        &mut self,
        payload: &[u8],
    ) -> Result<Option<Vec<u8>>, SecurityError> {
        if self.state != HandshakeState::Init {
            return Err(SecurityError::AuthenticationFailed(
                "Unexpected challenge request".to_string(),
            ));
        }

        if payload.len() < 32 {
            return Err(SecurityError::AuthenticationFailed(
                "Invalid challenge request (nonce too short)".to_string(),
            ));
        }

        // Extract remote nonce
        let mut remote_nonce = [0u8; 32];
        remote_nonce.copy_from_slice(&payload[0..32]);
        self.remote_nonce = Some(remote_nonce);

        // Generate our own nonce
        let mut local_nonce = [0u8; 32];
        self.rng
            .fill(&mut local_nonce)
            .map_err(|_| SecurityError::AuthenticationFailed("RNG failed".to_string()))?;
        self.local_nonce = Some(local_nonce);

        self.state = HandshakeState::ChallengeReceived;

        // Build challenge response
        // Format: [message_type(1) | local_nonce(32) | remote_nonce(32)]
        let mut response = Vec::with_capacity(65);
        response.push(HandshakeMessageType::ChallengeResponse.to_byte());
        response.extend_from_slice(&local_nonce);
        response.extend_from_slice(&remote_nonce);

        Ok(Some(response))
    }

    /// Handle challenge response (as initiator)
    fn handle_challenge_response(
        &mut self,
        payload: &[u8],
    ) -> Result<Option<Vec<u8>>, SecurityError> {
        if self.state != HandshakeState::ChallengeSent {
            return Err(SecurityError::AuthenticationFailed(
                "Unexpected challenge response".to_string(),
            ));
        }

        if payload.len() < 64 {
            return Err(SecurityError::AuthenticationFailed(
                "Invalid challenge response (nonce too short)".to_string(),
            ));
        }

        // Extract remote nonce and echoed local nonce
        let mut remote_nonce = [0u8; 32];
        remote_nonce.copy_from_slice(&payload[0..32]);
        self.remote_nonce = Some(remote_nonce);

        let mut echoed_nonce = [0u8; 32];
        echoed_nonce.copy_from_slice(&payload[32..64]);

        // Verify that the echoed nonce matches our local nonce
        if let Some(local_nonce) = self.local_nonce {
            if echoed_nonce != local_nonce {
                return Err(SecurityError::AuthenticationFailed(
                    "Nonce mismatch - possible replay attack".to_string(),
                ));
            }
        } else {
            return Err(SecurityError::AuthenticationFailed(
                "No local nonce found".to_string(),
            ));
        }

        // Build final message
        // Format: [message_type(1) | remote_nonce(32)]
        let mut final_msg = Vec::with_capacity(33);
        final_msg.push(HandshakeMessageType::FinalMessage.to_byte());
        final_msg.extend_from_slice(&remote_nonce);

        self.state = HandshakeState::Completed;

        Ok(Some(final_msg))
    }

    /// Handle final message (as responder)
    fn handle_final_message(&mut self, payload: &[u8]) -> Result<Option<Vec<u8>>, SecurityError> {
        if self.state != HandshakeState::ChallengeReceived {
            return Err(SecurityError::AuthenticationFailed(
                "Unexpected final message".to_string(),
            ));
        }

        if payload.len() < 32 {
            return Err(SecurityError::AuthenticationFailed(
                "Invalid final message (nonce too short)".to_string(),
            ));
        }

        // Verify that the echoed nonce matches our local nonce
        let mut echoed_nonce = [0u8; 32];
        echoed_nonce.copy_from_slice(&payload[0..32]);

        if let Some(local_nonce) = self.local_nonce {
            if echoed_nonce != local_nonce {
                return Err(SecurityError::AuthenticationFailed(
                    "Nonce mismatch - possible replay attack".to_string(),
                ));
            }
        } else {
            return Err(SecurityError::AuthenticationFailed(
                "No local nonce found".to_string(),
            ));
        }

        self.state = HandshakeState::Completed;

        // Handshake completed - no response needed
        Ok(None)
    }

    /// Check if handshake is completed successfully
    pub fn is_completed(&self) -> bool {
        self.state == HandshakeState::Completed
    }

    /// Get the shared secret (derived from both nonces)
    ///
    /// # Returns
    ///
    /// * `Some(secret)` - 64-byte shared secret (nonce_a || nonce_b, lexicographically sorted)
    /// * `None` - Handshake not completed
    ///
    /// Note: Uses lexicographic ordering to ensure both parties derive the same secret
    pub fn shared_secret(&self) -> Option<Vec<u8>> {
        if self.state != HandshakeState::Completed {
            return None;
        }

        let local_nonce = self.local_nonce?;
        let remote_nonce = self.remote_nonce?;

        // Combine both nonces in lexicographic order to ensure deterministic secret
        // (both initiator and responder will produce the same secret)
        let mut secret = Vec::with_capacity(64);
        if local_nonce < remote_nonce {
            secret.extend_from_slice(&local_nonce);
            secret.extend_from_slice(&remote_nonce);
        } else {
            secret.extend_from_slice(&remote_nonce);
            secret.extend_from_slice(&local_nonce);
        }

        Some(secret)
    }
}

#[cfg(feature = "security")]
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
enum HandshakeMessageType {
    ChallengeRequest = 1,
    ChallengeResponse = 2,
    FinalMessage = 3,
}

#[cfg(feature = "security")]
impl HandshakeMessageType {
    fn from_u8(value: u8) -> Result<Self, SecurityError> {
        match value {
            1 => Ok(Self::ChallengeRequest),
            2 => Ok(Self::ChallengeResponse),
            3 => Ok(Self::FinalMessage),
            _ => Err(SecurityError::AuthenticationFailed(format!(
                "Unknown handshake message type: {}",
                value
            ))),
        }
    }

    const fn to_byte(self) -> u8 {
        match self {
            Self::ChallengeRequest => 1,
            Self::ChallengeResponse => 2,
            Self::FinalMessage => 3,
        }
    }
}

#[cfg(all(test, feature = "security"))]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_success() {
        let mut initiator = HandshakeFsm::new();
        let mut responder = HandshakeFsm::new();

        // Step 1: Initiator sends challenge request
        let challenge_req = initiator.begin_handshake().expect("Begin handshake failed");
        assert_eq!(challenge_req.len(), 33); // 1 byte type + 32 byte nonce

        // Step 2: Responder processes challenge and sends response
        let challenge_resp = responder
            .process_message(&challenge_req)
            .expect("Process challenge failed")
            .expect("Expected challenge response");
        assert_eq!(challenge_resp.len(), 65); // 1 byte type + 32 + 32 nonces

        // Step 3: Initiator processes response and sends final message
        let final_msg = initiator
            .process_message(&challenge_resp)
            .expect("Process response failed")
            .expect("Expected final message");
        assert_eq!(final_msg.len(), 33); // 1 byte type + 32 byte nonce

        // Step 4: Responder processes final message
        let result = responder
            .process_message(&final_msg)
            .expect("Process final failed");
        assert!(result.is_none()); // No response needed

        // Verify both sides completed
        assert!(initiator.is_completed());
        assert!(responder.is_completed());

        // Verify shared secrets match
        let initiator_secret = initiator.shared_secret().expect("No initiator secret");
        let responder_secret = responder.shared_secret().expect("No responder secret");
        assert_eq!(initiator_secret, responder_secret);
        assert_eq!(initiator_secret.len(), 64);
    }

    #[test]
    fn test_handshake_nonce_mismatch() {
        let mut initiator = HandshakeFsm::new();
        let mut responder = HandshakeFsm::new();

        // Step 1: Initiator sends challenge
        let challenge_req = initiator.begin_handshake().expect("Begin handshake failed");

        // Step 2: Responder sends response
        let _challenge_resp = responder
            .process_message(&challenge_req)
            .expect("Process challenge failed")
            .expect("Expected response");

        // Step 3: Tamper with final message (nonce mismatch)
        let mut tampered_final = vec![HandshakeMessageType::FinalMessage.to_byte()];
        tampered_final.extend_from_slice(&[0u8; 32]); // Wrong nonce

        // Step 4: Responder should reject tampered message
        let result = responder.process_message(&tampered_final);
        assert!(result.is_err());
        assert!(!responder.is_completed());
    }

    #[test]
    fn test_handshake_empty_message() {
        let mut fsm = HandshakeFsm::new();
        let result = fsm.process_message(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_handshake_invalid_message_type() {
        let mut fsm = HandshakeFsm::new();
        let invalid_msg = vec![99u8; 33]; // Invalid message type
        let result = fsm.process_message(&invalid_msg);
        assert!(result.is_err());
    }
}

#[cfg(not(feature = "security"))]
pub struct HandshakeFsm;
