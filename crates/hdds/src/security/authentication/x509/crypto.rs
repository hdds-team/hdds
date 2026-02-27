// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use crate::security::SecurityError;

#[cfg(feature = "security")]
use ring::rand::{SecureRandom, SystemRandom};
#[cfg(feature = "security")]
use ring::signature::{self, UnparsedPublicKey};
#[cfg(feature = "security")]
use x509_parser;

/// Generate a 32-byte cryptographically secure challenge nonce.
///
/// # Errors
///
/// Returns error if the system CSPRNG fails. This is a hard failure --
/// we refuse to proceed with a predictable challenge.
pub(crate) fn generate_challenge() -> Result<Vec<u8>, SecurityError> {
    #[cfg(feature = "security")]
    {
        let rng = SystemRandom::new();
        let mut challenge = vec![0u8; 32];
        rng.fill(&mut challenge).map_err(|_| {
            SecurityError::CryptoError(
                "SystemRandom failed to generate challenge nonce - refusing to use predictable value"
                    .to_string(),
            )
        })?;
        Ok(challenge)
    }

    #[cfg(not(feature = "security"))]
    {
        Err(SecurityError::CryptoError(
            "Challenge generation requires the 'security' feature".to_string(),
        ))
    }
}

/// Sign data using the provided private key (RSA or ECDSA).
pub(crate) fn sign_data(data: &[u8], private_key_pem: &[u8]) -> Result<Vec<u8>, SecurityError> {
    #[cfg(feature = "security")]
    {
        let pem = ::pem::parse(private_key_pem).map_err(|e| {
            SecurityError::AuthenticationFailed(format!("Failed to parse private key PEM: {}", e))
        })?;

        if let Ok(key_pair) = signature::RsaKeyPair::from_pkcs8(pem.contents()) {
            let rng = SystemRandom::new();
            let mut signature = vec![0u8; key_pair.public().modulus_len()];
            key_pair
                .sign(&signature::RSA_PKCS1_SHA256, &rng, data, &mut signature)
                .map_err(|e| {
                    SecurityError::AuthenticationFailed(format!("RSA signing failed: {:?}", e))
                })?;
            return Ok(signature);
        }

        if let Ok(key_pair) = signature::EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            pem.contents(),
            &SystemRandom::new(),
        ) {
            let rng = SystemRandom::new();
            let signature = key_pair.sign(&rng, data).map_err(|e| {
                SecurityError::AuthenticationFailed(format!("ECDSA signing failed: {:?}", e))
            })?;
            return Ok(signature.as_ref().to_vec());
        }

        Err(SecurityError::AuthenticationFailed(
            "Unsupported private key format (RSA/ECDSA required)".to_string(),
        ))
    }

    #[cfg(not(feature = "security"))]
    {
        let mut signature = data.to_vec();
        signature.extend_from_slice(private_key_pem);
        Ok(signature)
    }
}

/// Verify a signature produced by the remote participant certificate.
pub(crate) fn verify_signature(
    data: &[u8],
    signature: &[u8],
    certificate_pem: &[u8],
) -> Result<bool, SecurityError> {
    #[cfg(feature = "security")]
    {
        let (_, pem) = x509_parser::pem::parse_x509_pem(certificate_pem).map_err(|e| {
            SecurityError::CertificateInvalid(format!("Failed to parse remote cert: {:?}", e))
        })?;
        let cert = pem.parse_x509().map_err(|e| {
            SecurityError::CertificateInvalid(format!("Failed to parse remote cert: {:?}", e))
        })?;

        // For signature verification:
        // - public_key().raw: Full SubjectPublicKeyInfo DER (91 bytes for P-256)
        // - public_key().subject_public_key.data: Just the EC key bytes (65 bytes for uncompressed P-256)
        // - sign_data() uses ECDSA_P256_SHA256_FIXED_SIGNING which produces 64-byte signatures (r||s)
        let public_key_spki = cert.public_key().raw; // For RSA
        let public_key_ec = &cert.public_key().subject_public_key.data; // For ECDSA

        // Try RSA first (for RSA certificates) - needs full SPKI
        let rsa_public_key =
            UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, public_key_spki);
        if rsa_public_key.verify(data, signature).is_ok() {
            return Ok(true);
        }

        // Try ECDSA P-256 with fixed signature format (64 bytes: r||s from ECDSA_P256_SHA256_FIXED_SIGNING)
        let ecdsa_public_key_fixed =
            UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, public_key_ec.as_ref());
        if ecdsa_public_key_fixed.verify(data, signature).is_ok() {
            return Ok(true);
        }

        // Try ECDSA P-256 with ASN.1 DER signature format (for compatibility)
        let ecdsa_public_key =
            UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, public_key_ec.as_ref());
        if ecdsa_public_key.verify(data, signature).is_ok() {
            return Ok(true);
        }

        Ok(false)
    }

    #[cfg(not(feature = "security"))]
    {
        let _ = certificate_pem;
        Ok(!data.is_empty() && !signature.is_empty())
    }
}
