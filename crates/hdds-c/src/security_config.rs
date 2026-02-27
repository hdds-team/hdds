// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! DDS Security configuration C FFI bindings.
//!
//! Provides opaque handle and setter API for configuring DDS Security v1.1.
//! The security config is attached to a `HddsParticipantConfig` before building.
//!
//! # Usage from C
//!
//! ```c
//! HddsSecurityConfig* sec = hdds_security_config_create();
//! hdds_security_config_set_identity_cert(sec, "/certs/part1.pem");
//! hdds_security_config_set_private_key(sec, "/certs/part1_key.pem");
//! hdds_security_config_set_ca_cert(sec, "/certs/ca.pem");
//! hdds_security_config_enable_encryption(sec, true);
//! hdds_config_set_security(cfg, sec); // attach to participant config
//! // sec is consumed, do NOT destroy it
//! ```

use std::ffi::CStr;
use std::os::raw::c_char;
use std::path::PathBuf;
use std::ptr;

use crate::HddsError;

/// Internal security config accumulator with pub fields.
/// Translated to `SecurityConfig` at participant build time.
pub(crate) struct SecurityConfigInner {
    pub identity_certificate: Option<PathBuf>,
    pub private_key: Option<PathBuf>,
    pub ca_certificates: Option<PathBuf>,
    pub governance_xml: Option<PathBuf>,
    pub permissions_xml: Option<PathBuf>,
    pub enable_encryption: bool,
    pub enable_audit_log: bool,
    pub audit_log_path: Option<PathBuf>,
    pub require_authentication: bool,
    pub check_certificate_revocation: bool,
}

impl SecurityConfigInner {
    fn new() -> Self {
        Self {
            identity_certificate: None,
            private_key: None,
            ca_certificates: None,
            governance_xml: None,
            permissions_xml: None,
            enable_encryption: false,
            enable_audit_log: false,
            audit_log_path: None,
            require_authentication: true,
            check_certificate_revocation: false,
        }
    }
}

/// Opaque handle to a security configuration.
#[repr(C)]
pub struct HddsSecurityConfig {
    _private: [u8; 0],
}

// =============================================================================
// Create / Destroy
// =============================================================================

/// Create a new security configuration.
///
/// Must be attached to a participant config via `hdds_config_set_security`
/// or freed with `hdds_security_config_destroy`.
#[no_mangle]
pub unsafe extern "C" fn hdds_security_config_create() -> *mut HddsSecurityConfig {
    let inner = SecurityConfigInner::new();
    Box::into_raw(Box::new(inner)).cast::<HddsSecurityConfig>()
}

/// Destroy a security configuration.
///
/// Only call this if NOT passed to `hdds_config_set_security` (which consumes it).
///
/// # Safety
/// - `config` must be a valid pointer from `hdds_security_config_create`, or NULL.
#[no_mangle]
pub unsafe extern "C" fn hdds_security_config_destroy(config: *mut HddsSecurityConfig) {
    if !config.is_null() {
        let _ = Box::from_raw(config.cast::<SecurityConfigInner>());
    }
}

// =============================================================================
// Certificate paths
// =============================================================================

/// Set the identity certificate path (X.509 PEM format, required).
///
/// # Safety
/// - `config` must be valid. `path` must be null-terminated.
#[no_mangle]
pub unsafe extern "C" fn hdds_security_config_set_identity_cert(
    config: *mut HddsSecurityConfig,
    path: *const c_char,
) -> HddsError {
    if config.is_null() || path.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let Ok(path_str) = CStr::from_ptr(path).to_str() else {
        return HddsError::HddsInvalidArgument;
    };
    let inner = &mut *config.cast::<SecurityConfigInner>();
    inner.identity_certificate = Some(PathBuf::from(path_str));
    HddsError::HddsOk
}

/// Set the private key path (PEM format, required).
///
/// # Safety
/// - `config` must be valid. `path` must be null-terminated.
#[no_mangle]
pub unsafe extern "C" fn hdds_security_config_set_private_key(
    config: *mut HddsSecurityConfig,
    path: *const c_char,
) -> HddsError {
    if config.is_null() || path.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let Ok(path_str) = CStr::from_ptr(path).to_str() else {
        return HddsError::HddsInvalidArgument;
    };
    let inner = &mut *config.cast::<SecurityConfigInner>();
    inner.private_key = Some(PathBuf::from(path_str));
    HddsError::HddsOk
}

/// Set the CA certificates path (PEM format, required).
///
/// # Safety
/// - `config` must be valid. `path` must be null-terminated.
#[no_mangle]
pub unsafe extern "C" fn hdds_security_config_set_ca_cert(
    config: *mut HddsSecurityConfig,
    path: *const c_char,
) -> HddsError {
    if config.is_null() || path.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let Ok(path_str) = CStr::from_ptr(path).to_str() else {
        return HddsError::HddsInvalidArgument;
    };
    let inner = &mut *config.cast::<SecurityConfigInner>();
    inner.ca_certificates = Some(PathBuf::from(path_str));
    HddsError::HddsOk
}

/// Set the governance XML path (optional, for domain-level security rules).
///
/// # Safety
/// - `config` must be valid. `path` must be null-terminated.
#[no_mangle]
pub unsafe extern "C" fn hdds_security_config_set_governance_xml(
    config: *mut HddsSecurityConfig,
    path: *const c_char,
) -> HddsError {
    if config.is_null() || path.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let Ok(path_str) = CStr::from_ptr(path).to_str() else {
        return HddsError::HddsInvalidArgument;
    };
    let inner = &mut *config.cast::<SecurityConfigInner>();
    inner.governance_xml = Some(PathBuf::from(path_str));
    HddsError::HddsOk
}

/// Set the permissions XML path (optional, for topic/partition authorization).
///
/// # Safety
/// - `config` must be valid. `path` must be null-terminated.
#[no_mangle]
pub unsafe extern "C" fn hdds_security_config_set_permissions_xml(
    config: *mut HddsSecurityConfig,
    path: *const c_char,
) -> HddsError {
    if config.is_null() || path.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let Ok(path_str) = CStr::from_ptr(path).to_str() else {
        return HddsError::HddsInvalidArgument;
    };
    let inner = &mut *config.cast::<SecurityConfigInner>();
    inner.permissions_xml = Some(PathBuf::from(path_str));
    HddsError::HddsOk
}

// =============================================================================
// Boolean toggles
// =============================================================================

/// Enable or disable AES-256-GCM encryption (default: false).
///
/// # Safety
/// - `config` must be valid.
#[no_mangle]
pub unsafe extern "C" fn hdds_security_config_enable_encryption(
    config: *mut HddsSecurityConfig,
    enabled: bool,
) -> HddsError {
    if config.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let inner = &mut *config.cast::<SecurityConfigInner>();
    inner.enable_encryption = enabled;
    HddsError::HddsOk
}

/// Enable or disable audit logging (default: false).
///
/// # Safety
/// - `config` must be valid.
#[no_mangle]
pub unsafe extern "C" fn hdds_security_config_enable_audit_log(
    config: *mut HddsSecurityConfig,
    enabled: bool,
) -> HddsError {
    if config.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let inner = &mut *config.cast::<SecurityConfigInner>();
    inner.enable_audit_log = enabled;
    HddsError::HddsOk
}

/// Set audit log file path (optional, in-memory only if not set).
///
/// # Safety
/// - `config` must be valid. `path` must be null-terminated.
#[no_mangle]
pub unsafe extern "C" fn hdds_security_config_set_audit_log_path(
    config: *mut HddsSecurityConfig,
    path: *const c_char,
) -> HddsError {
    if config.is_null() || path.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let Ok(path_str) = CStr::from_ptr(path).to_str() else {
        return HddsError::HddsInvalidArgument;
    };
    let inner = &mut *config.cast::<SecurityConfigInner>();
    inner.audit_log_path = Some(PathBuf::from(path_str));
    HddsError::HddsOk
}

/// Require authentication for all participants (default: true).
///
/// # Safety
/// - `config` must be valid.
#[no_mangle]
pub unsafe extern "C" fn hdds_security_config_require_authentication(
    config: *mut HddsSecurityConfig,
    required: bool,
) -> HddsError {
    if config.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let inner = &mut *config.cast::<SecurityConfigInner>();
    inner.require_authentication = required;
    HddsError::HddsOk
}

/// Enable CRL/OCSP certificate revocation checking (default: false).
///
/// Adds ~50-200ms network round-trip per participant.
///
/// # Safety
/// - `config` must be valid.
#[no_mangle]
pub unsafe extern "C" fn hdds_security_config_check_revocation(
    config: *mut HddsSecurityConfig,
    enabled: bool,
) -> HddsError {
    if config.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let inner = &mut *config.cast::<SecurityConfigInner>();
    inner.check_certificate_revocation = enabled;
    HddsError::HddsOk
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn test_security_config_create_destroy() {
        unsafe {
            let config = hdds_security_config_create();
            assert!(!config.is_null());
            hdds_security_config_destroy(config);
        }
    }

    #[test]
    fn test_security_config_null_safety() {
        unsafe {
            hdds_security_config_destroy(ptr::null_mut());
            assert_eq!(
                hdds_security_config_set_identity_cert(ptr::null_mut(), ptr::null()),
                HddsError::HddsInvalidArgument,
            );
            assert_eq!(
                hdds_security_config_set_private_key(ptr::null_mut(), ptr::null()),
                HddsError::HddsInvalidArgument,
            );
            assert_eq!(
                hdds_security_config_set_ca_cert(ptr::null_mut(), ptr::null()),
                HddsError::HddsInvalidArgument,
            );
            assert_eq!(
                hdds_security_config_enable_encryption(ptr::null_mut(), true),
                HddsError::HddsInvalidArgument,
            );
        }
    }

    #[test]
    fn test_security_config_setters() {
        unsafe {
            let config = hdds_security_config_create();

            let cert = CString::new("/certs/participant1.pem").unwrap();
            let key = CString::new("/certs/participant1_key.pem").unwrap();
            let ca = CString::new("/certs/ca.pem").unwrap();
            let gov = CString::new("/certs/governance.xml").unwrap();
            let perms = CString::new("/certs/permissions.xml").unwrap();
            let audit = CString::new("/var/log/hdds_audit.log").unwrap();

            assert_eq!(
                hdds_security_config_set_identity_cert(config, cert.as_ptr()),
                HddsError::HddsOk,
            );
            assert_eq!(
                hdds_security_config_set_private_key(config, key.as_ptr()),
                HddsError::HddsOk,
            );
            assert_eq!(
                hdds_security_config_set_ca_cert(config, ca.as_ptr()),
                HddsError::HddsOk,
            );
            assert_eq!(
                hdds_security_config_set_governance_xml(config, gov.as_ptr()),
                HddsError::HddsOk,
            );
            assert_eq!(
                hdds_security_config_set_permissions_xml(config, perms.as_ptr()),
                HddsError::HddsOk,
            );
            assert_eq!(
                hdds_security_config_enable_encryption(config, true),
                HddsError::HddsOk,
            );
            assert_eq!(
                hdds_security_config_enable_audit_log(config, true),
                HddsError::HddsOk,
            );
            assert_eq!(
                hdds_security_config_set_audit_log_path(config, audit.as_ptr()),
                HddsError::HddsOk,
            );
            assert_eq!(
                hdds_security_config_require_authentication(config, false),
                HddsError::HddsOk,
            );
            assert_eq!(
                hdds_security_config_check_revocation(config, true),
                HddsError::HddsOk,
            );

            // Verify internal state
            let inner = &*config.cast::<SecurityConfigInner>();
            assert_eq!(
                inner.identity_certificate.as_ref().unwrap().to_str().unwrap(),
                "/certs/participant1.pem",
            );
            assert_eq!(
                inner.private_key.as_ref().unwrap().to_str().unwrap(),
                "/certs/participant1_key.pem",
            );
            assert_eq!(
                inner.ca_certificates.as_ref().unwrap().to_str().unwrap(),
                "/certs/ca.pem",
            );
            assert!(inner.enable_encryption);
            assert!(inner.enable_audit_log);
            assert!(!inner.require_authentication);
            assert!(inner.check_certificate_revocation);

            hdds_security_config_destroy(config);
        }
    }
}
