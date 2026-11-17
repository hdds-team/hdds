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

use crate::HddsError;

/// Internal security config accumulator with pub fields.
/// Translated to `SecurityConfig` at participant build time.
pub(crate) struct SecurityConfigInner {
    pub identity_certificate: Option<PathBuf>,
    pub private_key: Option<PathBuf>,
    pub ca_certificates: Option<PathBuf>,
    pub governance_xml: Option<PathBuf>,
    pub permissions_xml: Option<PathBuf>,
    pub permissions_ca: Option<PathBuf>,
    pub certificate_revocation_list: Option<PathBuf>,
    pub permissions_overlay: Option<PathBuf>,
    pub permissions_overlay_poll_ms: u64,
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
            permissions_ca: None,
            certificate_revocation_list: None,
            permissions_overlay: None,
            permissions_overlay_poll_ms: 0,
            enable_encryption: false,
            enable_audit_log: false,
            audit_log_path: None,
            require_authentication: true,
            check_certificate_revocation: false,
        }
    }
}

/// Opaque handle to a security configuration.
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

/// Set the Permissions CA certificate path (X.509 PEM).
///
/// DDS-Security v1.1 Table 56 `dds.sec.access.permissions_ca`: the trust anchor
/// that signed the governance and permissions documents. It is REQUIRED as soon
/// as either document is configured, and it is a different trust anchor from the
/// identity CA set by `hdds_security_config_set_ca_cert`.
///
/// A document that is not signed by this CA makes the participant build fail.
/// There is no C API to turn that check off.
///
/// # Safety
/// - `config` must be valid. `path` must be null-terminated.
#[no_mangle]
pub unsafe extern "C" fn hdds_security_config_set_permissions_ca(
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
    inner.permissions_ca = Some(PathBuf::from(path_str));
    HddsError::HddsOk
}

/// Set the certificate revocation list (CRL) the identity certificates are
/// checked against.
///
/// REQUIRED as soon as `hdds_security_config_check_revocation(cfg, true)` is
/// called: the Rust core refuses to build a configuration whose revocation
/// flag is on with no list, because a flag that cannot be honoured is worse
/// than one that is off. This function is how the C API supplies it.
///
/// The file is a PEM bundle of CRLs - one per issuing CA in your trust store,
/// concatenated - or a single DER CRL. Each CRL must be signed by the CA that
/// issued the certificates it covers, and must not be past its `nextUpdate`.
///
/// Setting a list without turning the flag on is also refused at build time:
/// a list nobody consults is a configuration that looks like revocation
/// checking and is not.
///
/// # Safety
/// - `config` must be valid. `path` must be null-terminated.
#[no_mangle]
pub unsafe extern "C" fn hdds_security_config_set_crl(
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
    inner.certificate_revocation_list = Some(PathBuf::from(path_str));
    HddsError::HddsOk
}

/// Set a local permission file that RESTRICTS what the signed permissions
/// document already granted.
///
/// This is an overlay, not a second source of permissions: it can only take
/// an action away. DDS-Security v1.1 9.4.1.3 makes the Permissions CA the
/// root of what a participant may do, so an unsigned file that could widen
/// that would be a way around the chain of trust. Narrowing needs no
/// signature, and it is what lets an operator close a topic on a running
/// fleet without reissuing a signed XML document.
///
/// A subject the file does not name is not restricted at all. The file uses
/// the line-based format documented on `hdds::security::permissions`.
///
/// Pair it with [`hdds_security_config_set_permissions_overlay_poll_ms`] to
/// have it re-read when it changes; without that it is read once, at
/// participant creation. A file that does not exist fails the build by name:
/// a missing restriction file silently leaves a topic open.
///
/// # Safety
/// - `config` must be valid. `path` must be null-terminated.
#[no_mangle]
pub unsafe extern "C" fn hdds_security_config_set_permissions_overlay(
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
    inner.permissions_overlay = Some(PathBuf::from(path_str));
    HddsError::HddsOk
}

/// Re-read the permission overlay every `interval_ms` milliseconds.
///
/// `0` disables polling, which is the default: the file is read once. Setting
/// an interval without naming a file with
/// [`hdds_security_config_set_permissions_overlay`] fails the participant
/// build, because there is nothing to re-read.
///
/// # Safety
/// - `config` must be valid.
#[no_mangle]
pub unsafe extern "C" fn hdds_security_config_set_permissions_overlay_poll_ms(
    config: *mut HddsSecurityConfig,
    interval_ms: u64,
) -> HddsError {
    if config.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let inner = &mut *config.cast::<SecurityConfigInner>();
    inner.permissions_overlay_poll_ms = interval_ms;
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

/// Enable certificate revocation checking against a CRL (default: false).
///
/// Pair this with [`hdds_security_config_set_crl`]: with the flag on and no
/// list, the participant build FAILS by name, because revocation cannot be
/// checked against a list that does not exist. OCSP is not supported - it
/// needs an outbound HTTP connection an air-gapped deployment does not have.
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
mod crl_setter_tests {
    use super::*;
    use std::ffi::CString;

    /// The flag and its list are now BOTH reachable from C, and the setter
    /// stores what it was given.
    ///
    /// The pairing itself (flag on with no list) is refused by the Rust
    /// builder inside `hdds_config_build`, which lives in `transport_config`
    /// and needs a whole participant config to exercise; what belongs here is
    /// that the C entry point exists, validates its arguments, and lands the
    /// path in the field the forwarding layer reads.
    #[test]
    fn the_crl_setter_reaches_the_field() {
        unsafe {
            let config = hdds_security_config_create();
            assert!(!config.is_null());

            // Null arguments are refused, not stored.
            assert_eq!(
                hdds_security_config_set_crl(std::ptr::null_mut(), c"/x".as_ptr()),
                HddsError::HddsInvalidArgument
            );
            assert_eq!(
                hdds_security_config_set_crl(config, std::ptr::null()),
                HddsError::HddsInvalidArgument
            );
            assert!((*config.cast::<SecurityConfigInner>())
                .certificate_revocation_list
                .is_none());

            let path = CString::new("/certs/crl.pem").expect("CString");
            assert_eq!(
                hdds_security_config_set_crl(config, path.as_ptr()),
                HddsError::HddsOk
            );
            let inner = &*config.cast::<SecurityConfigInner>();
            assert_eq!(
                inner
                    .certificate_revocation_list
                    .as_ref()
                    .expect("the setter stored the path")
                    .to_str()
                    .expect("utf-8"),
                "/certs/crl.pem"
            );
            hdds_security_config_destroy(config);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::ptr;

    #[test]
    fn test_security_config_create_destroy() {
        unsafe {
            let config = hdds_security_config_create();
            assert!(!config.is_null());
            hdds_security_config_destroy(config);
        }
    }

    /// The Permissions CA setter reaches the accumulator, and rejects the
    /// argument shapes every other setter rejects.
    #[test]
    fn set_permissions_ca_roundtrip() {
        unsafe {
            let config = hdds_security_config_create();
            let perm_ca = CString::new("/certs/permissions_ca.pem").unwrap();

            assert_eq!(
                hdds_security_config_set_permissions_ca(config, perm_ca.as_ptr()),
                HddsError::HddsOk,
            );
            let inner = &*config.cast::<SecurityConfigInner>();
            assert_eq!(
                inner.permissions_ca.as_ref().unwrap().to_str().unwrap(),
                "/certs/permissions_ca.pem",
            );

            assert_eq!(
                hdds_security_config_set_permissions_ca(ptr::null_mut(), perm_ca.as_ptr()),
                HddsError::HddsInvalidArgument,
            );
            assert_eq!(
                hdds_security_config_set_permissions_ca(config, ptr::null()),
                HddsError::HddsInvalidArgument,
            );

            hdds_security_config_destroy(config);
        }
    }

    /// The escape hatch that accepts unsigned documents is Rust-only by
    /// decision: nothing in the C surface may switch the signature check off.
    #[test]
    fn no_c_symbol_disables_document_verification() {
        // Built at run time so this very assertion is not what it finds.
        let needle = format!("{}{}", "insecure_allow_", "unsigned_documents");
        let source = include_str!("security_config.rs");
        assert!(
            !source.contains(&needle),
            "the unsigned-document escape hatch must stay out of the C ABI"
        );
        let header = include_str!("../../../sdk/c/include/hdds.h");
        assert!(
            !header.contains("allow_unsigned"),
            "the unsigned-document escape hatch must stay out of hdds.h"
        );
        let loader = include_str!("transport_config.rs");
        assert!(
            !loader.contains(&needle),
            "the unsigned-document escape hatch must stay out of the XML/YAML loader"
        );
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
            // The list the flag above needs: the Rust builder refuses a
            // revocation flag with no list.
            let crl = CString::new("/certs/crl.pem").expect("CString");
            assert_eq!(
                hdds_security_config_set_crl(config, crl.as_ptr()),
                HddsError::HddsOk,
            );

            // Verify internal state
            let inner = &*config.cast::<SecurityConfigInner>();
            assert_eq!(
                inner
                    .identity_certificate
                    .as_ref()
                    .unwrap()
                    .to_str()
                    .unwrap(),
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
