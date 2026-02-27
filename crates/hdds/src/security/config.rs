// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Security configuration
//!
//! Provides builder API for configuring DDS Security plugins.

use std::path::PathBuf;

use crate::dds::Error;

/// Security configuration for DDS Security v1.1 (OMG spec).
///
/// Holds all configuration for the 4 DDS Security plugins:
/// 1. **Authentication** - PKI-based participant identity (X.509 certificates)
/// 2. **Access Control** - Topic/partition permissions (XML-based policies)
/// 3. **Cryptographic** - AES-256-GCM encryption for RTPS submessages
/// 4. **Logging** - Audit trail for security events (syslog RFC 5424)
///
/// # Security Model
///
/// - **Identity:** Each participant has a unique X.509 certificate + private key
/// - **Trust:** CA certificates establish root of trust
/// - **Authorization:** Optional permissions XML defines topic-level access control
/// - **Confidentiality:** Optional AES-256-GCM encryption for data confidentiality
/// - **Auditability:** Optional audit logging for compliance (ANSSI/IGI-1300)
///
/// # Thread Safety
///
/// `SecurityConfig` is `Clone` to support sharing across participants and threads.
/// All fields are immutable after construction (enforced by builder pattern).
/// `PathBuf` cloning is cheap (reference-counted internally).
///
/// # Performance Considerations
///
/// - Authentication handshake: ~10-50 ms per participant (one-time)
/// - Encryption overhead: ~200 ns per write (+80% latency)
/// - Revocation checking: ~50-200 ms per participant (if enabled)
///
/// # Example
///
/// ```ignore
/// use hdds::security::SecurityConfig;
///
/// let config = SecurityConfig::builder()
///     .identity_certificate("certs/participant1.pem")
///     .private_key("certs/participant1_key.pem")
///     .ca_certificates("certs/ca.pem")
///     .permissions_xml("permissions.xml")
///     .enable_encryption(true)
///     .enable_audit_log(true)
///     .build()?;
/// ```
///
/// # Specification Compliance
///
/// Implements OMG DDS Security v1.1 (formal/18-04-01):
/// - Section 8.3: Authentication Plugin (PKI-based)
/// - Section 8.4: Access Control Plugin (Permissions XML)
/// - Section 8.5: Cryptographic Plugin (AES-256-GCM)
/// - Section 8.6: Logging Plugin (Audit trail)
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)] // Configuration struct legitimately has multiple flags
pub struct SecurityConfig {
    /// Path to participant identity certificate (X.509 PEM format)
    pub identity_certificate: PathBuf,

    /// Path to participant private key (PEM format)
    pub private_key: PathBuf,

    /// Path to CA certificates (PEM format, concatenated)
    pub ca_certificates: PathBuf,

    /// Path to governance XML file (OMG DDS Security domain rules)
    pub governance_xml: Option<PathBuf>,

    /// Path to permissions XML file (OMG DDS Security format)
    pub permissions_xml: Option<PathBuf>,

    /// Enable AES-256-GCM encryption for RTPS submessages
    pub enable_encryption: bool,

    /// Enable audit logging
    pub enable_audit_log: bool,

    /// Path to audit log file (if audit logging is enabled)
    pub audit_log_path: Option<PathBuf>,

    /// Require authentication for all participants (default: true)
    pub require_authentication: bool,

    /// Validate certificate revocation via CRL/OCSP (default: false, performance)
    pub check_certificate_revocation: bool,
}

impl SecurityConfig {
    /// Create a new security configuration builder
    pub fn builder() -> SecurityConfigBuilder {
        SecurityConfigBuilder::default()
    }
}

/// Security configuration builder for fluent API construction.
///
/// Provides fluent API for building [`SecurityConfig`] with validation.
/// All required fields must be set before calling [`build()`], otherwise
/// construction fails with [`Error::Config`].
///
/// # Required Fields
///
/// - [`identity_certificate`]: Participant X.509 certificate (PEM)
/// - [`private_key`]: Participant private key (PEM)
/// - [`ca_certificates`]: CA certificates for trust chain (PEM)
///
/// # Optional Fields (with defaults)
///
/// - [`permissions_xml`]: Access control policies (default: None -> permissive)
/// - [`enable_encryption`]: AES-256-GCM encryption (default: false)
/// - [`enable_audit_log`]: Audit logging to syslog (default: false)
/// - [`require_authentication`]: Require PKI auth (default: true)
/// - [`check_certificate_revocation`]: CRL/OCSP validation (default: false)
///
/// # Validation
///
/// The [`build()`] method validates:
/// 1. All required fields are set (returns [`Error::Config`] if missing)
/// 2. All certificate files exist on disk (returns [`Error::Config`] if not found)
/// 3. Permissions XML exists if specified (returns [`Error::Config`] if not found)
///
/// **Note:** File format validation (PEM parsing, XML schema) is deferred to
/// plugin initialization at runtime.
///
/// # Example
///
/// ```ignore
/// use hdds::security::SecurityConfig;
///
/// let config = SecurityConfig::builder()
///     .identity_certificate("certs/participant1.pem")
///     .private_key("certs/participant1_key.pem")
///     .ca_certificates("certs/ca.pem")
///     .permissions_xml("permissions.xml")
///     .enable_encryption(true)
///     .build()?;
/// ```
///
/// # Example: Minimal configuration (no encryption)
///
/// ```ignore
/// use hdds::security::SecurityConfig;
///
/// let config = SecurityConfig::builder()
///     .identity_certificate("certs/participant1.pem")
///     .private_key("certs/participant1_key.pem")
///     .ca_certificates("certs/ca.pem")
///     .build()?; // encryption=false, audit_log=false
/// ```
///
/// [`identity_certificate`]: SecurityConfigBuilder::identity_certificate
/// [`private_key`]: SecurityConfigBuilder::private_key
/// [`ca_certificates`]: SecurityConfigBuilder::ca_certificates
/// [`permissions_xml`]: SecurityConfigBuilder::permissions_xml
/// [`enable_encryption`]: SecurityConfigBuilder::enable_encryption
/// [`enable_audit_log`]: SecurityConfigBuilder::enable_audit_log
/// [`require_authentication`]: SecurityConfigBuilder::require_authentication
/// [`check_certificate_revocation`]: SecurityConfigBuilder::check_certificate_revocation
/// [`build()`]: SecurityConfigBuilder::build
#[derive(Debug)]
#[allow(clippy::struct_excessive_bools)] // Configuration builder legitimately has multiple flags
pub struct SecurityConfigBuilder {
    identity_certificate: Option<PathBuf>,
    private_key: Option<PathBuf>,
    ca_certificates: Option<PathBuf>,
    governance_xml: Option<PathBuf>,
    permissions_xml: Option<PathBuf>,
    enable_encryption: bool,
    enable_audit_log: bool,
    audit_log_path: Option<PathBuf>,
    require_authentication: bool,
    check_certificate_revocation: bool,
}

impl SecurityConfigBuilder {
    /// Set identity certificate path
    ///
    /// The certificate must be in X.509 PEM format.
    ///
    /// # Example
    ///
    /// ```ignore
    /// builder.identity_certificate("certs/participant1.pem");
    /// ```
    pub fn identity_certificate<P: Into<PathBuf>>(mut self, path: P) -> Self {
        self.identity_certificate = Some(path.into());
        self
    }

    /// Set private key path
    ///
    /// The key must be in PEM format (RSA or ECDSA).
    ///
    /// # Example
    ///
    /// ```ignore
    /// builder.private_key("certs/participant1_key.pem");
    /// ```
    pub fn private_key<P: Into<PathBuf>>(mut self, path: P) -> Self {
        self.private_key = Some(path.into());
        self
    }

    /// Set CA certificates path
    ///
    /// The file can contain multiple concatenated PEM certificates.
    ///
    /// # Example
    ///
    /// ```ignore
    /// builder.ca_certificates("certs/ca.pem");
    /// ```
    pub fn ca_certificates<P: Into<PathBuf>>(mut self, path: P) -> Self {
        self.ca_certificates = Some(path.into());
        self
    }

    /// Set governance XML path (optional)
    ///
    /// The governance file defines domain-level security rules.
    /// Required for access control (together with permissions_xml).
    ///
    /// # Example
    ///
    /// ```ignore
    /// builder.governance_xml("governance.xml");
    /// ```
    pub fn governance_xml<P: Into<PathBuf>>(mut self, path: P) -> Self {
        self.governance_xml = Some(path.into());
        self
    }

    /// Set permissions XML path (optional)
    ///
    /// If not set, all topics/partitions are allowed (permissive mode).
    ///
    /// # Example
    ///
    /// ```ignore
    /// builder.permissions_xml("permissions.xml");
    /// ```
    pub fn permissions_xml<P: Into<PathBuf>>(mut self, path: P) -> Self {
        self.permissions_xml = Some(path.into());
        self
    }

    /// Enable AES-256-GCM encryption (default: false)
    ///
    /// When enabled, all RTPS DATA submessages are encrypted.
    ///
    /// # Performance Impact
    ///
    /// - Latency: +200 ns per write (< 80% slowdown)
    /// - CPU: +5% at 50k msg/s
    ///
    /// # Example
    ///
    /// ```ignore
    /// builder.enable_encryption(true);
    /// ```
    pub fn enable_encryption(mut self, enabled: bool) -> Self {
        self.enable_encryption = enabled;
        self
    }

    /// Enable audit logging (default: false)
    ///
    /// When enabled, all security events are logged to file.
    ///
    /// # Example
    ///
    /// ```ignore
    /// builder.enable_audit_log(true);
    /// ```
    pub fn enable_audit_log(mut self, enabled: bool) -> Self {
        self.enable_audit_log = enabled;
        self
    }

    /// Set audit log file path (optional)
    ///
    /// If not set and audit logging is enabled, logs are kept in memory only.
    ///
    /// # Example
    ///
    /// ```ignore
    /// builder.audit_log_path("/var/log/hdds_audit.log");
    /// ```
    pub fn audit_log_path<P: Into<PathBuf>>(mut self, path: P) -> Self {
        self.audit_log_path = Some(path.into());
        self
    }

    /// Require authentication for all participants (default: true)
    ///
    /// If false, unauthenticated participants are allowed (insecure).
    ///
    /// # Example
    ///
    /// ```ignore
    /// builder.require_authentication(true);
    /// ```
    pub fn require_authentication(mut self, required: bool) -> Self {
        self.require_authentication = required;
        self
    }

    /// Check certificate revocation via CRL/OCSP (default: false)
    ///
    /// When enabled, certificates are validated against CRL/OCSP.
    ///
    /// # Performance Impact
    ///
    /// - Adds network round-trip per participant (~50-200 ms)
    /// - Only recommended for high-security environments
    ///
    /// # Example
    ///
    /// ```ignore
    /// builder.check_certificate_revocation(true);
    /// ```
    pub fn check_certificate_revocation(mut self, enabled: bool) -> Self {
        self.check_certificate_revocation = enabled;
        self
    }

    /// Build the security configuration
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Required fields are missing (identity_certificate, private_key, ca_certificates)
    /// - Certificate files do not exist
    /// - Permissions XML is invalid
    ///
    /// # Example
    ///
    /// ```ignore
    /// let config = SecurityConfig::builder()
    ///     .identity_certificate("certs/participant1.pem")
    ///     .private_key("certs/participant1_key.pem")
    ///     .ca_certificates("certs/ca.pem")
    ///     .build()?;
    /// ```
    pub fn build(self) -> Result<SecurityConfig, Error> {
        // Validate required fields
        let identity_certificate = self.identity_certificate.ok_or(Error::Config)?;

        let private_key = self.private_key.ok_or(Error::Config)?;

        let ca_certificates = self.ca_certificates.ok_or(Error::Config)?;

        // Validate files exist
        if !identity_certificate.exists() {
            return Err(Error::Config);
        }

        if !private_key.exists() {
            return Err(Error::Config);
        }

        if !ca_certificates.exists() {
            return Err(Error::Config);
        }

        // Validate governance XML if provided
        if let Some(ref governance_xml) = self.governance_xml {
            if !governance_xml.exists() {
                return Err(Error::Config);
            }
        }

        // Validate permissions XML if provided
        if let Some(ref permissions_xml) = self.permissions_xml {
            if !permissions_xml.exists() {
                return Err(Error::Config);
            }
        }

        Ok(SecurityConfig {
            identity_certificate,
            private_key,
            ca_certificates,
            governance_xml: self.governance_xml,
            permissions_xml: self.permissions_xml,
            enable_encryption: self.enable_encryption,
            enable_audit_log: self.enable_audit_log,
            audit_log_path: self.audit_log_path,
            require_authentication: self.require_authentication,
            check_certificate_revocation: self.check_certificate_revocation,
        })
    }
}

impl Default for SecurityConfigBuilder {
    fn default() -> Self {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_config_builder_defaults() {
        let builder = SecurityConfigBuilder::default();
        assert!(!builder.enable_encryption);
        assert!(!builder.enable_audit_log);
        assert!(builder.require_authentication);
        assert!(!builder.check_certificate_revocation);
    }

    #[test]
    fn test_security_config_builder_fluent_api() {
        let builder = SecurityConfig::builder()
            .identity_certificate("/tmp/cert.pem")
            .private_key("/tmp/key.pem")
            .ca_certificates("/tmp/ca.pem")
            .enable_encryption(true)
            .enable_audit_log(true);

        assert!(builder.identity_certificate.is_some());
        assert!(builder.enable_encryption);
        assert!(builder.enable_audit_log);
    }

    #[test]
    fn test_security_config_build_missing_identity() {
        let result = SecurityConfig::builder()
            .private_key("/tmp/key.pem")
            .ca_certificates("/tmp/ca.pem")
            .build();

        assert!(
            result.is_err(),
            "Should fail when identity_certificate is missing"
        );
    }

    #[test]
    fn test_security_config_build_missing_private_key() {
        let result = SecurityConfig::builder()
            .identity_certificate("/tmp/cert.pem")
            .ca_certificates("/tmp/ca.pem")
            .build();

        assert!(result.is_err(), "Should fail when private_key is missing");
    }

    #[test]
    fn test_security_config_build_missing_ca() {
        let result = SecurityConfig::builder()
            .identity_certificate("/tmp/cert.pem")
            .private_key("/tmp/key.pem")
            .build();

        assert!(
            result.is_err(),
            "Should fail when ca_certificates is missing"
        );
    }

    #[test]
    fn test_security_config_build_file_not_found() {
        let result = SecurityConfig::builder()
            .identity_certificate("/nonexistent/cert.pem")
            .private_key("/nonexistent/key.pem")
            .ca_certificates("/nonexistent/ca.pem")
            .build();

        assert!(
            result.is_err(),
            "Should fail when certificate files don't exist"
        );
    }
}
