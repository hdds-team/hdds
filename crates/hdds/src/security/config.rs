// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Security configuration
//!
//! Provides builder API for configuring DDS Security plugins.

use std::path::PathBuf;

use crate::dds::Error;

/// Authentication plugin kind.
///
/// Selects which implementation backs the [`authentication`] plugin slot.
/// Only `X509` is shipped today; the enum provides a config-driven seam so
/// future alternatives (PSK, Kerberos) can be added without touching
/// `create_authentication_plugin`.
///
/// [`authentication`]: crate::security::authentication
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum AuthPluginKind {
    /// X.509 certificate-based PKI-DH authentication (DDS Security v1.1 section 8.3).
    ///
    /// This is the only concrete implementation today and the default for all
    /// builder constructors.
    #[default]
    X509,
}

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

    /// Path to the Permissions CA certificate (X.509 PEM).
    ///
    /// DDS-Security v1.1 Table 56 `dds.sec.access.permissions_ca`: the trust
    /// anchor that signed the governance and permissions documents. It is a
    /// DISTINCT role from [`ca_certificates`], which anchors participant
    /// identities: a key that can issue identities must not, by that fact
    /// alone, be able to forge permissions.
    ///
    /// Required as soon as [`governance_xml`] or [`permissions_xml`] is set,
    /// unless [`insecure_allow_unsigned_documents`] is on.
    ///
    /// [`ca_certificates`]: SecurityConfig::ca_certificates
    /// [`governance_xml`]: SecurityConfig::governance_xml
    /// [`permissions_xml`]: SecurityConfig::permissions_xml
    /// [`insecure_allow_unsigned_documents`]: SecurityConfig::insecure_allow_unsigned_documents
    pub permissions_ca: Option<PathBuf>,

    /// Accept plain, unsigned governance and permissions XML (default: `false`).
    ///
    /// DDS-Security v1.1 9.4.1.2 and 9.4.1.3 require both documents to be
    /// signed by the Permissions CA, so an unsigned document is refused and
    /// `Participant::build()` fails. This flag reopens that hole for local
    /// development. It is deliberately absent from the C ABI and from the
    /// XML/YAML loader: a knob that disables a signature check should not be
    /// reachable by copying a configuration file.
    ///
    /// Turning it on logs a warning and, when audit logging is enabled, writes
    /// an audit record naming the document that was accepted unsigned.
    ///
    /// It covers this participant's OWN documents only. A remote peer's
    /// permissions document is always required to verify against the
    /// Permissions CA, whatever this flag says.
    pub insecure_allow_unsigned_documents: bool,

    /// Path to a local permission file that RESTRICTS what the signed
    /// permissions document already granted (default: none).
    ///
    /// This is an overlay, not a second source of permissions. It can only
    /// take an action away: DDS-Security v1.1 section 9.4.1.3 makes the
    /// Permissions CA the root of what a participant may do, so an unsigned
    /// file that could widen that would be a way around the whole chain of
    /// trust. Narrowing needs no signature. A subject this file never names
    /// gets no restriction at all, and the signed decision stands untouched.
    ///
    /// The file uses the line-based format documented in
    /// [`security::permissions::dynamic`](crate::security::permissions::dynamic)
    /// and it is re-read on every change when
    /// [`permissions_overlay_poll`](Self::permissions_overlay_poll) is set -
    /// which is the point: a topic can be taken away from a running fleet
    /// without re-signing and redistributing an XML document.
    pub permissions_overlay: Option<PathBuf>,

    /// How often to re-read [`permissions_overlay`](Self::permissions_overlay)
    /// (default: none - the file is read once at startup).
    pub permissions_overlay_poll: Option<std::time::Duration>,

    /// Read the permissions documents' allowed partitions conditions with the
    /// "legacy matching" (default: `false`, the specification's matching).
    ///
    /// DDS-Security v1.1 Sec.9.4.1.3.2.3.1.4: an allow rule's `<partitions>`
    /// is met when EVERY partition of the endpoint matches one of its
    /// expressions (a rule for {A, B} allows {A}, {B}, {A, B}, not
    /// {A, B, C}); "for legacy reasons DDS-Security implementations shall
    /// provide a way to select an alternative "legacy matching" behavior",
    /// met when ONE of them matches ({A, B, C} allowed). It applies to this
    /// participant's own document and to the documents its peers present.
    /// Deny rules read the same either way.
    pub legacy_partition_matching: bool,

    /// Read a peer's unsigned permissions document, for the fixtures that
    /// have no permissions CA key to sign one with. Test builds only.
    #[cfg(all(test, feature = "security"))]
    pub(crate) accept_unsigned_remote_documents_for_tests: bool,

    /// Enable AES-256-GCM encryption for RTPS submessages
    pub enable_encryption: bool,

    /// Enable audit logging
    pub enable_audit_log: bool,

    /// Path to audit log file (if audit logging is enabled)
    pub audit_log_path: Option<PathBuf>,

    /// RFC 5424 syslog collector for the audit trail, over UDP.
    ///
    /// Optional and independent of [`audit_log_path`]: with both, the file is
    /// the tamper-evident record and the export is a mirror whose failure is
    /// logged, not fatal; with only this, the export IS the record and a
    /// failed emit degrades the chain. Requires
    /// [`enable_audit_log`](SecurityConfig::enable_audit_log).
    ///
    /// [`audit_log_path`]: SecurityConfig::audit_log_path
    pub audit_syslog_address: Option<std::net::SocketAddr>,

    /// Require authentication for all participants (default: true)
    pub require_authentication: bool,

    /// Validate certificate revocation via CRL (default: `false` for bare builder,
    /// `true` for [`SecurityConfig::secure_builder`]).
    ///
    /// When `true`, certificate validation requires CRL data to be present.
    /// OCSP is not supported (requires outbound HTTP, incompatible with air-gap
    /// deployments); omitting CRL data while enabling this flag is an explicit
    /// configuration error rather than a silent skip.
    pub check_certificate_revocation: bool,

    /// PEM or DER certificate revocation list, checked against every REMOTE
    /// peer certificate during the handshake.
    ///
    /// Required when [`check_certificate_revocation`] is set, and the build
    /// refuses the pair without it.
    ///
    /// [`check_certificate_revocation`]: SecurityConfig::check_certificate_revocation
    pub certificate_revocation_list: Option<PathBuf>,

    /// Authentication plugin implementation (default: [`AuthPluginKind::X509`]).
    ///
    /// Consumed by [`authentication::create_authentication_plugin`] to select
    /// the concrete plugin at construction time. X.509 is the only available
    /// implementation today.
    ///
    /// [`authentication::create_authentication_plugin`]: crate::security::authentication::create_authentication_plugin
    pub auth_plugin_kind: AuthPluginKind,

    /// Key-agreement algorithm for PKI-DH handshake (DDS Security v1.1 section 9.3.1.1.1).
    ///
    /// Supported values:
    /// - `"ECDH+prime256v1-CEUM"` -- elliptic-curve DH on P-256 (default,
    ///   spec-defined)
    /// - `"ECDH+secp384r1-CEUM"` -- elliptic-curve DH on P-384 with
    ///   HKDF-SHA384 (an HDDS extension following the spec's naming pattern;
    ///   v1.1 itself defines only the P-256 and finite-field strings)
    ///
    /// The spec-defined `"DH+MODP-2048-256"` (finite-field DH) is NOT
    /// implemented and is refused.
    ///
    /// The string is advertised in `AuthRequest.kagree_algo` only -- there is
    /// no AuthReply echo (an earlier version of this doc claimed one; the
    /// token has no such field). The RESPONDER enforces an exact match
    /// against its own configured value and refuses the handshake otherwise:
    /// suite selection is policy, not negotiation, so a downgrade cannot
    /// happen silently. An unrecognised value is not an error at config
    /// time; it fails loudly when the first handshake starts.
    pub key_establishment_algorithm: String,
}

impl SecurityConfig {
    /// Create a new security configuration builder.
    ///
    /// Defaults: `check_certificate_revocation = false` (backward-compatible).
    /// Use [`secure_builder`] for high-assurance deployments.
    ///
    /// [`secure_builder`]: SecurityConfig::secure_builder
    pub fn builder() -> SecurityConfigBuilder {
        SecurityConfigBuilder::default()
    }

    /// Create a builder pre-configured for high-assurance (air-gap) deployments.
    ///
    /// Differences from [`builder`]:
    /// - `check_certificate_revocation` defaults to **`true`** (CRL required).
    ///
    /// # Revocation
    ///
    /// This profile sets `check_certificate_revocation` to `true`, so it also
    /// requires [`certificate_revocation_list`]. Building without one is a
    /// configuration error, by name: revocation cannot be checked against a
    /// list that does not exist, and starting anyway would mean reporting a
    /// guarantee nobody is providing.
    ///
    /// Name a CRL here: both the local identity and every remote peer
    /// certificate are checked against it.
    ///
    /// [`certificate_revocation_list`]: SecurityConfigBuilder::certificate_revocation_list
    /// [`builder`] with `check_certificate_revocation = false` remains a
    /// legitimate configuration. It means accepting that revocation is out of
    /// scope for the deployment - defensible with short-lived certificates
    /// (under 24 h), and a sentence that has to be said out loud rather than
    /// discovered.
    ///
    /// # Air-gap note
    ///
    /// OCSP is not supported: it requires an outbound HTTP connection to a
    /// revocation responder that is unavailable in air-gapped environments.
    ///
    /// [`builder`]: SecurityConfig::builder
    pub fn secure_builder() -> SecurityConfigBuilder {
        SecurityConfigBuilder {
            check_certificate_revocation: true,
            ..SecurityConfigBuilder::default()
        }
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
/// - [`enable_audit_log`]: Audit trail, to a file and/or an RFC 5424 syslog
///   collector (default: false).
/// - [`require_authentication`]: Require PKI auth (default: true)
/// - [`check_certificate_revocation`]: CRL/OCSP validation (default: false)
/// - [`key_establishment_algorithm`]: kagree_algo for PKI-DH (default: `"ECDH+prime256v1-CEUM"`)
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
/// [`key_establishment_algorithm`]: SecurityConfigBuilder::key_establishment_algorithm
/// [`build()`]: SecurityConfigBuilder::build
#[derive(Debug)]
#[allow(clippy::struct_excessive_bools)] // Configuration builder legitimately has multiple flags
pub struct SecurityConfigBuilder {
    identity_certificate: Option<PathBuf>,
    private_key: Option<PathBuf>,
    ca_certificates: Option<PathBuf>,
    governance_xml: Option<PathBuf>,
    permissions_xml: Option<PathBuf>,
    permissions_ca: Option<PathBuf>,
    certificate_revocation_list: Option<PathBuf>,
    insecure_allow_unsigned_documents: bool,
    permissions_overlay: Option<PathBuf>,
    permissions_overlay_poll: Option<std::time::Duration>,
    legacy_partition_matching: bool,
    enable_encryption: bool,
    enable_audit_log: bool,
    audit_log_path: Option<PathBuf>,
    audit_syslog_address: Option<std::net::SocketAddr>,
    require_authentication: bool,
    check_certificate_revocation: bool,
    auth_plugin_kind: AuthPluginKind,
    key_establishment_algorithm: String,
    #[cfg(all(test, feature = "security"))]
    accept_unsigned_remote_documents_for_tests: bool,
}

impl SecurityConfigBuilder {
    /// Read a peer's unsigned permissions document. Test builds only.
    #[cfg(all(test, feature = "security"))]
    pub(crate) fn accept_unsigned_remote_documents_for_tests(mut self) -> Self {
        self.accept_unsigned_remote_documents_for_tests = true;
        self
    }

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

    /// Set the Permissions CA certificate path (X.509 PEM).
    ///
    /// This is the only trust anchor for the governance and permissions
    /// documents. Certificates carried inside a signed document are never
    /// used as anchors.
    ///
    /// # Example
    ///
    /// ```ignore
    /// builder.permissions_ca("certs/permissions_ca.pem");
    /// ```
    pub fn permissions_ca<P: Into<PathBuf>>(mut self, path: P) -> Self {
        self.permissions_ca = Some(path.into());
        self
    }

    /// Accept unsigned governance and permissions documents (default: `false`).
    ///
    /// Development escape hatch. With it on, a plain-XML document is accepted
    /// with a warning and an audit record instead of failing the build. Leave
    /// it off in anything that ships: an unsigned permissions file is a file
    /// anyone who can write to the disk can rewrite. Local documents only: a
    /// peer's unsigned permissions document is refused regardless.
    ///
    /// # Example
    ///
    /// ```ignore
    /// builder.insecure_allow_unsigned_documents(true);
    /// ```
    pub fn insecure_allow_unsigned_documents(mut self, allow: bool) -> Self {
        self.insecure_allow_unsigned_documents = allow;
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
    /// Export every audit record to an RFC 5424 syslog collector over UDP.
    ///
    /// Independent of [`audit_log_path`](Self::audit_log_path): configure
    /// both and the file is the tamper-evident record while the export is a
    /// mirror; configure only this and the export is the record, so a failed
    /// emit degrades the chain.
    /// Apply a local permission file as a RESTRICTION OVERLAY on top of the
    /// signed permissions document.
    ///
    /// It can only take an action away - see
    /// [`SecurityConfig::permissions_overlay`] for why an unsigned file is
    /// allowed to do that and not the reverse. Pair it with
    /// [`permissions_overlay_poll`](Self::permissions_overlay_poll) for
    /// hot-reload.
    #[must_use]
    pub fn permissions_overlay<P: Into<PathBuf>>(mut self, path: P) -> Self {
        self.permissions_overlay = Some(path.into());
        self
    }

    /// Re-read the permission overlay whenever it changes, at this interval.
    ///
    /// Without it the overlay is read once, at participant construction.
    #[must_use]
    pub fn permissions_overlay_poll(mut self, interval: std::time::Duration) -> Self {
        self.permissions_overlay_poll = Some(interval);
        self
    }

    #[must_use]
    pub fn audit_syslog_address(mut self, address: std::net::SocketAddr) -> Self {
        self.audit_syslog_address = Some(address);
        self
    }

    pub fn audit_log_path<P: Into<PathBuf>>(mut self, path: P) -> Self {
        self.audit_log_path = Some(path.into());
        self
    }

    /// Select the "legacy matching" of the permissions' allowed partitions
    /// conditions (default: `false`); see
    /// [`SecurityConfig::legacy_partition_matching`].
    ///
    /// # Example
    ///
    /// ```ignore
    /// builder.legacy_partition_matching(true);
    /// ```
    pub fn legacy_partition_matching(mut self, legacy: bool) -> Self {
        self.legacy_partition_matching = legacy;
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

    /// Check certificate revocation via CRL (default: false for [`SecurityConfig::builder`],
    /// true for [`SecurityConfig::secure_builder`]).
    ///
    /// When enabled, certificates are validated against CRL data loaded into the
    /// validator. OCSP is intentionally unsupported (requires outbound HTTP,
    /// incompatible with air-gap deployments).
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

    /// Name the certificate revocation list to check remote peers against.
    ///
    /// PEM or DER. Required whenever
    /// [`check_certificate_revocation`](Self::check_certificate_revocation) is
    /// on: a deployment that asks for revocation checking and supplies no list
    /// is asking for a guarantee nobody can give, and this builder says so
    /// rather than starting and checking nothing.
    pub fn certificate_revocation_list<P: Into<PathBuf>>(mut self, path: P) -> Self {
        self.certificate_revocation_list = Some(path.into());
        self
    }

    /// Set the authentication plugin kind (default: [`AuthPluginKind::X509`]).
    ///
    /// Determines which concrete implementation is constructed by
    /// [`create_authentication_plugin`]. X.509 is the only available
    /// implementation today.
    ///
    /// [`create_authentication_plugin`]: crate::security::authentication::create_authentication_plugin
    ///
    /// # Example
    ///
    /// ```ignore
    /// use hdds::security::config::AuthPluginKind;
    /// builder.auth_plugin_kind(AuthPluginKind::X509);
    /// ```
    pub fn auth_plugin_kind(mut self, kind: AuthPluginKind) -> Self {
        self.auth_plugin_kind = kind;
        self
    }

    /// Set key-establishment algorithm for the PKI-DH handshake (default: `"ECDH+prime256v1-CEUM"`)
    ///
    /// Per DDS Security v1.1 section 9.3.1.1.1, two values are formally defined:
    /// - `"DH+MODP-2048-256"` -- finite-field Diffie-Hellman (RFC 3526 Group 14)
    /// - `"ECDH+prime256v1-CEUM"` -- elliptic-curve DH on P-256
    ///
    /// The algorithm string is placed in `AuthRequest.kagree_algo` so the peer
    /// can verify compatibility before completing the exchange.
    ///
    /// # Example
    ///
    /// ```ignore
    /// builder.key_establishment_algorithm("ECDH+prime256v1-CEUM");
    /// ```
    pub fn key_establishment_algorithm<S: Into<String>>(mut self, algo: S) -> Self {
        self.key_establishment_algorithm = algo.into();
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
        let identity_certificate = self
            .identity_certificate
            .ok_or_else(|| Error::Config("identity_certificate is required".to_string()))?;

        let private_key = self
            .private_key
            .ok_or_else(|| Error::Config("private_key is required".to_string()))?;

        let ca_certificates = self
            .ca_certificates
            .ok_or_else(|| Error::Config("ca_certificates is required".to_string()))?;

        // Validate files exist
        if !identity_certificate.exists() {
            return Err(Error::Config(format!(
                "identity_certificate not found: {}",
                identity_certificate.display()
            )));
        }

        if !private_key.exists() {
            return Err(Error::Config(format!(
                "private_key not found: {}",
                private_key.display()
            )));
        }

        if !ca_certificates.exists() {
            return Err(Error::Config(format!(
                "ca_certificates not found: {}",
                ca_certificates.display()
            )));
        }

        // Validate governance XML if provided
        if let Some(ref governance_xml) = self.governance_xml {
            if !governance_xml.exists() {
                return Err(Error::Config(format!(
                    "governance_xml not found: {}",
                    governance_xml.display()
                )));
            }
        }

        // Validate permissions XML if provided
        if let Some(ref permissions_xml) = self.permissions_xml {
            if !permissions_xml.exists() {
                return Err(Error::Config(format!(
                    "permissions_xml not found: {}",
                    permissions_xml.display()
                )));
            }
        }

        // Validate the permissions CA if provided
        if let Some(ref permissions_ca) = self.permissions_ca {
            if !permissions_ca.exists() {
                return Err(Error::Config(format!(
                    "permissions_ca not found: {}",
                    permissions_ca.display()
                )));
            }
        }

        // A restriction file that is not there restricts nothing, which is
        // the one failure mode this overlay must not have: it is configured
        // to TAKE AWAY, so a missing file silently leaves a topic open.
        if let Some(ref overlay) = self.permissions_overlay {
            if !overlay.exists() {
                return Err(Error::Config(format!(
                    "permissions_overlay not found: {}",
                    overlay.display()
                )));
            }
        }

        // A poll interval with no file to poll is a configuration that does
        // not do what it says.
        if self.permissions_overlay_poll.is_some() && self.permissions_overlay.is_none() {
            return Err(Error::Config(
                "permissions_overlay_poll is set but permissions_overlay is not: there is no                  file to re-read"
                    .to_string(),
            ));
        }

        // DDS-Security v1.1 9.4.1.2 / 9.4.1.3: the governance and permissions
        // documents are signed by the Permissions CA, so configuring either
        // without naming that CA leaves nothing to verify against. There is no
        // fallback to `ca_certificates`: identity issuance and permissions
        // issuance are separate trust roles (Table 56).
        if (self.governance_xml.is_some() || self.permissions_xml.is_some())
            && self.permissions_ca.is_none()
            && !self.insecure_allow_unsigned_documents
        {
            return Err(Error::Config(
                "permissions_ca is required when governance_xml or permissions_xml is set: \
                 DDS-Security v1.1 9.4.1.2/9.4.1.3 sign both documents with the Permissions \
                 CA, which is a different trust anchor from ca_certificates"
                    .to_string(),
            ));
        }

        // A deployment that turns revocation ON and names no list is asking for
        // a guarantee nothing can provide. `secure_builder()` defaults this
        // flag to TRUE, so the pairing has to be enforced here, at build time
        // and in one place - a participant that discovers the gap mid-handshake
        // has already announced itself.
        if self.check_certificate_revocation && self.certificate_revocation_list.is_none() {
            return Err(Error::Config(
                "check_certificate_revocation is on but no certificate_revocation_list was \
                 given: revocation cannot be checked against a list that does not exist. \
                 Name a CRL, or set check_certificate_revocation(false) to state plainly \
                 that revocation is out of scope for this deployment"
                    .to_string(),
            ));
        }
        // And the converse: a list nobody consults is a configuration that
        // LOOKS like revocation checking and is not. The flag is the single
        // switch; a list without it is refused rather than quietly ignored.
        if let Some(ref list) = self.certificate_revocation_list {
            if !self.check_certificate_revocation {
                return Err(Error::Config(
                    "certificate_revocation_list is set but check_certificate_revocation is \
                     off: the list would never be consulted. Turn the flag on, or drop the list"
                        .to_string(),
                ));
            }
            if !list.exists() {
                return Err(Error::Config(format!(
                    "certificate_revocation_list not found: {}",
                    list.display()
                )));
            }
        }

        Ok(SecurityConfig {
            identity_certificate,
            private_key,
            ca_certificates,
            governance_xml: self.governance_xml,
            permissions_xml: self.permissions_xml,
            permissions_ca: self.permissions_ca,
            certificate_revocation_list: self.certificate_revocation_list,
            insecure_allow_unsigned_documents: self.insecure_allow_unsigned_documents,
            permissions_overlay: self.permissions_overlay,
            permissions_overlay_poll: self.permissions_overlay_poll,
            legacy_partition_matching: self.legacy_partition_matching,
            #[cfg(all(test, feature = "security"))]
            accept_unsigned_remote_documents_for_tests: self
                .accept_unsigned_remote_documents_for_tests,
            enable_encryption: self.enable_encryption,
            enable_audit_log: self.enable_audit_log,
            audit_log_path: self.audit_log_path,
            audit_syslog_address: self.audit_syslog_address,
            require_authentication: self.require_authentication,
            check_certificate_revocation: self.check_certificate_revocation,
            auth_plugin_kind: self.auth_plugin_kind,
            key_establishment_algorithm: self.key_establishment_algorithm,
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
            permissions_ca: None,
            certificate_revocation_list: None,
            insecure_allow_unsigned_documents: false,
            permissions_overlay: None,
            permissions_overlay_poll: None,
            legacy_partition_matching: false,
            enable_encryption: false,
            enable_audit_log: false,
            audit_log_path: None,
            audit_syslog_address: None,
            require_authentication: true,
            check_certificate_revocation: false,
            auth_plugin_kind: AuthPluginKind::X509,
            // Default to the EC-based algorithm: wider interop + smaller key
            // than the MODP variant (DDS Security v1.1 section 9.3.1.1.1).
            key_establishment_algorithm: "ECDH+prime256v1-CEUM".to_string(),
            #[cfg(all(test, feature = "security"))]
            accept_unsigned_remote_documents_for_tests: false,
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
        // Bare builder: revocation OFF for backward compat.
        assert!(!builder.check_certificate_revocation);
        assert_eq!(builder.auth_plugin_kind, AuthPluginKind::X509);
        assert_eq!(builder.key_establishment_algorithm, "ECDH+prime256v1-CEUM");
    }

    #[test]
    fn test_secure_builder_enables_revocation() {
        // secure_builder() must default revocation ON.
        let builder = SecurityConfig::secure_builder();
        assert!(
            builder.check_certificate_revocation,
            "secure_builder must default check_certificate_revocation to true"
        );
        // All other defaults must be identical to the bare builder.
        assert!(!builder.enable_encryption);
        assert!(builder.require_authentication);
        assert_eq!(builder.auth_plugin_kind, AuthPluginKind::X509);
    }

    #[test]
    fn test_auth_plugin_kind_override() {
        // Verify the fluent setter is respected.
        let builder = SecurityConfigBuilder::default().auth_plugin_kind(AuthPluginKind::X509);
        assert_eq!(builder.auth_plugin_kind, AuthPluginKind::X509);
    }

    #[test]
    fn test_key_establishment_algorithm_roundtrip() {
        // Verify the builder method stores the value and build() propagates it.
        // Uses non-existent paths so build() fails at the file-exists check,
        // meaning we can only test the in-builder field -- use default() directly.
        let builder =
            SecurityConfigBuilder::default().key_establishment_algorithm("DH+MODP-2048-256");
        assert_eq!(builder.key_establishment_algorithm, "DH+MODP-2048-256");
    }

    #[test]
    fn test_key_establishment_algorithm_default_is_ecdh() {
        // SecurityConfigBuilder default must select ECDH+prime256v1-CEUM per
        // DDS Security v1.1 section 9.3.1.1.1: this is the EC-based algorithm that
        // provides both interop and smaller key sizes compared to MODP.
        let builder = SecurityConfigBuilder::default();
        assert!(
            builder.key_establishment_algorithm.starts_with("ECDH"),
            "default kagree_algo must be ECDH-based, got {:?}",
            builder.key_establishment_algorithm
        );
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

    /// The legacy partition matching is off unless asked for, with either
    /// builder, and the builder carries it to the configuration.
    #[test]
    fn legacy_partition_matching_defaults_off_and_round_trips() {
        let cert = tempfile::NamedTempFile::new().expect("temp");
        let key = tempfile::NamedTempFile::new().expect("temp");
        let ca = tempfile::NamedTempFile::new().expect("temp");
        let build = |builder: SecurityConfigBuilder| {
            builder
                .identity_certificate(cert.path())
                .private_key(key.path())
                .ca_certificates(ca.path())
                .build()
                .expect("minimal configuration must build")
        };
        assert!(!build(SecurityConfig::builder()).legacy_partition_matching);
        assert!(
            !build(SecurityConfig::secure_builder().check_certificate_revocation(false))
                .legacy_partition_matching
        );
        assert!(
            build(SecurityConfig::builder().legacy_partition_matching(true))
                .legacy_partition_matching
        );
    }

    /// The Permissions CA defaults to absent, and unsigned documents are
    /// refused unless the caller says otherwise.
    #[test]
    fn allow_unsigned_documents_defaults_false() {
        let cert = tempfile::NamedTempFile::new().expect("temp");
        let key = tempfile::NamedTempFile::new().expect("temp");
        let ca = tempfile::NamedTempFile::new().expect("temp");
        let config = SecurityConfig::builder()
            .identity_certificate(cert.path())
            .private_key(key.path())
            .ca_certificates(ca.path())
            .build()
            .expect("minimal configuration must build");
        assert!(!config.insecure_allow_unsigned_documents);
        assert!(config.permissions_ca.is_none());
    }

    /// A Permissions CA path that does not exist is a configuration error, not
    /// a runtime surprise.
    #[test]
    fn permissions_ca_missing_file_is_config_error() {
        let cert = tempfile::NamedTempFile::new().expect("temp");
        let key = tempfile::NamedTempFile::new().expect("temp");
        let ca = tempfile::NamedTempFile::new().expect("temp");
        let err = SecurityConfig::builder()
            .identity_certificate(cert.path())
            .private_key(key.path())
            .ca_certificates(ca.path())
            .permissions_ca("/nonexistent/permissions_ca.pem")
            .build()
            .expect_err("a missing permissions CA must fail the build");
        assert!(
            err.to_string().contains("permissions_ca not found"),
            "got: {}",
            err
        );
    }

    /// The builder round-trips the Permissions CA path.
    #[test]
    fn builder_permissions_ca_roundtrip() {
        let cert = tempfile::NamedTempFile::new().expect("temp");
        let key = tempfile::NamedTempFile::new().expect("temp");
        let ca = tempfile::NamedTempFile::new().expect("temp");
        let perm_ca = tempfile::NamedTempFile::new().expect("temp");
        let config = SecurityConfig::builder()
            .identity_certificate(cert.path())
            .private_key(key.path())
            .ca_certificates(ca.path())
            .permissions_ca(perm_ca.path())
            .insecure_allow_unsigned_documents(true)
            .build()
            .expect("configuration must build");
        assert_eq!(config.permissions_ca.as_deref(), Some(perm_ca.path()));
        assert!(config.insecure_allow_unsigned_documents);
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
