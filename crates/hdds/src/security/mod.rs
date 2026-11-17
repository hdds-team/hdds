// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! DDS Security v1.1 implementation
//!
//! Provides secure DDS communication with:
//! - **Authentication** -- X.509 certificate-based identity verification
//! - **Access Control** -- Permissions XML for topic/partition authorization
//! - **Cryptographic** -- AES-256-GCM encryption for data confidentiality
//! - **Logging** -- Audit trail for security events
//!
//! # Architecture
//!
//! Everything hangs off one `SecurityPluginSuite`, shared via `Arc`:
//!
//! ```text
//! SecurityPluginSuite
//! +-- authentication  (dyn AuthenticationPlugin, X.509 certificate validation)
//! +-- access_control  (access::AccessControlPlugin, permissions XML enforcement)
//! +-- cryptographic   (crypto::CryptoPlugin, the encryption-requested marker;
//! |                    the sealing itself lives in crypto::user_data)
//! +-- logging         (audit::LoggingPlugin, hash-chained audit trail)
//! +-- handshakes      (handshake::HandshakeMachine, PKI-DH per remote peer)
//! +-- data_keys       (crypto::data_keys::DataKeyStore, data-plane writer keys)
//! +-- participant_keys (crypto::participant_keys::ParticipantKeyStore, RTPS message keys)
//! +-- volatile_replay  (crypto::volatile::ReplaySequenceGuard, per-peer high-water mark)
//! +-- volatile        (volatile_channel::VolatileChannel, the volatile channel's state)
//! ```
//!
//! # Usage
//!
//! ```ignore
//! use hdds::api::Participant;
//! use hdds::security::SecurityConfig;
//!
//! let security = SecurityConfig::builder()
//!     .identity_certificate("certs/participant1.pem")
//!     .private_key("certs/participant1_key.pem")
//!     .ca_certificates("certs/ca.pem")
//!     .permissions_xml("permissions.xml")
//!     .enable_encryption(true)
//!     .enable_audit_log(true)
//!     .build()?;
//!
//! let participant = Participant::builder("secure_app")
//!     .security(security)
//!     .build()?;
//! ```
//!
//! # References
//!
//! - [OMG DDS Security v1.1](https://www.omg.org/spec/DDS-SECURITY/1.1/)
//! - [RTPS v2.5 Security Extensions](https://www.omg.org/spec/DDSI-RTPS/2.5/)
//! - [X.509 Certificate Profile (RFC 5280)](https://datatracker.ietf.org/doc/html/rfc5280)

/// Access Control plugin (permissions XML, topic allow/deny rules).
#[cfg(feature = "security")]
pub mod access;
/// Audit logging plugin (audit trail, file backend, ANSSI hash-chain).
#[cfg(feature = "security")]
pub mod audit;
/// Authentication plugins (X.509 handshake implementations).
pub mod authentication;
/// CMS / PKCS#7 SignedData verification against the configured Permissions CA.
///
/// DDS-Security v1.1 9.4.3: a governance or permissions document is only
/// honoured once its signature verifies. The only trust anchor is the
/// configured Permissions CA; certificates carried inside the envelope are
/// never anchors.
#[cfg(feature = "security")]
pub(crate) mod cms;
/// Builder and configuration utilities for DDS security.
pub mod config;
/// Cryptographic plugin (AES-256-GCM encryption, ECDH key exchange).
#[cfg(feature = "security")]
pub mod crypto;
/// End-to-end DDS-Security tests over a real UDP transport (two participants).
#[cfg(all(test, feature = "security"))]
mod e2e_tests;
/// The ParticipantStatelessMessage envelope (DDS Security v1.1 Sec.7.4.3.3)
/// around a handshake token on the wire.
#[cfg(feature = "security")]
pub(crate) mod generic_message;
/// PKI-DH 3-message authentication handshake state machine.
///
/// Drives the Participant-Authentication protocol (DDS Security v1.1 section 9.3.4)
/// for all known remote participants. Tokens are exchanged over the
/// Participant-Stateless-Message builtin channel provided by `stateless`.
#[cfg(feature = "security")]
pub mod handshake;
/// PKCS#7 / S/MIME envelope splitter for governance and permissions files.
///
/// DDS-Security v1.1 9.4.1: governance and permissions documents are wrapped in a
/// PKCS#7 SignedData envelope, as S/MIME multipart/signed text or as DER. The
/// module splits the envelope into document, signed bytes and CMS blob; the
/// signature itself is checked elsewhere.
#[cfg(feature = "security")]
pub(crate) mod p7s;
/// Local restriction overlay: hot-reloadable, deny-only permission rules.
///
/// Complements [`access`], it never replaces it. The signed permissions
/// document remains the only thing that GRANTS; a rule read from this
/// unsigned, hot-reloaded file can only take an action away. See
/// [`permissions::dynamic::DynamicPermissionManager`].
#[cfg(feature = "security")]
pub mod permissions;
/// Endpoint protection resolved once per document generation (the governance
/// walk the write and read data planes used to pay per sample).
#[cfg(feature = "security")]
pub(crate) mod protection_cache;
/// Stateless-channel <-> HandshakeMachine bridge (DDS Security v1.1 gap C3).
///
/// `drain_incoming` routes DATA payloads from the BuiltinParticipantStatelessMessageReader
/// into `HandshakeMachine::on_message` and enqueues any resulting outgoing tokens.
/// `drain_outgoing` harvests encoded tokens for the BuiltinParticipantStatelessMessageWriter.
pub mod pump;
pub(crate) mod revocation;
/// Fail-closed loading of the signed governance and permissions documents.
#[cfg(feature = "security")]
pub(crate) mod signed_document;
/// Participant-Stateless-Message tunnel (DDS Security v1.1 section 7.4.5).
///
/// Plaintext, BEST_EFFORT, VOLATILE channel for the PKI-DH authentication
/// handshake. Provides the queue plumbing only; the handshake-content driver
/// lands in security gap #3.
pub mod stateless;
/// Outbound RTPS writer for the BuiltinParticipantStatelessMessageWriter (entity 0x000201C3).
///
/// Drains `StatelessChannel::tx_tokens` produced by the `HandshakeMachine` and serialises
/// each token into a complete RTPS packet (RTPS header + INFO_DST + INFO_TS + DATA),
/// then sends it via the UDP transport to the remote participant's metatraffic unicast address.
pub mod stateless_writer;
/// Shared PKI fixtures (CA + identity certificate + private key) for tests.
#[cfg(all(test, feature = "security"))]
pub(crate) mod test_pki;
/// The ParticipantVolatileMessageSecure channel state (DDS Security v1.1
/// Sec.7.4.4).
#[cfg(feature = "security")]
pub(crate) mod volatile_channel;

pub use config::{SecurityConfig, SecurityConfigBuilder};

use crate::dds::Error;

/// Security plugin suite
///
/// Holds all 4 security plugins (authentication, access control, cryptographic, logging).
///
/// # Lifecycle
///
/// 1. Created via `SecurityConfig::build()`
/// 2. Attached to `Participant` during creation
/// 3. Plugins invoked during discovery, data send/receive
pub struct SecurityPluginSuite {
    /// Authentication plugin (X.509 certificate validation)
    ///
    /// Connected to DiscoveryFsm via SecurityValidatorAdapter for automatic
    /// participant authentication during SPDP discovery. Remote participants
    /// with invalid identity_tokens are rejected per DDS Security v1.1 Sec.8.4.
    pub(crate) authentication: Box<dyn authentication::AuthenticationPlugin>,

    /// Access Control plugin (permissions XML enforcement)
    ///
    /// Optional: Only created if `governance_xml` and `permissions_xml` are both provided.
    #[cfg(feature = "security")]
    pub(crate) access_control: Option<access::AccessControlPlugin>,

    /// Cryptographic plugin (AES-256-GCM encryption, ECDH key exchange)
    ///
    /// Optional: Only created if `enable_encryption` is true.
    #[cfg(feature = "security")]
    pub(crate) cryptographic: Option<crypto::CryptoPlugin>,

    /// Logging plugin (audit trail with ANSSI-compliant hash-chain)
    ///
    /// Optional: Only created if `enable_audit_log` is true. ONE chain for
    /// the whole suite: the same `Arc` is handed to the handshake machine
    /// and the data-key store at construction, so every family of event
    /// (authentication, access control, crypto) lands in one hash chain.
    /// Carries the sticky degraded flag (see `audit`).
    #[cfg(feature = "security")]
    pub(crate) logging: Option<audit::SharedAuditLogger>,

    /// PKI-DH authentication handshake state machine.
    ///
    /// Manages one `HandshakeState` per remote participant GUID. Drives the
    /// 3-message exchange (AuthRequest / AuthReply / AuthFinal) over the
    /// `StatelessChannel` from `secure_builtins`. Shared across threads via
    /// `Arc` so the SPDP handler and the stateless-channel dispatcher can
    /// both advance it concurrently.
    #[cfg(feature = "security")]
    pub(crate) handshakes: std::sync::Arc<handshake::HandshakeMachine>,

    /// What a REMOTE peer's permissions document has to be judged against.
    ///
    /// `Some` exactly when `access_control` is, and built from the same
    /// verified material: the governance content the loader returned and the
    /// permissions CA it checked it with. Retained here rather than turned
    /// into an evaluator on the spot because the evaluator also needs the
    /// domain id, which only the participant builder knows. See
    /// [`Self::remote_access_control`].
    #[cfg(feature = "security")]
    pub(crate) remote_access_inputs: Option<access::RemoteAccessInputs>,

    /// Data-plane writer keys, local and remote, keyed `(writer GUID, key id)`.
    ///
    /// ONE store for both directions: local writers register what the
    /// distributor announces, and keys received on the volatile channel land
    /// here for readers to look up. See `crypto::data_keys` for why this map
    /// is separate from the handshake map.
    #[cfg(feature = "security")]
    pub(crate) data_keys: std::sync::Arc<crypto::data_keys::DataKeyStore>,

    /// This participant's own key material for whole RTPS message protection
    /// and each authenticated peer's, exchanged as ParticipantCryptoTokens
    /// (Sec.7.4.4.6.1, Table 70/71). Not the key material of secure SEDP.
    #[cfg(feature = "security")]
    pub(crate) participant_keys: crypto::participant_keys::ParticipantKeyStore,

    /// Replay guard for the volatile channel, keyed by source GUID prefix.
    /// See `crypto::volatile::ReplaySequenceGuard`.
    #[cfg(feature = "security")]
    pub(crate) volatile_replay: crypto::volatile::ReplaySequenceGuard,

    /// The ParticipantVolatileMessageSecure channel's own state. See
    /// `volatile_channel::VolatileChannel`.
    #[cfg(feature = "security")]
    pub(crate) volatile: volatile_channel::VolatileChannel,

    /// Local restriction overlay, when `SecurityConfig::permissions_overlay`
    /// names a file.
    ///
    /// Consulted AFTER `access_control` and able only to refuse. It carries
    /// this participant's own subject name because that is what its rules are
    /// matched against, and resolving it once at construction keeps a
    /// certificate re-read off every endpoint creation.
    #[cfg(feature = "security")]
    pub(crate) permissions_overlay: Option<PermissionOverlay>,

    /// Configuration (certificates, permissions, etc.)
    pub(crate) config: SecurityConfig,
}

/// A loaded permission overlay together with the subject its rules apply to.
#[cfg(feature = "security")]
pub(crate) struct PermissionOverlay {
    manager: permissions::dynamic::DynamicPermissionManager,
    subject: access::DistinguishedName,
}

#[cfg(feature = "security")]
impl PermissionOverlay {
    /// Load the overlay file `path` for the participant whose identity
    /// certificate is `identity_certificate`.
    ///
    /// The subject is read from the certificate's DER name
    /// (`access::subject::certificate_subject`), the one reader of
    /// certificate subjects, never from a printed form of it.
    fn load(
        path: &std::path::Path,
        identity_certificate: &std::path::Path,
        poll: Option<std::time::Duration>,
    ) -> Result<Self, Error> {
        let subject = std::fs::read(identity_certificate)
            .map_err(|err| SecurityError::ConfigError(err.to_string()))
            .and_then(|pem| access::subject::certificate_subject(&pem))
            .map_err(|e| {
                Error::Config(format!(
                    "permissions_overlay needs this participant's own subject name and \
                     the identity certificate at {} is unreadable: {}",
                    identity_certificate.display(),
                    e
                ))
            })?;

        let manager = permissions::dynamic::DynamicPermissionManager::new(path.to_path_buf())
            .map_err(|e| {
                Error::Config(format!(
                    "failed to load permissions_overlay from {}: {}",
                    path.display(),
                    e
                ))
            })?;

        if let Some(interval) = poll {
            manager
                .start_watching(interval)
                .map_err(|e| Error::Config(e.to_string()))?;
        }

        Ok(Self { manager, subject })
    }

    /// The overlay's verdict on `action` for `topic` in every one of
    /// `partitions` (the default partition when none is named).
    fn check(
        &self,
        action: permissions::dynamic::RuleAction,
        topic: &str,
        partitions: &[String],
    ) -> Result<(), SecurityError> {
        if partitions.is_empty() {
            return self
                .manager
                .check_local_restriction(&self.subject, topic, "", action);
        }
        for partition in partitions {
            self.manager
                .check_local_restriction(&self.subject, topic, partition, action)?;
        }
        Ok(())
    }
}

impl SecurityPluginSuite {
    /// Create a new security plugin suite
    ///
    /// # The domain
    ///
    /// `domain_id` is a construction parameter and not a later setter because
    /// every access control decision this suite makes is scoped to it:
    /// DDS-Security v1.1 section 9.4.1.3 scopes each grant rule to the domains
    /// it names, and a plugin that does not know where it is cannot apply
    /// that. A suite built without a domain would have to guess, and the guess
    /// would be "every domain" - which is exactly the defect this parameter
    /// closes.
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Certificate files cannot be loaded
    /// - Permissions XML is invalid
    /// - Crypto initialization fails
    pub fn new(config: SecurityConfig, domain_id: u32) -> Result<Self, Error> {
        // Consumed by the access-control block below, which is security-gated;
        // without the feature there is no grant to scope, so the domain has
        // nothing to scope. Named here so the featureless build does not
        // report the parameter unused - the parameter is still right to exist.
        #[cfg(not(feature = "security"))]
        let _ = domain_id;

        // Audit logging is built FIRST so the document loader can record an
        // accepted-unsigned-document event; every other plugin below took its
        // logger from this same value already.
        #[cfg(feature = "security")]
        let logging = if config.enable_audit_log {
            let plugin = match &config.audit_log_path {
                Some(path) => audit::LoggingPlugin::with_file(path).map_err(|e| {
                    Error::Config(format!(
                        "failed to open audit log at {}: {}",
                        path.display(),
                        e
                    ))
                })?,
                None => audit::LoggingPlugin::new(),
            };
            // The RFC 5424 export, when one is configured. Attached AFTER the
            // file so the chain-start marker is written once, to the file
            // alone; every record from here on goes to both.
            let plugin = match config.audit_syslog_address {
                Some(address) => plugin.with_syslog(address).map_err(|e| {
                    Error::Config(format!(
                        "failed to open the audit syslog export to {}: {}",
                        address, e
                    ))
                })?,
                None => plugin,
            };
            Some(std::sync::Arc::new(audit::AuditChain::new(plugin)))
        } else {
            None
        };

        // Access control, once both documents have been VERIFIED against the
        // configured Permissions CA (DDS-Security v1.1 9.4.1.2 / 9.4.1.3 /
        // 9.4.3). Any failure here aborts participant creation.
        // The revocation list, read once here rather than per handshake, and
        // ONLY when `check_certificate_revocation` is on: the flag is the one
        // switch, and a list named while it is off is never loaded, so there
        // is no state where the list is consulted and the flag says it is not.
        // The builder refuses "flag on, no list" and "list, flag off", but the
        // struct has public fields, so both are enforced again here. What CAN
        // still fail is the file, and that fails the participant rather than
        // the handshake - a deployment that cannot read its own CRL has not
        // configured revocation, whatever its flag says.
        #[cfg(feature = "security")]
        let revocation_list: Option<Vec<u8>> = if config.check_certificate_revocation {
            let Some(path) = &config.certificate_revocation_list else {
                return Err(Error::Config(
                    "check_certificate_revocation is on but no certificate_revocation_list \
                     was given; revocation cannot be checked against a list that does not exist"
                        .to_string(),
                ));
            };
            Some(std::fs::read(path).map_err(|e| {
                Error::Config(format!(
                    "failed to read certificate revocation list from {}: {}",
                    path.display(),
                    e
                ))
            })?)
        } else {
            None
        };

        // The signed permissions blob, kept alongside the parsed plugin so the
        // handshake can present it as `c.perm`. Declared out here because the
        // block below returns the plugin, and the blob has to outlive it.
        #[cfg(feature = "security")]
        let mut local_permissions: Option<Vec<u8>> = None;

        // The other half of the same load: what a PEER's document will be
        // judged against. Declared out here for the same reason as
        // `local_permissions` - the block below returns the plugin.
        #[cfg(feature = "security")]
        let mut remote_access_inputs: Option<access::RemoteAccessInputs> = None;

        #[cfg(feature = "security")]
        let access_control = {
            match (&config.governance_xml, &config.permissions_xml) {
                (Some(governance), Some(permissions)) => {
                    let permissions_ca = match &config.permissions_ca {
                        Some(path) => {
                            let pem = std::fs::read(path).map_err(|e| {
                                Error::Config(format!(
                                    "failed to read permissions CA from {}: {}",
                                    path.display(),
                                    e
                                ))
                            })?;
                            Some(cms::PermissionsCa::from_pem(&pem).map_err(|e| {
                                Error::Config(format!(
                                    "permissions CA at {} is unusable: {}",
                                    path.display(),
                                    e
                                ))
                            })?)
                        }
                        None => None,
                    };

                    let policy = signed_document::DocumentPolicy {
                        permissions_ca: permissions_ca.as_ref(),
                        allow_unsigned: config.insecure_allow_unsigned_documents,
                        now_unix: signed_document::now_unix(),
                        audit: logging.as_deref(),
                    };

                    let governance_bytes = std::fs::read(governance).map_err(|e| {
                        Error::Config(format!(
                            "failed to read governance file from {}: {}",
                            governance.display(),
                            e
                        ))
                    })?;
                    let governance_content = signed_document::load_verified(
                        &governance_bytes,
                        &governance.display().to_string(),
                        signed_document::DocumentKind::Governance,
                        &policy,
                    )
                    .map_err(Error::from)?;

                    // Kept verbatim below, not just parsed: this exact blob,
                    // with its CMS signature intact, is what travels as
                    // `c.perm` so the peer can verify it against the
                    // permissions CA. A re-serialised document would not
                    // verify.
                    let permissions_bytes = std::fs::read(permissions).map_err(|e| {
                        Error::Config(format!(
                            "failed to read permissions file from {}: {}",
                            permissions.display(),
                            e
                        ))
                    })?;
                    let permissions_content = signed_document::load_verified(
                        &permissions_bytes,
                        &permissions.display().to_string(),
                        signed_document::DocumentKind::Permissions,
                        &policy,
                    )
                    .map_err(Error::from)?;
                    // Only after it verified against OUR permissions CA. We do
                    // not hand a peer a document we have not checked ourselves.
                    local_permissions = Some(permissions_bytes);

                    // A peer's document is verified against the SAME anchor and
                    // read against the SAME governance, so both are kept here
                    // rather than re-read from disk later: a governance file
                    // edited between participant build and peer discovery must
                    // not change the rules half way through a run.
                    remote_access_inputs = Some(access::RemoteAccessInputs {
                        governance_xml: governance_content.clone(),
                        permissions_ca: permissions_ca.clone(),
                        #[cfg(test)]
                        accept_unsigned_for_tests: config
                            .accept_unsigned_remote_documents_for_tests,
                        legacy_partition_matching: config.legacy_partition_matching,
                    });

                    // DDS-Security v1.1 9.4.3: only the grants issued to THIS
                    // identity, and only while they are in force.
                    let identity_cert =
                        std::fs::read(&config.identity_certificate).map_err(|e| {
                            Error::Config(format!(
                                "failed to read identity certificate {}: {}",
                                config.identity_certificate.display(),
                                e
                            ))
                        })?;
                    let identity = access::subject::certificate_subject(&identity_cert)?;

                    if let Ok(governance) =
                        access::permissions::GovernanceConfig::parse(&governance_content)
                    {
                        for warning in governance.unauthenticated_access_control_warnings(domain_id)
                        {
                            log::warn!("[security] {}", warning);
                        }
                    }

                    Some(
                        access::AccessControlPlugin::from_documents_for_name(
                            &governance_content,
                            &permissions_content,
                            &identity,
                            policy.now_unix,
                            domain_id,
                        )
                        .map_err(|e| {
                            Error::Config(format!("failed to apply access control XML: {}", e))
                        })?
                        .with_legacy_partition_matching(config.legacy_partition_matching),
                    )
                }
                // Access control needs BOTH documents: the governance file
                // says which domains are protected and the permissions file
                // says what this participant may do in them. Half a
                // configuration used to disable access control silently, which
                // reads from the outside exactly like the verified path.
                (Some(_), None) => {
                    return Err(Error::Config(
                        "governance_xml is set but permissions_xml is not: DDS-Security v1.1 \
                         9.4.1.2/9.4.1.3 access control needs both documents, and half a \
                         configuration would run fully permissive"
                            .to_string(),
                    ))
                }
                (None, Some(_)) => {
                    return Err(Error::Config(
                        "permissions_xml is set but governance_xml is not: DDS-Security v1.1 \
                         9.4.1.2/9.4.1.3 access control needs both documents, and half a \
                         configuration would run fully permissive"
                            .to_string(),
                    ))
                }
                // No access control configured at all.
                (None, None) => None,
            }
        };

        // Initialize cryptographic plugin if encryption is enabled
        #[cfg(feature = "security")]
        let cryptographic = if config.enable_encryption {
            Some(crypto::CryptoPlugin::new())
        } else {
            None
        };

        // The list is re-read while the participant runs, from the file it was
        // loaded from, and judged against the CA certificates it was loaded with.
        #[cfg(feature = "security")]
        let revocation_source: Option<(Box<dyn revocation::RevocationFile>, Vec<u8>)> =
            match &config.certificate_revocation_list {
                Some(path) if revocation_list.is_some() => {
                    let ca = std::fs::read(&config.ca_certificates).map_err(|e| {
                        Error::Config(format!(
                            "failed to read CA certificates from {}: {}",
                            config.ca_certificates.display(),
                            e
                        ))
                    })?;
                    Some((Box::new(revocation::FileRevocation(path.clone())), ca))
                }
                _ => None,
            };

        // The list in force is one cell, shared by the handshake machine (which
        // re-reads the file into it) and the authentication plugin (which judges
        // the local identity against it), so that both judge against the same list.
        #[cfg(feature = "security")]
        let list_in_force: revocation::ListInForce =
            std::sync::Arc::new(parking_lot::Mutex::new(revocation_list.clone()));
        #[cfg(not(feature = "security"))]
        let list_in_force: revocation::ListInForce =
            std::sync::Arc::new(parking_lot::Mutex::new(None));

        // Initialize authentication plugin (always required)
        let authentication = authentication::create_authentication_plugin_sharing(
            &config,
            std::sync::Arc::clone(&list_in_force),
        )?;

        #[cfg(feature = "security")]
        let handshakes = std::sync::Arc::new(
            handshake::HandshakeMachine::with_kagree_algo(&config.key_establishment_algorithm)
                .with_audit_logger(logging.clone())
                .with_shared_revocation(std::sync::Arc::clone(&list_in_force))
                .with_revocation_file(revocation_source)
                .with_local_permissions(local_permissions.clone()),
        );
        #[cfg(feature = "security")]
        let data_keys = std::sync::Arc::new(crypto::data_keys::DataKeyStore::with_audit_logger(
            logging.clone(),
        ));
        #[cfg(feature = "security")]
        let participant_keys = crypto::participant_keys::ParticipantKeyStore::new(
            config.enable_encryption,
            logging.clone(),
        )?;
        #[cfg(feature = "security")]
        let volatile_replay = crypto::volatile::ReplaySequenceGuard::new();
        #[cfg(feature = "security")]
        let volatile = volatile_channel::VolatileChannel::new();

        // The local restriction overlay. Every failure here is fatal on
        // purpose: it was configured to CLOSE something, so a participant that
        // starts without it enforces less than its operator asked for.
        #[cfg(feature = "security")]
        let permissions_overlay = match &config.permissions_overlay {
            Some(path) => Some(PermissionOverlay::load(
                path,
                &config.identity_certificate,
                config.permissions_overlay_poll,
            )?),
            None => None,
        };

        Ok(Self {
            authentication,
            #[cfg(feature = "security")]
            access_control,
            #[cfg(feature = "security")]
            cryptographic,
            #[cfg(feature = "security")]
            logging,
            #[cfg(feature = "security")]
            handshakes,
            #[cfg(feature = "security")]
            remote_access_inputs,
            #[cfg(feature = "security")]
            data_keys,
            #[cfg(feature = "security")]
            participant_keys,
            #[cfg(feature = "security")]
            volatile_replay,
            #[cfg(feature = "security")]
            volatile,
            #[cfg(feature = "security")]
            permissions_overlay,
            config,
        })
    }

    /// Check if security is enabled
    pub fn is_enabled(&self) -> bool {
        true
    }

    /// Check if encryption is enabled
    pub fn is_encryption_enabled(&self) -> bool {
        self.config.enable_encryption
    }

    /// Check if audit logging is enabled
    pub fn is_audit_log_enabled(&self) -> bool {
        self.config.enable_audit_log
    }

    /// Check if access control is enabled
    #[cfg(feature = "security")]
    pub fn is_access_control_enabled(&self) -> bool {
        self.access_control.is_some()
    }

    /// Get reference to access control plugin
    #[cfg(feature = "security")]
    pub fn access_control(&self) -> Option<&access::AccessControlPlugin> {
        self.access_control.as_ref()
    }

    /// Apply the local restriction overlay to one endpoint creation.
    ///
    /// `Ok(())` when no overlay is configured, when it names no rule for this
    /// participant, or when its rules allow the action. It can only REFUSE:
    /// the signed permissions document remains the only thing that grants
    /// anything (DDS-Security v1.1 section 9.4.1.3), and this file is read
    /// after that decision, never instead of it.
    ///
    /// The overlay is evaluated on EVERY partition the endpoint is in, as
    /// the signed document is (DDS-Security v1.1 Sec.9.4.1.3.2.3.1.4): a
    /// refusal in any one of them refuses the endpoint. No partition named
    /// is the default partition, the empty string.
    #[cfg(feature = "security")]
    pub(crate) fn check_local_restriction(
        &self,
        action: permissions::dynamic::RuleAction,
        topic: &str,
        partitions: &[String],
    ) -> Result<(), SecurityError> {
        let Some(overlay) = &self.permissions_overlay else {
            return Ok(());
        };
        overlay.check(action, topic, partitions)
    }

    /// Whether the overlay has a PARTITION-SCOPED rule for `action` on
    /// `topic`: `false` without an overlay. When `true`,
    /// [`Self::check_local_restriction`] against the default partition (or
    /// no partition) is not authoritative for every partition a remote
    /// endpoint might announce, and the caller must re-check once the
    /// endpoint's own announced partitions are known
    /// ([`permissions::dynamic::DynamicPermissionManager::has_partition_scoped_rule`]).
    #[cfg(feature = "security")]
    pub(crate) fn local_restriction_is_partition_scoped(
        &self,
        action: permissions::dynamic::RuleAction,
        topic: &str,
    ) -> bool {
        self.permissions_overlay.as_ref().is_some_and(|overlay| {
            overlay
                .manager
                .has_partition_scoped_rule(&overlay.subject, topic, action)
        })
    }

    /// How many times the local restriction overlay's document has been
    /// replaced by a reload, `0` without an overlay. The value a remote-
    /// admission cache keyed on it (`DiscoveryFsm::admission_epoch`) must
    /// see move for a revoking reload to be noticed without a per-packet
    /// re-check.
    #[cfg(feature = "security")]
    pub(crate) fn local_restriction_generation(&self) -> u64 {
        self.permissions_overlay
            .as_ref()
            .map_or(0, |overlay| overlay.manager.generation())
    }

    /// Whether ANY policy has a say in endpoint creation.
    ///
    /// False for a suite built with neither the signed documents nor an
    /// overlay: such a participant takes no endpoint decision, so it writes no
    /// `AccessControl` record. A record saying "Allowed" when nothing was
    /// consulted would put a decision nobody made into the audit chain.
    #[cfg(feature = "security")]
    pub(crate) fn evaluates_endpoint_access(&self) -> bool {
        self.access_control.is_some() || self.permissions_overlay.is_some()
    }

    /// Force the local restriction overlay to re-read its file now, outside
    /// `SecurityConfig::permissions_overlay_poll`'s own schedule. `Ok(None)`
    /// without an overlay configured at all; otherwise the watcher's own
    /// [`permissions::dynamic::ReloadResult`].
    ///
    /// Reaches past this participant's running endpoints too: a revoking
    /// reload moves [`Self::local_restriction_generation`], and every
    /// matched remote endpoint whose admission reads it is judged again at
    /// its next packet (`DiscoveryFsm::admission_epoch`), not only new ones.
    ///
    /// # Errors
    ///
    /// Whatever reading or parsing the file failed with
    /// ([`permissions::dynamic::DynamicPermissionManager::reload`]).
    #[cfg(feature = "security")]
    pub fn reload_permissions_overlay(
        &self,
    ) -> Result<Option<permissions::dynamic::ReloadResult>, SecurityError> {
        match &self.permissions_overlay {
            Some(overlay) => overlay.manager.reload().map(Some),
            None => Ok(None),
        }
    }

    /// Get reference to cryptographic plugin
    #[cfg(feature = "security")]
    pub fn cryptographic(&self) -> Option<&crypto::CryptoPlugin> {
        self.cryptographic.as_ref()
    }

    /// Build the evaluator that judges a REMOTE peer's endpoints on `domain_id`.
    ///
    /// `None` when this participant was configured without access control, and
    /// the discovery gate is then never installed: a participant that declared
    /// no governance has nothing to judge a peer against, and must behave
    /// exactly as it did before this gate existed.
    ///
    /// Returns a fresh evaluator, with a fresh verdict cache, on every call.
    /// It is called once per participant, from `discovery_setup`, which is the
    /// first place both the suite and the domain id are in scope.
    #[cfg(feature = "security")]
    pub(crate) fn remote_access_control(
        &self,
        domain_id: u32,
    ) -> Option<std::sync::Arc<access::RemoteAccessControl>> {
        let inputs = self.remote_access_inputs.clone()?;
        Some(std::sync::Arc::new(access::RemoteAccessControl::new(
            inputs, domain_id,
        )))
    }

    // There is no `&mut` accessor for the cryptographic plugin: the suite
    // exists only behind an `Arc` handed out by clone, so no `&mut Self` can be
    // obtained at runtime. Per-peer key state lives in `HandshakeMachine`
    // instead, which is `&self`-mutable through its internal `RwLock`.

    /// Get reference to the suite's audit chain.
    ///
    /// The chain, not the raw plugin behind it: every append has to pass
    /// [`audit::AuditChain::record`], which is what marks the chain degraded
    /// when a record is lost. Handing out the plugin's mutex would have left
    /// a public door around the fail-closed gates that read that flag.
    #[cfg(feature = "security")]
    pub fn logging(&self) -> Option<&audit::AuditChain> {
        self.logging.as_deref()
    }

    /// True once the audit chain has lost a record.
    ///
    /// Sticky for the life of the suite. While set, the handshake machine
    /// refuses to start or advance any handshake and the data-key store
    /// refuses to install any new key (fail closed); the participant must be
    /// rebuilt with a working audit backend. Always `false` when audit
    /// logging is disabled.
    #[cfg(feature = "security")]
    pub fn is_audit_degraded(&self) -> bool {
        audit::is_degraded(&self.logging)
    }

    /// Log a security event (thread-safe)
    ///
    /// Returns Ok(()) if logging is disabled or if the event was logged
    /// successfully. A failure marks the chain degraded before it is returned.
    #[cfg(feature = "security")]
    pub fn log_security_event(
        &self,
        event: &audit::SecurityEvent,
    ) -> Result<(), crate::security::SecurityError> {
        match &self.logging {
            Some(chain) => chain.record(event),
            None => Ok(()),
        }
    }

    /// Get reference to authentication plugin
    pub fn authentication(&self) -> &dyn authentication::AuthenticationPlugin {
        self.authentication.as_ref()
    }

    /// Get reference to configuration
    pub fn config(&self) -> &SecurityConfig {
        &self.config
    }

    /// Build the SPDP IdentityToken and PermissionsToken DataHolders.
    ///
    /// Returns serialized values ready to be carried in
    /// `PID_IDENTITY_TOKEN` (0x1001) and `PID_PERMISSIONS_TOKEN` (0x1007)
    /// per DDS Security v1.1 section 7.4.1.4. Each value uses the DataHolder CDR
    /// layout (section 7.2.4).
    ///
    /// # IdentityToken (DDS Security v1.1 section 9.3.2.1)
    ///
    /// `class_id = "DDS:Auth:PKI-DH:1.0"` and 4 string properties:
    /// - `dds.cert.sn` -- identity certificate Subject DN (RFC 4514)
    /// - `dds.cert.algo` -- identity signature algorithm string
    ///   (`RSA-2048`, `RSA-3072`, `RSA-4096`, `EC-prime256v1`,
    ///   `EC-secp384r1`)
    /// - `dds.ca.sn` -- identity CA Subject DN
    /// - `dds.ca.algo` -- identity CA signature algorithm
    ///
    /// # PermissionsToken (DDS Security v1.1 section 9.4.2.3)
    ///
    /// `class_id = "DDS:Access:Permissions:1.0"` and 2 string properties:
    /// - `dds.perm_ca.sn` -- permissions CA Subject DN
    /// - `dds.perm_ca.algo` -- permissions CA signature algorithm
    ///
    /// The DER cert itself is exchanged during the PKI-DH handshake, not in
    /// SPDP, hence no binary properties.
    ///
    /// # Errors
    ///
    /// Returns `Err` if any certificate file cannot be read, parsed, or
    /// inspected. Bootstrap is expected to propagate the error so a
    /// security-enabled participant never starts with malformed material.
    /// `dds.perm_ca.*` describes the configured Permissions CA. It falls back
    /// to `ca_certificates` only when no Permissions CA is configured at all,
    /// which is only reachable when no governance or permissions document is
    /// in use: as soon as one is, `SecurityConfigBuilder::build` requires a
    /// Permissions CA.
    /// The DER SubjectName of this participant's identity certificate: what
    /// its GUID prefix is bound to (`authentication::guid_binding`).
    #[cfg(feature = "security")]
    pub(crate) fn identity_subject_name_der(&self) -> Result<Vec<u8>, SecurityError> {
        let pem = std::fs::read(self.config.identity_certificate.as_path()).map_err(|err| {
            SecurityError::ConfigError(format!(
                "cannot read identity_certificate {}: {}",
                self.config.identity_certificate.display(),
                err
            ))
        })?;
        authentication::guid_binding::subject_name_der(&pem)
    }

    #[cfg(feature = "security")]
    pub fn build_spdp_tokens(&self) -> Result<(Vec<u8>, Vec<u8>), SecurityError> {
        use crate::protocol::discovery::spdp::data_holder::serialize_data_holder;

        let (identity_sn, identity_algo) = describe_certificate(&self.config.identity_certificate)?;
        let (identity_ca_sn, identity_ca_algo) =
            describe_certificate(&self.config.ca_certificates)?;
        let (perm_ca_sn, perm_ca_algo) = describe_certificate(
            self.config
                .permissions_ca
                .as_ref()
                .unwrap_or(&self.config.ca_certificates),
        )?;

        let identity_token = serialize_data_holder(
            "DDS:Auth:PKI-DH:1.0",
            &[
                ("dds.cert.sn".to_string(), identity_sn, true),
                ("dds.cert.algo".to_string(), identity_algo, true),
                ("dds.ca.sn".to_string(), identity_ca_sn, true),
                ("dds.ca.algo".to_string(), identity_ca_algo, true),
            ],
            &[],
        )
        .map_err(|e| {
            SecurityError::ConfigError(format!(
                "{} token does not fit its CDR length fields: {:?}",
                "identity", e
            ))
        })?;

        let permissions_token = serialize_data_holder(
            "DDS:Access:Permissions:1.0",
            &[
                ("dds.perm_ca.sn".to_string(), perm_ca_sn, true),
                ("dds.perm_ca.algo".to_string(), perm_ca_algo, true),
            ],
            &[],
        )
        .map_err(|e| {
            SecurityError::ConfigError(format!(
                "{} token does not fit its CDR length fields: {:?}",
                "permissions", e
            ))
        })?;

        Ok((identity_token, permissions_token))
    }
}

/// Inspect a PEM-encoded certificate and return `(subject_dn, signature_algo)`.
///
/// `subject_dn` is the RFC 4514 string of the certificate's Subject. The
/// `signature_algo` string follows the DDS-Security v1.1 section 9.3.2.1 / section 9.4.2.3
/// canonical naming:
/// - RSA keys yield `RSA-2048`, `RSA-3072`, `RSA-4096` (length derived from
///   the modulus); other sizes yield `RSA-<bits>`.
/// - EC keys yield `EC-prime256v1`, `EC-secp384r1`, `EC-secp521r1`; unknown
///   curves yield `EC-<oid>`.
/// - Unknown key types yield `<oid>` directly. This keeps the property
///   present (spec requires it) without inventing a name.
#[cfg(feature = "security")]
fn describe_certificate(path: &std::path::Path) -> Result<(String, String), SecurityError> {
    use x509_parser::pem::parse_x509_pem;

    let pem_bytes = std::fs::read(path).map_err(|err| {
        SecurityError::ConfigError(format!("Failed to read certificate {:?}: {}", path, err))
    })?;

    let (_, pem) = parse_x509_pem(&pem_bytes).map_err(|err| {
        SecurityError::ConfigError(format!("Failed to parse PEM for {:?}: {}", path, err))
    })?;

    let (_, cert) = x509_parser::parse_x509_certificate(&pem.contents).map_err(|err| {
        SecurityError::ConfigError(format!(
            "Failed to parse X.509 certificate {:?}: {}",
            path, err
        ))
    })?;

    let subject_dn = cert.subject().to_string();
    let algo = describe_subject_pki(&cert.tbs_certificate.subject_pki);
    Ok((subject_dn, algo))
}

/// Map a parsed `SubjectPublicKeyInfo` to a DDS-Security v1.1 algorithm string.
///
/// For EC keys the named curve is derived from the public key size
/// (uncompressed `04 || X || Y` -> 2*bytes => bits = bytes*8/2 per
/// `x509_parser::public_key::ECPoint::key_size`). This sidesteps having
/// to re-parse the `AlgorithmIdentifier::parameters` OID, which is
/// awkward through the `asn1_rs::Any` shim x509-parser exposes.
#[cfg(feature = "security")]
fn describe_subject_pki(spki: &x509_parser::x509::SubjectPublicKeyInfo<'_>) -> String {
    use x509_parser::public_key::PublicKey;

    let oid_id = spki.algorithm.algorithm.to_id_string();

    match spki.parsed() {
        Ok(PublicKey::RSA(rsa)) => {
            // RSAPublicKey::key_size accounts for the leading-zero DER quirk
            // (returns 0 when the high bit is set on the modulus). Fall back
            // to a manual count when key_size reports 0.
            let bits = match rsa.key_size() {
                0 => rsa.modulus.iter().filter(|b| **b != 0).count() * 8,
                n => n,
            };
            match bits {
                2048 => "RSA-2048".to_string(),
                3072 => "RSA-3072".to_string(),
                4096 => "RSA-4096".to_string(),
                other => format!("RSA-{}", other),
            }
        }
        Ok(PublicKey::EC(ec)) => match ec.key_size() {
            // RFC 5480: prime256v1 has 256-bit coordinates,
            // secp384r1 384, secp521r1 521 (rounded to 528 on
            // ECPoint::key_size which counts bytes).
            256 => "EC-prime256v1".to_string(),
            384 => "EC-secp384r1".to_string(),
            520 | 521 | 528 => "EC-secp521r1".to_string(),
            other => format!("EC-{}", other),
        },
        // Other key types: keep the algorithm OID string. The property
        // must be present per spec but no canonical short string exists.
        _ => oid_id,
    }
}

impl std::fmt::Debug for SecurityPluginSuite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug = f.debug_struct("SecurityPluginSuite");
        debug.field("authentication", &self.authentication);

        #[cfg(feature = "security")]
        {
            debug.field(
                "access_control",
                &self.access_control.as_ref().map(|_| "AccessControlPlugin"),
            );
            debug.field(
                "cryptographic",
                &self.cryptographic.as_ref().map(|_| "CryptoPlugin"),
            );
            debug.field(
                "logging",
                &self.logging.as_ref().map(|chain| {
                    if chain.is_degraded() {
                        "AuditChain(degraded)"
                    } else {
                        "AuditChain"
                    }
                }),
            );
            debug.field("handshakes", &"HandshakeMachine");
        }

        debug.field("config", &self.config);
        debug.finish()
    }
}

/// Security error types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityError {
    /// Certificate validation failed
    CertificateInvalid(String),

    /// Certificate expired
    CertificateExpired,

    /// Certificate revoked (CRL/OCSP)
    CertificateRevoked,

    /// Authentication handshake failed
    AuthenticationFailed(String),

    /// Permissions denied
    PermissionsDenied(String),

    /// Encryption/decryption failed
    CryptoFailed(String),

    /// Cryptographic operation error (AES-GCM, ECDH, HKDF)
    CryptoError(String),

    /// Configuration error
    ConfigError(String),
}

impl std::fmt::Display for SecurityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CertificateInvalid(msg) => write!(f, "Certificate invalid: {}", msg),
            Self::CertificateExpired => write!(f, "Certificate expired"),
            Self::CertificateRevoked => write!(f, "Certificate revoked"),
            Self::AuthenticationFailed(msg) => write!(f, "Authentication failed: {}", msg),
            Self::PermissionsDenied(msg) => write!(f, "Permissions denied: {}", msg),
            Self::CryptoFailed(msg) => write!(f, "Crypto operation failed: {}", msg),
            Self::CryptoError(msg) => write!(f, "Cryptographic error: {}", msg),
            Self::ConfigError(msg) => write!(f, "Security configuration error: {}", msg),
        }
    }
}

impl std::error::Error for SecurityError {}

impl From<SecurityError> for Error {
    fn from(err: SecurityError) -> Self {
        Error::Config(err.to_string())
    }
}

// ============================================================================
// Security Validator Adapter (DDS Security v1.1 Sec.8.4)
// ============================================================================
//
// Bridges AuthenticationPlugin to DiscoveryFsm's SecurityValidator trait.
// This enables automatic participant authentication during SPDP discovery.

#[cfg(feature = "security")]
mod validator_adapter {
    use super::SecurityPluginSuite;
    use crate::core::discovery::multicast::SecurityValidator;
    use crate::core::discovery::GUID;
    use std::sync::Arc;

    /// Adapter that bridges AuthenticationPlugin to SecurityValidator.
    ///
    /// Used by DiscoveryFsm to validate incoming participant identity_tokens
    /// during SPDP discovery. Delegates to the AuthenticationPlugin from
    /// SecurityPluginSuite.
    ///
    /// # DDS Security Spec Reference
    ///
    /// Per DDS Security v1.1 Sec.8.4.2.3:
    /// > "The Authentication Plugin shall verify that the identity_token
    /// > presented by a remote DomainParticipant is valid and trusted."
    pub struct SecurityValidatorAdapter {
        security_suite: Arc<SecurityPluginSuite>,
    }

    impl SecurityValidatorAdapter {
        /// Create a new adapter wrapping the security suite.
        pub fn new(security_suite: Arc<SecurityPluginSuite>) -> Self {
            Self { security_suite }
        }
    }

    impl SecurityValidator for SecurityValidatorAdapter {
        /// Validate a remote participant's identity token.
        ///
        /// The identity_token from SPDP is a serialized
        /// `DataHolder` (DDS Security v1.1 section 7.2.4) carrying the remote
        /// participant's certificate Subject DN, signature algorithm, and
        /// CA Subject DN per section 9.3.2.1. We decode the CDR and validate that
        /// (a) the payload is well-formed and (b) its class id is ours as
        /// validate_remote_identity compares them (Sec.9.3.3, Table 52: the
        /// PluginClassName `DDS:Auth:PKI-DH` and the MajorVersion `1`). Its
        /// properties are optional (Table 45, "The presence of each of
        /// properties is optional"; Cyclone DDS sends none) and are not
        /// read. The actual certificate chain is verified during the
        /// subsequent PKI-DH handshake; this method is the pre-handshake
        /// admission check.
        fn validate_identity(
            &self,
            participant_guid: GUID,
            identity_token: &[u8],
        ) -> Result<(), String> {
            use crate::protocol::discovery::spdp::data_holder::parse_data_holder;

            // Validate local identity first (ensures our own cert is valid).
            self.security_suite
                .authentication()
                .validate_identity()
                .map_err(|e| format!("Local identity validation failed: {}", e))?;

            // Decode the wire DataHolder. Bytes come straight from
            // `parse_spdp` so they are the raw CDR value of PID 0x1001.
            let holder = parse_data_holder(identity_token).ok_or_else(|| {
                let reason = "malformed IdentityToken DataHolder CDR".to_string();
                log::warn!(
                    "[security] Rejected participant {:?}: {}",
                    participant_guid,
                    reason
                );
                reason
            })?;

            // "<PluginClassName>:<MajorVersion>.<MinorVersion>", the
            // PluginClassName ending at the last ':' (Sec.9.3.2.1).
            let same_plugin = holder
                .class_id
                .rsplit_once(':')
                .and_then(|(plugin, version)| Some((plugin, version.split_once('.')?.0)))
                .is_some_and(|(plugin, major)| plugin == "DDS:Auth:PKI-DH" && major == "1");
            if !same_plugin {
                let reason = format!("unexpected IdentityToken class_id {:?}", holder.class_id);
                log::warn!(
                    "[security] Rejected participant {:?}: {}",
                    participant_guid,
                    reason
                );
                return Err(reason);
            }

            let cert_sn = holder
                .properties
                .iter()
                .find(|(n, _, _)| n == "dds.cert.sn")
                .map(|(_, v, _)| v.as_str())
                .unwrap_or("");
            let ca_sn = holder
                .properties
                .iter()
                .find(|(n, _, _)| n == "dds.ca.sn")
                .map(|(_, v, _)| v.as_str())
                .unwrap_or("");

            log::debug!(
                "[security] Admitted participant {:?} (cert.sn={:?} ca.sn={:?})",
                participant_guid,
                cert_sn,
                ca_sn
            );
            Ok(())
        }
    }
}

#[cfg(feature = "security")]
pub use validator_adapter::SecurityValidatorAdapter;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_error_display() {
        let err = SecurityError::CertificateInvalid("bad format".to_string());
        assert_eq!(err.to_string(), "Certificate invalid: bad format");

        let err = SecurityError::CertificateExpired;
        assert_eq!(err.to_string(), "Certificate expired");

        let err = SecurityError::AuthenticationFailed("challenge mismatch".to_string());
        assert_eq!(err.to_string(), "Authentication failed: challenge mismatch");
    }

    #[test]
    fn test_security_error_into_api_error() {
        let sec_err = SecurityError::CertificateExpired;
        let api_err: Error = sec_err.into();
        assert!(matches!(api_err, Error::Config(_)));
    }

    /// DDS-Security v1.1 Sec.9.4.1.3: a rule applies to the subject name of
    /// the identity certificate. A certificate whose ONE attribute is the
    /// common name `bob, O=Admin` is not the subject `CN=bob,O=Admin` (two
    /// attributes), so the overlay file naming that subject says nothing
    /// about this participant; the file that escapes the comma does.
    #[cfg(feature = "security")]
    #[test]
    fn a_comma_in_the_identity_name_takes_no_other_subjects_overlay_rules() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        fn file(contents: &[u8]) -> NamedTempFile {
            let mut f = NamedTempFile::new().expect("temp file");
            f.write_all(contents).expect("write");
            f
        }

        let cert = file(&access::subject::certificate_named("bob, O=Admin"));
        let action = permissions::dynamic::RuleAction::Publish;

        let other = file(b"[subject: CN=bob,O=Admin]\ndefault: allow\ndeny publish: T\n");
        let overlay = PermissionOverlay::load(other.path(), cert.path(), None).expect("loads");
        assert!(
            overlay.check(action, "T", &[]).is_ok(),
            "a common name holding a comma took the rules of the subject CN=bob,O=Admin"
        );

        let own = file(b"[subject: CN=bob\\, O=Admin]\ndefault: allow\ndeny publish: T\n");
        let overlay = PermissionOverlay::load(own.path(), cert.path(), None).expect("loads");
        assert!(
            overlay.check(action, "T", &[]).is_err(),
            "the overlay naming the escaped common name did not apply to its owner"
        );
    }

    /// Fail-closed loading of the signed governance and permissions documents
    /// (DDS-Security v1.1 9.4.1.2 / 9.4.1.3 / 9.4.3).
    #[cfg(feature = "security")]
    mod signed_documents {
        use crate::security::test_pki::{
            GOVERNANCE_EC_SMIME, GOVERNANCE_PLAIN_XML, PERMISSIONS_EC_SMIME,
            PERMISSIONS_EXPIRED_GRANT_SMIME, PERMISSIONS_OTHER_CA_SMIME,
            PERMISSIONS_OTHER_SUBJECT_SMIME, PERMISSIONS_PLAIN_XML, PERMISSIONS_TAMPERED_SMIME,
            PERM_CA_EC_PEM, TEST_CA_CERT_PEM, TEST_IDENTITY_CERT_PEM, TEST_IDENTITY_KEY_PEM,
        };
        use crate::security::{SecurityConfig, SecurityPluginSuite};
        use std::io::Write;
        use tempfile::NamedTempFile;

        fn temp(bytes: &[u8]) -> NamedTempFile {
            let mut f = NamedTempFile::new().expect("temp file");
            f.write_all(bytes).expect("write fixture");
            f.flush().expect("flush fixture");
            f
        }

        /// Build a suite whose access-control documents are the two byte blobs given.
        fn suite_from(
            governance: &[u8],
            permissions: &[u8],
        ) -> Result<SecurityPluginSuite, crate::dds::Error> {
            let cert = temp(TEST_IDENTITY_CERT_PEM);
            let key = temp(TEST_IDENTITY_KEY_PEM);
            let ca = temp(TEST_CA_CERT_PEM);
            let perm_ca = temp(PERM_CA_EC_PEM);
            let gov = temp(governance);
            let perms = temp(permissions);

            let config = SecurityConfig::builder()
                .identity_certificate(cert.path())
                .private_key(key.path())
                .ca_certificates(ca.path())
                .permissions_ca(perm_ca.path())
                .governance_xml(gov.path())
                .permissions_xml(perms.path())
                .build()?;

            SecurityPluginSuite::new(config, 0)
        }

        /// Build a suite that names only ONE of the two documents.
        fn suite_from_one(
            governance: Option<&[u8]>,
            permissions: Option<&[u8]>,
        ) -> Result<SecurityPluginSuite, crate::dds::Error> {
            let cert = temp(TEST_IDENTITY_CERT_PEM);
            let key = temp(TEST_IDENTITY_KEY_PEM);
            let ca = temp(TEST_CA_CERT_PEM);
            let perm_ca = temp(PERM_CA_EC_PEM);
            let gov = governance.map(temp);
            let perms = permissions.map(temp);

            let mut builder = SecurityConfig::builder()
                .identity_certificate(cert.path())
                .private_key(key.path())
                .ca_certificates(ca.path())
                .permissions_ca(perm_ca.path());
            if let Some(gov) = gov.as_ref() {
                builder = builder.governance_xml(gov.path());
            }
            if let Some(perms) = perms.as_ref() {
                builder = builder.permissions_xml(perms.path());
            }

            SecurityPluginSuite::new(builder.build()?, 0)
        }

        /// A permissions document with no governance document is a
        /// configuration error, not silently-disabled access control.
        #[test]
        fn suite_new_rejects_a_permissions_document_with_no_governance() {
            let err = suite_from_one(None, Some(PERMISSIONS_EC_SMIME))
                .expect_err("half a configuration must not run permissive");
            let text = err.to_string();
            assert!(text.contains("governance_xml is not"), "got: {}", text);
        }

        /// And the same the other way round.
        #[test]
        fn suite_new_rejects_a_governance_document_with_no_permissions() {
            let err = suite_from_one(Some(GOVERNANCE_EC_SMIME), None)
                .expect_err("half a configuration must not run permissive");
            let text = err.to_string();
            assert!(text.contains("permissions_xml is not"), "got: {}", text);
        }

        /// Naming neither document leaves access control off, as before.
        #[test]
        fn suite_new_without_either_document_has_no_access_control() {
            let suite = suite_from_one(None, None).expect("no access control is a valid setup");
            assert!(suite.access_control().is_none());
        }

        /// A governance and a permissions document signed by the configured
        /// permissions CA are accepted.
        #[test]
        fn suite_new_accepts_ec_signed_governance_and_permissions() {
            suite_from(GOVERNANCE_EC_SMIME, PERMISSIONS_EC_SMIME)
                .expect("documents signed by the configured permissions CA must be accepted");
        }

        /// A permissions document whose XML was edited after signing is refused.
        #[test]
        fn suite_new_rejects_forged_permissions() {
            let err = suite_from(GOVERNANCE_EC_SMIME, PERMISSIONS_TAMPERED_SMIME)
                .expect_err("a tampered permissions document must be refused");
            let text = err.to_string();
            assert!(
                text.contains("permissions"),
                "error must name the document: {}",
                text
            );
        }

        /// A permissions document signed by a different CA is refused.
        #[test]
        fn suite_new_rejects_documents_signed_by_other_ca() {
            suite_from(GOVERNANCE_EC_SMIME, PERMISSIONS_OTHER_CA_SMIME)
                .expect_err("a document signed by an unconfigured CA must be refused");
        }

        /// Plain, unsigned XML is refused unless the caller opts in explicitly.
        #[test]
        fn suite_new_rejects_unsigned_permissions() {
            suite_from(GOVERNANCE_PLAIN_XML, PERMISSIONS_PLAIN_XML)
                .expect_err("unsigned documents must be refused by default");
        }

        /// A permissions document that verifies perfectly but was issued to
        /// another subject grants nothing (DDS-Security v1.1 9.4.3).
        #[test]
        fn suite_new_rejects_permissions_issued_to_another_subject() {
            let err = suite_from(GOVERNANCE_EC_SMIME, PERMISSIONS_OTHER_SUBJECT_SMIME)
                .expect_err("a grant for another subject must not be honoured");
            assert!(
                err.to_string().contains("for another subject"),
                "got: {}",
                err
            );
        }

        /// A grant whose validity window has closed grants nothing.
        #[test]
        fn suite_new_rejects_permissions_whose_grant_expired() {
            let err = suite_from(GOVERNANCE_EC_SMIME, PERMISSIONS_EXPIRED_GRANT_SMIME)
                .expect_err("an expired grant must not be honoured");
            assert!(
                err.to_string().contains("outside their validity"),
                "got: {}",
                err
            );
        }

        /// Both documents must be signed, not just the permissions one.
        #[test]
        fn suite_new_rejects_forged_governance() {
            suite_from(PERMISSIONS_TAMPERED_SMIME, PERMISSIONS_EC_SMIME)
                .expect_err("a tampered governance document must be refused");
        }

        /// Configuring a document without naming the CA that signed it is refused
        /// at build time, before anything is read.
        #[test]
        fn config_requires_a_permissions_ca_for_signed_documents() {
            let cert = temp(TEST_IDENTITY_CERT_PEM);
            let key = temp(TEST_IDENTITY_KEY_PEM);
            let ca = temp(TEST_CA_CERT_PEM);
            let gov = temp(GOVERNANCE_EC_SMIME);
            let perms = temp(PERMISSIONS_EC_SMIME);

            let err = SecurityConfig::builder()
                .identity_certificate(cert.path())
                .private_key(key.path())
                .ca_certificates(ca.path())
                .governance_xml(gov.path())
                .permissions_xml(perms.path())
                .build()
                .expect_err("a permissions CA is mandatory");
            assert!(
                err.to_string().contains("permissions_ca is required"),
                "got: {}",
                err
            );
        }

        /// The escape hatch lets plain XML through, and says so in the log.
        #[test]
        fn suite_new_accepts_unsigned_documents_with_the_explicit_opt_in() {
            let cert = temp(TEST_IDENTITY_CERT_PEM);
            let key = temp(TEST_IDENTITY_KEY_PEM);
            let ca = temp(TEST_CA_CERT_PEM);
            let gov = temp(GOVERNANCE_PLAIN_XML);
            let perms = temp(PERMISSIONS_PLAIN_XML);

            let config = SecurityConfig::builder()
                .identity_certificate(cert.path())
                .private_key(key.path())
                .ca_certificates(ca.path())
                .governance_xml(gov.path())
                .permissions_xml(perms.path())
                .insecure_allow_unsigned_documents(true)
                .build()
                .expect("the opt-in must make the configuration buildable");
            SecurityPluginSuite::new(config, 0).expect("the opt-in must accept unsigned documents");
        }

        /// The escape hatch covers the documents this participant reads from
        /// its own disk, never a peer's: a remote permissions document is what
        /// grants the peer rights here (DDS Security v1.1 Sec.9.4.1.3, signed
        /// by the Permissions CA), and an unsigned one is a claim anyone can
        /// write. The same plain document the local side accepted is refused
        /// when a peer presents it.
        #[test]
        fn the_unsigned_documents_opt_in_never_reaches_a_peers_document() {
            let cert = temp(TEST_IDENTITY_CERT_PEM);
            let key = temp(TEST_IDENTITY_KEY_PEM);
            let ca = temp(TEST_CA_CERT_PEM);
            let gov = temp(GOVERNANCE_PLAIN_XML);
            let perms = temp(PERMISSIONS_PLAIN_XML);

            let config = SecurityConfig::builder()
                .identity_certificate(cert.path())
                .private_key(key.path())
                .ca_certificates(ca.path())
                .governance_xml(gov.path())
                .permissions_xml(perms.path())
                .insecure_allow_unsigned_documents(true)
                .build()
                .expect("the opt-in makes the local configuration buildable");
            let suite = SecurityPluginSuite::new(config, 0).expect("local documents accepted");
            let remote = suite
                .remote_access_control(0)
                .expect("governance configured: peers are judged");
            let peer = crate::core::discovery::GUID::new(
                [0x5A; 12],
                crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT,
            );
            let err = remote
                .check_remote_endpoint(
                    &peer,
                    TEST_IDENTITY_CERT_PEM,
                    Some(PERMISSIONS_PLAIN_XML),
                    "any/topic",
                    true,
                )
                .expect_err("a peer's unsigned permissions document grants nothing");
            assert!(err.to_string().contains("did not verify"), "{}", err);
        }

        /// Revocation on with no list is refused at BUILD time, by name.
        ///
        /// `secure_builder()` turns the flag on by default, so this pairing is
        /// the one an operator reaches by accident. Refusing here rather than
        /// mid-handshake matters: a participant that discovers the gap during
        /// a handshake has already bound its sockets and announced itself.
        #[test]
        fn revocation_without_a_list_is_refused_when_the_configuration_is_built() {
            let cert = temp(TEST_IDENTITY_CERT_PEM);
            let key = temp(TEST_IDENTITY_KEY_PEM);
            let ca = temp(TEST_CA_CERT_PEM);

            let err = SecurityConfig::builder()
                .identity_certificate(cert.path())
                .private_key(key.path())
                .ca_certificates(ca.path())
                .check_certificate_revocation(true)
                .build()
                .expect_err("revocation cannot be checked against a list that does not exist");
            let text = format!("{}", err);
            assert!(
                text.contains("certificate_revocation_list"),
                "the refusal must name what is missing, got: {}",
                text
            );
        }

        /// DDS Security v1.1 Table 45: an IdentityToken's properties
        /// (`dds.cert.sn`, `dds.cert.algo`, `dds.ca.sn`, `dds.ca.algo`) are
        /// optional, "The presence of each of properties is optional", and
        /// Cyclone DDS sends none; and Table 52, validate_remote_identity:
        /// the class ids are compared by PluginClassName and MajorVersion,
        /// a MinorVersion is no reason to refuse.
        #[test]
        fn an_identity_token_without_properties_is_admitted() {
            use crate::core::discovery::multicast::SecurityValidator;
            use crate::core::discovery::GUID;
            use crate::protocol::discovery::spdp::data_holder::serialize_data_holder;
            use crate::security::SecurityValidatorAdapter;
            let cert = temp(TEST_IDENTITY_CERT_PEM);
            let key = temp(TEST_IDENTITY_KEY_PEM);
            let ca = temp(TEST_CA_CERT_PEM);
            let config = SecurityConfig::builder()
                .identity_certificate(cert.path())
                .private_key(key.path())
                .ca_certificates(ca.path())
                .build()
                .expect("the configuration is complete");
            let adapter = SecurityValidatorAdapter::new(std::sync::Arc::new(
                SecurityPluginSuite::new(config, 0).expect("suite"),
            ));
            let guid = GUID::new([0x01; 12], [0, 0, 1, 0xC1]);
            let token = |class_id: &str| serialize_data_holder(class_id, &[], &[]).expect("encode");
            for (class_id, admitted) in [
                ("DDS:Auth:PKI-DH:1.0", true),
                ("DDS:Auth:PKI-DH:1.3", true),
                ("DDS:Auth:PKI-DH:2.0", false),
                ("DDS:Auth:PKI-RSA:1.0", false),
                ("DDS:Auth:PKI-DH", false),
            ] {
                assert_eq!(
                    adapter.validate_identity(guid, &token(class_id)).is_ok(),
                    admitted,
                    "{}",
                    class_id
                );
            }
        }

        /// And with a list it builds, and the LOCAL identity is checked
        /// against it.
        ///
        /// A revoked local identity is refused, while a certificate listed in
        /// no CRL still authenticates.
        #[test]
        fn a_revoked_local_identity_cannot_authenticate() {
            use crate::security::test_pki::{
                REVOCATION_CA_PEM, REVOCATION_CRL_PEM, REVOCATION_EMPTY_CRL_PEM,
                REVOCATION_REVOKED_IDENTITY_PEM,
            };

            let cert = temp(REVOCATION_REVOKED_IDENTITY_PEM);
            let key = temp(TEST_IDENTITY_KEY_PEM);
            let ca = temp(REVOCATION_CA_PEM);
            let crl = temp(REVOCATION_CRL_PEM);
            let empty = temp(REVOCATION_EMPTY_CRL_PEM);

            let build = |list: &std::path::Path| {
                SecurityConfig::builder()
                    .identity_certificate(cert.path())
                    .private_key(key.path())
                    .ca_certificates(ca.path())
                    .check_certificate_revocation(true)
                    .certificate_revocation_list(list)
                    .build()
                    .expect("the configuration is complete")
            };

            // `validate_identity()` is the live entry point: the discovery
            // FSM reaches it through SecurityValidatorAdapter for every remote
            // participant it considers, so this is the call that runs in
            // production, not a construction-time side effect.
            let permissive = SecurityPluginSuite::new(build(empty.path()), 0)
                .expect("the configuration is complete");
            permissive
                .authentication()
                .validate_identity()
                .expect("a certificate listed in no CRL must authenticate");

            // The local identity is judged with the list at
            // CONSTRUCTION as well, so a revoked identity never builds a
            // suite: the participant fails before it binds a socket or
            // announces itself, which is earlier than the handshake and
            // therefore better. The refusal must still say why.
            let text = match SecurityPluginSuite::new(build(crl.path()), 0) {
                Ok(_) => panic!("a revoked identity must not build a security suite"),
                Err(e) => format!("{}", e),
            };
            assert!(
                text.contains("REVOKED"),
                "the refusal must say the certificate is revoked, got: {}",
                text
            );
        }

        /// The converse pairing: a list named while the flag is OFF is a
        /// configuration that looks like revocation checking and is not. It
        /// is refused rather than quietly ignored.
        #[test]
        fn a_list_without_the_flag_is_refused_when_the_configuration_is_built() {
            use crate::security::test_pki::REVOCATION_CRL_PEM;
            let cert = temp(TEST_IDENTITY_CERT_PEM);
            let key = temp(TEST_IDENTITY_KEY_PEM);
            let ca = temp(TEST_CA_CERT_PEM);
            let crl = temp(REVOCATION_CRL_PEM);

            let err = SecurityConfig::builder()
                .identity_certificate(cert.path())
                .private_key(key.path())
                .ca_certificates(ca.path())
                .certificate_revocation_list(crl.path())
                .build()
                .expect_err("a list nobody consults is refused");
            let text = format!("{}", err);
            assert!(
                text.contains("would never be consulted"),
                "the refusal must say the list is inert, got: {}",
                text
            );
        }

        /// The SPDP PermissionsToken describes the Permissions CA, not the
        /// identity CA.
        #[test]
        fn spdp_permissions_token_describes_permissions_ca() {
            let cert = temp(TEST_IDENTITY_CERT_PEM);
            let key = temp(TEST_IDENTITY_KEY_PEM);
            let ca = temp(TEST_CA_CERT_PEM);
            let perm_ca = temp(PERM_CA_EC_PEM);

            let config = SecurityConfig::builder()
                .identity_certificate(cert.path())
                .private_key(key.path())
                .ca_certificates(ca.path())
                .permissions_ca(perm_ca.path())
                .build()
                .expect("configuration must build");
            let suite = SecurityPluginSuite::new(config, 0).expect("suite must build");
            let (_identity, permissions_token) =
                suite.build_spdp_tokens().expect("tokens must serialize");
            let text = String::from_utf8_lossy(&permissions_token).to_string();
            assert!(
                text.contains("HDDS Test Permissions CA"),
                "the token must name the permissions CA: {}",
                text
            );
            assert!(
                !text.contains("DDS Test CA"),
                "the token must not name the identity CA: {}",
                text
            );
        }
    }
}
