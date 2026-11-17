// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! The security attributes the AccessControl plugin derives from the
//! governance document, and their wire masks.
//!
//! DDS-Security v1.1 Sec.8.4.2.4 to 8.4.2.8 define what the middleware is told
//! about how to protect a participant (`ParticipantSecurityAttributes`, Table
//! 27), a topic (`TopicSecurityAttributes`, Table 29) and an endpoint
//! (`EndpointSecurityAttributes`, Table 30). Sec.9.4.2.3 to 9.4.2.6 add the
//! builtin plugins' own halves (`PluginParticipantSecurityAttributes`,
//! `PluginEndpointSecurityAttributes`). The governance elements fill them as
//! Sec.9.4.1.2.5 and 9.4.1.2.6 say, and each of them travels in discovery as a
//! pair of 32-bit masks (Sec.7.2.7 `ParticipantSecurityInfo`, Sec.7.2.8
//! `EndpointSecurityInfo`) whose bits are Tables 28, 31, 60 and 62.
//!
//! The bit values below are read from the specification text, not from an
//! implementation:
//!
//! ```text
//! Table 28  PARTICIPANT_SECURITY_ATTRIBUTES_FLAG_IS_RTPS_PROTECTED      (0x00000001 << 0)
//!           PARTICIPANT_SECURITY_ATTRIBUTES_FLAG_IS_DISCOVERY_PROTECTED (0x00000001 << 1)
//!           PARTICIPANT_SECURITY_ATTRIBUTES_FLAG_IS_LIVELINESS_PROTECTED(0x00000001 << 2)
//!           PARTICIPANT_SECURITY_ATTRIBUTES_FLAG_IS_VALID               (0x00000001 << 31)
//! Table 31  ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_READ_PROTECTED         (0x00000001 << 0)
//!           ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_WRITE_PROTECTED        (0x00000001 << 1)
//!           ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_DISCOVERY_PROTECTED    (0x00000001 << 2)
//!           ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_SUBMESSAGE_PROTECTED   (0x00000001 << 3)
//!           ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_PAYLOAD_PROTECTED      (0x00000001 << 4)
//!           ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_KEY_PROTECTED          (0x00000001 << 5)
//!           ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_LIVELINESS_PROTECTED   (0x00000001 << 6)
//!           ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_VALID                  (0x00000001 << 31)
//! Table 60  PLUGIN_PARTICIPANT_..._IS_RTPS_ENCRYPTED                    (0x00000001 << 0)
//!           PLUGIN_PARTICIPANT_..._BUILTIN_IS_DISCOVERY_ENCRYPTED       (0x00000001 << 1)
//!           PLUGIN_PARTICIPANT_..._IS_LIVELINESS_ENCRYPTED              (0x00000001 << 2)
//!           PLUGIN_PARTICIPANT_..._IS_RTPS_ORIGIN_AUTHENTICATED         (0x00000001 << 3)
//!           PLUGIN_PARTICIPANT_..._IS_DISCOVERY_ORIGIN_AUTHENTICATED    (0x00000001 << 4)
//!           ..._IS_LIVELINESS_ORIGIN_AUTHENTICATED                      (0x00000001 << 5)
//! Table 62  PLUGIN_ENDPOINT_..._IS_SUBMESSAGE_ENCRYPTED                 (0x00000001 << 0)
//!           PLUGIN_ENDPOINT_..._IS_PAYLOAD_ENCRYPTED                    (0x00000001 << 1)
//!           PLUGIN_ENDPOINT_..._IS_SUBMESSAGE_ORIGIN_AUTHENTICATED      (0x00000001 << 2)
//! ```
//!
//! The plugin masks carry the is_valid bit too: Sec.7.2.7 "The most-significant
//! bit of PluginParticipantSecurityAttributesMask and
//! ParticipantSecurityAttributesMask is called the is_valid bit", and Sec.7.2.8
//! says the same of the two endpoint masks.

/// `ProtectionKind` (DDS-Security v1.1 Sec.9.4.1.2.1, 9.4.1.2.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtectionKind {
    /// No cryptographic transformation.
    None,
    /// A message authentication code only (AES-GMAC).
    Sign,
    /// Encryption followed by a MAC (AES-GCM).
    Encrypt,
    /// [`Self::Sign`] plus receiver-specific MACs.
    SignWithOriginAuthentication,
    /// [`Self::Encrypt`] plus receiver-specific MACs.
    EncryptWithOriginAuthentication,
}

impl ProtectionKind {
    /// The kind spelled as the XSD enumerates it (Sec.9.4.1.2.3), or `None`.
    #[must_use]
    pub fn from_xml(text: &str) -> Option<Self> {
        match text {
            "NONE" => Some(Self::None),
            "SIGN" => Some(Self::Sign),
            "ENCRYPT" => Some(Self::Encrypt),
            "SIGN_WITH_ORIGIN_AUTHENTICATION" => Some(Self::SignWithOriginAuthentication),
            "ENCRYPT_WITH_ORIGIN_AUTHENTICATION" => Some(Self::EncryptWithOriginAuthentication),
            _ => None,
        }
    }

    /// The XSD spelling.
    #[must_use]
    pub fn as_xml(self) -> &'static str {
        match self {
            Self::None => "NONE",
            Self::Sign => "SIGN",
            Self::Encrypt => "ENCRYPT",
            Self::SignWithOriginAuthentication => "SIGN_WITH_ORIGIN_AUTHENTICATION",
            Self::EncryptWithOriginAuthentication => "ENCRYPT_WITH_ORIGIN_AUTHENTICATION",
        }
    }

    /// Anything but NONE: the `is_*_protected` attributes (Sec.9.4.1.2.5.4:
    /// "FALSE if the value ... is NONE and to TRUE otherwise").
    #[must_use]
    pub fn is_protected(self) -> bool {
        self != Self::None
    }

    /// ENCRYPT or ENCRYPT_WITH_ORIGIN_AUTHENTICATION: the `is_*_encrypted`
    /// plugin attributes.
    #[must_use]
    pub fn is_encrypted(self) -> bool {
        matches!(self, Self::Encrypt | Self::EncryptWithOriginAuthentication)
    }

    /// The two WITH_ORIGIN_AUTHENTICATION kinds: the
    /// `is_*_origin_authenticated` plugin attributes.
    #[must_use]
    pub fn is_origin_authenticated(self) -> bool {
        matches!(
            self,
            Self::SignWithOriginAuthentication | Self::EncryptWithOriginAuthentication
        )
    }
}

/// `BasicProtectionKind` (Sec.9.4.1.2.1): the kinds `data_protection_kind`
/// may take (Sec.9.4.1.2.3, DDSSEC11-11).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BasicProtectionKind {
    /// No transformation of the SerializedPayload.
    None,
    /// A MAC of the SerializedPayload.
    Sign,
    /// The SerializedPayload encrypted, then a MAC.
    Encrypt,
}

impl BasicProtectionKind {
    /// The kind spelled as the XSD enumerates it, or `None`.
    #[must_use]
    pub fn from_xml(text: &str) -> Option<Self> {
        match text {
            "NONE" => Some(Self::None),
            "SIGN" => Some(Self::Sign),
            "ENCRYPT" => Some(Self::Encrypt),
            _ => None,
        }
    }

    /// The XSD spelling.
    #[must_use]
    pub fn as_xml(self) -> &'static str {
        match self {
            Self::None => "NONE",
            Self::Sign => "SIGN",
            Self::Encrypt => "ENCRYPT",
        }
    }
}

/// The is_valid bit of all four masks (Sec.7.2.7, 7.2.8).
pub const SECURITY_ATTRIBUTES_FLAG_IS_VALID: u32 = 1 << 31;

/// Table 28.
pub const PARTICIPANT_SECURITY_ATTRIBUTES_FLAG_IS_RTPS_PROTECTED: u32 = 1 << 0;
/// Table 28.
pub const PARTICIPANT_SECURITY_ATTRIBUTES_FLAG_IS_DISCOVERY_PROTECTED: u32 = 1 << 1;
/// Table 28.
pub const PARTICIPANT_SECURITY_ATTRIBUTES_FLAG_IS_LIVELINESS_PROTECTED: u32 = 1 << 2;

/// Table 60.
pub const PLUGIN_PARTICIPANT_SECURITY_ATTRIBUTES_FLAG_IS_RTPS_ENCRYPTED: u32 = 1 << 0;
/// Table 60.
pub const PLUGIN_PARTICIPANT_SECURITY_ATTRIBUTES_FLAG_IS_DISCOVERY_ENCRYPTED: u32 = 1 << 1;
/// Table 60.
pub const PLUGIN_PARTICIPANT_SECURITY_ATTRIBUTES_FLAG_IS_LIVELINESS_ENCRYPTED: u32 = 1 << 2;
/// Table 60.
pub const PLUGIN_PARTICIPANT_SECURITY_ATTRIBUTES_FLAG_IS_RTPS_ORIGIN_AUTHENTICATED: u32 = 1 << 3;
/// Table 60.
pub const PLUGIN_PARTICIPANT_SECURITY_ATTRIBUTES_FLAG_IS_DISCOVERY_ORIGIN_AUTHENTICATED: u32 =
    1 << 4;
/// Table 60.
pub const PLUGIN_PARTICIPANT_SECURITY_ATTRIBUTES_FLAG_IS_LIVELINESS_ORIGIN_AUTHENTICATED: u32 =
    1 << 5;

/// Table 31.
pub const ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_READ_PROTECTED: u32 = 1 << 0;
/// Table 31.
pub const ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_WRITE_PROTECTED: u32 = 1 << 1;
/// Table 31.
pub const ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_DISCOVERY_PROTECTED: u32 = 1 << 2;
/// Table 31.
pub const ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_SUBMESSAGE_PROTECTED: u32 = 1 << 3;
/// Table 31.
pub const ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_PAYLOAD_PROTECTED: u32 = 1 << 4;
/// Table 31.
pub const ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_KEY_PROTECTED: u32 = 1 << 5;
/// Table 31.
pub const ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_LIVELINESS_PROTECTED: u32 = 1 << 6;

/// Table 62.
pub const PLUGIN_ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_SUBMESSAGE_ENCRYPTED: u32 = 1 << 0;
/// Table 62.
pub const PLUGIN_ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_PAYLOAD_ENCRYPTED: u32 = 1 << 1;
/// Table 62.
pub const PLUGIN_ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_SUBMESSAGE_ORIGIN_AUTHENTICATED: u32 = 1 << 2;

fn bit(set: bool, flag: u32) -> u32 {
    if set {
        flag
    } else {
        0
    }
}

/// `PluginParticipantSecurityAttributes` of the builtin plugins (Sec.9.4.2.3).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PluginParticipantSecurityAttributes {
    pub is_rtps_encrypted: bool,
    pub is_discovery_encrypted: bool,
    pub is_liveliness_encrypted: bool,
    pub is_rtps_origin_authenticated: bool,
    pub is_discovery_origin_authenticated: bool,
    pub is_liveliness_origin_authenticated: bool,
}

impl PluginParticipantSecurityAttributes {
    /// `PluginParticipantSecurityAttributesMask` (Table 60), is_valid set.
    #[must_use]
    pub fn mask(&self) -> u32 {
        SECURITY_ATTRIBUTES_FLAG_IS_VALID
            | bit(
                self.is_rtps_encrypted,
                PLUGIN_PARTICIPANT_SECURITY_ATTRIBUTES_FLAG_IS_RTPS_ENCRYPTED,
            )
            | bit(
                self.is_discovery_encrypted,
                PLUGIN_PARTICIPANT_SECURITY_ATTRIBUTES_FLAG_IS_DISCOVERY_ENCRYPTED,
            )
            | bit(
                self.is_liveliness_encrypted,
                PLUGIN_PARTICIPANT_SECURITY_ATTRIBUTES_FLAG_IS_LIVELINESS_ENCRYPTED,
            )
            | bit(
                self.is_rtps_origin_authenticated,
                PLUGIN_PARTICIPANT_SECURITY_ATTRIBUTES_FLAG_IS_RTPS_ORIGIN_AUTHENTICATED,
            )
            | bit(
                self.is_discovery_origin_authenticated,
                PLUGIN_PARTICIPANT_SECURITY_ATTRIBUTES_FLAG_IS_DISCOVERY_ORIGIN_AUTHENTICATED,
            )
            | bit(
                self.is_liveliness_origin_authenticated,
                PLUGIN_PARTICIPANT_SECURITY_ATTRIBUTES_FLAG_IS_LIVELINESS_ORIGIN_AUTHENTICATED,
            )
    }
}

/// `ParticipantSecurityAttributes` (Table 27), as `get_participant_sec_attributes`
/// returns them for the domain rule that applies (Sec.9.4.1.2.5.2 to 9.4.1.2.5.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParticipantSecurityAttributes {
    pub allow_unauthenticated_participants: bool,
    pub is_access_protected: bool,
    pub is_rtps_protected: bool,
    pub is_discovery_protected: bool,
    pub is_liveliness_protected: bool,
    /// The protection kind of the secure builtin discovery endpoints
    /// (`discovery_protection_kind`, Sec.9.4.1.2.5.4). The two booleans of
    /// the plugin attributes are derived from it; the kind itself is what
    /// the transformation is chosen by.
    pub discovery_protection_kind: ProtectionKind,
    pub plugin: PluginParticipantSecurityAttributes,
}

impl ParticipantSecurityAttributes {
    /// The attributes a domain rule produces.
    #[must_use]
    pub fn from_kinds(
        allow_unauthenticated_participants: bool,
        enable_join_access_control: bool,
        discovery: ProtectionKind,
        liveliness: ProtectionKind,
        rtps: ProtectionKind,
    ) -> Self {
        Self {
            allow_unauthenticated_participants,
            is_access_protected: enable_join_access_control,
            is_rtps_protected: rtps.is_protected(),
            is_discovery_protected: discovery.is_protected(),
            is_liveliness_protected: liveliness.is_protected(),
            discovery_protection_kind: discovery,
            plugin: PluginParticipantSecurityAttributes {
                is_rtps_encrypted: rtps.is_encrypted(),
                is_discovery_encrypted: discovery.is_encrypted(),
                is_liveliness_encrypted: liveliness.is_encrypted(),
                is_rtps_origin_authenticated: rtps.is_origin_authenticated(),
                is_discovery_origin_authenticated: discovery.is_origin_authenticated(),
                is_liveliness_origin_authenticated: liveliness.is_origin_authenticated(),
            },
        }
    }

    /// `ParticipantSecurityAttributesMask` (Table 28), is_valid set.
    /// `allow_unauthenticated_participants` and `is_access_protected` have
    /// "No mapping, this attribute is not checked remotely."
    #[must_use]
    pub fn mask(&self) -> u32 {
        SECURITY_ATTRIBUTES_FLAG_IS_VALID
            | bit(
                self.is_rtps_protected,
                PARTICIPANT_SECURITY_ATTRIBUTES_FLAG_IS_RTPS_PROTECTED,
            )
            | bit(
                self.is_discovery_protected,
                PARTICIPANT_SECURITY_ATTRIBUTES_FLAG_IS_DISCOVERY_PROTECTED,
            )
            | bit(
                self.is_liveliness_protected,
                PARTICIPANT_SECURITY_ATTRIBUTES_FLAG_IS_LIVELINESS_PROTECTED,
            )
    }

    /// The two masks, as discovery carries them.
    #[must_use]
    pub fn security_info(&self) -> crate::protocol::discovery::ParticipantSecurityInfo {
        crate::protocol::discovery::ParticipantSecurityInfo {
            participant_security_attributes: self.mask(),
            plugin_participant_security_attributes: self.plugin.mask(),
        }
    }

    /// The 8 octets of `PID_PARTICIPANT_SECURITY_INFO` (Sec.7.2.7, 7.4.1.4):
    /// `participant_security_attributes` then
    /// `plugin_participant_security_attributes`, little endian as the
    /// parameter list this release writes.
    #[must_use]
    pub fn security_info_le(&self) -> [u8; 8] {
        let mut out = [0u8; 8];
        out[..4].copy_from_slice(&self.mask().to_le_bytes());
        out[4..].copy_from_slice(&self.plugin.mask().to_le_bytes());
        out
    }
}

/// `TopicSecurityAttributes` (Table 29), as `get_topic_sec_attributes`
/// returns them for the topic rule that applies (Sec.9.4.1.2.6.2 to
/// 9.4.1.2.6.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TopicSecurityAttributes {
    pub is_read_protected: bool,
    pub is_write_protected: bool,
    pub is_discovery_protected: bool,
    pub is_liveliness_protected: bool,
}

/// `PluginEndpointSecurityAttributes` of the builtin plugins (Sec.9.4.2.5).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PluginEndpointSecurityAttributes {
    pub is_submessage_encrypted: bool,
    pub is_payload_encrypted: bool,
    pub is_submessage_origin_authenticated: bool,
}

impl PluginEndpointSecurityAttributes {
    /// `PluginEndpointSecurityAttributesMask` (Table 62), is_valid set.
    #[must_use]
    pub fn mask(&self) -> u32 {
        SECURITY_ATTRIBUTES_FLAG_IS_VALID
            | bit(
                self.is_submessage_encrypted,
                PLUGIN_ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_SUBMESSAGE_ENCRYPTED,
            )
            | bit(
                self.is_payload_encrypted,
                PLUGIN_ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_PAYLOAD_ENCRYPTED,
            )
            | bit(
                self.is_submessage_origin_authenticated,
                PLUGIN_ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_SUBMESSAGE_ORIGIN_AUTHENTICATED,
            )
    }
}

/// `EndpointSecurityAttributes` (Table 30): the topic's attributes and the
/// endpoint's own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EndpointSecurityAttributes {
    pub topic: TopicSecurityAttributes,
    pub is_submessage_protected: bool,
    pub is_payload_protected: bool,
    pub is_key_protected: bool,
    pub plugin: PluginEndpointSecurityAttributes,
}

impl EndpointSecurityAttributes {
    /// The attributes of a DataWriter or DataReader of a topic whose rule
    /// asks `metadata` and `data` (Sec.9.4.1.2.6.6, 9.4.1.2.6.7):
    ///
    /// - `is_submessage_protected`: metadata is not NONE;
    /// - `is_submessage_encrypted`: metadata is an ENCRYPT kind;
    /// - `is_submessage_origin_authenticated`: metadata is a
    ///   WITH_ORIGIN_AUTHENTICATION kind;
    /// - data NONE: `is_payload_protected`, `is_key_protected` and
    ///   `is_payload_encrypted` FALSE; SIGN: only `is_payload_protected`;
    ///   ENCRYPT: all three.
    ///
    /// 9.4.1.2.6.7 names `get_datawriter_sec_attributes`, and Table 30 has a
    /// DataReader decode the payload when `is_payload_protected` is set. The
    /// same values are produced for both kinds of endpoint, as the two open
    /// implementations of the builtin plugin do: the masks are compared when
    /// endpoints match (Sec.7.2.8), and a reader announcing other bits than
    /// its writer would never match it.
    #[must_use]
    pub fn from_rule(
        topic: TopicSecurityAttributes,
        metadata: ProtectionKind,
        data: BasicProtectionKind,
    ) -> Self {
        Self {
            topic,
            is_submessage_protected: metadata.is_protected(),
            is_payload_protected: data != BasicProtectionKind::None,
            is_key_protected: data == BasicProtectionKind::Encrypt,
            plugin: PluginEndpointSecurityAttributes {
                is_submessage_encrypted: metadata.is_encrypted(),
                is_payload_encrypted: data == BasicProtectionKind::Encrypt,
                is_submessage_origin_authenticated: metadata.is_origin_authenticated(),
            },
        }
    }

    /// `EndpointSecurityAttributesMask` (Table 31), is_valid set.
    #[must_use]
    pub fn mask(&self) -> u32 {
        SECURITY_ATTRIBUTES_FLAG_IS_VALID
            | bit(
                self.topic.is_read_protected,
                ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_READ_PROTECTED,
            )
            | bit(
                self.topic.is_write_protected,
                ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_WRITE_PROTECTED,
            )
            | bit(
                self.topic.is_discovery_protected,
                ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_DISCOVERY_PROTECTED,
            )
            | bit(
                self.is_submessage_protected,
                ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_SUBMESSAGE_PROTECTED,
            )
            | bit(
                self.is_payload_protected,
                ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_PAYLOAD_PROTECTED,
            )
            | bit(
                self.is_key_protected,
                ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_KEY_PROTECTED,
            )
            | bit(
                self.topic.is_liveliness_protected,
                ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_LIVELINESS_PROTECTED,
            )
    }

    /// The two masks, as discovery carries them.
    #[must_use]
    pub fn security_info(&self) -> crate::protocol::discovery::EndpointSecurityInfo {
        crate::protocol::discovery::EndpointSecurityInfo {
            endpoint_security_attributes: self.mask(),
            plugin_endpoint_security_attributes: self.plugin.mask(),
        }
    }

    /// The 8 octets of `PID_ENDPOINT_SECURITY_INFO` (Sec.7.2.8, 7.4.1.5):
    /// `endpoint_security_attributes` then
    /// `plugin_endpoint_security_attributes`, little endian.
    #[must_use]
    pub fn security_info_le(&self) -> [u8; 8] {
        let mut out = [0u8; 8];
        out[..4].copy_from_slice(&self.mask().to_le_bytes());
        out[4..].copy_from_slice(&self.plugin.mask().to_le_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every bit of Table 28 and Table 60, one attribute at a time: a mask
    /// that put two attributes on one bit, or one on the wrong bit, fails the
    /// assertion naming it.
    #[test]
    fn each_participant_attribute_sets_its_own_bit() {
        let none = ParticipantSecurityAttributes::from_kinds(
            false,
            false,
            ProtectionKind::None,
            ProtectionKind::None,
            ProtectionKind::None,
        );
        assert_eq!(none.mask(), 0x8000_0000);
        assert_eq!(none.plugin.mask(), 0x8000_0000);

        let p = |d, l, r| ParticipantSecurityAttributes::from_kinds(true, true, d, l, r);
        use ProtectionKind::*;
        assert_eq!(p(None, None, Sign).mask(), 0x8000_0001, "rtps bit 0");
        assert_eq!(p(Sign, None, None).mask(), 0x8000_0002, "discovery bit 1");
        assert_eq!(p(None, Sign, None).mask(), 0x8000_0004, "liveliness bit 2");
        assert_eq!(p(None, None, Encrypt).plugin.mask(), 0x8000_0001);
        assert_eq!(p(Encrypt, None, None).plugin.mask(), 0x8000_0002);
        assert_eq!(p(None, Encrypt, None).plugin.mask(), 0x8000_0004);
        assert_eq!(
            p(None, None, SignWithOriginAuthentication).plugin.mask(),
            0x8000_0008
        );
        assert_eq!(
            p(SignWithOriginAuthentication, None, None).plugin.mask(),
            0x8000_0010
        );
        assert_eq!(
            p(None, SignWithOriginAuthentication, None).plugin.mask(),
            0x8000_0020
        );
        assert_eq!(
            p(EncryptWithOriginAuthentication, None, None).plugin.mask(),
            0x8000_0012,
            "encrypted and origin authenticated"
        );
        // Not checked remotely: no bit (Table 28).
        assert_eq!(p(None, None, None).mask(), 0x8000_0000);
    }

    /// `PID_PARTICIPANT_SECURITY_INFO` decoded from its octets.
    #[test]
    fn the_participant_security_info_is_two_little_endian_masks() {
        let attributes = ParticipantSecurityAttributes::from_kinds(
            false,
            true,
            ProtectionKind::Encrypt,
            ProtectionKind::None,
            ProtectionKind::None,
        );
        assert_eq!(
            attributes.security_info_le(),
            [0x02, 0x00, 0x00, 0x80, 0x02, 0x00, 0x00, 0x80]
        );
    }

    /// Every bit of Table 31 and Table 62.
    #[test]
    fn each_endpoint_attribute_sets_its_own_bit() {
        let topic = |r, w, d, l| TopicSecurityAttributes {
            is_read_protected: r,
            is_write_protected: w,
            is_discovery_protected: d,
            is_liveliness_protected: l,
        };
        let e = |t, m, d| EndpointSecurityAttributes::from_rule(t, m, d);
        use BasicProtectionKind as B;
        use ProtectionKind as P;
        let off = topic(false, false, false, false);
        assert_eq!(e(off, P::None, B::None).mask(), 0x8000_0000);
        assert_eq!(e(off, P::None, B::None).plugin.mask(), 0x8000_0000);
        assert_eq!(
            e(topic(true, false, false, false), P::None, B::None).mask(),
            0x8000_0001
        );
        assert_eq!(
            e(topic(false, true, false, false), P::None, B::None).mask(),
            0x8000_0002
        );
        assert_eq!(
            e(topic(false, false, true, false), P::None, B::None).mask(),
            0x8000_0004
        );
        assert_eq!(e(off, P::Sign, B::None).mask(), 0x8000_0008);
        assert_eq!(
            e(off, P::None, B::Sign).mask(),
            0x8000_0010,
            "SIGN: payload only"
        );
        assert_eq!(
            e(off, P::None, B::Encrypt).mask(),
            0x8000_0030,
            "ENCRYPT: payload and key"
        );
        assert_eq!(
            e(topic(false, false, false, true), P::None, B::None).mask(),
            0x8000_0040
        );
        assert_eq!(e(off, P::Encrypt, B::None).plugin.mask(), 0x8000_0001);
        assert_eq!(e(off, P::None, B::Encrypt).plugin.mask(), 0x8000_0002);
        assert_eq!(e(off, P::None, B::Sign).plugin.mask(), 0x8000_0000);
        assert_eq!(
            e(off, P::SignWithOriginAuthentication, B::None)
                .plugin
                .mask(),
            0x8000_0004
        );
        assert_eq!(
            e(off, P::EncryptWithOriginAuthentication, B::None)
                .plugin
                .mask(),
            0x8000_0005
        );
    }

    #[test]
    fn the_endpoint_security_info_is_two_little_endian_masks() {
        let attributes = EndpointSecurityAttributes::from_rule(
            TopicSecurityAttributes {
                is_read_protected: true,
                is_write_protected: true,
                is_discovery_protected: true,
                is_liveliness_protected: false,
            },
            ProtectionKind::None,
            BasicProtectionKind::Encrypt,
        );
        assert_eq!(
            attributes.security_info_le(),
            [0x37, 0x00, 0x00, 0x80, 0x02, 0x00, 0x00, 0x80]
        );
    }

    #[test]
    fn a_protection_kind_is_read_by_its_xsd_name_only() {
        for kind in [
            ProtectionKind::None,
            ProtectionKind::Sign,
            ProtectionKind::Encrypt,
            ProtectionKind::SignWithOriginAuthentication,
            ProtectionKind::EncryptWithOriginAuthentication,
        ] {
            assert_eq!(ProtectionKind::from_xml(kind.as_xml()), Some(kind));
        }
        assert_eq!(ProtectionKind::from_xml("encrypt"), None);
        for kind in [
            BasicProtectionKind::None,
            BasicProtectionKind::Sign,
            BasicProtectionKind::Encrypt,
        ] {
            assert_eq!(BasicProtectionKind::from_xml(kind.as_xml()), Some(kind));
        }
        assert_eq!(
            BasicProtectionKind::from_xml("ENCRYPT_WITH_ORIGIN_AUTHENTICATION"),
            None,
            "data_protection_kind is a BasicProtectionKind"
        );
    }
}
