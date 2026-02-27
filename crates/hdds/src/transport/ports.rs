// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! RTPS v2.5 Port Mapping
//!
//! Implements OMG DDS-RTPS v2.5 port allocation formula.
//! Allows multiple participants per domain via participant_id uniqueness.

use crate::config::{
    DOMAIN_ID_GAIN, PARTICIPANT_ID_GAIN, PORT_BASE, SEDP_UNICAST_OFFSET, USER_UNICAST_OFFSET,
};
use crate::dds::Error;
use std::convert::TryFrom;

/// Port mapping for a participant in a domain
#[derive(Debug, Clone, Copy)]
pub struct PortMapping {
    /// Multicast port for SPDP discovery
    pub metatraffic_multicast: u16,
    /// Multicast port for SEDP discovery (RTPS v2.5)
    pub sedp_multicast: u16,
    /// Unicast port for metatraffic (discovery response)
    pub metatraffic_unicast: u16,
    /// Unicast port for user data
    pub user_unicast: u16,
}

/// Custom port configuration for overriding RTPS v2.5 defaults.
///
/// Use this when you need to use non-standard ports (e.g., firewall restrictions,
/// FastDDS XML config with custom ports, multi-tenancy, testing isolation).
///
/// **Important**: All participants must use the same custom ports to discover each other.
///
/// # Example
/// ```no_run
/// use hdds::transport::CustomPortMapping;
///
/// let custom = CustomPortMapping {
///     spdp_multicast: 9400,
///     sedp_unicast: 9410,
///     user_unicast: 9411,
/// };
/// ```
#[derive(Debug, Clone, Copy)]
pub struct CustomPortMapping {
    /// Multicast port for SPDP discovery (default: 7400)
    pub spdp_multicast: u16,
    /// Unicast port for SEDP/control traffic (default: 7410)
    pub sedp_unicast: u16,
    /// Unicast port for user data traffic (default: 7411)
    pub user_unicast: u16,
}

impl PortMapping {
    /// Create PortMapping from custom ports (override RTPS formula).
    ///
    /// Use this for non-standard port configurations (firewall restrictions,
    /// FastDDS XML custom ports, testing, etc.).
    ///
    /// # Example
    /// ```no_run
    /// use hdds::transport::{PortMapping, CustomPortMapping};
    ///
    /// let custom = CustomPortMapping {
    ///     spdp_multicast: 9400,
    ///     sedp_unicast: 9410,
    ///     user_unicast: 9411,
    /// };
    /// let mapping = PortMapping::from_custom(custom);
    /// ```
    pub fn from_custom(custom: CustomPortMapping) -> Self {
        crate::trace_fn!("PortMapping::from_custom");
        PortMapping {
            metatraffic_multicast: custom.spdp_multicast,
            sedp_multicast: custom.spdp_multicast, // Same as SPDP
            metatraffic_unicast: custom.sedp_unicast,
            user_unicast: custom.user_unicast,
        }
    }

    /// Calculate ports from domain_id + participant_id (RTPS v2.5 formula)
    pub fn calculate(domain_id: u32, participant_id: u8) -> Result<Self, Error> {
        crate::trace_fn!("PortMapping::calculate");
        // Validate inputs per RTPS spec
        if domain_id >= 233 {
            return Err(Error::InvalidDomainId(domain_id));
        }
        if participant_id >= 120 {
            return Err(Error::InvalidParticipantId(participant_id));
        }

        // RTPS formula (OMG DDS-RTPS v2.5, Section 9.6.1.1)
        let domain = u16::try_from(domain_id).map_err(|_| Error::InvalidDomainId(domain_id))?;
        let multicast_base = PORT_BASE + (DOMAIN_ID_GAIN * domain);
        let unicast_base = PORT_BASE + SEDP_UNICAST_OFFSET + (DOMAIN_ID_GAIN * domain);

        Ok(PortMapping {
            metatraffic_multicast: multicast_base, // 7400 + 250xD (SPDP)
            sedp_multicast: multicast_base, // v126: 7400 + 250xD (SEDP) - Same as SPDP per FastDDS/RTI/Cyclone behavior
            metatraffic_unicast: unicast_base + (PARTICIPANT_ID_GAIN * u16::from(participant_id)),
            user_unicast: unicast_base
                + (USER_UNICAST_OFFSET - SEDP_UNICAST_OFFSET)
                + (PARTICIPANT_ID_GAIN * u16::from(participant_id)),
        })
    }

    /// Auto-assign participant_id by probing free ports (0..120)
    ///
    /// Iterates through participant IDs and returns the first one where
    /// the unicast ports (metatraffic + user data) are available.
    /// Multicast port (7400) is shared by all participants via SO_REUSEADDR.
    pub fn auto_assign(domain_id: u32) -> Result<(Self, u8), Error> {
        crate::trace_fn!("PortMapping::auto_assign");
        for pid in 0..120u8 {
            if let Ok(mapping) = Self::calculate(domain_id, pid) {
                // Multicast port (7400) is shared - no need to probe
                // But unicast ports MUST be unique per participant
                if Self::is_port_available(mapping.metatraffic_unicast)
                    && Self::is_port_available(mapping.user_unicast)
                {
                    log::debug!(
                        "[PortMapping] auto_assign: domain={} participant_id={} (ports {}, {})",
                        domain_id,
                        pid,
                        mapping.metatraffic_unicast,
                        mapping.user_unicast
                    );
                    return Ok((mapping, pid));
                }
            }
        }
        Err(Error::NoAvailableParticipantId)
    }

    /// Check if a port is available for binding
    fn is_port_available(port: u16) -> bool {
        use std::net::UdpSocket;
        match UdpSocket::bind(("0.0.0.0", port)) {
            Ok(socket) => {
                drop(socket);
                true
            }
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_calculation_domain_0() {
        // Domain 0, Participant 0
        let p0 = PortMapping::calculate(0, 0)
            .expect("port calculation should succeed for domain 0, participant 0");
        assert_eq!(p0.metatraffic_multicast, 7400); // SPDP
        assert_eq!(p0.sedp_multicast, 7400); // v126: SEDP same as SPDP per FastDDS/RTI behavior
        assert_eq!(p0.metatraffic_unicast, 7410);
        assert_eq!(p0.user_unicast, 7411);

        // Domain 0, Participant 1
        let p1 = PortMapping::calculate(0, 1)
            .expect("port calculation should succeed for domain 0, participant 1");
        assert_eq!(p1.metatraffic_multicast, 7400); // Same SPDP multicast
        assert_eq!(p1.sedp_multicast, 7400); // v126: Same SEDP multicast port (7400)
        assert_eq!(p1.metatraffic_unicast, 7412);
        assert_eq!(p1.user_unicast, 7413);

        // Domain 0, Participant 2
        let p2 = PortMapping::calculate(0, 2)
            .expect("port calculation should succeed for domain 0, participant 2");
        assert_eq!(p2.sedp_multicast, 7400); // v126: Same SEDP multicast port (7400)
        assert_eq!(p2.metatraffic_unicast, 7414);
        assert_eq!(p2.user_unicast, 7415);
    }

    #[test]
    fn test_port_calculation_domain_1() {
        // Domain 1, Participant 0
        let p0 = PortMapping::calculate(1, 0)
            .expect("port calculation should succeed for domain 1, participant 0");
        assert_eq!(p0.metatraffic_multicast, 7650); // 7400 + 250x1 (SPDP)
        assert_eq!(p0.sedp_multicast, 7650); // v126: 7400 + 250x1 (SEDP) - same as SPDP
        assert_eq!(p0.metatraffic_unicast, 7660);
        assert_eq!(p0.user_unicast, 7661);

        // Domain 1, Participant 1
        let p1 = PortMapping::calculate(1, 1)
            .expect("port calculation should succeed for domain 1, participant 1");
        assert_eq!(p1.metatraffic_multicast, 7650); // Same SPDP multicast
        assert_eq!(p1.sedp_multicast, 7650); // v126: Same SEDP multicast port (7650 for domain 1)
        assert_eq!(p1.metatraffic_unicast, 7662);
        assert_eq!(p1.user_unicast, 7663);
    }

    #[test]
    fn test_invalid_domain_id() {
        let result = PortMapping::calculate(233, 0);
        assert!(result.is_err(), "domain_id must be < 233");
    }

    #[test]
    fn test_invalid_participant_id() {
        let result = PortMapping::calculate(0, 120);
        assert!(result.is_err(), "participant_id must be < 120");
    }

    #[test]
    fn test_custom_port_mapping() {
        let custom = CustomPortMapping {
            spdp_multicast: 9400,
            sedp_unicast: 9410,
            user_unicast: 9411,
        };

        let mapping = PortMapping::from_custom(custom);

        assert_eq!(mapping.metatraffic_multicast, 9400);
        assert_eq!(mapping.sedp_multicast, 9400); // Same as SPDP
        assert_eq!(mapping.metatraffic_unicast, 9410);
        assert_eq!(mapping.user_unicast, 9411);
    }

    #[test]
    fn test_custom_ports_fastdds_compatible() {
        // FastDDS XML example: custom ports for firewall compatibility
        let custom = CustomPortMapping {
            spdp_multicast: 8400,
            sedp_unicast: 8410,
            user_unicast: 8411,
        };

        let mapping = PortMapping::from_custom(custom);

        // Verify all ports are custom
        assert_eq!(mapping.metatraffic_multicast, 8400);
        assert_eq!(mapping.metatraffic_unicast, 8410);
        assert_eq!(mapping.user_unicast, 8411);
    }
}
