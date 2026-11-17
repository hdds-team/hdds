//! Announced addresses that are NOT bound locally.
//!
//! Every locator HDDS advertises today is read off a local interface
//! ([`get_unicast_locators_filtered`](super::multicast::get_unicast_locators_filtered)),
//! and its port is always the port a socket is bound to. That is exactly
//! right on a LAN and unusable across a NAT, where the address a peer must
//! send to belongs to a router and the public port generally differs from
//! the private one.
//!
//! An [`ExternalLocator`] is that missing pair: one address and its two
//! ports (metatraffic and user data), supplied by configuration and
//! advertised ALONGSIDE the local locators, never instead of them. The LAN
//! keeps working directly, because a peer sharing one of our subnets
//! prefers the local address, and a peer sharing none can still reach the
//! external one.
//!
//! # What this type does NOT do
//!
//! It does not verify that the pair is reachable, because nothing on this
//! host can: the mapping lives in a router or a relay we cannot see. The
//! constructor only refuses addresses that can never be a destination for a
//! remote peer at all (see [`ExternalLocator::new`]). Whoever configures one
//! asserts that traffic arriving there is delivered to this participant's
//! metatraffic and user-data sockets.
//!
//! # Interaction with the receiver's choice
//!
//! A remote HDDS participant picks among the locators we announce with
//! `select_best_locator`, which prefers, in order, an address inside one of
//! ITS OWN subnets, then a globally routable one, then the rest. An address
//! taken from a documentation range (192.0.2.0/24, 198.51.100.0/24,
//! 203.0.113.0/24) is accepted here but is not "globally routable" for that
//! selector, so a peer would keep preferring its own private candidates over
//! it. Such addresses are fine in a lab and a poor choice in production.

use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

/// Environment variable carrying a comma-separated list of external
/// locators, each written `ADDRESS:METATRAFFIC_PORT:USER_PORT`.
pub const ENV_EXTERNAL_LOCATOR: &str = "HDDS_EXTERNAL_LOCATOR";

/// An address:port pair advertised to peers although no local socket is
/// bound to it: the public side of a NAT mapping, or a relay endpoint.
///
/// Construct with [`ExternalLocator::new`] or by parsing the textual form
/// `ADDRESS:METATRAFFIC_PORT:USER_PORT` (see [`FromStr`]). Both ports are
/// required and independent: a NAT that maps 7410 and 7411 to two unrelated
/// public ports is the normal case, not an exotic one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExternalLocator {
    address: Ipv4Addr,
    metatraffic_port: u16,
    user_port: u16,
}

impl ExternalLocator {
    /// Validate and build an external locator.
    ///
    /// The address is IPv4 by type, not by check: `UdpTransport` binds IPv4
    /// sockets only, so an IPv6 external address could never be relayed back
    /// to a socket this participant holds. Making that a signature instead
    /// of a runtime error is deliberate.
    ///
    /// # Errors
    ///
    /// [`ExternalLocatorError::UnroutableAddress`] when the address can never
    /// be a unicast destination for a remote peer, and
    /// [`ExternalLocatorError::InvalidPort`] when either port is zero, which
    /// encodes as `LOCATOR_PORT_INVALID` on the wire.
    ///
    /// Private addresses (10/8, 172.16/12, 192.168/16) and carrier-grade NAT
    /// addresses (100.64/10) are ACCEPTED: a port forwarded on a router in a
    /// different subnet, or an address reachable over a site-to-site tunnel,
    /// is a legitimate external locator even though it is not public.
    pub fn new(
        address: Ipv4Addr,
        metatraffic_port: u16,
        user_port: u16,
    ) -> Result<Self, ExternalLocatorError> {
        if let Some(reason) = unroutable_reason(address) {
            return Err(ExternalLocatorError::UnroutableAddress { address, reason });
        }
        if metatraffic_port == 0 {
            return Err(ExternalLocatorError::InvalidPort {
                role: "metatraffic",
            });
        }
        if user_port == 0 {
            return Err(ExternalLocatorError::InvalidPort { role: "user data" });
        }
        Ok(Self {
            address,
            metatraffic_port,
            user_port,
        })
    }

    /// The advertised address.
    #[must_use]
    pub fn address(&self) -> Ipv4Addr {
        self.address
    }

    /// Public port that reaches this participant's metatraffic unicast
    /// socket (SPDP/SEDP/ACKNACK).
    #[must_use]
    pub fn metatraffic_port(&self) -> u16 {
        self.metatraffic_port
    }

    /// Public port that reaches this participant's user-data unicast socket.
    #[must_use]
    pub fn user_port(&self) -> u16 {
        self.user_port
    }

    /// Parse a comma-separated list, as accepted by
    /// [`ENV_EXTERNAL_LOCATOR`].
    ///
    /// An empty or whitespace-only input yields an empty list. Anything else
    /// must be a complete list of valid entries.
    ///
    /// # Errors
    ///
    /// The first entry that fails to parse or to validate, so a malformed
    /// list is refused as a whole rather than silently half-applied.
    pub fn parse_list(text: &str) -> Result<Vec<Self>, ExternalLocatorError> {
        if text.trim().is_empty() {
            return Ok(Vec::new());
        }
        text.split(',').map(|entry| entry.trim().parse()).collect()
    }
}

impl fmt::Display for ExternalLocator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}",
            self.address, self.metatraffic_port, self.user_port
        )
    }
}

impl FromStr for ExternalLocator {
    type Err = ExternalLocatorError;

    /// Parse `ADDRESS:METATRAFFIC_PORT:USER_PORT`, for example
    /// `203.0.113.7:7410:7411`.
    ///
    /// Both ports are mandatory. A two-field short form is deliberately NOT
    /// accepted: it would have to guess whether the second value is the
    /// metatraffic port or both ports, and a NAT mapping where the two
    /// happen to coincide is the exception, not the rule.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let malformed = |reason: &'static str| ExternalLocatorError::Malformed {
            text: text.to_string(),
            reason,
        };

        let mut fields = text.split(':');
        let (Some(address), Some(metatraffic), Some(user), None) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return Err(malformed(
                "expected exactly three fields: ADDRESS:METATRAFFIC_PORT:USER_PORT",
            ));
        };

        let address: Ipv4Addr = address
            .parse()
            .map_err(|_| malformed("the first field is not an IPv4 address"))?;
        let metatraffic: u16 = metatraffic
            .parse()
            .map_err(|_| malformed("the metatraffic port is not a number in 0..=65535"))?;
        let user: u16 = user
            .parse()
            .map_err(|_| malformed("the user-data port is not a number in 0..=65535"))?;

        Self::new(address, metatraffic, user)
    }
}

/// Why an address can never be a unicast destination for a REMOTE peer.
///
/// Returns `None` when the address is acceptable. Each rejection names a
/// range whose failure is a property of IP routing, not of our deployment:
/// what is merely unlikely to work (a documentation range, an address behind
/// a NAT we do not know about) is accepted, because only the operator can
/// judge it.
fn unroutable_reason(address: Ipv4Addr) -> Option<&'static str> {
    if address.octets()[0] == 0 {
        // RFC 1122 s3.2.1.3: "this network". Includes 0.0.0.0 itself.
        return Some("0.0.0.0/8 is a source-only range, never a destination");
    }
    if address.is_loopback() {
        return Some("127.0.0.0/8 reaches the SENDING host, not this one");
    }
    if address.is_multicast() {
        return Some("a multicast group is not a unicast destination");
    }
    if address.is_broadcast() {
        return Some("255.255.255.255 is not a unicast destination");
    }
    if address.is_link_local() {
        return Some("169.254.0.0/16 does not route past the sender's own link");
    }
    if address.octets()[0] >= 240 {
        return Some("240.0.0.0/4 is reserved and not routed");
    }
    None
}

/// Why an external locator was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExternalLocatorError {
    /// The address can never be a unicast destination for a remote peer.
    UnroutableAddress {
        /// The address that was refused.
        address: Ipv4Addr,
        /// Which routing property makes it unusable.
        reason: &'static str,
    },
    /// A port is zero, which is `LOCATOR_PORT_INVALID` on the wire.
    InvalidPort {
        /// Which of the two ports: `"metatraffic"` or `"user data"`.
        role: &'static str,
    },
    /// The textual form could not be read.
    Malformed {
        /// The entry as supplied.
        text: String,
        /// What was expected instead.
        reason: &'static str,
    },
}

impl fmt::Display for ExternalLocatorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnroutableAddress { address, reason } => {
                write!(
                    f,
                    "external locator address {address} is unusable: {reason}"
                )
            }
            Self::InvalidPort { role } => {
                write!(f, "external locator {role} port must not be zero")
            }
            Self::Malformed { text, reason } => {
                write!(f, "cannot read external locator '{text}': {reason}")
            }
        }
    }
}

impl std::error::Error for ExternalLocatorError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn public() -> Ipv4Addr {
        Ipv4Addr::new(93, 184, 216, 34)
    }

    #[test]
    fn accepts_a_public_address_with_two_distinct_ports() {
        let locator = ExternalLocator::new(public(), 40001, 40002).expect("valid");
        assert_eq!(locator.address(), public());
        assert_eq!(locator.metatraffic_port(), 40001);
        assert_eq!(locator.user_port(), 40002);
    }

    #[test]
    fn accepts_private_and_cgnat_addresses() {
        // A port forwarded on a router in another subnet, or a site-to-site
        // tunnel, is a legitimate external locator.
        for address in [
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(172, 16, 4, 9),
            Ipv4Addr::new(192, 168, 1, 50),
            Ipv4Addr::new(100, 64, 0, 1),
        ] {
            assert!(
                ExternalLocator::new(address, 7410, 7411).is_ok(),
                "{address} should be accepted"
            );
        }
    }

    #[test]
    fn refuses_addresses_that_can_never_be_a_destination() {
        for address in [
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::new(0, 1, 2, 3),
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::new(239, 255, 0, 1),
            Ipv4Addr::BROADCAST,
            Ipv4Addr::new(169, 254, 1, 1),
            Ipv4Addr::new(240, 0, 0, 1),
        ] {
            let error = ExternalLocator::new(address, 7410, 7411)
                .expect_err("an address that cannot be a destination must be refused");
            assert!(
                matches!(error, ExternalLocatorError::UnroutableAddress { .. }),
                "{address} refused for the wrong reason: {error}"
            );
        }
    }

    #[test]
    fn refuses_a_zero_port_and_names_which_one() {
        let error = ExternalLocator::new(public(), 0, 7411).expect_err("zero metatraffic port");
        assert_eq!(
            error,
            ExternalLocatorError::InvalidPort {
                role: "metatraffic"
            }
        );
        let error = ExternalLocator::new(public(), 7410, 0).expect_err("zero user port");
        assert_eq!(
            error,
            ExternalLocatorError::InvalidPort { role: "user data" }
        );
    }

    #[test]
    fn parses_the_textual_form_round_trip() {
        let locator: ExternalLocator = "93.184.216.34:40001:40002".parse().expect("valid");
        assert_eq!(
            locator,
            ExternalLocator::new(public(), 40001, 40002).expect("valid")
        );
        assert_eq!(locator.to_string(), "93.184.216.34:40001:40002");
    }

    #[test]
    fn refuses_a_two_field_form_rather_than_guessing() {
        let error = "93.184.216.34:7410"
            .parse::<ExternalLocator>()
            .expect_err("two fields");
        assert!(matches!(error, ExternalLocatorError::Malformed { .. }));
    }

    #[test]
    fn refuses_a_four_field_form() {
        assert!("93.184.216.34:7410:7411:7412"
            .parse::<ExternalLocator>()
            .is_err());
    }

    #[test]
    fn refuses_a_non_ipv4_first_field() {
        // An IPv6 literal cannot even be spelled here: the transport binds
        // IPv4 sockets, so the type refuses it before validation does.
        assert!("::1:7410:7411".parse::<ExternalLocator>().is_err());
        assert!("example.com:7410:7411".parse::<ExternalLocator>().is_err());
    }

    #[test]
    fn refuses_an_out_of_range_port() {
        assert!("93.184.216.34:70000:7411"
            .parse::<ExternalLocator>()
            .is_err());
    }

    #[test]
    fn parse_list_accepts_empty_and_several_entries() {
        assert!(ExternalLocator::parse_list("").expect("empty").is_empty());
        assert!(ExternalLocator::parse_list("   ")
            .expect("blank")
            .is_empty());

        let list = ExternalLocator::parse_list("93.184.216.34:40001:40002, 198.51.100.9:7410:7411")
            .expect("two entries");
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].metatraffic_port(), 40001);
        assert_eq!(list[1].address(), Ipv4Addr::new(198, 51, 100, 9));
    }

    #[test]
    fn parse_list_refuses_the_whole_list_on_one_bad_entry() {
        // All-or-nothing: a half-applied list would announce a locator set
        // the operator never asked for.
        let error = ExternalLocator::parse_list("93.184.216.34:40001:40002,garbage")
            .expect_err("one bad entry");
        assert!(matches!(error, ExternalLocatorError::Malformed { .. }));
    }

    #[test]
    fn error_messages_name_the_offending_value() {
        let error = ExternalLocator::new(Ipv4Addr::LOCALHOST, 7410, 7411).expect_err("loopback");
        let rendered = error.to_string();
        assert!(rendered.contains("127.0.0.1"), "{rendered}");
        assert!(rendered.contains("SENDING host"), "{rendered}");
    }
}
