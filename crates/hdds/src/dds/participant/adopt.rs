// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Type-name adoption for endpoints created without a type name.
//!
//! DDS-XTypes v1.3 Sec.7.6.3.4.2 Step 2: when a TypeObject is missing on one
//! side, the writer's and the reader's type names must be equal. A raw
//! endpoint (`create_raw_reader`, the C ABI constructors that take no type)
//! has no type of its own, so the name it announces is a placeholder
//! (`RawBytes`) that no typed peer announces.
//!
//! Such an endpoint adopts the name the opposite endpoints of its topic
//! already announce. The decision is taken once, at creation (control path):
//! the name is handed to the builder as an override, nothing changes on the
//! data path, and the endpoint is never re-announced under another name.
//!
//! Only endpoints with no type at all adopt. An endpoint created for a type
//! (a generated type, a ROS 2 message) announces that type's name and never
//! takes a peer's: adopting a foreign name would pair it with a writer or
//! reader whose bytes it cannot decode.
//!
//! The order of what an endpoint that adopts (one with no type and no name)
//! announces, one rule for every builder ([`Participant::settle_type`]); an
//! endpoint created for a type is not settled and announces its own type:
//! 1. the type registered for the topic on this participant (its name and
//!    its TypeObject);
//! 2. else the name its topic's opposite endpoints announce, with NO
//!    TypeObject (the endpoint carries bytes, not the peer's type);
//! 3. else the placeholder [`PLACEHOLDER_TYPE_NAME`], passed explicitly.
//!
//! The name that comes out is the one announced in SEDP AND the one the
//! intra-process match key is built from.

use super::live_capture::DiscoveredEndpointKind;
use super::runtime::Participant;
use crate::core::discovery::multicast::SedpEndpointKind;
use crate::xtypes::CompleteTypeObject;
use std::collections::BTreeSet;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// The type name an endpoint with no type of its own announces. It carries
/// no information, so it is never adopted from a peer.
pub const PLACEHOLDER_TYPE_NAME: &str = "RawBytes";

/// Environment variable: how long (milliseconds) endpoint creation waits for
/// a name to be discovered when none is known yet. Unset, empty or 0 means no
/// wait. It is read ONCE per process, at the first endpoint creation that
/// needs it: set it before the first endpoint is created, a later change has
/// no effect. The wait blocks the calling thread.
pub const ADOPT_WAIT_ENV: &str = "HDDS_TYPE_ADOPT_WAIT_MS";

/// Upper bound of [`ADOPT_WAIT_ENV`], so a typo cannot hang a constructor.
const ADOPT_WAIT_MAX_MS: u64 = 10_000;

/// Poll period of the optional wait.
const ADOPT_POLL: Duration = Duration::from_millis(20);

/// What the names announced on a topic say.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Adoption {
    /// Exactly one real name is announced: adopt it.
    Adopt(String),
    /// Nothing is announced (nothing discovered yet): a name may still come.
    Nothing,
    /// Only the placeholder is announced: there is nothing to adopt, and a
    /// typed name arriving later would make the topic ambiguous, never
    /// adoptable, so waiting cannot change the answer.
    PlaceholderOnly,
    /// Several different names are announced, a live placeholder endpoint
    /// among them: no guess is made.
    Ambiguous(Vec<String>),
}

/// Decide from the names announced by the opposite endpoints of a topic.
///
/// An opposite endpoint announcing the placeholder counts as a name: beside
/// a typed peer it makes the topic ambiguous, so a new raw endpoint keeps
/// the placeholder and stays paired with the raw endpoint already there,
/// instead of leaving it for the typed peer. The placeholder alone adopts
/// nothing (it is what the endpoint announces anyway) and ends any wait.
pub(crate) fn decide<I, S>(names: I) -> Adoption
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let announced: BTreeSet<String> = names
        .into_iter()
        .map(|name| name.as_ref().to_string())
        .filter(|name| !name.is_empty())
        .collect();
    let mut iter = announced.into_iter();
    match (iter.next(), iter.next()) {
        (None, _) => Adoption::Nothing,
        (Some(only), None) if only == PLACEHOLDER_TYPE_NAME => Adoption::PlaceholderOnly,
        (Some(only), None) => Adoption::Adopt(only),
        (Some(first), Some(second)) => {
            let mut all = vec![first, second];
            all.extend(iter);
            Adoption::Ambiguous(all)
        }
    }
}

/// What [`ADOPT_WAIT_ENV`] asks for, in milliseconds, clamped to
/// [`ADOPT_WAIT_MAX_MS`], and whether it was clamped. `None` for a value that
/// is not a number of milliseconds (the wait is then 0).
fn parse_wait_ms(raw: &str) -> Option<(u64, bool)> {
    let ms = raw.trim().parse::<u64>().ok()?;
    Some((ms.min(ADOPT_WAIT_MAX_MS), ms > ADOPT_WAIT_MAX_MS))
}

/// The wait [`ADOPT_WAIT_ENV`] asks for, read once per process. A value
/// that is not a number of milliseconds, or above the 10 s bound, is
/// reported once.
fn configured_wait() -> Duration {
    static WAIT: OnceLock<Duration> = OnceLock::new();
    *WAIT.get_or_init(|| {
        let Ok(raw) = std::env::var(ADOPT_WAIT_ENV) else {
            return Duration::ZERO;
        };
        // Set but empty (`HDDS_TYPE_ADOPT_WAIT_MS=`): the same as unset.
        if raw.trim().is_empty() {
            return Duration::ZERO;
        }
        match parse_wait_ms(&raw) {
            Some((ms, clamped)) => {
                if clamped {
                    log::warn!(
                        "[adopt] {ADOPT_WAIT_ENV}='{raw}' is above the {ADOPT_WAIT_MAX_MS} ms \
                         bound: using {ms} ms"
                    );
                }
                Duration::from_millis(ms)
            }
            None => {
                log::warn!(
                    "[adopt] {ADOPT_WAIT_ENV}='{raw}' is not a number of milliseconds: \
                     creation does not wait"
                );
                Duration::ZERO
            }
        }
    })
}

/// The type an endpoint settles on at build time
/// ([`Participant::settle_type`]).
#[derive(Debug, Default)]
pub(crate) struct SettledType {
    /// The name to announce; `None` leaves the builder's default (the type's
    /// own name).
    pub(crate) name: Option<String>,
    /// The TypeObject to announce.
    pub(crate) object: Option<CompleteTypeObject>,
    /// The name is announced alone: no TypeObject registered under it is
    /// looked up and attached.
    pub(crate) name_only: bool,
}

impl Participant {
    /// The real type names announced on `topic_name` by the endpoints a local
    /// endpoint of kind `local_kind` would pair with: this participant's own
    /// announcements and every endpoint discovery knows.
    fn announced_type_names(
        &self,
        topic_name: &str,
        local_kind: DiscoveredEndpointKind,
    ) -> Vec<String> {
        let wanted = match local_kind {
            DiscoveredEndpointKind::Reader => SedpEndpointKind::Writer,
            DiscoveredEndpointKind::Writer => SedpEndpointKind::Reader,
        };
        let mut names: Vec<String> = {
            let history = self
                .sedp_announcements
                .read()
                .unwrap_or_else(|e| e.into_inner());
            history
                .alive()
                .filter(|(data, kind)| *kind == wanted && data.topic_name == topic_name)
                .map(|(data, _)| data.type_name.clone())
                .collect()
        };
        if let Some(ref fsm) = self.discovery_fsm {
            // The same lists the writers walk to send (one topic's entries,
            // not a clone of the whole registry). `find_readers_for_topic`
            // leaves out a reader the security plugins do not admit: wanted
            // here, the name of an endpoint that is not allowed to talk to
            // us is not a name to adopt.
            let remote = match local_kind {
                DiscoveredEndpointKind::Reader => fsm.find_writers_for_topic(topic_name),
                DiscoveredEndpointKind::Writer => fsm.find_readers_for_topic(topic_name),
            };
            names.extend(remote.into_iter().map(|endpoint| endpoint.type_name));
        }
        names
    }

    /// The one rule that decides what a builder announces, and builds its
    /// intra-process match key from, when it was given no type name.
    ///
    /// `kind` is the kind of the endpoint being built and `adopt` says
    /// whether it is a raw endpoint (no type of its own: it asked to adopt).
    /// An explicit `name` always wins and is returned untouched, and an
    /// endpoint that does not adopt keeps its own type's name (nothing is
    /// settled for it). Otherwise, for an endpoint that adopts:
    /// 1. the type registered for `topic` on this participant: its name and
    ///    its TypeObject (not under `HDDS_DISABLE_TYPE_OBJECT`);
    /// 2. else the name the opposite endpoints announce
    ///    ([`Self::adopt_type_name`]) with no TypeObject, announced as a
    ///    name alone;
    /// 3. else the placeholder, passed explicitly.
    pub(crate) fn settle_type(
        &self,
        topic: &str,
        kind: DiscoveredEndpointKind,
        name: Option<String>,
        object: Option<CompleteTypeObject>,
        adopt: bool,
    ) -> SettledType {
        if name.is_some() {
            return SettledType {
                name,
                object,
                name_only: false,
            };
        }
        // An endpoint created for a type announces that type, whatever is
        // registered for the topic: only a type-less endpoint follows the
        // registered topic type or a peer.
        if !adopt {
            return SettledType {
                name: None,
                object,
                name_only: false,
            };
        }
        #[cfg(feature = "xtypes")]
        if std::env::var_os("HDDS_DISABLE_TYPE_OBJECT").is_none() {
            if let Some(handle) = self.topic_type_handle(topic) {
                return SettledType {
                    name: Some(handle.fqn.as_ref().to_string()),
                    object: Some(handle.complete.clone()),
                    name_only: false,
                };
            }
        }
        SettledType {
            name: Some(
                self.adopt_type_name(topic, kind)
                    .unwrap_or_else(|| PLACEHOLDER_TYPE_NAME.to_string()),
            ),
            object,
            name_only: true,
        }
    }

    /// The type name a reader or writer created WITHOUT one should announce.
    ///
    /// `local_kind` is the kind of the endpoint being created. A reader
    /// adopts the name its topic's writers announce, a writer the name its
    /// topic's readers announce (this participant's own endpoints included).
    ///
    /// - exactly one real name is announced: `Some(name)`;
    /// - nothing is announced yet, or only the placeholder `RawBytes`:
    ///   `None`, and the endpoint keeps announcing the placeholder, which
    ///   matches every other nameless endpoint. It is NOT re-announced when a
    ///   name is discovered later (an endpoint's type name is part of its
    ///   identity for the peers that already matched it); create it again, or
    ///   pass the name from [`Self::discover_topics`], when the type is
    ///   known only after startup. `HDDS_TYPE_ADOPT_WAIT_MS` makes creation
    ///   wait up to that long (at most 10 s) for a name; unset, it does not;
    /// - several different names are announced, the placeholder among them
    ///   (a live raw endpoint beside a typed one): `None` and a warning,
    ///   because any pick would silently choose which side is refused.
    ///
    /// Blocks the calling thread for the configured wait when nothing is
    /// announced. Cold path only: call it at endpoint creation, never per
    /// sample.
    #[must_use]
    pub fn adopt_type_name(
        &self,
        topic_name: &str,
        local_kind: DiscoveredEndpointKind,
    ) -> Option<String> {
        self.adopt_type_name_within(topic_name, local_kind, configured_wait())
    }

    /// [`Self::adopt_type_name`] with an explicit wait instead of the
    /// environment's.
    #[must_use]
    pub(crate) fn adopt_type_name_within(
        &self,
        topic_name: &str,
        local_kind: DiscoveredEndpointKind,
        wait: Duration,
    ) -> Option<String> {
        // A wait too large to add to the clock is no wait at all.
        let deadline = Instant::now()
            .checked_add(wait)
            .unwrap_or_else(Instant::now);
        loop {
            match decide(self.announced_type_names(topic_name, local_kind)) {
                Adoption::Adopt(name) => {
                    log::info!(
                        "[adopt] topic '{topic_name}': the {local_kind:?} adopts the type name \
                         '{name}' its opposite endpoints announce"
                    );
                    return Some(name);
                }
                Adoption::Ambiguous(names) => {
                    log::warn!(
                        "[adopt] topic '{}' is announced with several type names {:?}: \
                         the endpoint keeps the placeholder '{}' (pass a type name to choose)",
                        topic_name,
                        names,
                        PLACEHOLDER_TYPE_NAME
                    );
                    return None;
                }
                Adoption::PlaceholderOnly => {
                    log::info!(
                        "[adopt] topic '{topic_name}': only the placeholder '{}' is announced by \
                         the opposite endpoints: the {local_kind:?} announces it too",
                        PLACEHOLDER_TYPE_NAME
                    );
                    return None;
                }
                Adoption::Nothing => {}
            }
            // Nothing can arrive on a participant with no discovery.
            if self.discovery_fsm.is_none() || Instant::now() >= deadline {
                log::info!(
                    "[adopt] topic '{topic_name}': no type name announced by the opposite \
                     endpoints{}: the {local_kind:?} announces the placeholder '{}' and is not \
                     re-announced if a name is discovered later",
                    if self.discovery_fsm.is_none() {
                        " (no discovery on this participant)"
                    } else if wait.is_zero() {
                        " yet (no wait configured)"
                    } else {
                        " within the wait"
                    },
                    PLACEHOLDER_TYPE_NAME
                );
                return None;
            }
            std::thread::sleep(ADOPT_POLL.min(deadline.saturating_duration_since(Instant::now())));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_announced_adopts_nothing() {
        assert_eq!(decide(Vec::<String>::new()), Adoption::Nothing);
    }

    #[test]
    fn the_placeholder_alone_and_empty_names_adopt_nothing() {
        assert_eq!(
            decide(["RawBytes", "", "RawBytes"]),
            Adoption::PlaceholderOnly
        );
        assert_eq!(decide(["", ""]), Adoption::Nothing);
    }

    #[test]
    fn one_real_name_is_adopted_however_many_announce_it() {
        assert_eq!(
            decide(["X::Y", "", "X::Y"]),
            Adoption::Adopt("X::Y".to_string())
        );
    }

    #[test]
    fn a_live_placeholder_beside_a_real_name_is_ambiguous() {
        assert_eq!(
            decide(["RawBytes", "X::Y"]),
            Adoption::Ambiguous(vec!["RawBytes".to_string(), "X::Y".to_string()])
        );
    }

    #[test]
    fn the_wait_env_is_parsed_strictly_and_clamped() {
        assert_eq!(parse_wait_ms("250"), Some((250, false)));
        assert_eq!(parse_wait_ms(" 40 "), Some((40, false)));
        assert_eq!(parse_wait_ms("99999"), Some((ADOPT_WAIT_MAX_MS, true)));
        assert_eq!(parse_wait_ms("1000ms"), None);
        assert_eq!(parse_wait_ms("-1"), None);
    }

    #[test]
    fn two_real_names_are_ambiguous() {
        assert_eq!(
            decide(["B::T", "A::T", "B::T"]),
            Adoption::Ambiguous(vec!["A::T".to_string(), "B::T".to_string()])
        );
    }
}
