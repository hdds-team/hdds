// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! The OFF side of the unknown-writer fallback gate.
//!
//! `TopicRegistry::fallback_map_unknown_writer_to_single_topic` guesses that
//! a writer GUID nothing announced belongs to the one local topic that has
//! subscribers. That guess is a discovery workaround, not a default: it is
//! DISABLED unless `HDDS_ROUTE_UNKNOWN_WRITER_TO_SINGLE_TOPIC` is set.
//!
//! The fixture here is deliberately the one that WOULD be guessed - exactly
//! one topic, exactly one subscriber - so the `None` below can only come
//! from the gate. `env_flags_fallback_on_when_set` builds the identical
//! fixture with the variable set and asserts `Some`; between them the gate's
//! polarity is pinned from both sides.
//!
//! Two binaries rather than two `#[test]`s because the knob is answered once
//! per process: one process can only ever see one side of this gate. Each
//! also mutates process-global environment, so neither may share a process
//! with a parallel reader.

use hdds::engine::{CallbackSubscriber, TopicRegistry};
use std::sync::Arc;

const VAR: &str = "HDDS_ROUTE_UNKNOWN_WRITER_TO_SINGLE_TOPIC";

#[test]
fn an_unannounced_writer_is_not_guessed_onto_the_only_subscribed_topic() {
    // State the starting point instead of inheriting the operator's.
    std::env::remove_var(VAR);
    assert!(
        std::env::var(VAR).is_err(),
        "the environment must really be clear of {VAR}"
    );

    let registry = TopicRegistry::new();
    registry
        .register_subscriber(Arc::new(CallbackSubscriber::new(
            "the_only_topic".to_string(),
            |_topic: &str, _seq: u64, _data: &[u8]| {},
        )))
        .expect("register_subscriber on a fresh registry");

    let unannounced_writer = [0xAAu8; 16];
    assert_eq!(
        registry.fallback_map_unknown_writer_to_single_topic(unannounced_writer),
        None,
        "with {VAR} absent the fallback must refuse, even though this \
         registry has exactly one topic with exactly one subscriber"
    );
}
