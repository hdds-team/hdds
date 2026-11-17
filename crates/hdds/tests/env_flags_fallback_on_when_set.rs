// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! The ON side of the unknown-writer fallback gate.
//!
//! Same fixture as `env_flags_fallback_off_by_default` - one topic, one
//! subscriber - with `HDDS_ROUTE_UNKNOWN_WRITER_TO_SINGLE_TOPIC` set before
//! anything in this process has read it. The two binaries together are what
//! pin the gate's polarity: this one shows the body CAN answer with a topic,
//! that one shows the gate is what stops it.
//!
//! The variable is set at the very top, before the registry exists, because
//! the knob is answered by the first read and kept for the life of the
//! process. Own binary, one test, no parallel reader: `set_var` races every
//! concurrent `getenv` (edition 2024 makes it `unsafe` for that reason).

use hdds::engine::{CallbackSubscriber, TopicRegistry};
use std::sync::Arc;

const VAR: &str = "HDDS_ROUTE_UNKNOWN_WRITER_TO_SINGLE_TOPIC";

#[test]
fn the_operator_can_turn_the_unannounced_writer_guess_on() {
    std::env::set_var(VAR, "1");
    assert_eq!(
        std::env::var(VAR).ok().as_deref(),
        Some("1"),
        "the environment write itself must have landed"
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
        registry
            .fallback_map_unknown_writer_to_single_topic(unannounced_writer)
            .as_deref(),
        Some("the_only_topic"),
        "with {VAR} set the fallback must bind the writer to the single \
         subscribed topic"
    );

    // The binding is remembered, not recomputed per packet.
    assert_eq!(
        registry.get_topic_by_guid(&unannounced_writer).as_deref(),
        Some("the_only_topic"),
        "the fallback registers the GUID it guessed"
    );
}
