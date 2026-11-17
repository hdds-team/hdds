// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use hdds::dds::filter::ContentFilter;
use hdds::{Participant, TransportMode};

#[derive(Clone, hdds::DDS)]
struct FilterConfigurationSample {
    value: i64,
}

#[test]
fn reader_rejects_unconfigured_filter_before_installation() {
    let participant = Participant::builder("filter_configuration")
        .domain_id(0)
        .with_transport(TransportMode::IntraProcess)
        .build()
        .unwrap();
    let filter = ContentFilter::new("value > %0").unwrap();
    let topic = participant
        .topic::<FilterConfigurationSample>("filter_configuration")
        .unwrap();
    let result = topic
        .reader()
        .with_content_filter(filter.evaluator())
        .build();
    assert!(
        matches!(result, Err(hdds::Error::InvalidState(ref message)) if message.contains("Invalid content filter parameters"))
    );

    filter.try_set_parameters(vec!["40".into()]).unwrap();
    let _reader = topic
        .reader()
        .with_content_filter(filter.evaluator())
        .build()
        .unwrap();
    assert!(participant
        .create_content_filtered_topic::<FilterConfigurationSample>(
            "bad_configuration",
            "filter_configuration",
            "value > %0",
            vec!["1e400".into()],
        )
        .is_err());
}
