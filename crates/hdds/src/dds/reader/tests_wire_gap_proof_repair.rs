// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::*;
use crate::core::discovery::multicast::control::release_group_reorder_gate;
use crate::core::discovery::multicast::control_types::{GapInfo, GroupInfo};
use crate::engine::Subscriber as _;

fn writer(index: usize) -> [u8; 16] {
    let mut writer = [0; 16];
    writer[..12].copy_from_slice(&PREFIX);
    writer[12..].copy_from_slice(&WRITERS[index]);
    writer
}

fn connected_group() -> Group {
    let group = configured_group_for_presentation_with_registry(
        false,
        None,
        true,
        true,
        true,
        true,
        None,
        false,
        (crate::dds::qos::PresentationAccessScope::Group, true),
        true,
        crate::protocol::group::GroupDialect::Spec,
    );
    for index in 0..2 {
        group
            .registry
            .register_writer_ownership_kind(writer(index), crate::dds::qos::OwnershipKind::Shared);
        group
            .registry
            .register_writer_partition(writer(index), crate::dds::qos::Partition::default());
    }
    group
}

fn proof_gap(group: &Group, native: (u64, u64), global: (u64, u64)) {
    let gap = GapInfo {
        writer_entity_id: WRITERS[0],
        gap_start: native.0,
        gap_list_base: native.1,
        gap_list_seqs: (native.0..native.1).collect(),
    };
    assert!(release_group_reorder_gate(
        &group.registry,
        &PREFIX,
        &gap,
        [0; 4],
        None,
        true,
        Some(GroupInfo::Gap {
            start_gsn: global.0,
            end_gsn: global.1
        }),
    ));
}

fn collect_visible(group: &Group, values: &mut Vec<i32>) {
    group.subscriber.end_access().unwrap();
    group.subscriber.begin_access().unwrap();
    while let Some(value) = group.readers[0].take().unwrap() {
        values.push(value.value);
    }
}

#[test]
fn irregular_gap_saturation_keeps_real_native_repair_requests() {
    let group = connected_group();
    let mut gsn = 2;
    let mut sn = 2;
    let intervals: Vec<_> = (1..=600)
        .map(|width| {
            let interval = ((sn, sn + width), (gsn, gsn + width));
            sn += width;
            gsn += width + 1;
            interval
        })
        .collect();
    let last_gsn = gsn;
    let last_sn = sn;
    let digest = crate::protocol::group::group_digest(WRITERS);
    // A retains its old DATA and a later DATA that this reader has not
    // received. Neither firstSN nor firstGSN can prove the internal holes.
    group.heartbeat(0, [last_gsn, 1, last_gsn], Some(digest));
    group.heartbeat(1, [last_gsn, intervals[0].1 .1, last_gsn - 1], Some(digest));
    group.subscriber.begin_access().unwrap();
    group.send(0, 1, 1, -1);
    let mut observed = Vec::new();
    collect_visible(&group, &mut observed);
    assert_eq!(observed, [-1]);
    observed.clear();
    group._sinks[0].on_writer_heartbeat_range(writer(0), 1, last_sn);
    let _ = group.credits[0].answer_heartbeat(
        &writer(0),
        &crate::core::reader::HeartbeatSeen {
            first_seq: 1,
            last_seq: last_sn as i64,
            count: 1,
            final_flag: false,
        },
    );
    for (index, &(native, global)) in intervals.iter().enumerate() {
        proof_gap(&group, native, global);
        group.send(
            1,
            u64::try_from(index).expect("bounded sample index") + 1,
            global.1,
            i32::try_from(index).expect("bounded sample value"),
        );
    }
    assert!(
        group.credits[0].awaits(&writer(0), intervals[512].0 .0),
        "a native GAP acknowledged its sole ordering proof before consumption"
    );
    collect_visible(&group, &mut observed);
    assert_eq!(
        observed,
        (0..512).collect::<Vec<_>>(),
        "overflow must preserve the lowest proved prefix"
    );

    // Repair only what real ACKNACK output requests. No arbitrary proof is
    // re-injected: each omitted interval must remain requestable natively.
    for count in 2..=1202 {
        group._sinks[0].on_writer_heartbeat_range(writer(0), 1, last_sn);
        let answer = group.credits[0]
            .answer_heartbeat(
                &writer(0),
                &crate::core::reader::HeartbeatSeen {
                    first_seq: 1,
                    last_seq: last_sn as i64,
                    count,
                    final_flag: false,
                },
            )
            .expect("unconsumed proof must keep requesting repair");
        if answer.bitmap_base == last_sn {
            assert_eq!(observed, (0..600).collect::<Vec<_>>());
            assert!(group.credits[0].awaits(&writer(0), last_sn));
            assert_eq!(
                group.readers[0].get_sample_lost_status().total_count,
                0,
                "unused Publisher GSNs are not invented lost samples"
            );
            group.subscriber.end_access().unwrap();
            return;
        }
        assert!(!answer.final_flag);
        assert!(answer.missing.contains(&answer.bitmap_base));
        let &(native, global) = intervals
            .iter()
            .find(|(native, _)| native.0 <= answer.bitmap_base && answer.bitmap_base < native.1)
            .expect("ACKNACK must request an actual unconsumed GAP interval");
        proof_gap(&group, native, global);
        collect_visible(&group, &mut observed);
    }
    panic!("bounded GAP repairs did not finish the retained ordered samples");
}

#[test]
fn a_native_group_gap_before_heartbeat_counts_its_first_real_late_body_once() {
    let group = connected_group();
    let digest = crate::protocol::group::group_digest(WRITERS);
    group.heartbeat(1, [2, 2, 2], Some(digest));
    group.subscriber.begin_access().unwrap();
    proof_gap(&group, (1, 2), (1, 2));
    assert_eq!(
        group.readers[0].get_sample_lost_status().total_count,
        0,
        "a GAP before any actual WriterSN announcement invented sample loss"
    );
    group.send(1, 1, 2, 20);
    let mut observed = Vec::new();
    collect_visible(&group, &mut observed);
    assert_eq!(observed, [20]);
    group.send(0, 1, 1, 10);
    assert_eq!(
        group.readers[0].get_sample_lost_status().total_count,
        1,
        "declared irrelevance hid the first real late DATA loss"
    );
    assert!(
        !group.credits[0].awaits(&writer(0), 1),
        "an identified terminal late sample stayed unacknowledged"
    );
    group.send(0, 1, 1, 10);
    assert_eq!(
        group.readers[0].get_sample_lost_status().total_count,
        1,
        "a repeated late body counted one sample twice"
    );
    assert_eq!(group.readers[0].take().unwrap(), None);
    group.subscriber.end_access().unwrap();
}
