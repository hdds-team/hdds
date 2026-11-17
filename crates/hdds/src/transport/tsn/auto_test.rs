// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::*;

// -----------------------------------------------------------------------
// Helper: build capabilities with various features
// -----------------------------------------------------------------------

fn caps_none() -> TsnCapabilities {
    TsnCapabilities::default() // everything unsupported
}

fn caps_basic() -> TsnCapabilities {
    TsnCapabilities {
        so_txtime: SupportLevel::Supported,
        ..Default::default()
    }
}

fn caps_full() -> TsnCapabilities {
    TsnCapabilities {
        so_txtime: SupportLevel::SupportedWithOffload,
        etf_configured: true,
        taprio_configured: true,
        mqprio_configured: true,
        cbs_configured: true,
        hw_timestamping: SupportLevel::SupportedWithOffload,
        ..Default::default()
    }
}

// -----------------------------------------------------------------------
// 1. BestEffort + no hints -> no TSN
// -----------------------------------------------------------------------
#[test]
fn test_best_effort_no_hints_no_tsn() {
    let qos = QosHints::best_effort();
    let cfg = qos_to_tsn(&qos, &caps_full());

    assert!(!cfg.enabled);
    assert_eq!(cfg.pcp, None);
    assert_eq!(cfg.tx_time, TxTimePolicy::Disabled);
}

// -----------------------------------------------------------------------
// 2. No capabilities -> always disabled
// -----------------------------------------------------------------------
#[test]
fn test_no_capabilities_returns_disabled() {
    let qos = QosHints::default()
        .with_deadline(Duration::from_micros(500))
        .with_priority(80);

    let cfg = qos_to_tsn(&qos, &caps_none());

    // No TSN hardware at all -> disabled
    assert!(!cfg.enabled);
}

// -----------------------------------------------------------------------
// 3. High priority + small deadline -> high PCP + SO_TXTIME
// -----------------------------------------------------------------------
#[test]
fn test_high_priority_small_deadline() {
    let qos = QosHints::default()
        .with_deadline(Duration::from_micros(500))
        .with_priority(80)
        .with_reliable();

    let cfg = qos_to_tsn(&qos, &caps_full());

    assert!(cfg.enabled);
    // priority 80 -> PCP ~5-6, clamped to 7 max
    assert!(cfg.pcp.unwrap() >= 5);
    assert_eq!(cfg.dscp, Some(DSCP_EF)); // sub-ms -> EF
    assert_eq!(cfg.tx_time, TxTimePolicy::Mandatory); // reliable
    assert!(cfg.strict_deadline); // ETF present + sub-ms
}

// -----------------------------------------------------------------------
// 4. TransportPriority clamped to max_pcp
// -----------------------------------------------------------------------
#[test]
fn test_transport_priority_clamped_to_max_pcp() {
    let qos = QosHints::default()
        .with_priority(100) // would map to PCP 7
        .with_deadline(Duration::from_millis(5));

    // Without mqprio, max_pcp = 6
    let caps = TsnCapabilities {
        so_txtime: SupportLevel::Supported,
        mqprio_configured: false,
        ..Default::default()
    };

    let cfg = qos_to_tsn(&qos, &caps);

    assert!(cfg.enabled);
    assert!(
        cfg.pcp.unwrap() <= 6,
        "PCP should be clamped to 6 without mqprio"
    );
}

// -----------------------------------------------------------------------
// 5. Capability fallback: no SO_TXTIME -> skip txtime
// -----------------------------------------------------------------------
#[test]
fn test_no_so_txtime_skips_txtime() {
    let qos = QosHints::default()
        .with_deadline(Duration::from_micros(500))
        .with_reliable();

    // so_txtime unsupported but mqprio available
    let caps = TsnCapabilities {
        so_txtime: SupportLevel::Unsupported,
        mqprio_configured: true,
        ..Default::default()
    };

    let cfg = qos_to_tsn(&qos, &caps);

    assert!(cfg.enabled);
    assert_eq!(cfg.tx_time, TxTimePolicy::Disabled);
    // But PCP should still be set
    assert!(cfg.pcp.is_some());
}

// -----------------------------------------------------------------------
// 6. Default QoS mapping (no hints at all)
// -----------------------------------------------------------------------
#[test]
fn test_default_qos_mapping() {
    let qos = QosHints::default();
    let cfg = qos_to_tsn(&qos, &caps_full());

    // Default = BestEffort, infinite deadline, priority 0
    // -> should produce disabled config (no TSN overhead)
    assert!(!cfg.enabled);
}

// -----------------------------------------------------------------------
// 7. Medium deadline (1-10ms) -> AF41 DSCP + medium PCP
// -----------------------------------------------------------------------
#[test]
fn test_medium_deadline_mapping() {
    let qos = QosHints::default().with_deadline(Duration::from_millis(5));

    let cfg = qos_to_tsn(&qos, &caps_full());

    assert!(cfg.enabled);
    assert_eq!(cfg.dscp, Some(DSCP_AF41));
    // PCP should be in the 4-6 range for 5ms deadline
    let pcp = cfg.pcp.unwrap();
    assert!(
        (4..=7).contains(&pcp),
        "PCP {} should be 4-7 for 5ms deadline",
        pcp
    );
}

// -----------------------------------------------------------------------
// 8. Reliable + finite deadline -> txtime enabled
// -----------------------------------------------------------------------
#[test]
fn test_reliable_finite_deadline_enables_txtime() {
    let qos = QosHints::default()
        .with_deadline(Duration::from_millis(50))
        .with_reliable();

    let cfg = qos_to_tsn(&qos, &caps_basic());

    assert!(cfg.enabled);
    assert_ne!(cfg.tx_time, TxTimePolicy::Disabled);
}

// -----------------------------------------------------------------------
// 9. Negative transport priority -> PCP 0
// -----------------------------------------------------------------------
#[test]
fn test_negative_priority_maps_to_pcp_zero() {
    let qos = QosHints::default()
        .with_priority(-50)
        .with_deadline(Duration::from_millis(5)); // needs deadline to enable

    let cfg = qos_to_tsn(&qos, &caps_full());

    assert!(cfg.enabled);
    assert_eq!(cfg.pcp, Some(0));
}

// -----------------------------------------------------------------------
// 10. Sub-ms deadline without ETF -> no strict_deadline
// -----------------------------------------------------------------------
#[test]
fn test_sub_ms_without_etf_no_strict() {
    let qos = QosHints::default()
        .with_deadline(Duration::from_micros(500))
        .with_reliable();

    // so_txtime supported but no ETF qdisc
    let caps = TsnCapabilities {
        so_txtime: SupportLevel::Supported,
        etf_configured: false,
        ..Default::default()
    };

    let cfg = qos_to_tsn(&qos, &caps);

    assert!(cfg.enabled);
    assert!(!cfg.strict_deadline, "strict_deadline requires ETF qdisc");
}

// -----------------------------------------------------------------------
// 11. Lead time proportional to deadline
// -----------------------------------------------------------------------
#[test]
fn test_lead_time_proportional() {
    let qos = QosHints::default()
        .with_deadline(Duration::from_millis(5))
        .with_reliable();

    let cfg = qos_to_tsn(&qos, &caps_basic());

    // 10% of 5ms = 500us = 500_000 ns
    assert_eq!(cfg.lead_time_ns, 500_000);
}

// -----------------------------------------------------------------------
// 12. Lead time clamped to minimum (100us)
// -----------------------------------------------------------------------
#[test]
fn test_lead_time_minimum_clamp() {
    let qos = QosHints::default()
        .with_deadline(Duration::from_micros(100)) // 10% = 10us < 100us min
        .with_reliable();

    let cfg = qos_to_tsn(&qos, &caps_basic());

    assert!(
        cfg.lead_time_ns >= 100_000,
        "Lead time should be at least 100us"
    );
}

// -----------------------------------------------------------------------
// 13. Lead time clamped to maximum (5ms)
// -----------------------------------------------------------------------
#[test]
fn test_lead_time_maximum_clamp() {
    let qos = QosHints::default()
        .with_deadline(Duration::from_millis(500)) // 10% = 50ms > 5ms max
        .with_reliable();

    let cfg = qos_to_tsn(&qos, &caps_basic());

    assert!(
        cfg.lead_time_ns <= 5_000_000,
        "Lead time should be at most 5ms"
    );
}

// -----------------------------------------------------------------------
// 14. TsnMode variants
// -----------------------------------------------------------------------
#[test]
fn test_tsn_mode_default_is_off() {
    let mode = TsnMode::default();
    assert!(matches!(mode, TsnMode::Off));
}

#[test]
fn test_tsn_mode_manual() {
    let cfg = TsnConfig::high_priority();
    let mode = TsnMode::Manual(cfg.clone());
    if let TsnMode::Manual(c) = mode {
        assert_eq!(c.pcp, Some(6));
    } else {
        panic!("Expected TsnMode::Manual");
    }
}

#[test]
fn test_tsn_mode_auto() {
    let mode = TsnMode::Auto;
    assert!(matches!(mode, TsnMode::Auto));
}

// -----------------------------------------------------------------------
// 15. WriterTsnOverride
// -----------------------------------------------------------------------
#[test]
fn test_writer_override_none() {
    let over = WriterTsnOverride::none();
    let participant_cfg = TsnConfig::high_priority();

    let resolved = over.resolve(&participant_cfg);
    assert_eq!(resolved.pcp, Some(6));
    assert!(resolved.enabled);
}

#[test]
fn test_writer_override_with_config() {
    let over = WriterTsnOverride::with_config(TsnConfig::low_priority());
    let participant_cfg = TsnConfig::high_priority();

    let resolved = over.resolve(&participant_cfg);
    assert_eq!(resolved.pcp, Some(2));
}

#[test]
fn test_writer_override_force_off() {
    let over = WriterTsnOverride::off();
    let participant_cfg = TsnConfig::high_priority();

    let resolved = over.resolve(&participant_cfg);
    assert!(!resolved.enabled);
    assert_eq!(resolved.pcp, None);
}

// -----------------------------------------------------------------------
// 16. QosHints builder
// -----------------------------------------------------------------------
#[test]
fn test_qos_hints_default() {
    let h = QosHints::default();
    assert_eq!(h.transport_priority, 0);
    assert!(h.deadline_is_infinite());
    assert!(h.is_best_effort());
    assert!(!h.is_reliable());
}

#[test]
fn test_qos_hints_reliable_no_deadline() {
    let h = QosHints::reliable_no_deadline();
    assert!(h.is_reliable());
    assert!(h.deadline_is_infinite());
}

#[test]
fn test_qos_hints_deadline_ms() {
    let h = QosHints::default().with_deadline(Duration::from_millis(5));
    assert_eq!(h.deadline_ms(), 5);
    assert!(!h.deadline_is_infinite());
}

// -----------------------------------------------------------------------
// 17. derive_pcp edge cases
// -----------------------------------------------------------------------
#[test]
fn test_derive_pcp_priority_1_maps_to_at_least_1() {
    let qos = QosHints::default().with_priority(1);
    let pcp = derive_pcp(&qos);
    assert!(pcp >= 1, "Priority 1 should map to PCP >= 1, got {}", pcp);
}

#[test]
fn test_derive_pcp_priority_100_maps_to_7() {
    let qos = QosHints::default().with_priority(100);
    let pcp = derive_pcp(&qos);
    assert_eq!(pcp, 7);
}

#[test]
fn test_derive_pcp_priority_50_maps_to_3_or_4() {
    let qos = QosHints::default().with_priority(50);
    let pcp = derive_pcp(&qos);
    assert!((3..=4).contains(&pcp), "Priority 50 -> PCP {}", pcp);
}

// -----------------------------------------------------------------------
// 18. derive_dscp edge cases
// -----------------------------------------------------------------------
#[test]
fn test_derive_dscp_infinite_deadline() {
    let qos = QosHints::default(); // infinite deadline
    assert_eq!(derive_dscp(&qos), DSCP_BEST_EFFORT);
}

#[test]
fn test_derive_dscp_sub_ms() {
    let qos = QosHints::default().with_deadline(Duration::from_micros(500));
    assert_eq!(derive_dscp(&qos), DSCP_EF);
}

#[test]
fn test_derive_dscp_5ms() {
    let qos = QosHints::default().with_deadline(Duration::from_millis(5));
    assert_eq!(derive_dscp(&qos), DSCP_AF41);
}

#[test]
fn test_derive_dscp_100ms() {
    let qos = QosHints::default().with_deadline(Duration::from_millis(100));
    assert_eq!(derive_dscp(&qos), DSCP_BEST_EFFORT);
}

// -----------------------------------------------------------------------
// 19. BestEffort + tight deadline -> txtime opportunistic (not mandatory)
// -----------------------------------------------------------------------
#[test]
fn test_best_effort_tight_deadline_opportunistic_txtime() {
    let qos = QosHints::default().with_deadline(Duration::from_micros(500));

    let cfg = qos_to_tsn(&qos, &caps_basic());

    assert!(cfg.enabled);
    assert_eq!(cfg.tx_time, TxTimePolicy::Opportunistic);
}

// -----------------------------------------------------------------------
// 20. Reliable + infinite deadline + high priority -> TSN but no txtime
// -----------------------------------------------------------------------
#[test]
fn test_reliable_infinite_deadline_high_prio() {
    let qos = QosHints::default().with_priority(80).with_reliable();

    let cfg = qos_to_tsn(&qos, &caps_full());

    assert!(cfg.enabled);
    // High priority -> PCP set
    assert!(cfg.pcp.unwrap() >= 5);
    // Infinite deadline + reliable -> txtime NOT enabled
    // (should_enable_txtime requires deadline < 10ms or reliable+finite)
    assert_eq!(cfg.tx_time, TxTimePolicy::Disabled);
}

// -----------------------------------------------------------------------
// 21. Full integration: realistic DDS writer scenario
// -----------------------------------------------------------------------
#[test]
fn test_realistic_control_loop_writer() {
    // A 1kHz control loop writer: reliable, 1ms deadline, high priority
    let qos = QosHints::default()
        .with_deadline(Duration::from_millis(1))
        .with_priority(70)
        .with_reliable();

    let cfg = qos_to_tsn(&qos, &caps_full());

    assert!(cfg.enabled);
    assert!(cfg.pcp.unwrap() >= 4);
    assert_eq!(cfg.dscp, Some(DSCP_AF41)); // 1ms is not < 1ms
    assert_eq!(cfg.tx_time, TxTimePolicy::Mandatory);
    assert!(cfg.traffic_class.is_some());
}

// -----------------------------------------------------------------------
// 22. mqprio absent -> no traffic_class set
// -----------------------------------------------------------------------
#[test]
fn test_no_mqprio_no_traffic_class() {
    let qos = QosHints::default().with_deadline(Duration::from_millis(5));

    let caps = TsnCapabilities {
        so_txtime: SupportLevel::Supported,
        mqprio_configured: false,
        ..Default::default()
    };

    let cfg = qos_to_tsn(&qos, &caps);

    assert!(cfg.traffic_class.is_none());
}

// -----------------------------------------------------------------------
// 18. derive_pcp bands are the formula `tp * 7 / 100`, clamped to 1..=7
// -----------------------------------------------------------------------
#[test]
fn pcp_bands_match_formula() {
    for tp in 1..=100i32 {
        let qos = QosHints::default().with_priority(tp);
        let formula = (tp * 7 / 100).clamp(1, 7);
        assert_eq!(
            i32::from(derive_pcp(&qos)),
            formula,
            "transport_priority {tp}: band table disagrees with the formula"
        );
    }
    // Above the scale every priority saturates at the top band.
    for tp in [101, 255, 256, 1_000, i32::MAX] {
        let qos = QosHints::default().with_priority(tp);
        assert_eq!(derive_pcp(&qos), 7, "transport_priority {tp}");
    }
}
