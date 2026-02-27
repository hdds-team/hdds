// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::{Presentation, PresentationAccessScope};

#[test]
fn test_presentation_access_scope_default() {
    assert_eq!(
        PresentationAccessScope::default(),
        PresentationAccessScope::Instance
    );
}

#[test]
fn test_presentation_access_scope_ordering() {
    assert!(PresentationAccessScope::Instance < PresentationAccessScope::Topic);
    assert!(PresentationAccessScope::Topic < PresentationAccessScope::Group);
}

#[test]
fn test_presentation_default() {
    let policy = Presentation::default();
    assert_eq!(policy.access_scope, PresentationAccessScope::Instance);
    assert!(!policy.coherent_access);
    assert!(!policy.ordered_access);
}

#[test]
fn test_presentation_instance() {
    let policy = Presentation::instance();
    assert!(policy.is_instance_scope());
    assert!(!policy.coherent_access);
    assert!(!policy.ordered_access);
}

#[test]
fn test_presentation_topic_variants() {
    let coherent = Presentation::topic_coherent();
    assert!(coherent.is_topic_scope());
    assert!(coherent.coherent_access);
    assert!(!coherent.ordered_access);

    let ordered = Presentation::topic_ordered();
    assert!(ordered.is_topic_scope());
    assert!(!ordered.coherent_access);
    assert!(ordered.ordered_access);
}

#[test]
fn test_presentation_group_variants() {
    let coherent = Presentation::group_coherent();
    assert!(coherent.is_group_scope());
    assert!(coherent.coherent_access);
    assert!(!coherent.ordered_access);

    let both = Presentation::group_coherent_ordered();
    assert!(both.is_group_scope());
    assert!(both.coherent_access);
    assert!(both.ordered_access);
}

#[test]
fn test_presentation_new() {
    let policy = Presentation::new(PresentationAccessScope::Topic, true, true);
    assert_eq!(policy.access_scope, PresentationAccessScope::Topic);
    assert!(policy.coherent_access);
    assert!(policy.ordered_access);
}

#[test]
fn test_compatibility() {
    let instance = Presentation::instance();
    let topic = Presentation::topic_coherent();
    let group = Presentation::group_coherent();

    assert!(group.is_compatible_with(&topic));
    assert!(group.is_compatible_with(&instance));
    assert!(topic.is_compatible_with(&instance));

    assert!(!instance.is_compatible_with(&topic));
    assert!(!instance.is_compatible_with(&group));
    assert!(!topic.is_compatible_with(&group));
}

#[test]
fn test_compatibility_flags() {
    let writer = Presentation::new(PresentationAccessScope::Topic, false, false);
    let reader_coherent = Presentation::topic_coherent();
    let reader_ordered = Presentation::topic_ordered();

    assert!(!writer.is_compatible_with(&reader_coherent));
    assert!(!writer.is_compatible_with(&reader_ordered));

    let strong = Presentation::group_coherent_ordered();
    assert!(strong.is_compatible_with(&reader_coherent));
    assert!(strong.is_compatible_with(&reader_ordered));
}

#[test]
fn test_scope_helpers() {
    let instance = Presentation::instance();
    let topic = Presentation::topic_coherent();
    let group = Presentation::group_coherent();

    assert!(instance.is_instance_scope());
    assert!(!instance.is_topic_scope());
    assert!(!instance.is_group_scope());

    assert!(!topic.is_instance_scope());
    assert!(topic.is_topic_scope());
    assert!(!topic.is_group_scope());

    assert!(!group.is_instance_scope());
    assert!(!group.is_topic_scope());
    assert!(group.is_group_scope());
}
