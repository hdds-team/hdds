// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Event hub for broadcasting system events to multiple subscribers
//!
//! Implements MPSC producer -> NxSPSC subscribers pattern for discovery,
//! matcher, QoS, and telemetry events.

use crate::core::rt::indexring::{IndexEntry, IndexRing};
use crate::core::rt::slabpool::SlabHandle;
use std::convert::TryFrom;
use std::sync::{Arc, Mutex};

/// Event types published by discovery, matcher, QoS, telemetry
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    OnMatch { writer_id: u32, reader_id: u32 },
    OnUnmatch { writer_id: u32, reader_id: u32 },
    OnIncompatibleQos { reason: u8 },
    SystemStall,
}

/// Event hub: MPSC producer -> NxSPSC subscribers
///
/// Publishers (discovery, matcher, QoS) call publish() to broadcast events.
/// Subscribers call subscribe() to get a dedicated SPSC ring for receiving events.
///
/// Events are encoded into IndexEntry fields:
/// - seq: event type (0=OnMatch, 1=OnUnmatch, 2=OnIncompatibleQos, 3=SystemStall)
/// - handle: upper 16 bits = writer_id/reason, lower 16 bits = reader_id
/// - len: 0 (unused for events)
/// - flags: COMMITTED
pub struct Hub {
    /// List of subscriber rings (NxSPSC)
    subscribers: Arc<Mutex<Vec<Arc<Mutex<IndexRing>>>>>,

    /// Monotonic sequence number for events (reserved for future use)
    #[allow(dead_code)]
    seq_counter: Arc<Mutex<u32>>,
}

impl Hub {
    /// Create new event hub
    pub fn new() -> Self {
        Self {
            subscribers: Arc::new(Mutex::new(Vec::new())),
            seq_counter: Arc::new(Mutex::new(0)),
        }
    }

    /// Subscribe to events (returns dedicated SPSC ring)
    ///
    /// # Arguments
    /// - `cap`: Ring capacity (power of 2, rounded up)
    ///
    /// # Returns
    /// Dedicated IndexRing for receiving events. Call ring.pop() to read events.
    ///
    /// # Performance
    /// Subscribers should pop() events frequently to avoid ring full condition.
    /// If ring is full, publish() will drop events for this subscriber (lossy).
    pub fn subscribe(&self, cap: usize) -> Arc<Mutex<IndexRing>> {
        let ring = Arc::new(Mutex::new(IndexRing::with_capacity(cap)));

        let mut subs = match self.subscribers.lock() {
            Ok(lock) => lock,
            Err(e) => {
                log::debug!("[Hub::subscribe] subscribers lock poisoned, recovering");
                e.into_inner()
            }
        };
        subs.push(ring.clone());

        ring
    }

    /// Publish event to all subscribers
    ///
    /// Broadcasts event to all subscriber rings. If a ring is full, the event is
    /// dropped for that subscriber (lossy for app, system subscribers should use
    /// large capacity to avoid drops).
    ///
    /// # Performance
    /// Target: < 1 us (broadcast to N subscribers)
    pub fn publish(&self, event: Event) {
        let subs = match self.subscribers.lock() {
            Ok(lock) => lock,
            Err(e) => {
                log::debug!("[Hub::publish] subscribers lock poisoned, recovering");
                e.into_inner()
            }
        };

        // Encode event into IndexEntry
        let entry = Self::encode_event(event);

        // Broadcast to all subscribers
        for sub_ring in subs.iter() {
            let ring = match sub_ring.lock() {
                Ok(lock) => lock,
                Err(e) => {
                    log::debug!("[Hub::publish] subscriber ring lock poisoned, recovering");
                    e.into_inner()
                }
            };
            // Try push (non-blocking, drop if full)
            let _ = ring.push(entry);
        }
    }

    /// Encode Event into IndexEntry
    ///
    /// Encoding scheme:
    /// - seq: event type (0=OnMatch, 1=OnUnmatch, 2=OnIncompatibleQos, 3=SystemStall)
    /// - handle: upper 16 bits = writer_id/reason, lower 16 bits = reader_id
    pub fn encode_event(event: Event) -> IndexEntry {
        let (seq, writer_or_reason, reader_id) = match event {
            Event::OnMatch {
                writer_id,
                reader_id,
            } => (0, writer_id, reader_id),
            Event::OnUnmatch {
                writer_id,
                reader_id,
            } => (1, writer_id, reader_id),
            Event::OnIncompatibleQos { reason } => (2, u32::from(reason), 0),
            Event::SystemStall => (3, 0, 0),
        };

        IndexEntry::new(
            seq,
            SlabHandle((writer_or_reason << 16) | reader_id),
            0, // len unused for events
        )
    }

    /// Decode IndexEntry back to Event
    ///
    /// Used by subscribers to decode events from ring.pop().
    pub fn decode_event(entry: IndexEntry) -> Event {
        let writer_or_reason = entry.handle.0 >> 16;
        let reader_id = entry.handle.0 & 0xFFFF;

        match entry.seq {
            0 => Event::OnMatch {
                writer_id: writer_or_reason,
                reader_id,
            },
            1 => Event::OnUnmatch {
                writer_id: writer_or_reason,
                reader_id,
            },
            2 => {
                let reason = match u8::try_from(writer_or_reason) {
                    Ok(value) => value,
                    Err(_) => {
                        log::debug!(
                            "[Hub::decode_event] invalid QoS reason value: {}",
                            writer_or_reason
                        );
                        u8::MAX
                    }
                };
                Event::OnIncompatibleQos { reason }
            }
            3 => Event::SystemStall,
            _ => Event::SystemStall, // Fallback for unknown types
        }
    }
}

impl Default for Hub {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hub_subscribe() -> Result<(), String> {
        let hub = Hub::new();
        let ring1 = hub.subscribe(16);
        let ring2 = hub.subscribe(16);

        // Verify rings are different
        if Arc::ptr_eq(&ring1, &ring2) {
            return Err("Ring pointers should be different".to_string());
        }
        Ok(())
    }

    #[test]
    fn test_hub_publish_single_subscriber() -> Result<(), String> {
        let hub = Hub::new();
        let ring = hub.subscribe(16);

        let event = Event::OnMatch {
            writer_id: 42,
            reader_id: 1337,
        };
        hub.publish(event);

        // Pop event from ring
        let ring = match ring.lock() {
            Ok(lock) => lock,
            Err(e) => {
                log::debug!("[hub test] Lock poisoned, recovering");
                e.into_inner()
            }
        };
        let entry = ring.pop().ok_or("Expected entry in ring")?;
        let decoded = Hub::decode_event(entry);

        if decoded != event {
            return Err(crate::core::string_utils::format_string(format_args!(
                "Expected {:?}, got {:?}",
                event, decoded
            )));
        }
        Ok(())
    }

    #[test]
    fn test_hub_publish_multiple_subscribers() -> Result<(), String> {
        let hub = Hub::new();
        let ring1 = hub.subscribe(16);
        let ring2 = hub.subscribe(16);

        let event = Event::OnUnmatch {
            writer_id: 100,
            reader_id: 200,
        };
        hub.publish(event);

        // Both subscribers should receive the event
        let r1 = match ring1.lock() {
            Ok(lock) => lock,
            Err(e) => {
                log::debug!("[hub test] Ring1 lock poisoned, recovering");
                e.into_inner()
            }
        };
        let entry1 = r1.pop().ok_or("Expected entry in ring1")?;
        let decoded1 = Hub::decode_event(entry1);
        if decoded1 != event {
            return Err(crate::core::string_utils::format_string(format_args!(
                "Ring1: Expected {:?}, got {:?}",
                event, decoded1
            )));
        }

        let r2 = match ring2.lock() {
            Ok(lock) => lock,
            Err(e) => {
                log::debug!("[hub test] Ring2 lock poisoned, recovering");
                e.into_inner()
            }
        };
        let entry2 = r2.pop().ok_or("Expected entry in ring2")?;
        let decoded2 = Hub::decode_event(entry2);
        if decoded2 != event {
            return Err(crate::core::string_utils::format_string(format_args!(
                "Ring2: Expected {:?}, got {:?}",
                event, decoded2
            )));
        }

        Ok(())
    }

    #[test]
    fn test_hub_encode_decode_on_match() -> Result<(), String> {
        let event = Event::OnMatch {
            writer_id: 12345,
            reader_id: 54321, // Must fit in 16 bits (< 65536)
        };
        let entry = Hub::encode_event(event);
        let decoded = Hub::decode_event(entry);

        if decoded != event {
            return Err(crate::core::string_utils::format_string(format_args!(
                "Expected event {:?}, got {:?}",
                event, decoded
            )));
        }
        if entry.seq != 0 {
            return Err(crate::core::string_utils::format_string(format_args!(
                "Expected seq 0, got {}",
                entry.seq
            )));
        }
        Ok(())
    }

    #[test]
    fn test_hub_encode_decode_on_unmatch() -> Result<(), String> {
        let event = Event::OnUnmatch {
            writer_id: 999,
            reader_id: 111,
        };
        let entry = Hub::encode_event(event);
        let decoded = Hub::decode_event(entry);

        if decoded != event {
            return Err(crate::core::string_utils::format_string(format_args!(
                "Expected event {:?}, got {:?}",
                event, decoded
            )));
        }
        if entry.seq != 1 {
            return Err(crate::core::string_utils::format_string(format_args!(
                "Expected seq 1, got {}",
                entry.seq
            )));
        }
        Ok(())
    }

    #[test]
    fn test_hub_encode_decode_incompatible_qos() -> Result<(), String> {
        let event = Event::OnIncompatibleQos { reason: 7 };
        let entry = Hub::encode_event(event);
        let decoded = Hub::decode_event(entry);

        if decoded != event {
            return Err(crate::core::string_utils::format_string(format_args!(
                "Expected event {:?}, got {:?}",
                event, decoded
            )));
        }
        if entry.seq != 2 {
            return Err(crate::core::string_utils::format_string(format_args!(
                "Expected seq 2, got {}",
                entry.seq
            )));
        }
        Ok(())
    }

    #[test]
    fn test_hub_encode_decode_system_stall() -> Result<(), String> {
        let event = Event::SystemStall;
        let entry = Hub::encode_event(event);
        let decoded = Hub::decode_event(entry);

        if decoded != event {
            return Err(crate::core::string_utils::format_string(format_args!(
                "Expected event {:?}, got {:?}",
                event, decoded
            )));
        }
        if entry.seq != 3 {
            return Err(crate::core::string_utils::format_string(format_args!(
                "Expected seq 3, got {}",
                entry.seq
            )));
        }
        Ok(())
    }

    #[test]
    fn test_hub_publish_ring_full_drops_event() -> Result<(), String> {
        let hub = Hub::new();
        let ring = hub.subscribe(4); // Small capacity

        // Fill the ring (capacity - 1 due to one reserved slot)
        for i in 0..3 {
            hub.publish(Event::OnMatch {
                writer_id: i,
                reader_id: i * 10,
            });
        }

        // Next publish should be dropped (ring full)
        hub.publish(Event::SystemStall);

        // Verify only 3 events in ring
        let r = match ring.lock() {
            Ok(lock) => lock,
            Err(e) => {
                log::debug!("[hub test] Lock poisoned, recovering");
                e.into_inner()
            }
        };

        for i in 0..3 {
            let entry = r
                .pop()
                .ok_or(crate::core::string_utils::format_string(format_args!(
                    "Expected entry {} in ring",
                    i
                )))?;
            let event = Hub::decode_event(entry);
            match event {
                Event::OnMatch { writer_id, .. } => {
                    if writer_id != i {
                        return Err(crate::core::string_utils::format_string(format_args!(
                            "Expected writer_id {}, got {}",
                            i, writer_id
                        )));
                    }
                }
                _ => {
                    return Err(crate::core::string_utils::format_string(format_args!(
                        "Unexpected event type: {:?}",
                        event
                    )))
                }
            }
        }

        // No more events (SystemStall was dropped)
        if r.pop().is_some() {
            return Err("Expected no more events after SystemStall drop".to_string());
        }

        Ok(())
    }

    #[test]
    fn test_hub_broadcast_to_many_subscribers() -> Result<(), String> {
        let hub = Hub::new();
        let mut rings = Vec::new();

        // Create 10 subscribers
        for _ in 0..10 {
            rings.push(hub.subscribe(16));
        }

        // Publish event
        let event = Event::OnMatch {
            writer_id: 777,
            reader_id: 888,
        };
        hub.publish(event);

        // All 10 subscribers should receive the event
        for (idx, ring) in rings.into_iter().enumerate() {
            let r = match ring.lock() {
                Ok(lock) => lock,
                Err(e) => {
                    log::debug!(
                        "[hub test] Lock poisoned for subscriber {}, recovering",
                        idx
                    );
                    e.into_inner()
                }
            };
            let entry = r
                .pop()
                .ok_or(crate::core::string_utils::format_string(format_args!(
                    "Expected entry for subscriber {}",
                    idx
                )))?;
            let decoded = Hub::decode_event(entry);
            if decoded != event {
                return Err(crate::core::string_utils::format_string(format_args!(
                    "Subscriber {} got {:?}, expected {:?}",
                    idx, decoded, event
                )));
            }
        }

        Ok(())
    }
}
