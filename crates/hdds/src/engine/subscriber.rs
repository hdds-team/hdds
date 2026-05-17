// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Subscriber trait and implementations for receiving topic data

/// Dispose/unregister kind for instance lifecycle changes.
///
/// Maps to the PID_STATUS_INFO (0x0071) value in RTPS inline QoS.
/// DDS-RTPS Sec.9.6.3.4: StatusInfo_t.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisposeKind {
    /// Instance disposed by writer (NOT_ALIVE_DISPOSED_INSTANCE_STATE)
    Disposed = 1,
    /// Writer no longer claims ownership (NOT_ALIVE_NO_WRITERS_INSTANCE_STATE)
    Unregistered = 2,
    /// Both disposed and unregistered
    DisposedUnregistered = 3,
}

/// Subscriber trait for receiving topic data
///
/// # Thread Safety
/// Implementations must be Send + Sync as callbacks are invoked
/// from the Router background thread.
///
/// # Examples
/// ```no_run
/// use hdds::engine::Subscriber;
///
/// struct MySubscriber {
///     topic: String,
/// }
///
/// impl Subscriber for MySubscriber {
///     fn on_data(&self, topic: &str, seq: u64, data: &[u8]) {
///         println!("Received seq {} ({} bytes) on topic: {}", seq, data.len(), topic);
///     }
///
///     fn topic_name(&self) -> &str {
///         &self.topic
///     }
/// }
/// ```
pub trait Subscriber: Send + Sync {
    /// Called when data is received for this subscriber's topic
    ///
    /// # Arguments
    /// - `topic`: Topic name (for multi-topic subscribers)
    /// - `seq`: RTPS writer sequence number (for reliability tracking, Task 2.1)
    /// - `data`: Payload bytes (CDR2 payload from RTPS DATA submessage)
    ///
    /// # Panics
    /// If this method panics, Router will catch it and continue
    /// delivery to other subscribers (logged as delivery_error metric).
    fn on_data(&self, topic: &str, seq: u64, data: &[u8]);

    /// Same as [`Self::on_data`] but also receives the CDR encoding
    /// version extracted from the RTPS encapsulation header per
    /// DDS-RTPS v2.5 §10.7. The default implementation delegates to
    /// `on_data` (version ignored); implementors needing version-aware
    /// decoding should override this method instead.
    fn on_data_with_version(
        &self,
        topic: &str,
        seq: u64,
        data: &[u8],
        _version: crate::dds::CdrVersion,
    ) {
        self.on_data(topic, seq, data);
    }

    /// Same as [`Self::on_data_with_version`] but also forwards the 16-byte
    /// writer GUID (`guid_prefix || entity_id`). Implementations that need
    /// per-writer state (e.g. late-joiner sample reordering for non-Volatile
    /// durability per DDS-RTPS v2.5 §8.4.2.2) override this; others rely on
    /// the default forwarding.
    fn on_data_with_writer(
        &self,
        topic: &str,
        _writer_guid: [u8; 16],
        seq: u64,
        data: &[u8],
        version: crate::dds::CdrVersion,
    ) {
        self.on_data_with_version(topic, seq, data, version);
    }

    /// Notification that a HEARTBEAT was observed from the given writer
    /// advertising `first_seq` as its oldest available sample (RTPS v2.5
    /// §8.3.7.5). The default implementation is a no-op; subscribers that
    /// need to seed late-joiner ordering state for non-Volatile durability
    /// override this hook. Called from the discovery control thread, NOT
    /// the data-routing thread.
    fn on_writer_heartbeat(&self, _writer_guid: [u8; 16], _first_seq: u64) {
        // Volatile readers ignore HB seeding — the reorder gate is disabled.
    }

    /// Called when a dispose or unregister lifecycle change is received.
    ///
    /// # Arguments
    /// - `topic`: Topic name
    /// - `seq`: RTPS writer sequence number
    /// - `key_hash`: 16-byte instance key hash from PID_KEY_HASH
    /// - `kind`: Dispose or unregister
    ///
    /// Default implementation: no-op (silently ignores lifecycle changes).
    fn on_dispose(&self, _topic: &str, _seq: u64, _key_hash: [u8; 16], _kind: DisposeKind) {
        // Default: silently ignore lifecycle changes
    }

    /// Called when a remote DataWriter's endpoint is disposed (SEDP DATA(d)
    /// on `ENTITYID_BUILTIN_PUBLICATIONS_WRITER`). Implementations that
    /// track per-(writer, instance) state should iterate the instances
    /// they have ever received from `writer_guid` on `topic` and synthesize
    /// one `on_dispose` per such instance, so the application sees the
    /// per-instance `NOT_ALIVE_*` transition required by DDS v1.4 §2.2.4.2.2.
    ///
    /// Default implementation: no-op (subscribers that don't track per-writer
    /// instance state silently ignore writer-endpoint disposes).
    fn on_writer_dispose(&self, _topic: &str, _writer_guid: [u8; 16], _kind: DisposeKind) {
        // Default: silently ignore writer-endpoint disposals.
    }

    /// Returns the topic name this subscriber is registered for
    fn topic_name(&self) -> &str;
}

/// Callback-based subscriber wrapper
///
/// Wraps a closure/function as a Subscriber implementation.
/// Useful for simple callbacks without creating custom types.
///
/// # Examples
/// ```no_run
/// use hdds::engine::CallbackSubscriber;
/// use std::sync::Arc;
///
/// let subscriber = Arc::new(CallbackSubscriber::new(
///     "sensor/temperature".to_string(),
///     |topic, seq, data| {
///         println!("Callback: seq {} ({} bytes) on {}", seq, data.len(), topic);
///     },
/// ));
/// ```
pub struct CallbackSubscriber<F>
where
    F: Fn(&str, u64, &[u8]) + Send + Sync,
{
    topic: String,
    callback: F,
}

impl<F> CallbackSubscriber<F>
where
    F: Fn(&str, u64, &[u8]) + Send + Sync,
{
    /// Create new callback subscriber
    ///
    /// # Arguments
    /// - `topic`: Topic name to subscribe to
    /// - `callback`: Function called on data reception (topic, seq, data)
    ///
    /// # Examples
    /// ```no_run
    /// use hdds::engine::CallbackSubscriber;
    ///
    /// let sub = CallbackSubscriber::new(
    ///     "my_topic".to_string(),
    ///     |topic, seq, data| {
    ///         println!("Data seq {} on {}: {:?}", seq, topic, data);
    ///     },
    /// );
    /// ```
    pub fn new(topic: String, callback: F) -> Self {
        Self { topic, callback }
    }
}

impl<F> Subscriber for CallbackSubscriber<F>
where
    F: Fn(&str, u64, &[u8]) + Send + Sync,
{
    fn on_data(&self, topic: &str, seq: u64, data: &[u8]) {
        (self.callback)(topic, seq, data);
    }

    fn topic_name(&self) -> &str {
        &self.topic
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[test]
    fn test_callback_subscriber_creation() {
        let sub = CallbackSubscriber::new("test_topic".to_string(), |_topic, _seq, _data| {
            // Callback body
        });

        assert_eq!(sub.topic_name(), "test_topic");
    }

    #[test]
    fn test_callback_subscriber_on_data_invoked() {
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = Arc::clone(&counter);

        let sub = CallbackSubscriber::new("test_topic".to_string(), move |topic, seq, data| {
            assert_eq!(topic, "test_topic");
            assert_eq!(seq, 42);
            assert_eq!(data.len(), 10);
            counter_clone.fetch_add(1, Ordering::SeqCst);
        });

        let test_data = vec![0u8; 10];
        sub.on_data("test_topic", 42, &test_data);

        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_callback_subscriber_multiple_invocations() {
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = Arc::clone(&counter);

        let sub = Arc::new(CallbackSubscriber::new(
            "test_topic".to_string(),
            move |_topic, _seq, _data| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            },
        ));

        let test_data = vec![1, 2, 3];

        // Simulate multiple deliveries
        sub.on_data("test_topic", 1, &test_data);
        sub.on_data("test_topic", 2, &test_data);
        sub.on_data("test_topic", 3, &test_data);

        assert_eq!(counter.load(Ordering::SeqCst), 3);
    }
}
