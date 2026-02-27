// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Subscriber trait and implementations for receiving topic data

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
