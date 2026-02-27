// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! # DDS Topic
//!
//!
//! A [`Topic`] represents a named data channel with an associated type. Topics are
//! the connection point between DataWriters and DataReaders.
//!
//! ## Overview
//!
//! In DDS, a Topic defines:
//! - A **name** (string identifier for the data channel)
//! - A **type** (the Rust struct that will be serialized/deserialized)
//! - Association with a **Participant** (for discovery announcements)
//!
//! ## Example
//!
//! ```rust,no_run
//! use hdds::{Participant, QoS, DDS};
//!
//! #[derive(DDS)]
//! struct SensorData { value: f64 }
//!
//! let participant = Participant::builder("app").build()?;
//!
//! // Create a topic and get builders for reader/writer
//! let topic = participant.topic::<SensorData>("sensors/temperature")?;
//! let writer = topic.writer().qos(QoS::reliable()).build()?;
//! let reader = topic.reader().qos(QoS::reliable()).build()?;
//! # Ok::<(), hdds::Error>(())
//! ```
//!
//! ## See Also
//!
//! - [`DataWriter`](crate::DataWriter) - Publish samples to a topic
//! - [`DataReader`](crate::DataReader) - Subscribe to samples from a topic
//! - [DDS Spec Sec.2.2.2.3](https://www.omg.org/spec/DDS/1.4/) - Topic

use crate::dds::DDS;
use std::sync::Arc;

/// A typed DDS Topic - represents a named data channel.
///
/// `Topic<T>` binds a topic name to a data type `T` and provides factory methods
/// for creating [`DataReader`](crate::DataReader) and [`DataWriter`](crate::DataWriter)
/// instances.
///
/// # Type Parameter
///
/// * `T` - The data type, must implement [`DDS`](crate::dds::DDS)
///
/// # Example
///
/// ```rust,no_run
/// use hdds::{Participant, QoS, DDS};
///
/// #[derive(DDS)]
/// struct Command { action: u32 }
///
/// let participant = Participant::builder("robot").build()?;
/// let topic = participant.topic::<Command>("robot/commands")?;
///
/// // Use the topic to create reader or writer
/// let reader = topic.reader().build()?;
/// # Ok::<(), hdds::Error>(())
/// ```
///
/// # See Also
///
/// - `ReaderBuilder` - Returned by `topic.reader()`
/// - `WriterBuilder` - Returned by `topic.writer()`
pub struct Topic<T: DDS> {
    pub(crate) name: String,
    pub(crate) participant: Arc<crate::Participant>,
    _phantom: core::marker::PhantomData<T>,
}

impl<T: DDS> Topic<T> {
    pub(crate) fn new(name: String, participant: Arc<crate::Participant>) -> Self {
        Self {
            name,
            participant,
            _phantom: core::marker::PhantomData,
        }
    }

    /// Create a builder for a `DataReader<T>` bound to this topic.
    pub fn reader(&self) -> super::reader::ReaderBuilder<T> {
        super::reader::ReaderBuilder::new(self.name.clone())
            .with_participant(Arc::clone(&self.participant))
    }

    /// Create a builder for a `DataWriter<T>` bound to this topic.
    pub fn writer(&self) -> super::writer::WriterBuilder<T> {
        super::writer::WriterBuilder::new(self.name.clone())
            .with_participant(Arc::clone(&self.participant))
    }
}
