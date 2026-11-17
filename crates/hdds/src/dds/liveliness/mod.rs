// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! LIVELINESS (DDS v1.4 Sec.2.2.3.11; RTPS v2.5 Sec.8.4.13, Sec.8.7.2.2).
//!
//! A participant runs one scheduler thread (`scheduler`) over a heap of
//! lease deadlines (`leases`), on an injectable clock (`clock`).

mod assertion;
mod clock;
mod deadline;
mod leases;
mod reader;
mod scheduler;
mod writer;

#[cfg(test)]
mod tests_deadline;
#[cfg(test)]
mod tests_model;
#[cfg(test)]
mod tests_reader;
#[cfg(test)]
mod tests_scheduler;
#[cfg(test)]
mod tests_wire;
#[cfg(test)]
mod tests_writer;

pub(crate) use self::assertion::{
    answer_participant_message_acknack, handshake_heartbeat, AssertionWriter,
};
#[cfg(test)]
pub(crate) use self::clock::ManualClock;
pub(crate) use self::clock::{LivelinessClock, MonotonicClock};
pub(crate) use self::deadline::{FilterWakeSink, ReaderDeadlines, WriterDeadlines};
pub(crate) use self::leases::HeartbeatSink;
#[cfg(test)]
pub(crate) use self::leases::{LivelinessSink, WatchKey};
pub(crate) use self::reader::ReaderLiveliness;
pub(crate) use self::scheduler::{
    HeartbeatWatchHandle, LocalWriterLease, ManualWriterLease, Scheduler, Shared, WriterAssert,
};
pub(crate) use self::writer::WriterLiveliness;
