// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Vendor zone: how long a deleted DataWriter stays announced once its
//! readers have acknowledged its last lifecycle change.
//!
//! A conformant reader keeps the untaken samples of a writer that is gone:
//! the last sample the application takes for an instance is
//! NOT_ALIVE_DISPOSED when the last writer disposed it, and a disposed
//! instance's samples are purged only after autopurge_disposed_samples_delay
//! (DDS v1.4 Sec.2.2.3.22, READER_DATA_LIFECYCLE), infinite by default.
//! HDDS<->HDDS and every other peer therefore retire the writer as soon as
//! the change is acknowledged, with no wait. The vendors listed here are the
//! exception, resolved from the reader's participant at deletion time, never
//! on the data path.

use std::time::Duration;

use crate::core::rtps_constants::INTERCOM_VENDOR_ID_U16;

/// InterCOM DDS 4.3.1 acknowledges a dispose on receipt, but its reader
/// hands the change to the application only on the application's next
/// read, and a SEDP dispose of the writer that arrives first discards it:
/// the application never sees NOT_ALIVE_DISPOSED. Its own writer, deleted
/// right after disposing, loses the dispose the same way against its own
/// reader. Keeping the writer announced for this long after the
/// acknowledgement lets a reader that polls up to three times a 100 ms
/// read period take the change before the writer goes away.
pub(crate) const INTERCOM_LIFECYCLE_LINGER: Duration = Duration::from_millis(300);

/// The time a writer deleted after a lifecycle change waits, once the change
/// is acknowledged, before its SEDP dispose, for a reader of `vendor`
/// (`None`: a vendor not resolved). Zero for every vendor but those that
/// lose an acknowledged change on the writer's departure.
pub(crate) fn lifecycle_retirement_linger(vendor: Option<u16>) -> Duration {
    match vendor {
        Some(INTERCOM_VENDOR_ID_U16) => INTERCOM_LIFECYCLE_LINGER,
        _ => Duration::ZERO,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::rtps_constants::HDDS_VENDOR_ID_U16;

    /// A reader of HDDS, of another vendor, or of a vendor not resolved
    /// keeps the untaken dispose when the writer leaves (DDS v1.4
    /// Sec.2.2.3.22): the writer retires at once.
    #[test]
    fn a_conformant_reader_costs_the_writer_no_wait() {
        for vendor in [
            None,
            Some(HDDS_VENDOR_ID_U16),
            Some(0x0101), // RTI Connext
            Some(0x010F), // eProsima Fast DDS
            Some(0x0110), // Eclipse Cyclone DDS
            Some(0x011B), // zzdds
        ] {
            assert_eq!(
                lifecycle_retirement_linger(vendor),
                Duration::ZERO,
                "vendor {vendor:04x?}"
            );
        }
    }

    /// An InterCOM reader gets the linger.
    #[test]
    fn an_intercom_reader_holds_the_retirement() {
        assert_eq!(
            lifecycle_retirement_linger(Some(INTERCOM_VENDOR_ID_U16)),
            INTERCOM_LIFECYCLE_LINGER
        );
        assert!(INTERCOM_LIFECYCLE_LINGER >= Duration::from_millis(300));
    }
}
