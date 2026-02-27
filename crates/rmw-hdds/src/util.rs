// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use hdds_c::{HddsDataReader, HddsError};
use std::collections::{HashMap, HashSet};

/// Map triggered reader pointers back to their subscription indexes.
pub(crate) fn map_ready_indices(
    subscriptions: &[*mut HddsDataReader],
    readers: &[*mut HddsDataReader],
) -> Result<Vec<usize>, HddsError> {
    let mut index_map = HashMap::with_capacity(subscriptions.len());
    for (idx, &ptr) in subscriptions.iter().enumerate() {
        index_map.insert(ptr, idx);
    }

    let mut ready = Vec::with_capacity(readers.len());
    let mut seen = HashSet::with_capacity(readers.len());

    for &reader in readers {
        let Some(&index) = index_map.get(&reader) else {
            return Err(HddsError::HddsInvalidArgument);
        };
        if seen.insert(index) {
            ready.push(index);
        }
    }

    Ok(ready)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_reader_ptr(id: usize) -> *mut HddsDataReader {
        (id + 1) as *mut HddsDataReader
    }

    #[test]
    fn map_ready_indices_returns_ordered_unique_indices() {
        let subscriptions = [
            fake_reader_ptr(0),
            fake_reader_ptr(1),
            fake_reader_ptr(2),
            fake_reader_ptr(3),
        ];
        let readers = [
            subscriptions[2],
            subscriptions[0],
            subscriptions[2],
            subscriptions[1],
        ];
        let indices = map_ready_indices(&subscriptions, &readers).expect("indices");
        assert_eq!(indices, vec![2, 0, 1]);
    }

    #[test]
    fn map_ready_indices_errors_on_unknown_reader() {
        let subscriptions = [fake_reader_ptr(0)];
        let readers = [fake_reader_ptr(42)];
        let result = map_ready_indices(&subscriptions, &readers);
        assert_eq!(result, Err(HddsError::HddsInvalidArgument));
    }
}
