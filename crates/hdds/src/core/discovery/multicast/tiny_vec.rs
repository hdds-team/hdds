// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Small-vector optimization with inline storage + heap fallback.
//!
//! Stores up to N items inline (stack-allocated), spills to `Vec` if exceeded.
//! Zero external dependencies--used for topic indices where most entries are small.

use std::mem::MaybeUninit;

/// Small-vector optimization (inline storage + heap fallback)
///
/// Custom zero-dependency implementation to avoid external crate.
/// Stores up to N items inline (stack-allocated), spills to Vec if exceeded.
///
/// # Use Case
/// Used for topic index in ParticipantDB: most topics have 1-4 publishers/subscribers.
/// Inline storage avoids heap allocation for common case.
///
/// # Type Parameters
/// - `T`: Element type
/// - `N`: Inline capacity (const generic, typically 4)
///
/// # Memory Layout
/// - Inline mode: `[MaybeUninit<T>; N] + len: usize` (~32 bytes for N=4, T=GUID)
/// - Heap mode: `Vec<T>` pointer (~24 bytes)
pub enum TinyVec<T, const N: usize> {
    /// Inline storage (len <= N)
    Inline {
        data: [MaybeUninit<T>; N],
        len: usize,
    },
    /// Heap storage (len > N)
    Heap(Vec<T>),
}

// Manual Clone implementation (MaybeUninit doesn't derive Clone)
impl<T: Clone, const N: usize> Clone for TinyVec<T, N> {
    fn clone(&self) -> Self {
        match self {
            Self::Inline { data, len } => {
                let mut new_data: [MaybeUninit<T>; N] =
                    std::array::from_fn(|_| MaybeUninit::uninit());
                // SAFETY: Index required for unsafe pointer access
                #[allow(clippy::needless_range_loop)]
                #[allow(clippy::needless_range_loop)]
                for i in 0..*len {
                    // SAFETY:
                    // 1. Inline mode tracks initialized prefix of length `*len`.
                    // 2. Each element up to `len` is initialized; we read and clone it.
                    // 3. new_data[i] is uninitialized MaybeUninit, ready for write.
                    // 4. No aliasing occurs because we write into fresh array.
                    unsafe {
                        let val = (*data[i].as_ptr()).clone();
                        new_data[i] = MaybeUninit::new(val);
                    }
                }
                Self::Inline {
                    data: new_data,
                    len: *len,
                }
            }
            Self::Heap(vec) => Self::Heap(vec.clone()),
        }
    }
}

// Manual Debug implementation (MaybeUninit doesn't derive Debug)
impl<T: std::fmt::Debug, const N: usize> std::fmt::Debug for TinyVec<T, N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Inline { len, .. } => f
                .debug_struct("TinyVec::Inline")
                .field("len", len)
                .field("data", &self.as_slice())
                .finish(),
            Self::Heap(vec) => f.debug_tuple("TinyVec::Heap").field(vec).finish(),
        }
    }
}

impl<T, const N: usize> Default for TinyVec<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T, const N: usize> TinyVec<T, N> {
    /// Create new empty TinyVec
    ///
    /// Starts in inline mode with zero elements.
    ///
    /// # Examples
    /// ```
    /// use hdds::core::discovery::multicast::TinyVec;
    ///
    /// let vec: TinyVec<u32, 4> = TinyVec::new();
    /// assert_eq!(vec.len(), 0);
    /// assert!(vec.is_inline());
    /// ```
    pub fn new() -> Self {
        Self::Inline {
            data: std::array::from_fn(|_| MaybeUninit::uninit()),
            len: 0,
        }
    }

    /// Get current number of elements
    pub fn len(&self) -> usize {
        match self {
            Self::Inline { len, .. } => *len,
            Self::Heap(vec) => vec.len(),
        }
    }

    /// Check if TinyVec is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Check if currently using inline storage
    pub fn is_inline(&self) -> bool {
        matches!(self, Self::Inline { .. })
    }

    /// Push element to TinyVec
    ///
    /// If inline storage is full (len == N), transitions to heap mode.
    ///
    /// # Examples
    /// ```
    /// use hdds::core::discovery::multicast::TinyVec;
    ///
    /// let mut vec: TinyVec<u32, 2> = TinyVec::new();
    /// vec.push(10);
    /// vec.push(20);
    /// assert!(vec.is_inline());
    ///
    /// vec.push(30); // Spills to heap
    /// assert!(!vec.is_inline());
    /// assert_eq!(vec.len(), 3);
    /// ```
    pub fn push(&mut self, item: T)
    where
        T: Clone,
    {
        match self {
            Self::Inline { data, len } if *len < N => {
                // Still fits inline
                data[*len] = MaybeUninit::new(item);
                *len += 1;
            }
            Self::Inline { data, len } => {
                // Inline full, transition to heap
                let mut vec = Vec::with_capacity(N + 1);

                // SAFETY: First `len` elements are initialized
                // Index required for unsafe pointer access
                #[allow(clippy::needless_range_loop)]
                #[allow(clippy::needless_range_loop)]
                for i in 0..*len {
                    // SAFETY:
                    // 1. Inline storage has first `len` elements initialized.
                    // 2. We move each element into the new Vec exactly once.
                    // 3. After read, inline slot considered uninitialized (len updated).
                    // 4. No double-drop because MaybeUninit prevents Drop calls.
                    unsafe {
                        let val = std::ptr::read(data[i].as_ptr());
                        vec.push(val);
                    }
                }
                vec.push(item);
                *self = Self::Heap(vec);
            }
            Self::Heap(vec) => {
                vec.push(item);
            }
        }
    }

    /// Get slice of all elements
    ///
    /// Returns contiguous slice regardless of inline/heap mode.
    ///
    /// # Examples
    /// ```
    /// use hdds::core::discovery::multicast::TinyVec;
    ///
    /// let mut vec: TinyVec<u32, 4> = TinyVec::new();
    /// vec.push(1);
    /// vec.push(2);
    ///
    /// let slice = vec.as_slice();
    /// assert_eq!(slice, &[1, 2]);
    /// ```
    pub fn as_slice(&self) -> &[T] {
        match self {
            Self::Inline { data, len } => {
                // SAFETY: First `len` elements are initialized
                // MaybeUninit<T> has same layout as T, so cast is safe
                unsafe { std::slice::from_raw_parts(data.as_ptr().cast::<T>(), *len) }
            }
            Self::Heap(vec) => vec.as_slice(),
        }
    }

    /// Clear all elements
    pub fn clear(&mut self) {
        match self {
            Self::Inline { data, len } => {
                // SAFETY: Drop first `len` initialized elements
                // Index required for unsafe pointer access
                #[allow(clippy::needless_range_loop)]
                for i in 0..*len {
                    // SAFETY:
                    // 1. Inline storage initialises first `len` elements.
                    // 2. Each call drops a distinct initialized element.
                    // 3. After drop we won't access the element again (len set to 0).
                    // 4. No aliasing occurs (exclusive &mut self).
                    unsafe {
                        std::ptr::drop_in_place(data[i].as_mut_ptr());
                    }
                }
                *len = 0;
            }
            Self::Heap(vec) => vec.clear(),
        }
    }

    /// Remove element at index
    ///
    /// Returns removed element if index is valid, None otherwise.
    /// Maintains order by shifting elements left.
    pub fn remove(&mut self, index: usize) -> Option<T>
    where
        T: Clone,
    {
        if index >= self.len() {
            return None;
        }

        match self {
            Self::Inline { data, len } => {
                // SAFETY: index < len, so element is initialized
                // SAFETY:
                // 1. index < len checked above -> element initialized.
                // 2. read() moves value out without dropping it twice.
                // 3. After shifting, slot becomes uninitialized.
                let removed = unsafe { std::ptr::read(data[index].as_ptr()) };

                // Shift elements left
                for i in index..*len - 1 {
                    // SAFETY:
                    // 1. For i+1 < len, element is initialized.
                    // 2. We move element down one slot, leaving i+1 uninitialized.
                    // 3. Loop ensures each initialized element shifts exactly once.
                    // 4. No overlap since we move to lower index.
                    unsafe {
                        let val = std::ptr::read(data[i + 1].as_ptr());
                        data[i] = MaybeUninit::new(val);
                    }
                }

                *len -= 1;
                Some(removed)
            }
            Self::Heap(vec) => Some(vec.remove(index)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tinyvec_inline() {
        let mut vec: TinyVec<u32, 4> = TinyVec::new();
        assert!(vec.is_empty());
        assert!(vec.is_inline());

        vec.push(10);
        vec.push(20);
        vec.push(30);

        assert_eq!(vec.len(), 3);
        assert!(vec.is_inline());
        assert_eq!(vec.as_slice(), &[10, 20, 30]);
    }

    #[test]
    fn test_tinyvec_inline_to_heap() {
        let mut vec: TinyVec<u32, 2> = TinyVec::new();

        vec.push(1);
        vec.push(2);
        assert!(vec.is_inline());

        vec.push(3); // Triggers heap transition
        assert!(!vec.is_inline());
        assert_eq!(vec.len(), 3);
        assert_eq!(vec.as_slice(), &[1, 2, 3]);
    }

    #[test]
    fn test_tinyvec_heap_growth() {
        let mut vec: TinyVec<u32, 2> = TinyVec::new();

        for i in 0..10 {
            vec.push(i);
        }

        assert!(!vec.is_inline());
        assert_eq!(vec.len(), 10);
        assert_eq!(vec.as_slice(), &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
    }

    #[test]
    fn test_tinyvec_clear() {
        let mut vec: TinyVec<u32, 4> = TinyVec::new();
        vec.push(1);
        vec.push(2);

        vec.clear();
        assert_eq!(vec.len(), 0);
        assert!(vec.is_empty());
    }

    #[test]
    fn test_tinyvec_remove() {
        let mut vec: TinyVec<u32, 4> = TinyVec::new();
        vec.push(10);
        vec.push(20);
        vec.push(30);

        assert_eq!(vec.remove(1), Some(20));
        assert_eq!(vec.as_slice(), &[10, 30]);

        assert_eq!(vec.remove(5), None); // Out of bounds
    }

    #[test]
    fn test_tinyvec_memory_layout() {
        // Verify inline mode is reasonably sized
        let vec: TinyVec<u64, 4> = TinyVec::new();
        let size = std::mem::size_of_val(&vec);
        // Should be roughly: 4 * (size_of::<Option<u64>>()) + usize
        // Allow some variance for enum discriminant
        assert!(size <= 128);
    }

    #[test]
    fn test_tinyvec_remove_from_heap() {
        let mut vec: TinyVec<u32, 2> = TinyVec::new();
        for i in 0..4 {
            vec.push(i);
        }
        assert!(!vec.is_inline());
        assert_eq!(vec.remove(2), Some(2));
        assert_eq!(vec.as_slice(), &[0, 1, 3]);
    }

    #[test]
    fn test_tinyvec_clear_heap_and_reuse() {
        let mut vec: TinyVec<u32, 2> = TinyVec::new();
        for i in 0..5 {
            vec.push(i);
        }
        assert!(!vec.is_inline());

        vec.clear();
        assert!(vec.is_empty());

        vec.push(99);
        assert_eq!(vec.as_slice(), &[99]);
    }

    #[test]
    fn test_tinyvec_clone_inline_and_heap() {
        let mut inline_vec: TinyVec<u32, 4> = TinyVec::new();
        inline_vec.push(1);
        inline_vec.push(2);
        let cloned_inline = inline_vec.clone();
        assert_eq!(cloned_inline.as_slice(), &[1, 2]);

        let mut heap_vec: TinyVec<u32, 2> = TinyVec::new();
        for i in 0..5 {
            heap_vec.push(i);
        }
        let cloned_heap = heap_vec.clone();
        assert_eq!(cloned_heap.as_slice(), &[0, 1, 2, 3, 4]);
        assert!(!cloned_heap.is_inline());
    }
}
