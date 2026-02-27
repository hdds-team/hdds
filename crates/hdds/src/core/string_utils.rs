// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! String formatting utilities for hot paths.
use std::fmt::{self, Arguments};

#[inline]
pub fn format_string(args: Arguments<'_>) -> String {
    fmt::format(args)
}
