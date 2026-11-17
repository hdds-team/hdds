// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Presence probe for the git-ignored vendor sample config
//! `configs/rti_6x_sample_01.mcq.yaml` (matched by the repo `.gitignore` rule
//! `configs/rti*`). The two fixture-backed tests in `src/mcq/tests.rs`
//! `include_str!` that file, so they can only compile when it is present. This
//! sets `cfg(has_rti_sample_fixture)` when the fixture exists so those tests are
//! gated on availability instead of breaking the build in a clean checkout.

fn main() {
    println!("cargo::rustc-check-cfg=cfg(has_rti_sample_fixture)");
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../configs/rti_6x_sample_01.mcq.yaml"
    );
    if std::path::Path::new(fixture).exists() {
        println!("cargo::rustc-cfg=has_rti_sample_fixture");
    }
    println!("cargo::rerun-if-changed={fixture}");
}
