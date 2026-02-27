// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com
// Build script to generate C header using cbindgen

use std::env;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let crate_dir = env::var("CARGO_MANIFEST_DIR")?;
    let out_path = PathBuf::from(&crate_dir).join("hdds_micro.h");

    // Generate C header
    let config = cbindgen::Config::from_file("cbindgen.toml")?;

    cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(config)
        .generate()?
        .write_to_file(&out_path);

    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=cbindgen.toml");
    Ok(())
}
