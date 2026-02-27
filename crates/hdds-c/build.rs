// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use std::env;
use std::path::PathBuf;

fn main() {
    if let Err(e) = try_main() {
        eprintln!("Error generating C bindings: {e}");
        std::process::exit(1);
    }
}

fn try_main() -> Result<(), Box<dyn std::error::Error>> {
    let crate_dir = env::var("CARGO_MANIFEST_DIR")?;
    let out_path = PathBuf::from(&crate_dir).join("hdds.h");

    let config = cbindgen::Config::from_file("cbindgen.toml")?;

    cbindgen::Builder::new()
        .with_crate(crate_dir)
        .with_language(cbindgen::Language::C)
        .with_config(config)
        .generate()?
        .write_to_file(&out_path);

    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=src/qos.rs");
    println!("cargo:rerun-if-changed=src/rmw.rs");
    println!("cargo:rerun-if-changed=cbindgen.toml");
    println!("Generated C header: {}", out_path.display());

    Ok(())
}
