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
    let crate_path = PathBuf::from(&crate_dir);
    let out_path = crate_path.join("hdds.h");

    let config = cbindgen::Config::from_file("cbindgen.toml")?;

    cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_language(cbindgen::Language::C)
        .with_config(config)
        .generate()?
        .write_to_file(&out_path);

    // Sync to sdk/c/include/ (add copyright header)
    let sdk_path = crate_path.join("../../sdk/c/include/hdds.h");
    if sdk_path.parent().is_some_and(|p| p.exists()) {
        let generated = std::fs::read_to_string(&out_path)?;
        let with_copyright = format!(
            "// SPDX-License-Identifier: Apache-2.0 OR MIT\n\
             // Copyright (c) 2025-2026 naskel.com\n\n{generated}"
        );
        std::fs::write(&sdk_path, with_copyright)?;
        println!("Synced SDK header: {}", sdk_path.display());
    }

    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=src/qos.rs");
    println!("cargo:rerun-if-changed=src/rmw.rs");
    println!("cargo:rerun-if-changed=cbindgen.toml");
    println!("Generated C header: {}", out_path.display());

    Ok(())
}
