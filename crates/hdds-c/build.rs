// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use std::env;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

fn main() {
    if let Err(e) = try_main() {
        eprintln!("Error generating C bindings: {e}");
        std::process::exit(1);
    }
}

/// Write `contents` to `path`, tolerating a read-only tree ONLY when what is
/// already there is byte-identical.
///
/// The ROS 2 gate (scripts/ros2/gate-ros2-build.sh) bind-mounts the worktree
/// read only so a container build can never write into it. The generated
/// header is an artefact for C consumers, not an input to rustc, so a
/// read-only tree whose header is already correct is not a build failure. A
/// read-only tree whose header is STALE still is: the gate must never build
/// against a header that does not describe the source it just compiled.
fn write_or_verify(path: &Path, contents: &str) -> Result<(), Box<dyn std::error::Error>> {
    match std::fs::write(path, contents) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::PermissionDenied || e.raw_os_error() == Some(30) => {
            let on_disk = std::fs::read_to_string(path).map_err(|read_err| {
                format!(
                    "{} is not writable ({e}) and could not be read back either ({read_err})",
                    path.display()
                )
            })?;
            if on_disk == contents {
                println!(
                    "cargo:warning=read-only tree: {} already matches the generated header",
                    path.display()
                );
                Ok(())
            } else {
                Err(format!(
                    "{} is not writable ({e}) and its contents are STALE: regenerate it on a \
                     writable checkout before building here",
                    path.display()
                )
                .into())
            }
        }
        Err(e) => Err(e.into()),
    }
}

fn try_main() -> Result<(), Box<dyn std::error::Error>> {
    let crate_dir = env::var("CARGO_MANIFEST_DIR")?;
    let crate_path = PathBuf::from(&crate_dir);
    let out_path = crate_path.join("hdds.h");

    let config = cbindgen::Config::from_file("cbindgen.toml")?;

    let bindings = cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_language(cbindgen::Language::C)
        .with_config(config)
        .generate()?;

    let mut generated = Vec::new();
    bindings.write(&mut generated);
    let generated = String::from_utf8(generated)?;
    write_or_verify(&out_path, &generated)?;

    // Sync to sdk/c/include/ (add copyright header)
    let sdk_path = crate_path.join("../../sdk/c/include/hdds.h");
    if sdk_path.parent().is_some_and(|p| p.exists()) {
        let with_copyright = format!(
            "// SPDX-License-Identifier: Apache-2.0 OR MIT\n\
             // Copyright (c) 2025-2026 naskel.com\n\n{generated}"
        );
        write_or_verify(&sdk_path, &with_copyright)?;
        println!("Synced SDK header: {}", sdk_path.display());
    }

    // Watch the whole binding source tree, including nested and newly added
    // modules. A library rebuild alone does not rerun cbindgen when an API
    // changes in a source file omitted from an explicit watch list.
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=cbindgen.toml");
    println!("Generated C header: {}", out_path.display());

    Ok(())
}
