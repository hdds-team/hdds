// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! `hdds-gen --version` is documented (docs/getting-started/installation/windows.md)
//! and exercised by scripts/windows-gate.sh lane W4 under wine. This test pins
//! the flag on the host build: it exits 0 and prints the crate version.

use std::process::Command;

fn run(arg: &str) -> (i32, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_hdds-gen"))
        .arg(arg)
        .output()
        .expect("spawn hdds-gen");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

#[test]
fn version_flag_prints_crate_version_and_exits_zero() {
    let expected = format!("hdds-gen {}", env!("CARGO_PKG_VERSION"));
    for arg in ["--version", "-V", "version"] {
        let (code, stdout) = run(arg);
        assert_eq!(code, 0, "`hdds-gen {arg}` must exit 0");
        // `contains`, not an exact match: main() installs a global tracing
        // subscriber whose default sink is stdout, so an unrelated INFO event
        // from a dependency must not turn a correct --version into a failure.
        assert!(
            stdout.contains(&expected),
            "`hdds-gen {arg}` stdout must contain {expected:?}, got {stdout:?}"
        );
    }
}

#[test]
fn unknown_command_still_exits_one() {
    let (code, _) = run("--definitely-not-a-command");
    assert_eq!(code, 1);
}
