#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com
#
# Proves, at runtime, that the shell helper (scripts/domain-lease.sh) and a
# REAL Rust process using std::os::unix::net -- the exact same abstract-socket
# API crates/hdds/src/test_support/domains.rs's bind_token() calls -- cannot
# both hold the same domain, and that releasing one frees the domain for the
# other.
#
# Why this script exists instead of a Rust integration test: the cleanest
# proof would be a test under crates/hdds/tests/ that leases a domain with
# unique_domain() and sleeps while this script's Node/shell helper tries the
# same domain. That is out of scope here on purpose -- this worktree is
# restricted to sdk/typescript/ and scripts/, and crates/hdds/tests/ is
# neither. What follows is the closest thing buildable inside that scope: a
# tiny standalone Rust program, compiled on the fly with `rustc` (no cargo
# project, no dependency on the hdds crate), that reimplements ONLY the
# 3-line bind_token() body verbatim:
#
#     let name = format!("hdds-test-domain.v1.{domain}");
#     let addr = SocketAddr::from_abstract_name(name.as_bytes())?;
#     UnixListener::bind_addr(&addr)
#
# It does not call into, import, or depend on crates/hdds/src at all, so it
# does not touch the excluded paths. It is the same std API domains.rs uses,
# run as a genuinely separate OS process, which is exactly the boundary the
# real defect crosses (two different Rust test BINARIES, or a Rust binary and
# a Node/shell process -- either way, two processes, one kernel-arbitrated
# table).
#
# What this does NOT prove: that domains.rs's own DOMAIN_POOL selection logic
# (the exclusion lists) is bug-for-bug identical to this repo's hand-ported
# copies in domain-lease.sh / domain-lease.js -- that is checked separately,
# by structural assertions mirroring domains.rs's own unit tests (see
# sdk/typescript/tests/domain-lease.test.ts and the pool-invariant checks in
# scripts/domain-lease.sh). This script only proves the TOKEN -- the thing
# that actually arbitrates "who owns domain N right now" -- is shared.
#
# Requires: rustc, socat. Exits 77 (skip) if either is missing, matching the
# ros2 gate scripts' own SKIP convention. Exits 0 on success, 1 on any proof
# failure (printed).

set -uo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
SKIP_CODE=77

if ! command -v rustc >/dev/null 2>&1; then
    echo "SKIP: rustc not on PATH"
    exit "$SKIP_CODE"
fi
if ! command -v socat >/dev/null 2>&1; then
    echo "SKIP: socat not on PATH"
    exit "$SKIP_CODE"
fi
if [[ "$(uname -s)" != "Linux" ]]; then
    echo "SKIP: this proof only exercises the Linux abstract-socket path"
    exit "$SKIP_CODE"
fi

# shellcheck source=./domain-lease.sh
source "$SCRIPT_DIR/domain-lease.sh"

WORKDIR=$(mktemp -d -t hdds-domain-lease-interop.XXXXXX)
trap 'rm -rf "$WORKDIR"; [[ -n "${HOLDER_PID:-}" ]] && kill "$HOLDER_PID" 2>/dev/null; hdds_domain_lease_release' EXIT

cat > "$WORKDIR/holder.rs" <<'RUST'
// Standalone probe: reimplements ONLY the documented bind_token() body from
// crates/hdds/src/test_support/domains.rs (Linux #[cfg] arm), verbatim. Does
// not import or depend on the hdds crate.
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr, UnixListener};

fn bind_token(domain: &str) -> std::io::Result<UnixListener> {
    let name = format!("hdds-test-domain.v1.{domain}");
    let addr = SocketAddr::from_abstract_name(name.as_bytes())?;
    UnixListener::bind_addr(&addr)
}

fn main() {
    let mut args = std::env::args().skip(1);
    let domain = args.next().expect("usage: holder <domain> <hold-seconds>");
    let hold_secs: u64 = args
        .next()
        .expect("usage: holder <domain> <hold-seconds>")
        .parse()
        .expect("hold-seconds must be an integer");
    match bind_token(&domain) {
        Ok(_listener) => {
            println!("HELD {domain}");
            use std::io::Write;
            std::io::stdout().flush().ok();
            std::thread::sleep(std::time::Duration::from_secs(hold_secs));
            println!("RELEASING {domain}");
        }
        Err(e) => {
            println!("REFUSED {domain} {e}");
            std::process::exit(1);
        }
    }
}
RUST

echo "[interop-check] compiling the standalone Rust probe..."
if ! rustc -O "$WORKDIR/holder.rs" -o "$WORKDIR/holder" 2>"$WORKDIR/rustc.log"; then
    cat "$WORKDIR/rustc.log" >&2
    echo "FAIL: could not compile the Rust probe"
    exit 1
fi

FAIL=0
PROBE_DOMAIN=9101   # arbitrary id above MAX_DOMAIN_ID (232): never a real lease, so
                    # this proof can never collide with a genuinely running test suite.

echo "[interop-check] 1/2: Rust holds domain ${PROBE_DOMAIN}, shell helper must be refused"
"$WORKDIR/holder" "$PROBE_DOMAIN" 3 > "$WORKDIR/holder.out" &
HOLDER_PID=$!
# Wait for the probe to actually report HELD before testing against it --
# deterministic instead of a fixed sleep.
for _ in $(seq 1 200); do
    grep -q "^HELD ${PROBE_DOMAIN}$" "$WORKDIR/holder.out" 2>/dev/null && break
    sleep 0.01
done
if ! grep -q "^HELD ${PROBE_DOMAIN}$" "$WORKDIR/holder.out" 2>/dev/null; then
    echo "FAIL: Rust probe never reported HELD (see $WORKDIR/holder.out)"
    FAIL=1
else
    if _hdds_lease_try_bind "$PROBE_DOMAIN"; then
        echo "FAIL: shell helper bound domain ${PROBE_DOMAIN} while the Rust probe held it"
        hdds_domain_lease_release
        FAIL=1
    else
        echo "  ok: shell helper was refused (collision correctly detected)"
    fi
fi
wait "$HOLDER_PID" 2>/dev/null
HOLDER_PID=""

echo "[interop-check] 2/2: after Rust releases, the shell helper must succeed on the same id"
if _hdds_lease_try_bind "$PROBE_DOMAIN"; then
    if [[ "$HDDS_LEASED_DOMAIN" == "$PROBE_DOMAIN" ]]; then
        echo "  ok: shell helper leased domain ${PROBE_DOMAIN} once it was free"
    else
        echo "FAIL: shell helper leased the wrong domain (${HDDS_LEASED_DOMAIN} != ${PROBE_DOMAIN})"
        FAIL=1
    fi
    hdds_domain_lease_release
else
    echo "FAIL: shell helper could not lease domain ${PROBE_DOMAIN} after the Rust probe released it"
    FAIL=1
fi

if (( FAIL == 0 )); then
    echo "PASS: shell helper and a real Rust std::os::unix::net user share one token table"
    exit 0
else
    echo "FAIL: see above"
    exit 1
fi
