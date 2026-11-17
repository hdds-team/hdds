#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com
#
# Shell counterpart to crates/hdds/src/test_support/domains.rs.
#
# This is a hand-port of that module's protocol, not a wrapper around it: a
# domain leased through this file and a domain leased by a Rust test using
# domains.rs::unique_domain() come from the SAME kernel-arbitrated token
# table (an abstract Unix socket on Linux), so the two allocators can never
# hand out the same domain at the same time. It is also independent of the
# Node counterpart, sdk/typescript/scripts/domain-lease.js: ros2 gates run in
# a bare bash + docker host and must not gain a Node dependency just to pick
# a domain. There is no shared source of truth across the three -- if
# domains.rs's exclusion lists ever change, all three need the same edit by
# hand.
#
# THIS FILE IS MEANT TO BE SOURCED, NOT EXECUTED:
#   source "$(dirname "${BASH_SOURCE[0]}")/../scripts/domain-lease.sh"   # from scripts/ros2/*
#   if ! hdds_domain_lease_acquire; then
#       echo "SKIP: could not lease a DDS test domain" >&2
#       exit 77
#   fi
#   trap 'hdds_domain_lease_release; <rest of your own cleanup>' EXIT
#   echo "using domain $HDDS_LEASED_DOMAIN"
#
# It never calls `set -e`/`set -u`/`set -o pipefail` itself: sourcing runs in
# the CALLER's shell, and this file must not change the caller's shell
# options as a side effect.
#
# Protocol, copied BY HAND from domains.rs (keep in sync):
#   - Token: on Linux, an abstract Unix socket named
#     "hdds-test-domain.v1.<domain>". A second bind of an already-bound
#     abstract name fails with EADDRINUSE, machine-wide, across processes and
#     across languages -- proven against a real Rust
#     std::os::unix::net::UnixListener::bind_addr while writing this file
#     (see scripts/domain-lease-interop-check.sh). The kernel frees the name
#     when every descriptor holding it closes, including on a crash, so a
#     dead holder needs no special handling here either -- killing the socat
#     process below is exactly that close.
#   - Pool: domains 1..=232 (crate::config::MAX_DOMAIN_ID) minus
#     HDDS_FLEET_RESERVED_DOMAINS (domains used by HDDS's own long-running
#     tools), minus HDDS_TEST_PINNED_DOMAINS
#     {1, 232}, minus every domain whose 70-port RTPS block
#     (PORT_BASE=7400 + DOMAIN_ID_GAIN=250 * domain) overlaps the Linux
#     default ephemeral port range 32768-60999 (docs/reference/limits.md:
#     domains 102-214).
#   - Non-Linux: there is no abstract socket namespace outside Linux.
#     domains.rs falls back to a loopback TCP listener at
#     127.0.0.1:(6900+domain) there and says that path "is not exercised on
#     the Linux CI box"; this file does the SAME thing on Darwin (via socat
#     TCP4-LISTEN) so it still interoperates with a domains.rs test on the
#     SAME non-Linux host. On anything else (there is no realistic
#     Windows-native target for scripts/ros2, which already needs Docker and
#     bash) it REFUSES LOUDLY instead of silently reusing a fixed domain --
#     see the "unsupported" case in _hdds_lease_try_bind.

HDDS_LEASE_TOKEN_PREFIX="hdds-test-domain.v1."

# Verbatim from domains.rs FLEET_RESERVED_DOMAINS (39 hdds, 70 hdds-gen,
# 137 hdds-micro).
HDDS_FLEET_RESERVED_DOMAINS=(39 70 137)
# domains.rs TEST_PINNED_DOMAINS: {1, MAX_DOMAIN_ID}.
HDDS_TEST_PINNED_DOMAINS=(1 232)

HDDS_FIRST_POOL_DOMAIN=1
HDDS_LAST_POOL_DOMAIN=232        # crate::config::MAX_DOMAIN_ID
HDDS_PORT_BASE=7400              # crate::config::PORT_BASE
HDDS_DOMAIN_ID_GAIN=250          # crate::config::DOMAIN_ID_GAIN
HDDS_DOMAIN_PORT_BLOCK=70
HDDS_EPHEMERAL_PORT_LOW=32768
HDDS_EPHEMERAL_PORT_HIGH=60999

# domains.rs's own non-Linux fallback band (platform::bind_token).
HDDS_NON_LINUX_TOKEN_PORT_BASE=6900
HDDS_NON_LINUX_MAX_TOKEN_ID=499

# Set by hdds_domain_lease_acquire on success; consumed by
# hdds_domain_lease_release. Empty means "no lease held".
HDDS_LEASED_DOMAIN=""
HDDS_LEASE_SOCAT_PID=""
HDDS_LEASE_LOGFILE=""

_hdds_lease_in_array() {
    local needle="$1"
    shift
    local x
    for x in "$@"; do
        [[ "$x" == "$needle" ]] && return 0
    done
    return 1
}

_hdds_lease_touches_ephemeral() {
    local d="$1"
    local first=$(( HDDS_PORT_BASE + HDDS_DOMAIN_ID_GAIN * d ))
    local last=$(( first + HDDS_DOMAIN_PORT_BLOCK - 1 ))
    [[ $last -ge $HDDS_EPHEMERAL_PORT_LOW && $first -le $HDDS_EPHEMERAL_PORT_HIGH ]]
}

_hdds_lease_is_excluded() {
    local d="$1"
    _hdds_lease_in_array "$d" "${HDDS_FLEET_RESERVED_DOMAINS[@]}" && return 0
    _hdds_lease_in_array "$d" "${HDDS_TEST_PINNED_DOMAINS[@]}" && return 0
    _hdds_lease_touches_ephemeral "$d" && return 0
    return 1
}

_hdds_lease_platform() {
    case "$(uname -s)" in
        Linux)  echo linux ;;
        Darwin) echo darwin ;;
        *)      echo unsupported ;;
    esac
}

# Print the domain pool (one id per line) -- mostly for debugging / the
# interop-check script; hdds_domain_lease_acquire recomputes it inline.
hdds_domain_lease_pool() {
    local d
    for (( d = HDDS_FIRST_POOL_DOMAIN; d <= HDDS_LAST_POOL_DOMAIN; d++ )); do
        _hdds_lease_is_excluded "$d" || echo "$d"
    done
}

# Try to hold the token for exactly one domain.
#   0  -> bound; HDDS_LEASED_DOMAIN / HDDS_LEASE_SOCAT_PID / HDDS_LEASE_LOGFILE
#         are set, and the holder process is left running in the background.
#   1  -> collision (AddrInUse): nothing left running, caller should try the
#         next candidate.
#   2  -> any other failure (bad platform, socat missing, timeout): reported
#         on stderr already; caller should stop, not paper over it as a
#         collision (mirrors DomainAllocError::Io vs ::Exhausted).
_hdds_lease_try_bind() {
    local d="$1" plat addr
    plat=$(_hdds_lease_platform)
    case "$plat" in
        linux)
            addr="ABSTRACT-LISTEN:${HDDS_LEASE_TOKEN_PREFIX}${d}"
            ;;
        darwin)
            if (( d > HDDS_NON_LINUX_MAX_TOKEN_ID )); then
                echo "domain-lease: token id $d exceeds ${HDDS_NON_LINUX_MAX_TOKEN_ID} (non-Linux token band)" >&2
                return 2
            fi
            addr="TCP4-LISTEN:$(( HDDS_NON_LINUX_TOKEN_PORT_BASE + d )),bind=127.0.0.1"
            ;;
        *)
            echo "domain-lease: unsupported platform '$(uname -s)'. Refusing rather than" >&2
            echo "  silently reusing a fixed domain -- that would recreate the exact" >&2
            echo "  collision this helper exists to prevent. Use the Node helper" >&2
            echo "  (sdk/typescript/scripts/domain-lease.js), which implements the same" >&2
            echo "  loopback-TCP fallback domains.rs uses off Linux, on this platform." >&2
            return 2
            ;;
    esac
    if ! command -v socat >/dev/null 2>&1; then
        echo "domain-lease: socat not found on PATH; required to bind the lease token" >&2
        return 2
    fi
    local log
    log=$(mktemp -t hdds-domain-lease.XXXXXX.log)
    socat -d -d "$addr" STDOUT >/dev/null 2>"$log" &
    local pid=$!
    local waited_ms=0
    while (( waited_ms < 2000 )); do
        if grep -q "listening on" "$log" 2>/dev/null; then
            HDDS_LEASED_DOMAIN="$d"
            HDDS_LEASE_SOCAT_PID="$pid"
            HDDS_LEASE_LOGFILE="$log"
            return 0
        fi
        if ! kill -0 "$pid" 2>/dev/null; then
            wait "$pid" 2>/dev/null
            if grep -qi "already in use" "$log" 2>/dev/null; then
                rm -f "$log"
                return 1
            fi
            echo "domain-lease: socat exited without binding domain $d:" >&2
            sed 's/^/  /' "$log" >&2
            rm -f "$log"
            return 2
        fi
        sleep 0.01
        waited_ms=$(( waited_ms + 10 ))
    done
    echo "domain-lease: timed out waiting for socat to bind or fail on domain $d" >&2
    kill "$pid" 2>/dev/null
    rm -f "$log"
    return 2
}

# hdds_domain_lease_acquire [start_hint]
#
# Lease a DDS domain no other concurrently running test -- in this process,
# another shell invocation of this file, a Node process using
# sdk/typescript/scripts/domain-lease.js, or a Rust test using
# domains.rs::unique_domain() -- can hold at the same time.
#
# start_hint defaults to $$ (this shell's pid), the same spreading idea as
# try_unique_domain()'s process::id() seed; correctness comes entirely from
# the kernel-arbitrated token in _hdds_lease_try_bind, not from the hint.
#
# Returns 0 and sets HDDS_LEASED_DOMAIN on success; returns 1 and prints a
# reason on stderr otherwise (exhaustion or an outright failure).
hdds_domain_lease_acquire() {
    local start_hint="${1:-$$}"
    local -a pool=()
    local d
    for (( d = HDDS_FIRST_POOL_DOMAIN; d <= HDDS_LAST_POOL_DOMAIN; d++ )); do
        _hdds_lease_is_excluded "$d" || pool+=("$d")
    done
    local pool_len=${#pool[@]}
    if (( pool_len == 0 )); then
        echo "domain-lease: pool is empty (should never happen)" >&2
        return 1
    fi
    local start=$(( start_hint % pool_len ))
    local offset
    for (( offset = 0; offset < pool_len; offset++ )); do
        local idx=$(( (start + offset) % pool_len ))
        local candidate="${pool[$idx]}"
        _hdds_lease_try_bind "$candidate"
        local rc=$?
        if (( rc == 0 )); then
            return 0
        elif (( rc == 2 )); then
            return 1
        fi
        # rc == 1: collision, try the next candidate.
    done
    echo "domain-lease: all $pool_len test domains are leased by live processes; either too" >&2
    echo "  many tests are running at once or a caller is leaking a domain lease" >&2
    return 1
}

# Release the currently held lease, if any. Safe to call when nothing is
# held (e.g. from a generic EXIT trap that runs before acquire ever
# succeeded). Killing the socat process closes its socket, which is exactly
# what frees the abstract name -- the same "closing the fd releases the
# token" the Rust side relies on Drop for.
hdds_domain_lease_release() {
    if [[ -n "$HDDS_LEASE_SOCAT_PID" ]]; then
        kill "$HDDS_LEASE_SOCAT_PID" >/dev/null 2>&1
        wait "$HDDS_LEASE_SOCAT_PID" 2>/dev/null
    fi
    [[ -n "$HDDS_LEASE_LOGFILE" ]] && rm -f "$HDDS_LEASE_LOGFILE"
    HDDS_LEASED_DOMAIN=""
    HDDS_LEASE_SOCAT_PID=""
    HDDS_LEASE_LOGFILE=""
}
