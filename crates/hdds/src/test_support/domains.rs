// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Unique DDS domain allocation for tests.
//!
//! # Why hand-written domain constants are not allowed here
//!
//! `cargo` compiles every file under `crates/hdds/tests/` into its own
//! executable, plus one more for the lib crate's own `#[cfg(test)]` code.
//! Plain `cargo test` does NOT run those executables in parallel: it runs
//! the lib binary and each integration-test binary one at a time.
//!
//! What does run concurrently is the default libtest harness INSIDE a
//! single binary: it spawns one thread per test and lets them race. Two
//! `#[test]` functions that hardcode the same domain id in the SAME binary
//! compute the same RTPS ports (`7400 + 250 * domain`, plus the
//! per-participant unicast offsets) and fight over them on those threads.
//! A binary boundary does not save a
//! hardcoded id either: the kernel-arbitrated token below is what makes
//! this safe against a differently-scheduled runner (`cargo nextest` runs
//! test binaries as separate concurrent OS processes by default, unlike
//! plain `cargo test`), a manually parallel invocation, or a completely
//! unrelated `cargo test` running on this machine at the same time.
//!
//! A per-file constant cannot see what any other file, any other `#[test]`
//! function in its own binary, or any other process on the machine picked
//! (two tests sharing one id show up as "Address already in use"), so no
//! amount of care in choosing it fixes this -- the allocation has to be
//! arbitrated outside the process. On top of that, a development machine
//! may run long-lived services on well-known DDS domains (see
//! [`RESERVED_DOMAINS`]): a test that binds one of those can see, and
//! be seen by, a live service.
//!
//! # Usage
//!
//! ```text
//! use hdds::test_support::domains::unique_domain;
//!
//! let domain = unique_domain();          // declare the lease FIRST
//! let participant = Participant::builder("probe")
//!     .domain_id(domain.id())
//!     .build()?;                         // dropped BEFORE the lease
//! ```
//!
//! Declare the lease before anything that binds sockets on it. Rust drops
//! locals in reverse declaration order, so the participant is torn down
//! while the lease still holds the domain, and the domain only becomes
//! available to another test once its sockets are already closed.
//!
//! Holding the returned [`DomainLease`] is what reserves the domain. Writing
//! `let d = unique_domain().id();` drops the lease on the spot and hands the
//! domain straight back to the pool, which is exactly the bug this module
//! exists to prevent.

use std::fmt;
use std::io;
use std::process;

/// DDS domains used by HDDS's own long-running tools and services (39 for
/// `hdds`, 70 for `hdds-gen`, 137 for `hdds-micro`). A test that binds one
/// of these joins a live service's domain, so [`DOMAIN_POOL`] excludes
/// every one of them. Kept sorted so the exclusion is easy to eyeball.
pub const RESERVED_DOMAINS: &[u32] = &[39, 70, 137];

/// Domains a still-existing test builds a real transport or participant on
/// by literal number, because the number itself is the subject of that
/// test's assertion (an RTPS port-formula boundary, or "this exact domain
/// id round-trips") rather than an arbitrary pick. Excluded from
/// [`DOMAIN_POOL`] for the same reason reserved domains are: leasing one of
/// these out would eventually hand it to a concurrent test and recreate the
/// exact collision this module exists to prevent.
///
/// Kept as a named, documented list instead of leaving these tests to
/// silently rely on nobody else picking their number: whoever removes or
/// renumbers one of the tests below should also remove the matching entry
/// here, and whoever adds a new test that must pin a literal domain should
/// add one.
///
/// - `1`: `crates/hdds/tests/rtps_port_mapping.rs:184` builds a real
///   participant on domain 1 and asserts `d1.domain_id() == 1` plus the
///   RTPS ports the formula gives domain 1 specifically;
///   `crates/hdds/src/transport/udp_test.rs:48` separately asserts the same
///   domain-1 port mapping on a raw `UdpTransport`.
/// - [`crate::config::MAX_DOMAIN_ID`] (232): `crates/hdds/src/dds/
///   participant/builder/bootstrap.rs:1007` builds a REAL participant on
///   the highest domain the RTPS port formula can express, proving the
///   ceiling is inclusive rather than off-by-one.
pub const TEST_PINNED_DOMAINS: &[u32] = &[1, crate::config::MAX_DOMAIN_ID];

/// Lowest domain the pool will hand out. Domain 0 is deliberately excluded:
/// it is the default that any stray tool or forgotten process on this
/// machine binds without being asked to.
const FIRST_POOL_DOMAIN: u32 = 1;

/// Highest domain the pool will hand out. RTPS defines no port past this:
/// `PORT_BASE + DOMAIN_ID_GAIN * domain` must fit a `u16`, and the
/// `Participant` builder refuses anything higher with
/// `Error::InvalidDomainId`.
const LAST_POOL_DOMAIN: u32 = crate::config::MAX_DOMAIN_ID;

const fn is_reserved(domain: u32) -> bool {
    let mut i = 0;
    while i < RESERVED_DOMAINS.len() {
        if RESERVED_DOMAINS[i] == domain {
            return true;
        }
        i += 1;
    }
    false
}

const fn is_test_pinned(domain: u32) -> bool {
    let mut i = 0;
    while i < TEST_PINNED_DOMAINS.len() {
        if TEST_PINNED_DOMAINS[i] == domain {
            return true;
        }
        i += 1;
    }
    false
}

/// Low and high bound of the Linux default ephemeral port range, the values
/// in `/proc/sys/net/ipv4/ip_local_port_range` on an untuned host.
///
/// The kernel draws short-lived source ports from this range for any process
/// that opens an outbound connection, without knowing or caring that RTPS
/// wants some of them. `PORT_BASE + DOMAIN_ID_GAIN * domain` puts the ports
/// of domains 102 through 214 inside it, so a browser, a `curl` or a database
/// client can be handed the exact port a leased participant is about to bind.
/// That is not a test-only hazard -- see `docs/reference/limits.md` -- but in
/// the suite it shows up as an `AddrInUse` that no amount of leasing can
/// prevent, because the competitor is not playing our game.
///
/// The pool therefore skips every domain whose 70-port block touches this
/// range. `ephemeral_range_matches_this_host` below checks the assumption
/// against the machine actually running the tests.
const EPHEMERAL_PORT_LOW: u32 = 32_768;
const EPHEMERAL_PORT_HIGH: u32 = 60_999;

/// Ports a single domain occupies, from `docs/reference/limits.md`:
/// 7400-7469 for domain 0, so 70 ports starting at `PORT_BASE + 250 * domain`.
const DOMAIN_PORT_BLOCK: u32 = 70;

const fn touches_ephemeral_range(domain: u32) -> bool {
    let first = crate::config::PORT_BASE as u32 + crate::config::DOMAIN_ID_GAIN as u32 * domain; // @audit-ok: u16 -> u32 widening, lossless; `u32::from` is not callable in a const fn
    let last = first + DOMAIN_PORT_BLOCK - 1;
    last >= EPHEMERAL_PORT_LOW && first <= EPHEMERAL_PORT_HIGH
}

const fn is_excluded(domain: u32) -> bool {
    is_reserved(domain) || is_test_pinned(domain) || touches_ephemeral_range(domain)
}

const fn pool_len() -> usize {
    let mut count = 0;
    let mut domain = FIRST_POOL_DOMAIN;
    while domain <= LAST_POOL_DOMAIN {
        if !is_excluded(domain) {
            count += 1;
        }
        domain += 1;
    }
    count
}

const POOL_LEN: usize = pool_len();

const fn build_pool() -> [u32; POOL_LEN] {
    let mut pool = [0u32; POOL_LEN];
    let mut slot = 0;
    let mut domain = FIRST_POOL_DOMAIN;
    while domain <= LAST_POOL_DOMAIN {
        if !is_excluded(domain) {
            pool[slot] = domain;
            slot += 1;
        }
        domain += 1;
    }
    pool
}

/// Every domain [`unique_domain`] is allowed to return: `1..=232` minus the
/// reserved ids and [`TEST_PINNED_DOMAINS`]. Built at compile time
/// from the two bounds and those two exclusion lists, so the guarantees (no
/// domain 0, no reserved domain, no domain a test pins by literal number,
/// nothing above `MAX_DOMAIN_ID`) hold by construction rather than by
/// review.
pub const DOMAIN_POOL: [u32; POOL_LEN] = build_pool();

// =============================================================================
// The cross-process token
// =============================================================================
//
// A process-local counter is not enough: the lib test binary and each
// integration test binary are separate processes that start at the same
// moment, and each would start counting from the same place. The arbiter has
// to be something the kernel keeps for the whole machine, and it has to be
// released automatically when a test process dies -- a test killed by a
// panic-abort or by Ctrl-C must not poison a domain for every later run.

/// Linux: the abstract Unix socket namespace is the lock table.
///
/// Binding an abstract name that is already bound fails with `AddrInUse`,
/// machine-wide and across processes, and the kernel frees the name when the
/// last file descriptor holding it is closed -- including the implicit close
/// when a process dies for any reason. Nothing is written to the filesystem,
/// so there is no stale lock file to reclaim and therefore no reclaim race.
/// The namespace is per network namespace, which is exactly the right scope:
/// two test runs isolated in different netns cannot reach each other's RTPS
/// traffic either.
#[cfg(target_os = "linux")]
mod platform {
    use std::io;
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::{SocketAddr, UnixListener};

    /// Opaque handle whose lifetime is the reservation.
    pub type Token = UnixListener;

    pub fn bind_token(domain: u32) -> io::Result<Token> {
        let name = format!("hdds-test-domain.v1.{domain}");
        let addr = SocketAddr::from_abstract_name(name.as_bytes())?;
        UnixListener::bind_addr(&addr)
    }
}

/// Non-Linux: a loopback TCP listener on a token port is the lock table.
///
/// There is no abstract socket namespace outside Linux. A listening TCP
/// socket is the next best kernel-arbitrated, auto-released token: a second
/// `bind` of a live listening address fails with `AddrInUse`, and the OS
/// closes the socket when the process dies. The token port is derived from
/// the domain and sits below `PORT_BASE` (7400), so it can never collide
/// with the RTPS ports of any domain. It can collide with an unrelated local
/// service, and when it does that domain is simply skipped -- the pool
/// shrinks, nothing breaks. This path is not exercised on the Linux CI box.
#[cfg(not(target_os = "linux"))]
mod platform {
    use std::io;
    use std::net::{Ipv4Addr, TcpListener};

    /// First token port. The band is `6900..=7399`, i.e. it ends one port
    /// below `PORT_BASE` (7400), so no token can ever land on an RTPS port.
    const TOKEN_PORT_BASE: u16 = 6900;

    /// Largest id this token scheme can express. Comfortably above
    /// `MAX_DOMAIN_ID`; the headroom is what lets the unit tests name
    /// private tokens outside the real pool.
    const MAX_TOKEN_ID: u32 = 499;

    /// Opaque handle whose lifetime is the reservation.
    pub type Token = TcpListener;

    pub fn bind_token(domain: u32) -> io::Result<Token> {
        if domain > MAX_TOKEN_ID {
            return Err(io::Error::other(format!(
                "token id {domain} exceeds the {MAX_TOKEN_ID} this platform's token band can express"
            )));
        }
        let offset = u16::try_from(domain).map_err(io::Error::other)?;
        let port = TOKEN_PORT_BASE.checked_add(offset).ok_or_else(|| {
            io::Error::other(format!("token id {domain} overflows the port range"))
        })?;
        TcpListener::bind((Ipv4Addr::LOCALHOST, port))
    }
}

/// A reserved DDS domain. The reservation lasts exactly as long as this
/// value is alive; dropping it (or the process exiting, however abruptly)
/// releases the domain back to the pool.
#[derive(Debug)]
pub struct DomainLease {
    id: u32,
    /// The kernel-held token. Never read; its `Drop` is the whole point.
    _token: platform::Token,
}

impl DomainLease {
    /// The reserved domain id. Guaranteed to be in [`DOMAIN_POOL`]: not 0,
    /// not reserved, never above `MAX_DOMAIN_ID`.
    pub fn id(&self) -> u32 {
        self.id
    }
}

/// Print one line to stderr identifying who leased or released a domain,
/// when `HDDS_DOMAIN_LEASE_TRACE` is set in the environment. Checked on
/// every call rather than cached: this is diagnostic-only, never on a path
/// a benchmark cares about, and a test can flip the env var mid-run.
///
/// `std::thread::current().name()` is the libtest-assigned test path on the
/// thread actually running a test (`cargo test`'s default harness names
/// each test's thread after the test), so a trace line names the test that
/// leased or released a domain without the caller passing it in.
fn trace_lease_event(domain: u32, event: &str) {
    if std::env::var_os("HDDS_DOMAIN_LEASE_TRACE").is_none() {
        return;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    eprintln!(
        "[domain-lease] t={}.{:06} pid={} thread={:?} domain={domain} {event}",
        now.as_secs(),
        now.subsec_micros(),
        process::id(),
        std::thread::current().name().unwrap_or("<unnamed>"),
    );
}

impl Drop for DomainLease {
    fn drop(&mut self) {
        trace_lease_event(self.id, "RELEASED");
    }
}

impl fmt::Display for DomainLease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.id)
    }
}

/// Why [`try_unique_domain`] could not hand out a domain.
#[derive(Debug)]
pub enum DomainAllocError {
    /// Every domain in the pool is currently leased by a live process. This
    /// is the exhaustion failure mode, and it is deliberately a hard error:
    /// falling back to a domain that is already in use would resurrect the
    /// exact `AddrInUse` flake this module exists to kill. It means either
    /// far more concurrent tests than the pool has slots, or a test that
    /// leaks leases in a loop.
    Exhausted {
        /// Number of domains that were probed before giving up.
        pool_len: usize,
    },
    /// Probing a domain failed for a reason other than "already taken" (no
    /// permission to bind, file descriptor limit reached, ...). Reported
    /// rather than skipped, because silently walking past it would turn an
    /// environment problem into a confusing exhaustion report.
    Io(io::Error),
}

impl fmt::Display for DomainAllocError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DomainAllocError::Exhausted { pool_len } => write!(
                f,
                "all {pool_len} test domains are leased by live processes; \
                 either too many tests are running at once or a test is leaking DomainLease values"
            ),
            DomainAllocError::Io(e) => {
                write!(f, "could not probe a test domain: {e}")
            }
        }
    }
}

impl std::error::Error for DomainAllocError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DomainAllocError::Exhausted { .. } => None,
            DomainAllocError::Io(e) => Some(e),
        }
    }
}

/// Whether domain `domain`'s real RTPS sockets (the metatraffic multicast
/// port, and participant 0's metatraffic unicast port) are actually
/// bindable right now, probed with the exact same socket options the real
/// transport uses -- SO_REUSEADDR on the multicast port (so a PLAIN
/// non-cooperative holder is still caught, the same thing
/// `auto_assign_fails_fast_when_metatraffic_multicast_is_squatted` pins),
/// no reuse option at all on the unicast port (it is exclusive by design,
/// RTPS 2.5 9.6.1.1).
///
/// This is what makes the token above worth anything to a caller: the
/// abstract-namespace token is a logical reservation this module invented,
/// but the port is the resource a `Participant` actually needs, and the
/// two can transiently disagree -- a background thread finishing the last
/// `Arc<UdpTransport>` clone of the PREVIOUS holder of this exact domain
/// number a moment after that holder's lease let go, under enough load
/// that "a moment" stretches past the next taker's probe (with
/// `HDDS_DOMAIN_LEASE_TRACE=1` the trace shows a metatraffic unicast socket
/// closed from a thread named `hdds-stateless-writer`, not from the test
/// that leased the domain, after that lease had already been released and
/// handed back out). Returns `true` for a domain number with no real port mapping (the
/// out-of-range private tokens some unit tests below use): there is
/// nothing on the wire to squat, so there is nothing to probe.
fn domain_ports_are_free(domain: u32) -> bool {
    let Ok(mapping) = crate::transport::PortMapping::calculate(domain, 0) else {
        return true;
    };
    let multicast_free = (|| -> io::Result<()> {
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        socket.set_reuse_address(true)?;
        let addr: std::net::SocketAddr = (
            std::net::Ipv4Addr::UNSPECIFIED,
            mapping.metatraffic_multicast,
        )
            .into();
        socket.bind(&addr.into())
    })()
    .is_ok();
    let unicast_free =
        std::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, mapping.metatraffic_unicast))
            .is_ok();
    multicast_free && unicast_free
}

/// Walk `pool` starting at `start_hint` (wrapping) and lease the first
/// domain whose token AND whose real ports are free.
///
/// Split out from [`try_unique_domain`] so the exhaustion and reuse paths
/// can be tested against a private two- or three-element pool instead of
/// draining the real one, which would starve every test running in parallel.
fn lease_from_pool(pool: &[u32], start_hint: usize) -> Result<DomainLease, DomainAllocError> {
    assert!(!pool.is_empty(), "lease_from_pool: pool must not be empty");
    let start = start_hint % pool.len();
    for offset in 0..pool.len() {
        let domain = pool[(start + offset) % pool.len()];
        match platform::bind_token(domain) {
            Ok(token) => {
                if !domain_ports_are_free(domain) {
                    // The token says we won domain `domain`, but its real
                    // ports are still squatted by whatever held it last:
                    // drop the token (handing it straight back) and try
                    // the next candidate instead of returning a domain the
                    // caller's own bind is about to lose to AddrInUse.
                    trace_lease_event(domain, "TOKEN_WON_PORTS_STILL_BUSY");
                    drop(token);
                    continue;
                }
                trace_lease_event(domain, "LEASED");
                return Ok(DomainLease {
                    id: domain,
                    _token: token,
                });
            }
            Err(e) if e.kind() == io::ErrorKind::AddrInUse => {}
            Err(e) => return Err(DomainAllocError::Io(e)),
        }
    }
    Err(DomainAllocError::Exhausted {
        pool_len: pool.len(),
    })
}

/// Bumped once per [`try_unique_domain`] call (every thread of this process
/// shares it) so that successive leases do not all start their scan at the
/// identical pool slot. A pid-only hint spreads DIFFERENT processes apart,
/// but every thread of the SAME process computes the exact same `pid`, so
/// without this a hot binary's hundreds of threads all probe the same first
/// slot first: with `HDDS_DOMAIN_LEASE_TRACE=1` on a parallel
/// `cargo test -p hdds --lib --all-features` run, one domain can be leased
/// and released dozens of times within milliseconds while a domain a few
/// slots away is leased only a handful of times over the whole run -- a
/// self-inflicted hot slot, not a correctness bug (the
/// kernel token still refused every double-bind), but it manufactures far
/// more lease churn on one number than the pool needs, which is exactly the
/// kind of pressure that turns a borderline timing assumption elsewhere into
/// a flake. Contention-only, like the pid offset: see the module doc for
/// what actually makes the result safe.
static NEXT_SCAN_HINT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Lease a DDS domain no other concurrently running test, in this process or
/// any other on this machine, can hold at the same time.
///
/// The scan starts at a pid-derived offset, further spread by
/// [`NEXT_SCAN_HINT`], so that both binaries starting together AND threads
/// racing inside one binary spread out over the pool instead of piling onto
/// the same slot; that is a contention optimisation only. What makes the
/// result *correct* is the kernel-arbitrated token described at the top of
/// this module: the winner of a bind race is decided by the kernel, so two
/// processes can never both believe they own a domain.
pub fn try_unique_domain() -> Result<DomainLease, DomainAllocError> {
    // Pin the loopback interface before anything else in this call can
    // reach the transport layer, so a discovery-dependent test never races
    // host routing (VPN default route, container bridge, ...) to decide
    // which interface its participants land on. See
    // `super::network::pin_loopback_interface` for the full reasoning; this
    // is the one call site every multi-participant test already makes.
    super::network::pin_loopback_interface();
    let hint = (process::id() as usize)
        .wrapping_add(NEXT_SCAN_HINT.fetch_add(1, std::sync::atomic::Ordering::Relaxed));
    let deadline = std::time::Instant::now() + EXHAUSTION_WAIT;
    loop {
        match lease_from_pool(&DOMAIN_POOL, hint) {
            Err(DomainAllocError::Exhausted { .. }) if std::time::Instant::now() < deadline => {
                std::thread::sleep(EXHAUSTION_RETRY);
            }
            result => return result,
        }
    }
}

/// How long [`try_unique_domain`] waits for a lease to come back before it
/// reports the pool exhausted.
///
/// The pool is one table for the whole machine. A lib suite running its
/// tests on every core, next to another test process (a second worktree's
/// gate, a loop reproducing a flake), holds all of it for a moment, and a
/// test that asked then failed at once although a domain was released a few
/// milliseconds later. Waiting changes no guarantee: the lease handed out is
/// still one the kernel says nobody holds. A test leaking leases still
/// fails, after this long instead of at once.
const EXHAUSTION_WAIT: std::time::Duration = std::time::Duration::from_secs(60);

/// Interval between two scans of an exhausted pool.
const EXHAUSTION_RETRY: std::time::Duration = std::time::Duration::from_millis(20);

/// [`try_unique_domain`], panicking on failure. The form tests should use:
/// a test that cannot get a domain has nothing meaningful left to assert.
#[must_use]
pub fn unique_domain() -> DomainLease {
    match try_unique_domain() {
        Ok(lease) => lease,
        Err(e) => panic!("test_support::domains::unique_domain: {e}"),
    }
}

#[cfg(test)]
mod tests {
    /// The pool assumes the Linux DEFAULT ephemeral range. That range is a
    /// tunable, so this test asks the machine actually running the suite
    /// whether the assumption still holds, and fails with an instruction
    /// rather than letting a widened range reintroduce the flake silently.
    #[test]
    fn ephemeral_range_matches_this_host() {
        let Ok(raw) = std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range") else {
            // Not Linux, or a kernel without procfs: the constants are a
            // documented default, nothing to check against.
            return;
        };
        let mut parts = raw.split_whitespace();
        let (Some(low), Some(high)) = (parts.next(), parts.next()) else {
            return;
        };
        let (Ok(low), Ok(high)) = (low.parse::<u32>(), high.parse::<u32>()) else {
            return;
        };
        assert!(
            low >= EPHEMERAL_PORT_LOW && high <= EPHEMERAL_PORT_HIGH,
            "this host's ephemeral range is {low}-{high}, wider than the {}-{} the pool excludes. \
             Domains outside the excluded band can now lose a port to the kernel, which is exactly \
             the AddrInUse this exclusion exists to prevent. Widen EPHEMERAL_PORT_LOW/HIGH to cover \
             it, or narrow the host's range.",
            EPHEMERAL_PORT_LOW,
            EPHEMERAL_PORT_HIGH
        );
    }

    /// No domain in the pool can lose a port to the kernel's ephemeral
    /// allocator, checked per entry over its whole 70-port block rather than
    /// on the SPDP port alone.
    #[test]
    fn pool_never_touches_the_ephemeral_range() {
        for domain in DOMAIN_POOL {
            let first = u32::from(crate::config::PORT_BASE)
                + u32::from(crate::config::DOMAIN_ID_GAIN) * domain;
            let last = first + DOMAIN_PORT_BLOCK - 1;
            assert!(
                last < EPHEMERAL_PORT_LOW || first > EPHEMERAL_PORT_HIGH,
                "domain {domain} occupies ports {first}-{last}, which overlaps the ephemeral \
                 range {}-{}",
                EPHEMERAL_PORT_LOW,
                EPHEMERAL_PORT_HIGH
            );
        }
        assert!(
            !DOMAIN_POOL.is_empty(),
            "excluding the ephemeral range emptied the pool"
        );
    }

    use super::*;
    use std::collections::HashSet;
    use std::io::{BufRead, BufReader, Write};
    use std::process::{Child, Command, Stdio};
    use std::sync::{mpsc, Arc, Barrier};
    use std::thread;

    #[test]
    fn pool_never_contains_a_reserved_domain() {
        for domain in DOMAIN_POOL {
            assert!(
                !RESERVED_DOMAINS.contains(&domain),
                "domain {domain} is reserved for a long-running service"
            );
        }
        // And the exclusion actually removed something, i.e. the const-fn
        // filter is wired up rather than silently matching nothing.
        let in_range = RESERVED_DOMAINS
            .iter()
            .filter(|d| (FIRST_POOL_DOMAIN..=LAST_POOL_DOMAIN).contains(d))
            .count();
        assert!(
            in_range > 0,
            "test is vacuous: no reserved domain is in range"
        );
    }

    #[test]
    fn pool_never_contains_a_test_pinned_domain() {
        for domain in DOMAIN_POOL {
            assert!(
                !TEST_PINNED_DOMAINS.contains(&domain),
                "domain {domain} is pinned by a test that asserts its literal value"
            );
        }
        // And the exclusion actually removed something, i.e. the const-fn
        // filter is wired up rather than silently matching nothing.
        let in_range = TEST_PINNED_DOMAINS
            .iter()
            .filter(|d| (FIRST_POOL_DOMAIN..=LAST_POOL_DOMAIN).contains(d))
            .count();
        assert!(
            in_range > 0,
            "test is vacuous: no pinned domain is in range"
        );
    }

    #[test]
    fn pool_len_accounts_for_every_exclusion() {
        // The two exclusion lists must be disjoint, or the subtraction
        // below double-counts and this test would pass for the wrong
        // reason.
        assert!(
            RESERVED_DOMAINS
                .iter()
                .all(|d| !TEST_PINNED_DOMAINS.contains(d)),
            "a domain cannot be both reserved and test-pinned"
        );
        // Count every excluded domain ONCE, whatever its reason. Subtracting
        // per-reason counts is what broke when the ephemeral-range exclusion
        // was added: the three reasons overlap (a reserved domain can also sit
        // in the ephemeral band), so the arithmetic silently double-counted.
        // Counting the union is both simpler and immune to the next reason
        // somebody adds.
        let excluded = (FIRST_POOL_DOMAIN..=LAST_POOL_DOMAIN)
            .filter(|d| {
                RESERVED_DOMAINS.contains(d)
                    || TEST_PINNED_DOMAINS.contains(d)
                    || touches_ephemeral_range(*d)
            })
            .count();
        assert_eq!(
            DOMAIN_POOL.len(),
            (LAST_POOL_DOMAIN - FIRST_POOL_DOMAIN + 1) as usize - excluded,
            "the pool must contain exactly the domains no exclusion rejects"
        );
        // A pool that is technically correct and practically useless would
        // still pass the line above, so bound it from below too. The
        // allocator's own falsification test takes 12 concurrent leases.
        assert!(
            DOMAIN_POOL.len() >= 32,
            "only {} domains left after exclusions: too few for a parallel suite",
            DOMAIN_POOL.len()
        );
    }

    #[test]
    fn pool_never_exceeds_the_rtps_domain_ceiling() {
        for domain in DOMAIN_POOL {
            assert!(
                domain <= crate::config::MAX_DOMAIN_ID,
                "domain {domain} has no RTPS port"
            );
            assert!(domain >= 1, "domain 0 is the default domain");
            // The bound the ceiling exists for: every RTPS port of this
            // domain must fit a u16.
            assert!(
                crate::transport::PortMapping::calculate(domain, 0).is_ok(),
                "domain {domain} has no valid port mapping"
            );
        }
        assert!(!DOMAIN_POOL.is_empty());
    }

    #[test]
    fn leased_domains_are_unique_across_threads() {
        const THREADS: usize = 24;

        // Every thread holds its lease until all of them have one, so the
        // leases genuinely overlap in time instead of being handed the same
        // domain in sequence. Every thread reaches the barrier whatever its
        // allocation returned: a thread that panicked before it (the pool
        // exhausted by the other test processes of the machine) would leave
        // the others waiting forever, a hang instead of a failure.
        let barrier = Arc::new(Barrier::new(THREADS));
        let (tx, rx) = mpsc::channel();
        let handles: Vec<_> = (0..THREADS)
            .map(|_| {
                let barrier = Arc::clone(&barrier);
                let tx = tx.clone();
                thread::spawn(move || {
                    let lease = try_unique_domain();
                    let sent = lease
                        .as_ref()
                        .map(DomainLease::id)
                        .map_err(|e| e.to_string());
                    tx.send(sent).expect("collector alive");
                    barrier.wait();
                    drop(lease);
                })
            })
            .collect();
        drop(tx);

        let results: Vec<Result<u32, String>> = rx.iter().collect();
        for handle in handles {
            handle.join().expect("worker thread");
        }
        let ids: Vec<u32> = results
            .into_iter()
            .map(|r| r.unwrap_or_else(|e| panic!("a thread got no domain: {e}")))
            .collect();

        assert_eq!(ids.len(), THREADS);
        let unique: HashSet<u32> = ids.iter().copied().collect();
        assert_eq!(
            unique.len(),
            THREADS,
            "duplicate domain handed out: {ids:?}"
        );
        for id in ids {
            assert!(DOMAIN_POOL.contains(&id), "domain {id} is outside the pool");
        }
    }

    #[test]
    fn the_token_is_arbitrated_by_the_kernel_not_by_this_process() {
        // The property that makes the allocator cross-process safe: while a
        // lease is held, ANY binder of the same token is refused, including
        // one that knows nothing about this module's bookkeeping. A separate
        // process sees exactly this refusal.
        let lease = unique_domain();
        let err =
            platform::bind_token(lease.id()).expect_err("second bind of a held token must fail");
        assert_eq!(
            err.kind(),
            io::ErrorKind::AddrInUse,
            "unexpected error rebinding a held token: {err}"
        );
    }

    #[test]
    fn exhaustion_is_reported_never_papered_over() {
        // Build a private two-slot pool out of two domains this test already
        // owns. No third party can free them mid-test, and the real pool
        // loses only two slots instead of being drained (which would starve
        // every test running in parallel).
        let held_a = unique_domain();
        let held_b = unique_domain();
        assert_ne!(held_a.id(), held_b.id());
        let pool = [held_a.id(), held_b.id()];

        match lease_from_pool(&pool, 0) {
            Err(DomainAllocError::Exhausted { pool_len }) => assert_eq!(pool_len, pool.len()),
            Err(other) => panic!("expected Exhausted, got {other}"),
            Ok(lease) => panic!("handed out {} from an exhausted pool", lease.id()),
        }
    }

    /// A domain whose abstract-namespace TOKEN is free can still have its
    /// real RTPS ports squatted (a background thread finishing a previous
    /// holder's last transport clone a moment late, under load, is the
    /// mechanism): the pool must not hand such a domain out just because nobody else holds its token.
    #[test]
    fn a_domain_whose_real_ports_are_squatted_is_skipped_even_with_a_free_token() {
        let held = unique_domain();
        let held_id = held.id();
        let mapping = crate::transport::PortMapping::calculate(held_id, 0)
            .expect("pool domain has a mapping");
        let squatter = std::net::UdpSocket::bind(("0.0.0.0", mapping.metatraffic_multicast))
            .expect("squat the multicast port while the lease is still ours to squat under");
        let pool = [held_id];

        // Release the TOKEN only; the plain socket above keeps the real
        // port busy exactly like the lagging background thread this test
        // stands in for.
        drop(held);

        match lease_from_pool(&pool, 0) {
            Err(DomainAllocError::Exhausted { pool_len }) => assert_eq!(pool_len, pool.len()),
            Err(other) => panic!("expected Exhausted, got {other}"),
            Ok(lease) => panic!(
                "handed out domain {} although its multicast port is squatted",
                lease.id()
            ),
        }

        // Once the squat itself is gone, the same domain is leasable again:
        // this is about the PORT, not about poisoning the domain forever.
        // Not necessarily on the very next probe, though: dropping the
        // squatter only starts the socket's teardown, and on a machine
        // running several of this module's own test processes at once
        // (the more test processes run in parallel, the likelier) another
        // process -- any of its threads, not necessarily one running this same
        // test -- can win
        // this exact domain's now-free token in the gap between our drop
        // and our re-check, which looks identical to the port still being
        // busy. Poll for it instead of demanding it on the first try, same
        // discipline as `dropping_a_lease_frees_the_domain_for_the_next_
        // taker`, with a longer budget: that one re-takes a private token
        // only this process can ever want, so contention is one process
        // racing its own Drop; this one re-takes a real pool domain every
        // other process on the machine is also scanning.
        drop(squatter);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let relet = loop {
            match lease_from_pool(&pool, 0) {
                Ok(lease) => break lease,
                Err(_) if std::time::Instant::now() < deadline => {
                    thread::sleep(std::time::Duration::from_millis(20));
                }
                Err(e) => panic!("domain stayed refused after its squat was released: {e}"),
            }
        };
        assert_eq!(relet.id(), held_id);
    }

    /// Offset used to turn a leased domain into a token id that no real
    /// allocation can ever reach (`DOMAIN_POOL` stops at `MAX_DOMAIN_ID`).
    /// Small enough that the non-Linux token band can still express it.
    const PRIVATE_TOKEN_OFFSET: u32 = 233;

    #[test]
    fn dropping_a_lease_frees_the_domain_for_the_next_taker() {
        // A domain we hold gives us a token id nobody else running THIS
        // commit's allocator can also derive: real allocations never go
        // above MAX_DOMAIN_ID, and no other process can hold this anchor
        // domain. That does NOT make `private` globally unguessable, though:
        // the abstract-namespace token is a flat integer keyed by number,
        // shared machine-wide, and nothing stops a DIFFERENT checkout of
        // this same crate -- a different worktree, a different commit with
        // a different `MAX_DOMAIN_ID` or `PRIVATE_TOKEN_OFFSET` -- from
        // leasing a REAL domain that happens to equal our `private` number.
        // Re-taking the exact id we just dropped can therefore lose a race
        // against a completely unrelated process on this machine, which is
        // exactly the failure this test hit twice in seven runs
        // (`Exhausted { pool_len: 1 }` right after `drop(first)`).
        //
        // That race is about WHO holds the name for a moment, not about
        // whether Drop released it -- Drop is synchronous (closing the
        // underlying fd completes before `drop()` returns), so if this
        // process is the only thing that will ever contend for `private`,
        // the very first re-lease attempt always succeeds. The retry loop
        // below tolerates a transient outside contender without weakening
        // what is actually asserted: the second lease, once it lands, must
        // be the same id, and if Drop never really released the token the
        // loop exhausts its budget and fails loudly instead of hanging.
        let anchor = unique_domain();
        let private = PRIVATE_TOKEN_OFFSET + anchor.id();
        assert!(
            !DOMAIN_POOL.contains(&private),
            "private token id {private} collides with the real pool"
        );
        let pool = [private];

        let first = lease_from_pool(&pool, 0).expect("private token is free");
        assert_eq!(first.id(), private);
        assert!(
            matches!(
                lease_from_pool(&pool, 0),
                Err(DomainAllocError::Exhausted { .. })
            ),
            "a held domain must not be handed out a second time"
        );

        drop(first);

        const RETRY_ATTEMPTS: u32 = 100;
        const RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(20);
        let mut second = None;
        for attempt in 0..RETRY_ATTEMPTS {
            match lease_from_pool(&pool, 0) {
                Ok(lease) => {
                    second = Some(lease);
                    break;
                }
                Err(DomainAllocError::Exhausted { .. }) if attempt + 1 < RETRY_ATTEMPTS => {
                    thread::sleep(RETRY_DELAY);
                }
                Err(e) => panic!(
                    "domain released on drop: {e} (gave up after {} attempts / {:?})",
                    attempt + 1,
                    RETRY_DELAY * attempt
                ),
            }
        }
        let second = second.expect("unreachable: loop above always returns or panics");
        assert_eq!(second.id(), private);
        drop(anchor);
    }

    // =========================================================================
    // Real cross-process proof
    // =========================================================================
    //
    // Every test above runs the allocator against OTHER THREADS of this same
    // test binary. That is enough to exercise the kernel-arbitrated token
    // (its holder is a file descriptor, and the kernel does not distinguish
    // "another thread of mine" from "another process" when deciding who wins
    // a bind race), but it never actually spawns a second OS process, so it
    // never proves the one failure mode a thread cannot reproduce: a process
    // that dies WITHOUT running any of its own destructors (`SIGKILL`, no
    // unwind, no `Drop::drop`). These two tests spawn this test binary again
    // as a real child (the same pattern `hdds-discovery-server`'s
    // `managed_participant_child` uses) to prove both properties against an
    // actual separate process instead of an argument from kernel semantics.

    /// Set by the parent on a spawned child; nothing else ever sets it. Its
    /// presence, not its value, is what tells [`domain_lease_child`] it is
    /// running as that child rather than as part of a normal `cargo test`.
    const CHILD_MARKER: &str = "HDDS_DOMAIN_LEASE_CHILD";

    /// Set alongside [`CHILD_MARKER`] to make the child hold its lease and
    /// sleep instead of exiting right after reporting it, so the parent has
    /// a window to kill it while it still owns the domain.
    const CHILD_HOLD: &str = "HDDS_DOMAIN_LEASE_CHILD_HOLD";

    /// Not exercised by a normal test run (returns at once unless
    /// [`CHILD_MARKER`] is set): the body [`spawn_child`] below re-invokes as
    /// a separate process. Leases a domain, prints it on its own line and
    /// flushes, then either exits (two children can be compared) or sleeps
    /// (the parent can kill it while it still holds the lease).
    #[test]
    fn domain_lease_child() {
        if std::env::var_os(CHILD_MARKER).is_none() {
            return;
        }
        let lease = unique_domain();
        println!("{}", lease.id());
        std::io::stdout().flush().expect("flush child stdout");
        if std::env::var_os(CHILD_HOLD).is_some() {
            loop {
                thread::sleep(std::time::Duration::from_secs(3600));
            }
        }
    }

    /// Spawn [`domain_lease_child`] as a real child process with its stdout
    /// piped back to us.
    fn spawn_child(hold: bool) -> Child {
        let exe = std::env::current_exe().expect("locate this test binary");
        let mut cmd = Command::new(exe);
        cmd.arg("--exact")
            .arg("test_support::domains::tests::domain_lease_child")
            .arg("--nocapture")
            .env(CHILD_MARKER, "1")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if hold {
            cmd.env(CHILD_HOLD, "1");
        }
        cmd.spawn().expect("spawn domain lease child")
    }

    /// Read the child's stdout until a line parses as a domain id, skipping
    /// the libtest harness's own banner lines ("running 1 test", ...) ahead
    /// of it. Does not wait for the child to exit: a held child never does.
    fn read_reported_domain(child: &mut Child) -> u32 {
        let stdout = child.stdout.as_mut().expect("child stdout was piped");
        for line in BufReader::new(stdout).lines() {
            let line = line.expect("read a line of child stdout");
            if let Ok(domain) = line.trim().parse::<u32>() {
                return domain;
            }
        }
        panic!("domain lease child exited without ever reporting a domain");
    }

    #[test]
    fn two_real_processes_never_lease_the_same_domain() {
        // Both children HOLD (sleep instead of exiting) after reporting:
        // this is the same discipline leased_domains_are_unique_across_threads
        // uses a Barrier for. Without it, a slow-to-start child can lease the
        // very domain a fast one already released -- that is not a
        // collision, it is dropping_a_lease_frees_the_domain_for_the_next_taker
        // working as designed, and asserting "never the same number" against
        // two leases that never actually overlapped in time is a test bug,
        // not a property of the allocator (caught by this test failing on the
        // first real run, both children reporting domain 28).
        let mut a = spawn_child(true);
        let mut b = spawn_child(true);
        let domain_a = read_reported_domain(&mut a);
        let domain_b = read_reported_domain(&mut b);
        a.kill().expect("SIGKILL child a"); // Child::kill is SIGKILL on Unix.
        b.kill().expect("SIGKILL child b");
        a.wait().expect("reap child a");
        b.wait().expect("reap child b");
        assert_ne!(
            domain_a, domain_b,
            "two processes holding their lease AT THE SAME TIME leased the same domain"
        );
        assert!(
            DOMAIN_POOL.contains(&domain_a),
            "domain {domain_a} outside the pool"
        );
        assert!(
            DOMAIN_POOL.contains(&domain_b),
            "domain {domain_b} outside the pool"
        );
    }

    #[test]
    fn sigkilling_the_holder_releases_its_domain() {
        let mut child = spawn_child(true);
        let domain = read_reported_domain(&mut child);
        child.kill().expect("SIGKILL the holding child"); // Child::kill is SIGKILL on Unix.
        child.wait().expect("reap the killed child");

        // The kernel reclaims the killed process's token fd as part of
        // tearing it down; that reclaim is what frees the name, and it can
        // land a moment after `wait()` returns. Poll a private pool pinned
        // to exactly the domain we watched it hold, so a slow reclaim is
        // tolerated but a reclaim that never happens still fails loudly
        // instead of hanging.
        let pool = [domain];
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            match lease_from_pool(&pool, 0) {
                Ok(lease) => {
                    assert_eq!(lease.id(), domain);
                    return;
                }
                Err(DomainAllocError::Exhausted { .. }) if std::time::Instant::now() < deadline => {
                    thread::sleep(std::time::Duration::from_millis(20));
                }
                Err(e) => panic!("domain {domain} was not released by its SIGKILLed holder: {e}"),
            }
        }
    }
}
