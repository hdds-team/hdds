// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Dead-owner reclamation for single-owner SHM ring segments.
//!
//! A ring segment (`/hdds_d<domain>_w<guid>`) has exactly one legitimate
//! writer for its whole life: the DataWriter whose GUID names it, which
//! lives in exactly one process. `ShmWriterTransport::drop` already unlinks
//! it on a normal shutdown (see `integration.rs`). What that cannot do
//! anything about is a crash: `kill -9`, a panic that aborts instead of
//! unwinding, an OOM kill. None of those run any `Drop`, so before this
//! module the segment was left in `/dev/shm` forever, growing without bound
//! across restarts of whatever process creates ring writers.
//!
//! This module adds a side record -- deliberately NOT a change to
//! `ShmControl`, the mapped, versioned layout shared with every peer that
//! attaches to the ring. `ShmControl` already carries `owner_guid` and
//! `nonce`, but for a different question (proving identity to an attaching
//! reader); bumping its version to also carry a PID would force every peer
//! that only ATTACHES and never creates to agree on a new layout, for a
//! question that only the creator ever needs to answer, about itself, to
//! itself, at its own next startup. So the record lives beside the segment
//! as an ordinary file, never mapped, never sent to a peer, never read by
//! anything but this module.
//!
//! # Why only ring segments
//!
//! A topic's notify segment (`/hdds_notify_v2_d<domain>_<topic>`) does not
//! have single-owner semantics: several writers and readers for the same
//! topic, in different processes, share one segment, and whichever of them
//! happened to create it first is not "the owner" in any sense that makes
//! "it died, so reclaim" safe. Reclaiming it on the first creator's death
//! would silently split the topic: a process already attached keeps its
//! mapping (POSIX unlink does not invalidate it), while anything attaching
//! afterwards creates a fresh, disconnected segment under the same name.
//! Notify segments therefore carry their own cross-process user table and
//! are released by their last live user; see `notify.rs`. That table reuses
//! the liveness rules below (`owner_is_dead`) for each registered user, not
//! a sidecar file.

use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Sidecar format tag. Bumped whenever a field is added or the meaning of
/// an existing field changes, so an old-format record left by a prior
/// binary is never misread under the new layout: `parse_owner` rejects
/// anything whose first field is not exactly this.
const OWNER_RECORD_VERSION: &str = "v3";

/// `/proc/sys/kernel/random/boot_id`, cached for the process lifetime.
///
/// A PID is only meaningful within one boot: the kernel resets the PID
/// space at every boot, so a bare PID comparison across a reboot (if
/// `/dev/shm` ever survived one, which tmpfs normally does not) would
/// compare against an unrelated process that was later handed the same
/// number. Reading this once and caching it is cheap and it never changes
/// while this process runs.
pub(super) fn current_boot_id() -> &'static str {
    static BOOT_ID: OnceLock<String> = OnceLock::new();
    BOOT_ID.get_or_init(|| {
        std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .map(|s| s.trim().to_string())
            .unwrap_or_default()
    })
}

/// This process's own start time, in clock ticks since boot (field 22 of
/// `/proc/self/stat`), cached once.
///
/// PID alone is not enough to tell "my creator is still running" from "a
/// different process was handed my creator's old PID after it exited": PIDs
/// are reused within a boot, sometimes quickly on a busy box. The start
/// time pins down WHICH process held that PID, closing the reuse window a
/// boot-id-only check leaves open.
fn self_start_time() -> &'static str {
    static START: OnceLock<String> = OnceLock::new();
    START.get_or_init(|| read_start_time(std::process::id()).unwrap_or_default())
}

/// This process's PID namespace identity, as the inode number of
/// `/proc/self/ns/pid`, cached for the process lifetime.
///
/// `kill(pid, 0)` and `/proc/<pid>` are both relative to the CALLER's PID
/// namespace: a pid is just an integer with no cross-namespace meaning.
/// Two processes in different PID namespaces that happen to share
/// `/dev/shm` (a container bind-mounting the host's, or a host process and
/// a container both mapped into it) can each see a pid number that looks
/// like "no such process" in their own namespace while the real owner,
/// under a DIFFERENT number in ITS namespace, is very much alive. Recording
/// the creator's namespace identity and refusing to probe `kill`/`/proc`
/// across namespaces closes that false-dead reading; see `owner_is_dead`.
///
/// The inode of the `pid` namespace file, not its content, is the
/// namespace's identity (per `namespaces(7)`): two processes in the same
/// namespace always see the same inode number for it, and it is stable for
/// the namespace's whole lifetime, including across this process's own
/// pid changing meaning to nobody.
pub(super) fn current_pid_namespace() -> &'static str {
    use std::os::unix::fs::MetadataExt;
    static PID_NS: OnceLock<String> = OnceLock::new();
    PID_NS.get_or_init(|| {
        std::fs::metadata("/proc/self/ns/pid")
            .map(|m| m.ino().to_string())
            .unwrap_or_default()
    })
}

/// Read process `pid`'s start time (field 22) out of `/proc/<pid>/stat`.
///
/// The comm field (field 2) is parenthesized and may itself contain spaces
/// or parentheses, so the split point is the LAST `)` on the line, per
/// `proc(5)`, rather than naive whitespace splitting.
pub(super) fn read_start_time(pid: u32) -> Option<String> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let close_paren = stat.rfind(')')?;
    let rest = stat.get(close_paren + 1..)?;
    // After the `)`, fields run: state(3) ppid(4) ... starttime(22). Field 3
    // is the first whitespace token of `rest`, so starttime is token index
    // 22 - 3 = 19.
    rest.split_whitespace().nth(19).map(str::to_string)
}

/// Path of the sidecar record for a segment named e.g. `/hdds_d78_w...`.
fn owner_file_path(shm_name: &str) -> PathBuf {
    let base = shm_name.strip_prefix('/').unwrap_or(shm_name);
    Path::new("/dev/shm").join(format!("{base}.owner"))
}

/// Write `content` to `final_path` so that no reader ever observes a
/// partial write: create a uniquely-named temp file in the SAME directory
/// (so the final `rename` is on one filesystem and atomic), write the
/// whole payload, then rename it over `final_path`. A reader either sees
/// the old sidecar (rename not yet visible) or the complete new one,
/// never a prefix.
///
/// The temp file is created with `O_CREAT|O_EXCL` (via `create_new`) and
/// `O_NOFOLLOW`, mode 0600: a name under `/dev/shm`, a world-writable
/// directory, that this process did not create yet must never be a symlink
/// this process is tricked into writing through, and a dangling or
/// pre-existing name at that exact temp path must fail open rather than be
/// reused.
fn write_sidecar_atomically(final_path: &Path, content: &str) -> io::Result<()> {
    let dir = final_path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "sidecar path has no parent dir",
        )
    })?;
    let file_name = final_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("owner");
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp_path = dir.join(format!(".{file_name}.{}.{nanos}.tmp", std::process::id()));

    let write_result = (|| -> io::Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true) // O_CREAT | O_EXCL: never follows, never reuses
            .custom_flags(libc::O_NOFOLLOW)
            .mode(0o600)
            .open(&tmp_path)?;
        file.write_all(content.as_bytes())?;
        // No fsync: /dev/shm is tmpfs, nothing to flush to a durable medium,
        // and the atomicity this function provides comes from `rename`, not
        // from durability across a power loss that tmpfs never survives
        // anyway.
        std::fs::rename(&tmp_path, final_path)
    })();

    if write_result.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }
    write_result
}

/// Record this process as the owner of ring segment `shm_name`.
///
/// Best-effort: a failure here only means a crash of this process will not
/// be reclaimed automatically later (the segment behaves exactly as it
/// always has). It never blocks segment creation, which has already
/// succeeded by the time this is called.
pub(crate) fn record_owner(shm_name: &str) {
    let content = format!(
        "{}:{}:{}:{}:{}",
        OWNER_RECORD_VERSION,
        std::process::id(),
        current_boot_id(),
        current_pid_namespace(),
        self_start_time()
    );
    let _ = write_sidecar_atomically(&owner_file_path(shm_name), &content);
}

/// Remove the sidecar record for `shm_name`, if any.
///
/// Best-effort, mirrors `record_owner`: called from the same places that
/// unlink the segment itself, so a graceful shutdown leaves neither behind.
pub(crate) fn remove_owner_record(shm_name: &str) {
    let _ = std::fs::remove_file(owner_file_path(shm_name));
}

/// Parsed contents of an owner sidecar file.
pub(super) struct Owner {
    pub(super) pid: u32,
    pub(super) boot_id: String,
    pub(super) pid_ns: String,
    pub(super) start_time: String,
}

/// Whether `s` is a syntactically well-formed `boot_id`: exactly the
/// canonical UUID shape `/proc/sys/kernel/random/boot_id` prints (36
/// characters, hyphens at 8/13/18/23, hex digits everywhere else).
///
/// This is the check that closes the truncation bug: a prefix of a real
/// boot_id (what a short write on a full tmpfs, or a kill mid-`write`,
/// leaves behind) is never 36 characters, so it fails this check and the
/// whole record is rejected as unparseable -- never compared against
/// `current_boot_id()` at all, let alone found "different" by an
/// accidental string mismatch.
fn is_well_formed_boot_id(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, &c)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                c == b'-'
            } else {
                c.is_ascii_hexdigit()
            }
        })
}

/// Parse a sidecar record. Strict by design: this governs whether a
/// segment gets deleted out from under a possibly-live owner, so ANY
/// field that is missing, malformed, or trails extra unexpected data
/// makes the whole record unparseable -- `None`, "unknown", never
/// reclaimed -- rather than defaulting a missing or truncated field to
/// empty or to a leftover substring.
fn parse_owner(content: &str) -> Option<Owner> {
    let mut parts = content.split(':');
    let version = parts.next()?;
    if version != OWNER_RECORD_VERSION {
        return None;
    }
    let pid_str = parts.next()?;
    let boot_id = parts.next()?;
    let pid_ns = parts.next()?;
    let start_time = parts.next()?;
    if parts.next().is_some() {
        return None; // trailing garbage: the write was corrupt, not just short
    }

    let pid: u32 = pid_str.parse().ok()?;
    if pid == 0 {
        return None; // pid 0 is never a real process; a corrupt/empty field
    }
    if !is_well_formed_boot_id(boot_id) {
        return None;
    }
    if pid_ns.is_empty() || !pid_ns.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    if start_time.is_empty() || !start_time.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }

    Some(Owner {
        pid,
        boot_id: boot_id.to_string(),
        pid_ns: pid_ns.to_string(),
        start_time: start_time.to_string(),
    })
}

/// Whether `owner` names a process that can no longer be the one that
/// created the segment: either a different boot entirely (its whole PID
/// space is gone), or `kill(pid, 0)` says no such process, or the PID is
/// alive but its start time no longer matches (the PID was reused by an
/// unrelated process after the real owner exited).
///
/// Anything that cannot be verified (unreadable `/proc` entry, unparseable
/// record, a different PID namespace) must NOT be read as dead: this
/// governs whether a segment gets deleted out from under a possibly-live
/// owner, so the default on doubt is "leave it alone".
///
/// # Deployment caveat: PID namespaces
///
/// `kill(pid, 0)` and `/proc/<pid>` are resolved in THIS process's PID
/// namespace. If the recorded owner was created in a different PID
/// namespace that happens to share this `/dev/shm` (a container bind
/// mount, or a host process reusing a container's namespace), `owner.pid`
/// names a different process here -- or none -- and probing it would be
/// answering the wrong question. Such a sidecar is left alone forever by
/// this reclamation (never reclaimed, same as an unparseable one): the
/// process that recorded it, in its own namespace at its next startup,
/// will still reclaim it normally. A deployment that shares `/dev/shm`
/// across PID namespaces and wants reclamation across that boundary too
/// is out of scope here; it needs its reclaimer to run in a namespace that
/// can see both pid spaces.
pub(super) fn owner_is_dead(owner: &Owner) -> bool {
    if owner.boot_id != current_boot_id() {
        // Provable, not heuristic: no process from a previous boot can
        // exist in this one, regardless of what its PID now names.
        return true;
    }

    if owner.pid_ns != current_pid_namespace() {
        // See the caveat above: a pid number from another PID namespace
        // is not ours to probe. Not provable either way -- leave it alone.
        return false;
    }

    let Ok(pid) = i32::try_from(owner.pid) else {
        return false; // cannot even express the pid; do not guess
    };
    // SAFETY: signal 0 sends nothing; it only asks whether `pid` exists and
    // is signalable by us, via a plain libc wrapper with no preconditions
    // beyond a valid pid value, which the try_from above guarantees.
    let probe = unsafe { libc::kill(pid, 0) };
    if probe != 0 {
        let err = io::Error::last_os_error();
        // ESRCH: no such process -> dead. Anything else (notably EPERM: the
        // pid exists but belongs to another user) must NOT be read as dead
        // -- "never touch segments of live processes or other users".
        return err.raw_os_error() == Some(libc::ESRCH);
    }
    // The pid exists. If we recorded a start time and can still read one for
    // this pid, a mismatch means a different process now holds that number.
    // @audit-ok: not a swallowed error -- the pid already proved alive
    // (the `kill` probe above returned 0). This arm only covers "cannot
    // tell whether it is the SAME alive process" (no start time recorded,
    // or `/proc/<pid>/stat` unreadable in this instant), and the function's
    // contract is to never report dead on doubt, so `false` (not dead) is
    // the documented, deliberate answer, not a dropped result.
    match read_start_time(owner.pid) {
        Some(now) if !owner.start_time.is_empty() => now != owner.start_time,
        _ => false,
    }
}

/// Reclaim ring segments (`/hdds_d<domain_id>_w*`) whose recorded owner is
/// provably dead, and sweep up orphaned sidecar records left behind by an
/// earlier, incomplete reclamation.
///
/// Scoped to ring segments only -- see the module doc for why notify
/// segments are not touched here. A segment with no readable sidecar record
/// (created before this reclamation existed, or whose write raced a crash)
/// is left alone: with nothing to verify, nothing is reclaimed, by the same
/// "never touch what cannot be proven dead" rule that governs the checked
/// case.
///
/// Meant to run once, early, at participant startup for that participant's
/// own domain: one `/dev/shm` directory scan, safe to call redundantly
/// (idempotent -- nothing is left to reclaim on a second call).
///
/// # Orphaned sidecars
///
/// A SIGKILL landing between `ShmSegment::unlink`'s `shm_unlink` call and
/// its `remove_owner_record` call (both inside the same function, but not
/// atomic as a pair) leaves a `.owner` file with no segment behind it
/// forever: the main loop below only ever looks at names that pass the
/// segment prefix filter, so an orphaned `.owner` file was never visited
/// at all. A second pass below removes exactly that: a sidecar whose
/// segment no longer exists AND whose recorded owner is provably dead by
/// the same rules as the main pass -- never one whose segment still
/// exists (that sidecar is live bookkeeping, not an orphan) and never one
/// whose owner cannot be verified dead (the segment's absence alone is not
/// proof the recorded owner is gone; it only proves the SEGMENT is gone).
///
/// # Returns
/// Number of segments reclaimed (orphaned sidecars removed in the second
/// pass are not counted: no segment is deleted by them).
pub fn reclaim_dead_ring_segments(domain_id: u32) -> usize {
    let shm_dir = Path::new("/dev/shm");
    let prefix = format!("hdds_d{domain_id}_w");
    let mut reclaimed = 0;

    // ONE readdir for both passes below: this runs at every participant's
    // build() for its domain (see bootstrap.rs), so it is on a hot path
    // shared by every test and every production participant on this
    // domain, not just this module's own tests. A second directory scan
    // here would double that cost for every caller; a second linear pass
    // over an already-in-memory Vec of names does not.
    let Ok(entries) = std::fs::read_dir(shm_dir) else {
        return 0;
    };
    let names: Vec<String> = entries
        .flatten()
        .filter_map(|e| e.file_name().to_str().map(str::to_string))
        .collect();

    for name in &names {
        if !name.starts_with(&prefix) || name.ends_with(".owner") {
            continue;
        }

        let segment_name = format!("/{name}");
        let owner_path = owner_file_path(&segment_name);
        let Ok(content) = std::fs::read_to_string(&owner_path) else {
            continue; // no record to verify against: leave it alone
        };
        let Some(owner) = parse_owner(&content) else {
            continue;
        };
        if !owner_is_dead(&owner) {
            continue;
        }

        if super::segment::ShmSegment::unlink(&segment_name).is_ok() {
            log::debug!(
                "[SHM] reclaimed ring segment {} from dead owner pid {}",
                segment_name,
                owner.pid
            );
            reclaimed += 1;
        }
        let _ = std::fs::remove_file(&owner_path);
    }

    // Second pass, same cached listing (no second readdir): orphaned
    // sidecars for segments that are ALREADY gone (from an earlier run's
    // partial cleanup, or from the pass above). Segment existence is
    // checked FRESH here (a live syscall, not the stale `names` snapshot
    // above): the unlinks in the first pass, and any concurrent caller
    // entirely outside this function, can have changed what is actually
    // on disk since `names` was captured, and this check is exactly what
    // decides whether a sidecar gets deleted -- it must see the current
    // truth, not a snapshot.
    for name in &names {
        let Some(base) = name.strip_suffix(".owner") else {
            continue;
        };
        if !base.starts_with(&prefix) {
            continue;
        }

        let segment_name = format!("/{base}");
        if super::segment::ShmSegment::exists(&segment_name) {
            continue; // the segment is live: this sidecar is not an orphan
        }
        // Mutation-testing note: a mutant that deletes this `exists` guard
        // survives this module's whole test suite. That is not an
        // oversight -- it is structural. The first pass above ALWAYS
        // removes a dead owner's sidecar itself, unconditionally,
        // regardless of whether its `unlink` succeeded (see
        // `std::fs::remove_file(&owner_path)` right after it, outside the
        // `if ... .is_ok()`), so within a single call to this function a
        // segment that still exists can never reach this line with a
        // sidecar recording a dead owner: the first pass already took it.
        // The ONLY way to reach "segment exists, sidecar here, owner
        // dead" is a genuinely concurrent OTHER process creating or
        // recreating that exact segment between this function's readdir
        // and this check -- real OS-level concurrency a single-process
        // unit test cannot construct deterministically. The guard is kept
        // anyway, as defense-in-depth against exactly that external race
        // (and against a future change to the first pass that no longer
        // removes the sidecar unconditionally).

        let owner_path = shm_dir.join(name);
        let Ok(content) = std::fs::read_to_string(&owner_path) else {
            continue;
        };
        let Some(owner) = parse_owner(&content) else {
            continue; // cannot verify: leave it, same rule as the main pass
        };
        if !owner_is_dead(&owner) {
            continue; // the segment is gone, but its RECORDED owner is not
        }

        log::debug!(
            "[SHM] removed orphaned owner sidecar {} (segment already gone, owner pid {} dead)",
            owner_path.display(),
            owner.pid
        );
        let _ = std::fs::remove_file(&owner_path);
    }

    reclaimed
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Child, Command};
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    /// `reclaim_dead_ring_segments(0)` scans ALL `hdds_d0_w*` names in
    /// `/dev/shm`, not just the caller's own: every test below that calls
    /// it shares that one scan with whatever else is live on domain 0 at
    /// that instant, by design (see the test comments). cargo runs these
    /// tests on separate threads by default, so two of them calling it at
    /// the same moment can race -- one thread's call reclaiming the other
    /// thread's segment first, leaving the second thread's own local
    /// return value wrong even though the end state (segment and sidecar
    /// both gone) is exactly what both tests want. Serializing every test
    /// that calls `reclaim_dead_ring_segments` removes that race without
    /// weakening any assertion.
    fn serialize_reclaim_tests() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: Mutex<()> = Mutex::new(());
        LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn unique_name(tag: &str) -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        // Domain 0 on purpose: `reclaim_dead_ring_segments` keys on
        // `hdds_d<domain>_w`, and these tests want to hit exactly that
        // prefix match, not invent a parallel naming scheme.
        format!("/hdds_d0_w{tag}{ts}")
    }

    /// A spawned child plus the file its stderr was redirected to, so a
    /// test that never sees the child's sidecar appear can report WHY
    /// (e.g. a panic from `ShmRingWriter::create` failing) instead of just
    /// "it never showed up" -- the single biggest cost of the flaky
    /// timeout this guards against was not having this.
    struct SpawnedChild {
        child: Child,
        stderr_path: PathBuf,
    }

    /// Spawn this very test binary again, running exactly one other test by
    /// exact name, with an env var telling it which segment to create and
    /// then park on. This is the multi-process half of the reclamation
    /// tests below: a REAL separate process, not an in-process fork (which
    /// would risk the classic fork-after-threads hazards in a multithreaded
    /// `cargo test` run), created the same way `examples/shm_multiprocess.rs`
    /// already demonstrates for this crate.
    fn spawn_child_holding(segment_name: &str) -> SpawnedChild {
        let exe = std::env::current_exe().expect("current test binary");
        let stderr_path = std::env::temp_dir().join(format!(
            "hdds_owner_test_child_stderr.{}.{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let stderr_file =
            std::fs::File::create(&stderr_path).expect("create child stderr capture file");
        let child = Command::new(exe)
            .arg("--exact")
            .arg("transport::shm::owner::tests::child_park_holding_segment")
            .env("HDDS_OWNER_TEST_CHILD_SEGMENT", segment_name)
            .stderr(stderr_file)
            .spawn()
            .expect("spawn child");
        SpawnedChild { child, stderr_path }
    }

    /// Read back whatever the child wrote to stderr (a panic message, most
    /// likely), for inclusion in a failure message. Best-effort: this is
    /// diagnostic text, not a correctness check, so a read failure is
    /// reported as text too rather than panicking the reporting path
    /// itself.
    fn child_stderr_summary(stderr_path: &Path) -> String {
        match std::fs::read_to_string(stderr_path) {
            Ok(s) if s.trim().is_empty() => "<child produced no stderr output>".to_string(),
            Ok(s) => s,
            Err(e) => format!("<could not read child stderr capture: {e}>"),
        }
    }

    /// SIGKILLs a spawned child on drop unless disarmed first.
    ///
    /// Without this, a test that spawns a parked child (via
    /// `spawn_child_holding`) and then panics on an assertion BEFORE its
    /// own manual kill/reap -- e.g. `wait_for_owner_file` timing out
    /// under a loaded machine running the full suite in parallel -- leaks
    /// that child forever. A leaked child inherits this process's open
    /// file descriptors (for example a build lock), and keeps holding them
    /// long after the test binary itself has exited.
    ///
    /// Call `disarm()` once the test's own normal cleanup has already
    /// killed and reaped the child, so this guard's drop does not send a
    /// redundant signal to a pid number that may since have been reused
    /// by an unrelated process.
    struct KillOnDrop(Option<u32>);

    impl KillOnDrop {
        fn new(pid: u32) -> Self {
            Self(Some(pid))
        }

        fn disarm(&mut self) {
            self.0 = None;
        }
    }

    impl Drop for KillOnDrop {
        fn drop(&mut self) {
            if let Some(pid) = self.0.take() {
                // SAFETY: pid was this guard's own spawned child's pid at
                // construction and has not been reaped by anything else
                // yet (disarm() is only called after an explicit
                // kill+wait elsewhere); SIGKILL is a valid signal.
                // Best-effort: if it already exited for some other
                // reason, this is a harmless ESRCH.
                unsafe {
                    libc::kill(pid as i32, libc::SIGKILL);
                }
            }
        }
    }

    /// Not a test to be run directly: when `HDDS_OWNER_TEST_CHILD_SEGMENT`
    /// is unset (every normal run of the suite), this is a no-op. When the
    /// parent tests above spawn this binary filtered to exactly this test
    /// name with that env var set, it creates the named ring segment (which
    /// records this process as owner via `record_owner`, the same path a
    /// real `ShmRingWriter::create` takes) and then parks, so it stays the
    /// live owner until the parent kills it.
    #[test]
    fn child_park_holding_segment() {
        let Ok(name) = std::env::var("HDDS_OWNER_TEST_CHILD_SEGMENT") else {
            return;
        };
        let guid = [0x42u8; 16];
        let _writer =
            crate::transport::shm::ShmRingWriter::create(&name, 4, &guid).expect("child create");
        loop {
            std::thread::sleep(Duration::from_secs(5));
        }
    }

    fn wait_for_owner_file(segment_name: &str, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if owner_file_path(segment_name).exists() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        false
    }

    /// The end-to-end case: a writer process is
    /// killed (`SIGKILL`, no `Drop` runs), and the next participant start
    /// on that domain reclaims the segment it left behind.
    #[test]
    fn a_dead_owners_segment_is_reclaimed() {
        let _guard = serialize_reclaim_tests();
        let name = unique_name("dead");
        let SpawnedChild {
            mut child,
            stderr_path,
        } = spawn_child_holding(&name);
        let mut kill_guard = KillOnDrop::new(child.id());

        assert!(
            wait_for_owner_file(&name, Duration::from_secs(20)),
            "child never recorded itself as owner of {name}; child stderr:\n{}",
            child_stderr_summary(&stderr_path)
        );
        assert!(
            crate::transport::shm::ShmSegment::exists(&name),
            "child never created {name}"
        );

        let pid = i32::try_from(child.id()).expect("pid fits i32");
        // SAFETY: `pid` is this child's own pid, obtained from `Child::id()`
        // right above; SIGKILL is a valid signal number.
        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
        // Reap it: an un-waited child is a zombie, and `kill(pid, 0)` still
        // reports a zombie as existing, which would make the dead-owner
        // check below see a live pid and refuse to reclaim.
        child.wait().expect("reap child");
        kill_guard.disarm();

        let reclaimed = reclaim_dead_ring_segments(0);
        assert!(
            reclaimed >= 1,
            "expected the dead owner's segment to be counted as reclaimed, got {reclaimed}"
        );
        assert!(
            !crate::transport::shm::ShmSegment::exists(&name),
            "the dead owner's segment must be gone after reclamation"
        );
        assert!(
            !owner_file_path(&name).exists(),
            "the sidecar record must be removed along with the segment"
        );
        let _ = std::fs::remove_file(&stderr_path);
    }

    /// The safety half: a segment whose owner is still alive must never be
    /// touched, even while sitting right next to one that was just
    /// reclaimed in the same scan.
    #[test]
    fn a_live_owners_segment_is_left_alone() {
        let _guard = serialize_reclaim_tests();
        let name = unique_name("live");
        let SpawnedChild {
            mut child,
            stderr_path,
        } = spawn_child_holding(&name);
        let mut kill_guard = KillOnDrop::new(child.id());

        assert!(
            wait_for_owner_file(&name, Duration::from_secs(20)),
            "child never recorded itself as owner of {name}; child stderr:\n{}",
            child_stderr_summary(&stderr_path)
        );

        let reclaimed = reclaim_dead_ring_segments(0);
        assert_eq!(
            reclaimed, 0,
            "a live owner's segment must not be reclaimed by this call \
             (it may share the scan with dead ones from other tests, but \
             none of them should be this one)"
        );
        assert!(
            crate::transport::shm::ShmSegment::exists(&name),
            "the live owner's segment must still be present"
        );

        // Clean up: kill it, reap it, and let reclamation take it rather
        // than unlinking it ourselves, which doubles as one more assertion
        // that the normal path still works after the negative check above.
        let pid = i32::try_from(child.id()).expect("pid fits i32");
        // SAFETY: same as above -- `pid` is this child's own pid, SIGKILL
        // is a valid signal.
        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
        child.wait().expect("reap child");
        kill_guard.disarm();
        reclaim_dead_ring_segments(0);
        assert!(!crate::transport::shm::ShmSegment::exists(&name));
        let _ = std::fs::remove_file(&stderr_path);
    }

    /// `shm_unlink` without going through `ShmSegment::unlink` -- the raw
    /// syscall only, bypassing `remove_owner_record` -- to reproduce
    /// exactly what a SIGKILL between the two calls inside
    /// `ShmSegment::unlink` leaves behind: a segment that is gone and a
    /// sidecar that is not.
    fn raw_unlink_segment_only(name: &str) {
        let c_name = std::ffi::CString::new(name).expect("valid name");
        // SAFETY: c_name is a valid NUL-terminated C string; shm_unlink is
        // safe to call on a name that may or may not exist (this test
        // only calls it on a name it just confirmed exists).
        unsafe {
            libc::shm_unlink(c_name.as_ptr());
        }
    }

    /// LOW fix: a sidecar orphaned by a SIGKILL landing between
    /// `shm_unlink` and sidecar removal (never cleaned up before this
    /// fix, since the main scan only ever looks at segment names, never
    /// bare `.owner` names) is swept up on the next reclaim pass, once
    /// its recorded owner is provably dead.
    #[test]
    fn an_orphaned_sidecar_for_a_dead_owner_is_removed() {
        let _guard = serialize_reclaim_tests();
        let name = unique_name("orphandead");
        let SpawnedChild {
            mut child,
            stderr_path,
        } = spawn_child_holding(&name);
        let mut kill_guard = KillOnDrop::new(child.id());
        assert!(
            wait_for_owner_file(&name, Duration::from_secs(20)),
            "child never recorded itself as owner of {name}; child stderr:\n{}",
            child_stderr_summary(&stderr_path)
        );

        let pid = i32::try_from(child.id()).expect("pid fits i32");
        // SAFETY: pid is this child's own pid, SIGKILL is a valid signal.
        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
        child.wait().expect("reap child");
        kill_guard.disarm();

        // Orphan the sidecar: remove the segment WITHOUT removing the
        // record that names its (now dead) owner. No assertion in between
        // that the sidecar is still here: other tests in this file share
        // domain 0 and run concurrently, so a parallel reclaim call racing
        // this exact window is itself a legitimate way for the sidecar to
        // already be gone by the time this thread looks -- which is this
        // fix working, not a bug, and the final assertion below holds
        // either way.
        raw_unlink_segment_only(&name);
        assert!(!crate::transport::shm::ShmSegment::exists(&name));

        reclaim_dead_ring_segments(0);

        assert!(
            !owner_file_path(&name).exists(),
            "an orphaned sidecar whose recorded owner is dead must be swept up"
        );
        let _ = std::fs::remove_file(&stderr_path);
    }

    /// Safety half of the orphan sweep: a sidecar whose segment is gone
    /// but whose recorded owner is STILL ALIVE must never be touched --
    /// the segment's absence alone is not proof the owner died, and the
    /// owner may be about to recreate the same name.
    #[test]
    fn an_orphaned_sidecar_for_a_live_owner_is_left_alone() {
        let _guard = serialize_reclaim_tests();
        let name = unique_name("orphanlive");
        let SpawnedChild {
            mut child,
            stderr_path,
        } = spawn_child_holding(&name);
        let mut kill_guard = KillOnDrop::new(child.id());
        assert!(
            wait_for_owner_file(&name, Duration::from_secs(20)),
            "child never recorded itself as owner of {name}; child stderr:\n{}",
            child_stderr_summary(&stderr_path)
        );

        // Orphan the sidecar while the child (the recorded owner) is
        // still running.
        raw_unlink_segment_only(&name);
        assert!(!crate::transport::shm::ShmSegment::exists(&name));
        assert!(owner_file_path(&name).exists());

        reclaim_dead_ring_segments(0);

        assert!(
            owner_file_path(&name).exists(),
            "a sidecar naming a still-live owner must never be removed, \
             even once its segment is gone"
        );

        let pid = i32::try_from(child.id()).expect("pid fits i32");
        // SAFETY: pid is this child's own pid, SIGKILL is a valid signal.
        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
        child.wait().expect("reap child");
        kill_guard.disarm();
        let _ = std::fs::remove_file(owner_file_path(&name));
        let _ = std::fs::remove_file(&stderr_path);
    }

    #[test]
    fn owner_file_round_trips_pid_and_boot_id() {
        let name = unique_name("roundtrip");
        record_owner(&name);
        let content = std::fs::read_to_string(owner_file_path(&name)).expect("owner file");
        let owner = parse_owner(&content).expect("parse");
        assert_eq!(owner.pid, std::process::id());
        assert_eq!(owner.boot_id, current_boot_id());
        assert_eq!(owner.pid_ns, current_pid_namespace());
        assert!(!owner_is_dead(&owner), "this very process is alive");
        remove_owner_record(&name);
        assert!(!owner_file_path(&name).exists());
    }

    /// HIGH + MEDIUM fix, direct pin on `parse_owner` itself (no child
    /// process needed): every field it validates, exercised one defect at
    /// a time against a real, well-formed record as the baseline, so
    /// each assertion pins exactly one rejection rule rather than relying
    /// only on the end-to-end reclaim tests to notice a regression here.
    #[test]
    fn parse_owner_rejects_every_malformed_field() {
        let real_boot = current_boot_id();
        let good = format!("{OWNER_RECORD_VERSION}:4242:{real_boot}:99:123456");
        assert!(
            parse_owner(&good).is_some(),
            "the baseline record itself must parse"
        );

        assert!(
            parse_owner(&format!("v1:4242:{real_boot}:99:123456")).is_none(),
            "a record from an old/different format version must never be read \
             under the current field layout"
        );
        assert!(
            parse_owner(&format!("{OWNER_RECORD_VERSION}:0:{real_boot}:99:123456")).is_none(),
            "pid 0 is never a real process"
        );
        assert!(
            parse_owner(&format!(
                "{OWNER_RECORD_VERSION}:notanumber:{real_boot}:99:123456"
            ))
            .is_none(),
            "a non-numeric pid is corrupt, not pid 0 and not a valid pid"
        );
        assert!(
            parse_owner(&format!(
                "{OWNER_RECORD_VERSION}:4242:{}:99:123456",
                &real_boot[..real_boot.len() / 2]
            ))
            .is_none(),
            "a boot_id shorter than the canonical 36 chars (a truncated write) \
             must never parse"
        );
        assert!(
            parse_owner(&format!(
                "{OWNER_RECORD_VERSION}:4242:{real_boot}X:99:123456"
            ))
            .is_none(),
            "a boot_id with one extra trailing character must never parse either"
        );
        assert!(
            parse_owner(&format!(
                "{OWNER_RECORD_VERSION}:4242:{real_boot}:notanumber:123456"
            ))
            .is_none(),
            "a non-numeric PID namespace field is corrupt"
        );
        assert!(
            parse_owner(&format!("{OWNER_RECORD_VERSION}:4242:{real_boot}::123456")).is_none(),
            "an empty PID namespace field is corrupt"
        );
        assert!(
            parse_owner(&format!(
                "{OWNER_RECORD_VERSION}:4242:{real_boot}:99:notanumber"
            ))
            .is_none(),
            "a non-numeric start_time field is corrupt"
        );
        assert!(
            parse_owner(&format!(
                "{OWNER_RECORD_VERSION}:4242:{real_boot}:99:123456:extra"
            ))
            .is_none(),
            "trailing data after the last field must never be silently ignored"
        );
        assert!(
            parse_owner(&format!("{OWNER_RECORD_VERSION}:4242:{real_boot}:99")).is_none(),
            "a missing trailing field must never default to empty"
        );
    }

    /// Rule 4 (O_EXCL/O_NOFOLLOW, mode 0600): the sidecar this process
    /// writes is a regular file, not world- or group-readable, and
    /// writing it REPLACES a symlink a different, lower-privileged owner
    /// of this world-writable directory may have pre-planted at that
    /// exact name -- never written through it.
    #[test]
    fn record_owner_replaces_a_preplanted_symlink_without_following_it() {
        let name = unique_name("symlink");
        let path = owner_file_path(&name);
        let decoy_target = std::env::temp_dir().join(format!("hdds-owner-decoy-{}", name.len()));
        let _ = std::fs::remove_file(&decoy_target);
        std::os::unix::fs::symlink(&decoy_target, &path).expect("plant decoy symlink");

        record_owner(&name);

        let meta = std::fs::symlink_metadata(&path).expect("sidecar path exists");
        assert!(
            meta.file_type().is_file(),
            "record_owner must replace a pre-planted symlink with a real file, \
             never write through it to the symlink's target"
        );
        assert!(
            !decoy_target.exists(),
            "the symlink's target must never have been written to"
        );

        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "the sidecar must be created with mode 0600, got {mode:o}"
        );

        remove_owner_record(&name);
    }

    /// Same rule, the non-adversarial path: an ordinary fresh sidecar
    /// (the overwhelmingly common case -- no planted symlink) still gets
    /// mode 0600, not whatever the process umask would otherwise allow.
    #[test]
    fn a_fresh_sidecar_has_mode_0600() {
        let name = unique_name("freshmode");
        record_owner(&name);
        let meta = std::fs::metadata(owner_file_path(&name)).expect("sidecar exists");
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "got {mode:o}");
        remove_owner_record(&name);
    }

    /// MEDIUM fix: a pid number is only meaningful within its own PID
    /// namespace. A record from a different namespace must be left alone
    /// even when its (meaningless-to-us) pid number happens to look dead
    /// -- never probed, never reclaimed by this process.
    #[test]
    fn a_record_from_a_different_pid_namespace_is_never_reclaimed() {
        // A genuinely dead pid: spawn a trivial child, wait for it to
        // exit, and reap it, so kill(pid, 0) on it is guaranteed ESRCH --
        // if the pid_ns gate did not stop `owner_is_dead` before that
        // probe, it WOULD read this record as dead. start_time is a
        // plausible non-empty number too, so the only thing standing
        // between this record and a wrongly-"dead" verdict is the
        // pid_ns check itself.
        let mut child = Command::new("true").spawn().expect("spawn trivial child");
        let pid = child.id();
        child.wait().expect("reap trivial child");

        let owner = Owner {
            pid,
            boot_id: current_boot_id().to_string(),
            pid_ns: "not-our-pid-namespace".to_string(),
            start_time: "123456".to_string(),
        };
        assert!(
            !owner_is_dead(&owner),
            "a record from a different PID namespace must never be read as dead, \
             even when its (meaningless-to-us) pid number would otherwise probe \
             as ESRCH: its pid number is not ours to probe with kill(pid, 0)"
        );
    }

    #[test]
    fn a_record_from_a_different_boot_is_dead() {
        let owner = Owner {
            pid: std::process::id(),
            boot_id: "not-this-boot".to_string(),
            pid_ns: current_pid_namespace().to_string(),
            start_time: self_start_time().to_string(),
        };
        assert!(
            owner_is_dead(&owner),
            "a different boot id must be provably dead regardless of the pid"
        );
    }

    /// A sidecar truncated mid
    /// `boot_id` field (a short write on a full tmpfs, or this process
    /// killed mid-`record_owner`) still parses, and the truncated prefix
    /// never equals `current_boot_id()`, so `owner_is_dead` returns true
    /// without ever reaching the `kill(pid, 0)` probe -- reclaiming a live
    /// owner's segment.
    #[test]
    fn a_truncated_boot_id_in_the_sidecar_falsely_reclaims_a_live_owner() {
        let _guard = serialize_reclaim_tests();
        let name = unique_name("truncboot");
        let SpawnedChild {
            mut child,
            stderr_path,
        } = spawn_child_holding(&name);
        let mut kill_guard = KillOnDrop::new(child.id());

        assert!(
            wait_for_owner_file(&name, Duration::from_secs(20)),
            "child never recorded itself as owner of {name}; child stderr:\n{}",
            child_stderr_summary(&stderr_path)
        );
        assert!(crate::transport::shm::ShmSegment::exists(&name));

        // Simulate a short write (ENOSPC on a full /dev/shm, or this
        // process observed mid-write): same pid, boot id truncated to a
        // prefix (no trailing ':', so start_time is also lost), which is
        // exactly what a write() interrupted partway through the boot_id
        // field leaves on disk.
        let path = owner_file_path(&name);
        let real_content = std::fs::read_to_string(&path).expect("owner file");
        let real = parse_owner(&real_content).expect("own record parses");
        let truncated = format!("{}:{}", real.pid, &real.boot_id[..real.boot_id.len() / 2]);
        std::fs::write(&path, &truncated).expect("simulate short write");

        let reclaimed = reclaim_dead_ring_segments(0);

        // Clean up the child regardless of the outcome, before asserting,
        // so a failing assert! does not leak the process.
        let pid = i32::try_from(child.id()).expect("pid fits i32");
        let still_exists = crate::transport::shm::ShmSegment::exists(&name);
        if !still_exists {
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
            let _ = child.wait();
        } else {
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
            let _ = child.wait();
            let _ = crate::transport::shm::ShmSegment::unlink(&name);
        }
        kill_guard.disarm();

        assert_eq!(
            reclaimed, 0,
            "a live owner's segment was reclaimed solely because its sidecar \
             was truncated mid boot_id field -- owner_is_dead's boot-id \
             string-inequality check returned true on a truncated PREFIX \
             without ever probing kill(pid, 0), even though pid {pid} was \
             alive, same boot, at the moment of the scan"
        );
        assert!(
            still_exists,
            "the live owner's segment {name} must still exist after reclaim; \
             it was deleted based on a corrupted sidecar alone"
        );
        let _ = std::fs::remove_file(&stderr_path);
    }

    #[test]
    fn a_pid_reused_after_the_owner_exited_is_dead() {
        // This process's own pid, same boot, but a start time that cannot
        // match: the real owner (this process) is alive, but anything that
        // reused this pid after the recorded owner exited would look like
        // this to a later reclaim pass.
        let owner = Owner {
            pid: std::process::id(),
            boot_id: current_boot_id().to_string(),
            pid_ns: current_pid_namespace().to_string(),
            start_time: "0".to_string(),
        };
        assert!(
            owner_is_dead(&owner),
            "a start-time mismatch on a live pid means the recorded owner is gone, \
             even though the pid number itself is in use"
        );
    }
}
