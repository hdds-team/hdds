// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Logging Plugin for DDS Security v1.1
//!
//! Provides audit trail for security events per DDS Security spec Sec.8.6.
//!
//! # Record format
//!
//! One record per line:
//!
//! ```text
//! <event> prev=<64 hex> hash=<64 hex> seq=<n>
//! ```
//!
//! `<event>` is the `Debug` rendering of [`SecurityEvent`]; `prev` is the hash
//! of the previous line, `seq` is the line ordinal counted from the first line
//! of the file, and `hash` is `SHA-256(prev || seq || <event>)`.
//!
//! The chain is CONTINUOUS over the whole file. Every open appends an
//! `AuditChainStart { .. }` marker so a restarted participant is visible as a
//! boundary, but that marker chains onto the last line already in the file
//! (its `prev` is that line's `hash`, its `seq` the next ordinal), so removing
//! a whole run, or the tail of an earlier run, breaks a link. Only the very
//! first line of a file carries `prev` = all zeros and `seq` = 0.
//!
//! [`verify_chain`] walks a file and names the first line that is malformed,
//! out of sequence, or does not chain. What it CANNOT detect, and no in-band
//! scheme can, is the removal of the file's own tail: a prefix of a valid
//! chain is a valid chain. Detecting that needs an anchor outside the file
//! (an offsite copy of the last hash, or a signed rotation), which HDDS does
//! not ship yet.
//!
//! One file per participant. A path already open in this process is refused
//! at build (two chains interleaved into one file verify as tampering); the
//! same file opened by a SECOND PROCESS cannot be detected without a file
//! lock, so that stays a deployment rule.
//!
//! Audit files are created mode 0600 on unix: the records carry peer GUIDs,
//! key ids, topic and partition names.
//!
//! # Failure policy (fail closed)
//!
//! Opening the file is fail-closed at participant build (`SecurityPluginSuite`
//! returns `Error::Config`), and so is a file whose tail cannot be read back
//! (a fragment left by a crash mid-write, or a foreign format). A write that
//! fails at runtime cannot reverse the security decision that produced it --
//! the state transition has already committed -- so instead the chain is
//! marked DEGRADED, once and for the life of the participant. While the chain
//! is degraded the handshake machine refuses to start or advance any
//! handshake, the data-key store refuses to install any new key, and the
//! participant refuses to create any new endpoint: a lost record stops new
//! trust from being established. No audit I/O ever runs under a handshake or
//! key-store lock.
//!
//! # Timestamps
//!
//! Nanoseconds since the Unix epoch for every event family, through
//! [`timestamp_ns`], so one chain never mixes units.

use crate::security::SecurityError;
use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

/// One suite-wide audit chain shared by every security decision point.
pub(crate) type SharedAuditLogger = Arc<AuditChain>;

/// Marker written at every open: the chain crosses a participant restart.
const CHAIN_START_MARKER: &str = "AuditChainStart";

/// Bytes read back from the end of an existing file to recover its last line.
const TAIL_WINDOW: u64 = 64 * 1024;

/// Timestamp used by every production audit emitter: nanoseconds since the
/// Unix epoch, the unit the access-control records have always carried.
pub fn timestamp_ns() -> u64 {
    crate::telemetry::metrics::current_time_ns()
}

/// Every audit-log path currently open in this process.
///
/// Two participants appending to one file interleave two chains into
/// something no verifier can walk, so the second open of a path is refused.
///
/// This registry is process-global on purpose, and it is the one case where
/// that is the correct shape: the invariant it enforces - one hash chain per
/// file - is itself a property of the process, not of any participant. Scoping
/// it to an instance would let two participants in the same process each hold
/// their own empty set and both claim the same path, which is precisely the
/// corruption being prevented.
///
/// @audit-ok: process-wide by design, see above; the alternative cannot
/// enforce the invariant it exists for
static CLAIMED_PATHS: Mutex<BTreeSet<PathBuf>> = Mutex::new(BTreeSet::new());

fn claimed_paths() -> MutexGuard<'static, BTreeSet<PathBuf>> {
    CLAIMED_PATHS.lock().unwrap_or_else(|e| e.into_inner())
}

/// Take an advisory exclusive lock on an already-open audit file.
///
/// The in-process registry above stops two participants in ONE process from
/// sharing a file. It cannot see another process, and two processes appending
/// to one audit log interleave their chains just as thoroughly - the file then
/// contains two valid chains shuffled together, and a verifier walking
/// `previous_hash` links breaks at the first foreign record. The guarantee has
/// to reach across the process boundary or it does not hold at all.
///
/// `flock(LOCK_EX | LOCK_NB)` is the portable-enough answer on unix. The lock
/// belongs to the open file description, so it is released when the `File`
/// closes; `PathClaim` deliberately does not unlock it by hand.
///
/// Returns `Ok(false)` when the filesystem does not support locking at all.
/// That case is not a refusal: NFS mounts and some network filesystems answer
/// ENOLCK or EOPNOTSUPP, and refusing there would make the audit log unusable
/// on exactly the deployments most likely to want one. The in-process claim
/// still applies, and the caller records that the stronger guarantee is
/// absent.
#[cfg(unix)]
fn lock_audit_file(file: &File) -> Result<bool, std::io::Error> {
    use std::os::unix::io::AsRawFd;

    // SAFETY: `file` is an open File for the whole call, so its descriptor is
    // valid; flock takes no pointer and cannot outlive the borrow.
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc == 0 {
        return Ok(true);
    }
    let err = std::io::Error::last_os_error();
    match err.raw_os_error() {
        // Held by another process: this is the case we exist to catch.
        Some(libc::EWOULDBLOCK) => Err(err),
        // The filesystem cannot lock. Not a refusal, see above.
        Some(libc::ENOLCK) | Some(libc::EOPNOTSUPP) | Some(libc::ENOSYS) | Some(libc::EINVAL) => {
            Ok(false)
        }
        _ => Err(err),
    }
}

#[cfg(not(unix))]
fn lock_audit_file(_file: &File) -> Result<bool, std::io::Error> {
    Ok(false)
}

/// Exclusive claim on one audit-log path, released on drop.
///
/// Two layers, because one is not enough: a process-wide registry for
/// participants sharing this process, and an advisory file lock for other
/// processes on the same host. The lock lives on the `File`'s open file
/// description, so it releases when that file closes - this struct only has to
/// undo the registry entry.
#[derive(Debug)]
struct PathClaim {
    path: PathBuf,
}

impl PathClaim {
    fn acquire(path: &Path, file: &File) -> Result<Self, SecurityError> {
        let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        if !claimed_paths().insert(canonical.clone()) {
            return Err(SecurityError::ConfigError(format!(
                "audit log {} is already open in this process: one hash chain per file, \
                 two participants appending to one file cannot be verified",
                canonical.display()
            )));
        }

        let os_locked = match lock_audit_file(file) {
            Ok(locked) => locked,
            Err(e) => {
                // Undo the in-process claim before failing, or the path stays
                // poisoned for the lifetime of the process and a later,
                // legitimate open is refused for a reason nobody can find.
                claimed_paths().remove(&canonical);
                return Err(SecurityError::ConfigError(format!(
                    "audit log {} is locked by another process: one hash chain per file, \
                     two processes appending to one file cannot be verified ({})",
                    canonical.display(),
                    e
                )));
            }
        };

        if !os_locked {
            log::warn!(
                "[audit] {} could not be locked against other processes \
                 (filesystem does not support advisory locks); the one-chain-per-file \
                 guarantee holds within this process only",
                canonical.display()
            );
        }

        Ok(Self { path: canonical })
    }
}

impl Drop for PathClaim {
    fn drop(&mut self) {
        claimed_paths().remove(&self.path);
    }
}

/// The suite's single audit chain plus its sticky degraded flag.
///
/// `plugin` is the file-backed hash chain; `degraded` flips to `true` on the
/// first record that could not be written (or on a poisoned mutex) and never
/// flips back. Cold-path decision points read the flag with one atomic load
/// and refuse to establish new trust while it is set.
///
/// The chain is the ONLY way in: the plugin behind it is crate-private, so no
/// caller can append a record without passing the degradation bookkeeping.
pub struct AuditChain {
    plugin: Mutex<LoggingPlugin>,
    degraded: AtomicBool,
    /// How many key-change records the current window has written, and how
    /// many it counted instead (`record_key_change`).
    key_changes: Mutex<KeyChangeBudget>,
}

/// Key-change records written per `KEY_CHANGE_WINDOW`, past which they are
/// counted instead of written (`AuditChain::record_key_change`).
///
/// Every installed key that changed is a record, and every record a write
/// and an fsync: a peer that announces new key material in a loop (any
/// authenticated participant can) would otherwise set the disk's pace. 64
/// per second is far above what a deployment rekeys at, and bounds the
/// syncs a peer can cause.
const KEY_CHANGES_PER_WINDOW: u32 = 64;

/// The window `KEY_CHANGES_PER_WINDOW` is counted over.
const KEY_CHANGE_WINDOW: std::time::Duration = std::time::Duration::from_secs(1);

/// The key-change records of the current window (`AuditChain::key_changes`).
#[derive(Debug, Default)]
struct KeyChangeBudget {
    window_start: Option<std::time::Instant>,
    written: u32,
    /// Records not written since the last one that was: reported, as one
    /// record, ahead of the next one written, so the chain says how many it
    /// does not hold.
    suppressed: u64,
}

impl KeyChangeBudget {
    /// Whether a key-change record at `now` is written; when it is, the
    /// number of records suppressed before it, to report first.
    fn admit(&mut self, now: std::time::Instant) -> Option<u64> {
        let window_over = self
            .window_start
            .is_none_or(|start| now.saturating_duration_since(start) >= KEY_CHANGE_WINDOW);
        if window_over {
            self.window_start = Some(now);
            self.written = 0;
        }
        if self.written >= KEY_CHANGES_PER_WINDOW {
            self.suppressed = self.suppressed.saturating_add(1);
            return None;
        }
        self.written += 1;
        Some(std::mem::take(&mut self.suppressed))
    }
}

impl AuditChain {
    /// Wrap a logging plugin into a shareable chain.
    pub fn new(plugin: LoggingPlugin) -> Self {
        Self {
            plugin: Mutex::new(plugin),
            degraded: AtomicBool::new(false),
            key_changes: Mutex::new(KeyChangeBudget::default()),
        }
    }

    /// The underlying plugin, for the degradation tests only.
    ///
    /// Test-only on purpose: a record appended through the raw lock would not
    /// mark the chain degraded when it is lost, which is the one invariant
    /// every fail-closed gate reads. Production code goes through
    /// [`AuditChain::record`].
    ///
    /// Gated on linux as well as test: the only caller is the `/dev/full`
    /// degradation test, which is itself linux-only, so on every other
    /// target this method has no caller and `-D dead_code` rejects it.
    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn plugin(&self) -> &Mutex<LoggingPlugin> {
        &self.plugin
    }

    /// True once a record has been lost. Sticky for the life of the chain.
    pub fn is_degraded(&self) -> bool {
        self.degraded.load(Ordering::Acquire)
    }

    /// Test seam: set the sticky flag without a failing backend, so the
    /// fail-closed gates can be exercised through the public API.
    #[cfg(test)]
    pub(crate) fn mark_degraded_for_tests(&self) {
        self.degraded.store(true, Ordering::Release);
    }

    /// Append one record. A write failure or a poisoned lock marks the chain
    /// degraded before the error is returned; the caller's decision is never
    /// reversed, but no new trust is established afterwards.
    ///
    /// A degraded chain keeps appending: the records that still land are
    /// evidence, and stopping the file would destroy more of it.
    pub fn record(&self, event: &SecurityEvent) -> Result<(), SecurityError> {
        let mut guard = match self.plugin.lock() {
            Ok(guard) => guard,
            Err(_) => {
                self.degraded.store(true, Ordering::Release);
                return Err(SecurityError::ConfigError(
                    "audit logging mutex poisoned".to_string(),
                ));
            }
        };
        match guard.log_event(event) {
            Ok(()) => Ok(()),
            Err(error) => {
                self.degraded.store(true, Ordering::Release);
                Err(error)
            }
        }
    }
}

impl AuditChain {
    /// Record a key-change event (a key installed that changed), at most
    /// `KEY_CHANGES_PER_WINDOW` per `KEY_CHANGE_WINDOW`: past that the
    /// records are counted, and the count is written as one record of its
    /// own ahead of the next record that is (`KeyChangeBudget`), or when the
    /// chain closes.
    pub(crate) fn record_key_change(&self, event: &SecurityEvent) {
        self.record_key_change_at(event, std::time::Instant::now());
    }

    fn record_key_change_at(&self, event: &SecurityEvent, now: std::time::Instant) {
        let admitted = self
            .key_changes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .admit(now);
        let Some(suppressed) = admitted else {
            return;
        };
        if suppressed > 0 {
            self.record_logged(&suppressed_key_changes(suppressed));
        }
        self.record_logged(event);
    }

    /// `record`, a loss logged (`record_committed`).
    fn record_logged(&self, event: &SecurityEvent) {
        if let Err(error) = self.record(event) {
            log::error!(
                "[security::audit] record lost, chain degraded: refusing new handshakes, \
                 data keys and endpoints until this participant is rebuilt ({})",
                error
            );
        }
    }
}

/// The record that stands for `count` key-change records not written.
fn suppressed_key_changes(count: u64) -> SecurityEvent {
    SecurityEvent::Crypto {
        key_id: 0,
        operation: format!("key_change_records_suppressed:{}", count),
        outcome: CryptoOutcome::Success,
        timestamp: timestamp_ns(),
    }
}

impl Drop for AuditChain {
    fn drop(&mut self) {
        let suppressed = std::mem::take(
            &mut self
                .key_changes
                .get_mut()
                .unwrap_or_else(|e| e.into_inner())
                .suppressed,
        );
        if suppressed > 0 {
            self.record_logged(&suppressed_key_changes(suppressed));
        }
    }
}

impl std::fmt::Debug for AuditChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditChain")
            .field("degraded", &self.is_degraded())
            .finish_non_exhaustive()
    }
}

/// True when the suite has a chain and that chain lost a record.
pub(crate) fn is_degraded(chain: &Option<SharedAuditLogger>) -> bool {
    chain.as_ref().is_some_and(|chain| chain.is_degraded())
}

/// A key-change record (`AuditChain::record_key_change`), when there is a
/// chain.
pub(crate) fn record_key_change(chain: &Option<SharedAuditLogger>, event: &SecurityEvent) {
    if let Some(chain) = chain {
        chain.record_key_change(event);
    }
}

/// Record a transition that has already committed.
///
/// The security decision is never reversed by audit I/O: the handshake map or
/// the key store was updated before this call and stays updated. What a
/// failure does is mark the chain degraded, which closes the door on every
/// later handshake, key installation and endpoint creation until the
/// participant is rebuilt.
pub(crate) fn record_committed(chain: &Option<SharedAuditLogger>, event: &SecurityEvent) {
    let Some(chain) = chain else {
        return;
    };
    if let Err(error) = chain.record(event) {
        log::error!(
            "[security::audit] record lost, chain degraded: refusing new handshakes, \
             data keys and endpoints until this participant is rebuilt ({})",
            error
        );
    }
}

/// Security event types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityEvent {
    Authentication {
        participant_guid: [u8; 16],
        outcome: AuthenticationOutcome,
        timestamp: u64,
    },
    AccessControl {
        participant_guid: [u8; 16],
        action: String,
        resource: String,
        outcome: AccessOutcome,
        timestamp: u64,
    },
    Crypto {
        key_id: u64,
        operation: String,
        outcome: CryptoOutcome,
        timestamp: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticationOutcome {
    Success,
    Failed,
    Revoked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessOutcome {
    Allowed,
    Denied,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoOutcome {
    Success,
    Failed,
}

/// Logging Plugin implementing DDS Security v1.1 Sec.8.6
/// RFC 5424 export of the audit chain, over UDP.
///
/// A MIRROR of the file-backed chain, not a second chain: the same line the
/// chain hashes is what goes out, so a collector and the file agree record for
/// record and the hash links are verifiable from either.
///
/// UDP rather than a Unix datagram to `/dev/log`, deliberately: `/dev/log`
/// exists on Linux and not on the Windows lane this crate also ships, and the
/// deployments that want an audit export want it on a remote collector. RFC
/// 5424 over UDP is what both do.
///
/// # What a failure means
///
/// Emitting is best-effort WHEN A FILE BACKS THE CHAIN: the tamper-evident
/// record is the file, the export is a copy, and a dropped datagram must not
/// mark a chain degraded whose record is safely on disk. With NO file the
/// export is the only record, so a failure to emit IS a lost record and the
/// chain degrades. `append_record` says which case it is in.
struct SyslogSink {
    socket: UdpSocket,
    target: SocketAddr,
    /// RFC 5424 Sec.6.2.4 HOSTNAME, or `-` (NILVALUE) when unknown.
    hostname: String,
    /// RFC 5424 Sec.6.2.6 PROCID.
    procid: u32,
}

impl SyslogSink {
    fn connect(target: SocketAddr) -> Result<Self, SecurityError> {
        // Bind the family the target needs; port 0 is any free local port.
        let bind: SocketAddr = if target.is_ipv4() {
            "0.0.0.0:0".parse().map_err(|e| {
                SecurityError::ConfigError(format!("audit syslog bind address: {}", e))
            })?
        } else {
            "[::]:0".parse().map_err(|e| {
                SecurityError::ConfigError(format!("audit syslog bind address: {}", e))
            })?
        };
        let socket = UdpSocket::bind(bind).map_err(|e| {
            SecurityError::ConfigError(format!("failed to open audit syslog socket: {}", e))
        })?;
        Ok(Self {
            socket,
            target,
            hostname: std::env::var("HOSTNAME")
                .ok()
                .filter(|h| !h.is_empty() && h.is_ascii())
                .unwrap_or_else(|| "-".to_string()),
            procid: std::process::id(),
        })
    }

    /// One RFC 5424 frame, Sec.6:
    /// `<PRI>VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP SD SP MSG`
    ///
    /// PRI is facility 4 (security/authorization, Sec.6.2.1) times 8 plus
    /// severity 5 (Notice): 37. The MSG is the chained line verbatim, so the
    /// `prev=`/`hash=`/`seq=` links survive the export.
    fn frame(&self, line: &str, unix_seconds: u64) -> String {
        format!(
            "<37>1 {} {} hdds {} AUDIT - {}",
            crate::core::civil_time::rfc3339_utc(unix_seconds),
            self.hostname,
            self.procid,
            line.trim_end_matches('\n')
        )
    }

    fn emit(&self, line: &str, unix_seconds: u64) -> Result<(), SecurityError> {
        let frame = self.frame(line, unix_seconds);
        self.socket
            .send_to(frame.as_bytes(), self.target)
            .map(|_| ())
            .map_err(|e| {
                SecurityError::ConfigError(format!(
                    "failed to emit audit record to syslog {}: {}",
                    self.target, e
                ))
            })
    }
}

pub struct LoggingPlugin {
    file: Option<File>,
    /// RFC 5424 export, when the deployment configured one.
    syslog: Option<SyslogSink>,
    previous_hash: [u8; 32],
    next_seq: u64,
    /// Held for the life of the plugin so no second participant in this
    /// process can open the same file.
    _claim: Option<PathClaim>,
    /// Test seam: make `sync_all` fail while `write_all` succeeds, the one
    /// real ordering (delayed allocation surfaces ENOSPC at fsync) that a
    /// file-backed test cannot reach on its own.
    #[cfg(test)]
    fail_sync: bool,
}

impl LoggingPlugin {
    /// Create logging plugin with file backend.
    ///
    /// Opens in append mode (mode 0600 on unix at creation) and writes an
    /// `AuditChainStart` marker chained onto whatever the file already ends
    /// with, so a reopened file stays ONE continuous chain with a visible
    /// restart boundary. Fail closed: an unreadable tail, a path already open
    /// in this process, or a marker that cannot be written is an open failure.
    pub fn with_file<P: AsRef<Path>>(path: P) -> Result<Self, SecurityError> {
        let path = path.as_ref();
        let tail = read_chain_tail(path)?;

        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(path).map_err(|e| {
            SecurityError::ConfigError(format!("Failed to open audit log file: {}", e))
        })?;
        let claim = PathClaim::acquire(path, &file)?;

        let (previous_hash, next_seq) = match tail {
            Some(tail) => (tail.hash, tail.seq + 1),
            None => ([0u8; 32], 0),
        };
        let mut plugin = Self {
            file: Some(file),
            syslog: None,
            previous_hash,
            next_seq,
            _claim: Some(claim),
            #[cfg(test)]
            fail_sync: false,
        };
        let marker = format!("{} {{ timestamp: {} }}", CHAIN_START_MARKER, timestamp_ns());
        plugin.append_record(&marker)?;
        Ok(plugin)
    }

    /// Create logging plugin without file (in-memory only)
    pub fn new() -> Self {
        Self {
            file: None,
            syslog: None,
            previous_hash: [0u8; 32],
            next_seq: 0,
            _claim: None,
            #[cfg(test)]
            fail_sync: false,
        }
    }

    /// Attach an RFC 5424 export over UDP to this chain.
    ///
    /// This is the syslog export the README and `SecurityConfig`'s
    /// documentation describe, behind the existing hash chain rather than
    /// beside it.
    pub fn with_syslog(mut self, target: SocketAddr) -> Result<Self, SecurityError> {
        self.syslog = Some(SyslogSink::connect(target)?);
        Ok(self)
    }

    /// A plugin over an arbitrary already-open file, with no start marker.
    ///
    /// Test seam for the degradation path: `/dev/full` opens fine and refuses
    /// every write, which is the only deterministic way to make a record fail
    /// without touching the file system's state.
    #[cfg(test)]
    pub(crate) fn over_file_for_tests(file: File) -> Self {
        Self {
            file: Some(file),
            syslog: None,
            previous_hash: [0u8; 32],
            next_seq: 0,
            _claim: None,
            fail_sync: false,
        }
    }

    /// A plugin whose writes land but whose `sync_all` always fails.
    #[cfg(test)]
    pub(crate) fn over_file_failing_sync_for_tests(file: File) -> Self {
        let mut plugin = Self::over_file_for_tests(file);
        plugin.fail_sync = true;
        plugin
    }

    /// Log a security event
    pub fn log_event(&mut self, event: &SecurityEvent) -> Result<(), SecurityError> {
        let body = format!("{:?}", event);
        self.append_record(&body)
    }

    /// Chain `body` onto the previous record and write the line.
    ///
    /// The in-memory hash follows the FILE, not durability: it advances as
    /// soon as `write_all` reports the bytes written, before `sync_all` is
    /// attempted. A failing fsync (the shape ENOSPC takes on a delayed
    /// allocation file system) therefore degrades the chain without making
    /// every later record look tampered, while a failing `write_all` leaves
    /// the hash where it was.
    fn append_record(&mut self, body: &str) -> Result<(), SecurityError> {
        let seq = self.next_seq;
        let current_hash = chain_hash(&self.previous_hash, seq, body);
        let line = format!(
            "{} prev={} hash={} seq={}\n",
            body,
            hex(&self.previous_hash),
            hex(&current_hash),
            seq
        );

        #[cfg(test)]
        let fail_sync = self.fail_sync;
        #[cfg(not(test))]
        let fail_sync = false;

        // The export goes out FIRST, so a record the file accepts is a record
        // the collector saw too; a failure here is judged below, once it is
        // known whether a file also carries it.
        let syslog_result = self
            .syslog
            .as_ref()
            .map(|sink| sink.emit(&line, timestamp_ns() / 1_000_000_000));

        if let Some(ref mut file) = self.file {
            file.write_all(line.as_bytes()).map_err(|e| {
                SecurityError::ConfigError(format!("Failed to write audit log: {}", e))
            })?;
            self.previous_hash = current_hash;
            self.next_seq = seq + 1;
            if fail_sync {
                return Err(SecurityError::ConfigError(
                    "Failed to sync audit log: injected sync failure".to_string(),
                ));
            }
            file.sync_all().map_err(|e| {
                SecurityError::ConfigError(format!("Failed to sync audit log: {}", e))
            })?;
            if let Some(Err(e)) = syslog_result {
                log::warn!(
                    "[audit] record {} is on disk but its syslog export failed: {}",
                    seq,
                    e
                );
            }
            return Ok(());
        }

        self.previous_hash = current_hash;
        self.next_seq = seq + 1;

        // No file: the export IS the record, so a failed emit is a LOST
        // record and the caller (`AuditChain::record`) must mark the chain
        // degraded. With a file the export is a mirror and its failure is
        // reported at WARN without touching the chain's verdict - see
        // `SyslogSink`.
        if let Some(Err(e)) = syslog_result {
            return Err(e);
        }
        Ok(())
    }

    /// Get previous hash (for tamper detection)
    pub fn get_previous_hash(&self) -> [u8; 32] {
        self.previous_hash
    }
}

impl std::fmt::Debug for LoggingPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoggingPlugin")
            .field("file_backed", &self.file.is_some())
            .field("next_seq", &self.next_seq)
            .field("previous_hash", &hex(&self.previous_hash))
            .finish()
    }
}

impl Default for LoggingPlugin {
    fn default() -> Self {
        Self::new()
    }
}

/// `SHA-256(previous || seq || body)`: the link function of the chain.
fn chain_hash(previous: &[u8; 32], seq: u64, body: &str) -> [u8; 32] {
    use ring::digest::{digest, SHA256};

    let mut input = Vec::with_capacity(32 + 8 + body.len());
    input.extend_from_slice(previous);
    input.extend_from_slice(&seq.to_be_bytes());
    input.extend_from_slice(body.as_bytes());

    let hash = digest(&SHA256, &input);
    let mut result = [0u8; 32];
    result.copy_from_slice(hash.as_ref());
    result
}

fn hex(bytes: &[u8; 32]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0F) as usize] as char);
    }
    out
}

fn unhex(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, pair) in text.as_bytes().chunks(2).enumerate() {
        let digit = |c: u8| -> Option<u8> {
            match c {
                b'0'..=b'9' => Some(c - b'0'),
                b'a'..=b'f' => Some(c - b'a' + 10),
                b'A'..=b'F' => Some(c - b'A' + 10),
                _ => None,
            }
        };
        out[i] = (digit(pair[0])? << 4) | digit(pair[1])?;
    }
    Some(out)
}

/// One parsed audit line.
struct ParsedLine<'a> {
    body: &'a str,
    prev: [u8; 32],
    hash: [u8; 32],
    seq: u64,
}

/// Split `<body> prev=<hex> hash=<hex> seq=<n>`.
///
/// Every field is taken from the RIGHT, so a body that itself contains
/// ` prev=` or ` seq=` (topic and partition names are caller-controlled) is
/// still split at the real trailer.
fn parse_line(line: &str) -> Option<ParsedLine<'_>> {
    let (head, seq_text) = line.rsplit_once(" seq=")?;
    let seq = seq_text.parse::<u64>().ok()?;
    let (body, tail) = head.rsplit_once(" prev=")?;
    let (prev_hex, hash_hex) = tail.split_once(" hash=")?;
    Some(ParsedLine {
        body,
        prev: unhex(prev_hex)?,
        hash: unhex(hash_hex)?,
        seq,
    })
}

/// The last line of an existing audit file, so a reopen chains onto it.
struct ChainTail {
    hash: [u8; 32],
    seq: u64,
}

/// Read back the tail of `path`, or `None` when there is nothing to chain onto.
///
/// Fail closed on anything unreadable: a file that does not end at a record
/// boundary (a fragment left by a crash between `write_all` and the newline),
/// a last line longer than [`TAIL_WINDOW`], or a foreign format. Appending to
/// such a file would produce a chain no auditor can walk.
fn read_chain_tail(path: &Path) -> Result<Option<ChainTail>, SecurityError> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(SecurityError::ConfigError(format!(
                "Failed to reopen audit log to read its tail: {}",
                e
            )))
        }
    };
    let len = file
        .metadata()
        .map_err(|e| SecurityError::ConfigError(format!("Failed to stat audit log: {}", e)))?
        .len();
    if len == 0 {
        return Ok(None);
    }

    let window = len.min(TAIL_WINDOW);
    let offset = -(window as i64);
    file.seek(SeekFrom::End(offset))
        .map_err(|e| SecurityError::ConfigError(format!("Failed to seek audit log: {}", e)))?;
    let mut buffer = Vec::with_capacity(window as usize);
    file.read_to_end(&mut buffer).map_err(|e| {
        SecurityError::ConfigError(format!("Failed to read the audit log tail: {}", e))
    })?;
    let text = String::from_utf8(buffer).map_err(|_| {
        SecurityError::ConfigError(
            "audit log tail is not UTF-8: refusing to append to a file this chain cannot read"
                .to_string(),
        )
    })?;

    if !text.ends_with('\n') {
        return Err(SecurityError::ConfigError(
            "audit log does not end at a record boundary (a partially written line): \
             refusing to append, the chain would be unverifiable"
                .to_string(),
        ));
    }
    let last = text.lines().rev().find(|line| !line.trim().is_empty());
    let Some(last) = last else {
        return Ok(None);
    };
    let parsed = parse_line(last).ok_or_else(|| {
        SecurityError::ConfigError(
            "audit log tail is not a chained record: refusing to append to a file whose \
             last line cannot be parsed"
                .to_string(),
        )
    })?;
    Ok(Some(ChainTail {
        hash: parsed.hash,
        seq: parsed.seq,
    }))
}

/// Summary of a verified audit file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainSummary {
    /// Number of `AuditChainStart` markers (one per open of the file).
    pub chains: usize,
    /// Number of event records, markers excluded.
    pub records: usize,
}

/// Walk an audit file and check every link.
///
/// Returns the number of restart markers and records on success. Fails on the
/// first line that is malformed, whose `seq` is not the next ordinal, whose
/// `prev` is not the previous line's hash, or whose `hash` is not
/// `SHA-256(prev || seq || body)`. The whole file is ONE chain: only line 1
/// may carry a zero `prev`, so an excised run or an excised tail of an
/// earlier run is caught at the next line.
///
/// The removal of the file's own tail is NOT detectable here (a prefix of a
/// chain is a chain); that needs an anchor kept outside the file.
pub fn verify_chain(contents: &str) -> Result<ChainSummary, SecurityError> {
    let mut expected_prev = [0u8; 32];
    let mut summary = ChainSummary {
        chains: 0,
        records: 0,
    };

    for (index, line) in contents.lines().enumerate() {
        let line_no = index + 1;
        let parsed = parse_line(line).ok_or_else(|| {
            SecurityError::ConfigError(format!(
                "audit line {} is malformed: expected '<event> prev=<hex> hash=<hex> seq=<n>'",
                line_no
            ))
        })?;

        // The ordinal is the line number counted from zero: the file IS the
        // chain, from its first line.
        let expected_seq = index as u64;
        if parsed.seq != expected_seq {
            return Err(SecurityError::ConfigError(format!(
                "audit line {} is out of sequence: seq={}, expected {} (a record was \
                 removed, reordered or renumbered)",
                line_no, parsed.seq, expected_seq
            )));
        }
        if parsed.prev != expected_prev {
            return Err(SecurityError::ConfigError(format!(
                "audit line {} does not chain: prev does not match the previous record",
                line_no
            )));
        }
        if chain_hash(&parsed.prev, parsed.seq, parsed.body) != parsed.hash {
            return Err(SecurityError::ConfigError(format!(
                "audit line {} is tampered: hash does not cover its body",
                line_no
            )));
        }

        expected_prev = parsed.hash;
        if parsed.body.starts_with(CHAIN_START_MARKER) {
            summary.chains += 1;
        } else {
            summary.records += 1;
        }
    }

    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::NamedTempFile;

    /// A second holder of the audit file is refused, even when it is not this
    /// process's in-memory registry that notices.
    ///
    /// The registry cannot see another process, so this test bypasses it: it
    /// takes the advisory lock through an INDEPENDENT open file description,
    /// which is exactly the state another process would leave the file in
    /// (flock locks the open file description, not the process). The path is
    /// never claimed in the registry, so a refusal here can only come from the
    /// file lock.
    #[cfg(unix)]
    #[test]
    fn a_file_locked_by_another_holder_is_refused() {
        use std::os::unix::io::AsRawFd;

        let temp = NamedTempFile::new().expect("temp file");
        let path = temp.path().to_path_buf();

        let held = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .expect("open the file a second time");
        // SAFETY: `held` is open for the rest of the test, so its descriptor
        // is valid; flock takes no pointer.
        let rc = unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc != 0 {
            // No advisory locking on this filesystem (an NFS mount, say). The
            // guarantee genuinely does not hold there, so there is nothing to
            // assert - skip rather than pretend.
            eprintln!("skipping: filesystem does not support flock");
            return;
        }

        let err = LoggingPlugin::with_file(&path)
            .expect_err("a file already locked elsewhere must not be opened");
        let message = format!("{:?}", err);
        assert!(
            message.contains("locked by another process"),
            "expected a cross-process refusal, got: {}",
            message
        );

        // And once the other holder lets go, the path opens normally - the
        // lock must not leave the file permanently unusable.
        drop(held);
        LoggingPlugin::with_file(&path).expect("the file opens once the lock is released");
    }

    /// Releasing the claim must leave the path openable again. A refusal that
    /// outlives its cause is the same outage as a corrupt chain, arriving by a
    /// different road.
    #[test]
    fn a_released_audit_file_can_be_reopened() {
        let temp = NamedTempFile::new().expect("temp file");
        let path = temp.path().to_path_buf();

        let first = LoggingPlugin::with_file(&path).expect("first open");
        assert!(
            LoggingPlugin::with_file(&path).is_err(),
            "the same path must not be opened twice at once"
        );
        drop(first);
        LoggingPlugin::with_file(&path).expect("reopen after the first holder is dropped");
    }

    #[test]
    fn test_log_authentication_event() {
        let mut plugin = LoggingPlugin::new();

        let event = SecurityEvent::Authentication {
            participant_guid: [0x42; 16],
            outcome: AuthenticationOutcome::Success,
            timestamp: 1234567890,
        };

        assert!(plugin.log_event(&event).is_ok());
    }

    #[test]
    fn test_log_access_control_event() {
        let mut plugin = LoggingPlugin::new();

        let event = SecurityEvent::AccessControl {
            participant_guid: [0x42; 16],
            action: "create_writer".to_string(),
            resource: "sensor/temperature".to_string(),
            outcome: AccessOutcome::Allowed,
            timestamp: 1234567890,
        };

        assert!(plugin.log_event(&event).is_ok());
    }

    #[test]
    fn test_log_crypto_event() {
        let mut plugin = LoggingPlugin::new();

        let event = SecurityEvent::Crypto {
            key_id: 42,
            operation: "encrypt".to_string(),
            outcome: CryptoOutcome::Success,
            timestamp: 1234567890,
        };

        assert!(plugin.log_event(&event).is_ok());
    }

    #[test]
    fn test_log_to_file() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_owned();

        let mut plugin = LoggingPlugin::with_file(&path).unwrap();

        let event = SecurityEvent::Authentication {
            participant_guid: [0x42; 16],
            outcome: AuthenticationOutcome::Success,
            timestamp: 1234567890,
        };

        plugin.log_event(&event).unwrap();

        // Verify file was written
        let contents = fs::read_to_string(&path).unwrap();
        assert!(contents.contains("Authentication"));
        assert!(contents.contains("Success"));
    }

    #[test]
    fn test_hash_chain() {
        let mut plugin = LoggingPlugin::new();

        let event1 = SecurityEvent::Authentication {
            participant_guid: [0x01; 16],
            outcome: AuthenticationOutcome::Success,
            timestamp: 1,
        };

        let event2 = SecurityEvent::Authentication {
            participant_guid: [0x02; 16],
            outcome: AuthenticationOutcome::Success,
            timestamp: 2,
        };

        let hash_before = plugin.get_previous_hash();
        plugin.log_event(&event1).unwrap();
        let hash_after_1 = plugin.get_previous_hash();
        plugin.log_event(&event2).unwrap();
        let hash_after_2 = plugin.get_previous_hash();

        // Hashes should change
        assert_ne!(hash_before, hash_after_1);
        assert_ne!(hash_after_1, hash_after_2);
    }

    #[test]
    fn test_multiple_events_to_file() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_owned();

        let mut plugin = LoggingPlugin::with_file(&path).unwrap();

        for i in 0..10 {
            let event = SecurityEvent::Crypto {
                key_id: i,
                operation: "encrypt".to_string(),
                outcome: CryptoOutcome::Success,
                timestamp: i,
            };
            plugin.log_event(&event).unwrap();
        }

        let contents = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 11, "one chain-start marker plus ten records");
        assert!(lines[0].starts_with(CHAIN_START_MARKER));
    }

    fn crypto_event(key_id: u64) -> SecurityEvent {
        SecurityEvent::Crypto {
            key_id,
            operation: "install_data_key".to_string(),
            outcome: CryptoOutcome::Success,
            timestamp: timestamp_ns(),
        }
    }

    /// A flood of key changes writes at most `KEY_CHANGES_PER_WINDOW`
    /// records per window, then one record counting the rest ahead of the
    /// next window's first, and the chain still verifies.
    #[test]
    fn key_change_records_are_bounded_per_window_and_the_rest_counted() {
        let audit_file = NamedTempFile::new().expect("create audit fixture");
        let chain = AuditChain::new(LoggingPlugin::with_file(audit_file.path()).expect("open"));
        let start = std::time::Instant::now();
        let flood = 1000u64;
        for key_id in 0..flood {
            chain.record_key_change_at(&crypto_event(key_id + 1), start);
        }
        let records = fs::read_to_string(audit_file.path()).expect("read");
        assert_eq!(
            records.matches("install_data_key").count(),
            KEY_CHANGES_PER_WINDOW as usize,
            "one window writes at most its budget"
        );
        assert!(!records.contains("key_change_records_suppressed"));

        chain.record_key_change_at(&crypto_event(flood + 1), start + KEY_CHANGE_WINDOW);
        let records = fs::read_to_string(audit_file.path()).expect("read");
        let suppressed = flood - u64::from(KEY_CHANGES_PER_WINDOW);
        assert!(
            records.contains(&format!("key_change_records_suppressed:{}", suppressed)),
            "the next window first says how many records it does not hold"
        );
        assert_eq!(
            records.matches("install_data_key").count(),
            KEY_CHANGES_PER_WINDOW as usize + 1
        );
        verify_chain(&records).expect("the chain still verifies");
    }

    /// The announced "hash-chained event log": every line carries its own
    /// hash, its predecessor's and its ordinal; a reopen is a visible
    /// boundary that STILL chains onto the previous run; a single flipped
    /// byte, a removed record, a removed whole run and a removed run tail
    /// are all caught by the verifier.
    #[test]
    fn file_records_carry_a_verifiable_hash_chain_across_reopen() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_owned();

        {
            let mut first_run = LoggingPlugin::with_file(&path).unwrap();
            first_run.log_event(&crypto_event(1)).unwrap();
            first_run.log_event(&crypto_event(2)).unwrap();
        }
        {
            let mut second_run = LoggingPlugin::with_file(&path).unwrap();
            second_run.log_event(&crypto_event(3)).unwrap();
        }

        let contents = fs::read_to_string(&path).unwrap();
        for line in contents.lines() {
            assert!(
                line.contains(" prev=") && line.contains(" hash=") && line.contains(" seq="),
                "every line must carry both hashes and its ordinal: {}",
                line
            );
        }
        let summary = verify_chain(&contents).expect("an untouched file must verify");
        assert_eq!(
            summary,
            ChainSummary {
                chains: 2,
                records: 3
            },
            "two opens, three records"
        );

        // The restart is visible AND chained: the second marker carries the
        // hash of the last line of the first run, not zeros.
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 5);
        let marker_indices: Vec<usize> = lines
            .iter()
            .enumerate()
            .filter(|(_, l)| l.starts_with(CHAIN_START_MARKER))
            .map(|(i, _)| i)
            .collect();
        assert_eq!(marker_indices, vec![0, 3], "one marker per open");
        let first_marker = parse_line(lines[0]).expect("marker parses");
        assert_eq!(first_marker.prev, [0u8; 32], "line 1 opens the chain");
        assert_eq!(first_marker.seq, 0);
        let last_of_first_run = parse_line(lines[2]).expect("record parses");
        let second_marker = parse_line(lines[3]).expect("marker parses");
        assert_eq!(
            second_marker.prev, last_of_first_run.hash,
            "the reopen marker must chain onto the last line already in the file"
        );
        assert_eq!(second_marker.seq, 3, "ordinals continue across the reopen");

        // Tamper with one byte of a record body: the verifier names the line.
        let tampered = contents.replacen("key_id: 2", "key_id: 7", 1);
        assert_ne!(tampered, contents, "the fixture must contain the record");
        let error = verify_chain(&tampered).expect_err("a modified body must not verify");
        assert!(
            error.to_string().contains("line 3"),
            "the third line carries key_id 2: {}",
            error
        );

        // Drop a record from the middle: the ordinal gap names the line.
        let mut kept: Vec<&str> = lines.clone();
        kept.remove(1);
        let error = verify_chain(&kept.join("\n")).expect_err("a removed record must not verify");
        assert!(
            error.to_string().contains("out of sequence"),
            "removal must be reported: {}",
            error
        );

        // Drop the LAST line of the first run: the reopen marker no longer
        // chains, which is exactly what continuity across opens buys.
        let mut without_run_tail: Vec<&str> = lines.clone();
        without_run_tail.remove(2);
        let error = verify_chain(&without_run_tail.join("\n"))
            .expect_err("a truncated run tail must not verify");
        assert!(
            error.to_string().contains("out of sequence")
                || error.to_string().contains("does not chain"),
            "a truncated run tail must be reported: {}",
            error
        );

        // Excise the whole first run: the file now opens on a marker whose
        // prev is not zero and whose ordinal is not zero.
        let error =
            verify_chain(&lines[3..].join("\n")).expect_err("an excised run must not verify");
        assert!(
            error.to_string().contains("line 1"),
            "the excision is caught at the first surviving line: {}",
            error
        );

        // The limit, stated as a test rather than as prose: removing the
        // file's OWN tail leaves a valid prefix. Nothing in-band can catch
        // that; it needs an anchor kept outside the file.
        let prefix = lines[..4].join("\n");
        assert!(
            verify_chain(&prefix).is_ok(),
            "a prefix of a chain is a chain: tail truncation is out of scope"
        );
    }

    /// The clock behind every emitter is the metrics clock, in nanoseconds.
    ///
    /// This pins the UNIT of `timestamp_ns` alone. That all three event
    /// families actually go through it is pinned on disk, through the public
    /// API, by `security::e2e_tests` (Authentication and Crypto in domain
    /// 227, AccessControl in domain 229).
    #[test]
    fn timestamp_ns_is_the_metrics_clock_in_nanoseconds() {
        let stamped = timestamp_ns();
        let reference = crate::telemetry::metrics::current_time_ns();
        assert!(
            stamped > 1_000_000_000_000_000_000,
            "a 2026 nanosecond timestamp exceeds 1e18, got {}",
            stamped
        );
        assert!(
            reference.abs_diff(stamped) < 1_000_000_000,
            "audit and access-control stamps must come from the same clock and unit"
        );
    }

    /// A lost record marks the chain degraded, once and for good, and the
    /// hash never advances past a line that is not in the file.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_failed_write_degrades_the_chain_permanently() {
        let sink = File::create("/dev/full").expect("/dev/full opens for writing on linux");
        let chain = AuditChain::new(LoggingPlugin::over_file_for_tests(sink));
        assert!(!chain.is_degraded());

        let before = chain.plugin().lock().unwrap().get_previous_hash();
        let error = chain
            .record(&crypto_event(1))
            .expect_err("/dev/full refuses every write");
        assert!(error.to_string().contains("Failed to write audit log"));
        assert!(
            chain.is_degraded(),
            "the first lost record degrades the chain"
        );
        assert_eq!(
            chain.plugin().lock().unwrap().get_previous_hash(),
            before,
            "the chain hash must not advance past a record that is not on disk"
        );

        // Still degraded after another attempt: the flag is sticky.
        let _ = chain.record(&crypto_event(2));
        assert!(chain.is_degraded());
    }

    /// A record whose bytes reached the file but whose fsync failed (the
    /// shape ENOSPC takes on a delayed-allocation file system) degrades the
    /// chain WITHOUT poisoning it: the line is on disk, the next record
    /// chains onto it, and the file still verifies. The hash must advance to
    /// that line, or every later record would read as tampering.
    #[test]
    fn a_failed_sync_keeps_the_file_verifiable() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_owned();
        let sink = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .expect("open the sink");

        let chain = AuditChain::new(LoggingPlugin::over_file_failing_sync_for_tests(sink));
        let error = chain
            .record(&crypto_event(1))
            .expect_err("the injected fsync failure surfaces");
        assert!(
            error.to_string().contains("Failed to sync audit log"),
            "{}",
            error
        );
        assert!(chain.is_degraded(), "a record that is not durable is lost");

        chain
            .record(&crypto_event(2))
            .expect_err("the second sync fails too");

        let contents = fs::read_to_string(&path).unwrap();
        assert_eq!(contents.lines().count(), 2, "both lines reached the file");
        let summary = verify_chain(&contents)
            .expect("a file whose lines are all present must verify, degraded or not");
        assert_eq!(
            summary,
            ChainSummary {
                chains: 0,
                records: 2
            }
        );
    }

    /// A degraded chain is reported through the shared handle the machine
    /// and the key store hold, and an absent chain is never degraded.
    #[test]
    fn degradation_is_visible_through_the_shared_handle() {
        assert!(!is_degraded(&None));
        let chain: SharedAuditLogger = Arc::new(AuditChain::new(LoggingPlugin::new()));
        assert!(!is_degraded(&Some(chain.clone())));
        chain.mark_degraded_for_tests();
        assert!(is_degraded(&Some(chain)));
    }

    /// Two participants cannot share one audit file: the second open is
    /// refused, because their two chains would interleave into a file that
    /// verifies as tampering. The claim is released when the first plugin
    /// is dropped.
    #[test]
    fn one_audit_file_cannot_back_two_participants() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_owned();

        let first = LoggingPlugin::with_file(&path).expect("the first open succeeds");
        let error = LoggingPlugin::with_file(&path).expect_err("the second open is refused");
        assert!(
            error.to_string().contains("already open in this process"),
            "{}",
            error
        );

        drop(first);
        let reopened = LoggingPlugin::with_file(&path).expect("the claim is released on drop");
        drop(reopened);
        let contents = fs::read_to_string(&path).unwrap();
        assert_eq!(
            verify_chain(&contents).expect("the file verifies"),
            ChainSummary {
                chains: 2,
                records: 0
            },
            "two opens, no refused chain in between"
        );
    }

    /// A file that does not end at a record boundary, or whose last line is
    /// not a chained record, is an OPEN failure: appending to it would
    /// produce a chain no auditor can walk.
    #[test]
    fn a_file_whose_tail_cannot_be_read_fails_closed() {
        let fragment = NamedTempFile::new().unwrap();
        {
            let mut plugin = LoggingPlugin::with_file(fragment.path()).unwrap();
            plugin.log_event(&crypto_event(1)).unwrap();
        }
        let mut contents = fs::read_to_string(fragment.path()).unwrap();
        contents.push_str("Crypto { key_id: 9, partially writ");
        fs::write(fragment.path(), &contents).unwrap();
        let error = LoggingPlugin::with_file(fragment.path())
            .expect_err("a half-written last line is fail-closed");
        assert!(error.to_string().contains("record boundary"), "{}", error);

        let foreign = NamedTempFile::new().unwrap();
        fs::write(foreign.path(), "not an audit record at all\n").unwrap();
        let error = LoggingPlugin::with_file(foreign.path())
            .expect_err("a foreign last line is fail-closed");
        assert!(error.to_string().contains("cannot be parsed"), "{}", error);
    }

    // =======================================================================
    // RFC 5424 export (README.md:396 "Syslog integration support")
    // =======================================================================

    /// The export reaches a collector, and the datagram is RFC 5424.
    ///
    /// A real UDP socket, not a formatting assertion: what matters is that the
    /// bytes leave the process in the shape a collector parses.
    #[test]
    fn the_audit_export_is_an_rfc5424_datagram() {
        use std::net::UdpSocket;
        use std::time::Duration;

        let collector = UdpSocket::bind("127.0.0.1:0").expect("bind collector");
        collector
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("timeout");
        let target = collector.local_addr().expect("addr");

        let mut plugin = LoggingPlugin::new()
            .with_syslog(target)
            .expect("the export opens");
        plugin
            .append_record("AuthenticationOutcome { outcome: Success }")
            .expect("the record is emitted");

        let mut buf = [0u8; 2048];
        let n = collector.recv(&mut buf).expect("the collector receives it");
        let frame = std::str::from_utf8(&buf[..n]).expect("utf-8");

        // <PRI>VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP SD SP MSG
        assert!(frame.starts_with("<37>1 "), "PRI and version: {}", frame);
        let fields: Vec<&str> = frame.splitn(7, ' ').collect();
        assert_eq!(
            fields.len(),
            7,
            "seven header fields then the MSG: {}",
            frame
        );
        assert_eq!(fields[3], "hdds", "APP-NAME");
        assert_eq!(
            fields[4],
            std::process::id().to_string(),
            "PROCID is this process"
        );
        assert_eq!(fields[5], "AUDIT", "MSGID");

        // TIMESTAMP is RFC 3339 UTC, and it is THIS century rather than the
        // epoch: a clock read that silently failed would show 1970.
        let ts = fields[1];
        assert!(
            ts.starts_with("20") && ts.ends_with('Z'),
            "TIMESTAMP: {}",
            ts
        );
        assert_eq!(ts.len(), 20, "YYYY-MM-DDTHH:MM:SSZ: {}", ts);

        // The MSG is the chained line, links intact, so a collector and the
        // file can be compared record for record.
        let msg = fields[6];
        assert!(msg.contains("AuthenticationOutcome"), "MSG body: {}", msg);
        assert!(
            msg.contains("prev=") && msg.contains("hash=") && msg.contains("seq="),
            "the hash-chain links survive the export: {}",
            msg
        );
        assert!(
            !msg.ends_with('\n'),
            "no trailing newline inside a datagram"
        );
    }

    /// With NO file, the export IS the record: a failed emit is a lost record
    /// and must be an error, so `AuditChain::record` marks the chain degraded.
    /// With a file, the same failure is a warning and the chain stands.
    #[test]
    fn a_failed_export_degrades_only_when_nothing_else_holds_the_record() {
        // A target nobody listens on is not enough to make UDP fail, so the
        // failure is produced by closing the socket's own family: send to a
        // port 0 target, which the kernel refuses outright.
        let unusable: std::net::SocketAddr = "127.0.0.1:0".parse().expect("addr");
        let mut export_only = LoggingPlugin::new()
            .with_syslog(unusable)
            .expect("the socket opens");
        let verdict = export_only.append_record("probe");
        assert!(
            verdict.is_err(),
            "with no file the export is the record, so its failure is an error"
        );

        // And the same failure with a file behind it leaves the record safe.
        let temp = NamedTempFile::new().expect("temp file");
        let path = temp.path().to_path_buf();
        drop(temp);
        let mut both = LoggingPlugin::with_file(&path)
            .expect("file opens")
            .with_syslog(unusable)
            .expect("the socket opens");
        both.append_record("probe")
            .expect("the file holds the record, so the chain stands");
        let _ = std::fs::remove_file(&path);
    }
}
