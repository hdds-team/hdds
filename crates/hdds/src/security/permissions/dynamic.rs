// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Dynamic Permissions Engine with file-watching hot-reload
//!
//! Provides runtime-reloadable permission rules for topic/partition access control.
//! Permissions are loaded from a simple text-based configuration file and can be
//! reloaded automatically by polling the file's modification time.
//!
//! # Architecture
//!
//! ```text
//! DynamicPermissionManager
//! +-- document: Arc<RwLock<PermissionDocument>>   (current permissions)
//! +-- file_path: PathBuf                          (permission file to watch)
//! +-- poll thread                                 (mtime-based file watcher)
//! +-- audit_log: Arc<Mutex<Vec<AuditEntry>>>      (permission change log)
//! ```
//!
//! # File Format
//!
//! Uses a simple line-based format (no external YAML dependency required):
//!
//! ```text
//! # Comments start with '#'
//! [subject: CN=sensor-node-1,O=HDDS]
//! default: deny
//! allow publish: sensors/*
//! deny subscribe: admin/*
//! allow subscribe: commands/*
//! allow publish: data/raw partitions=p1,p2
//!
//! [subject: CN=dashboard,O=HDDS]
//! default: deny
//! allow subscribe: *
//! allow publish: commands/*
//! ```
//!
//! # Thread Safety
//!
//! The permission document is protected by `RwLock` for concurrent read access.
//! The watcher thread acquires a write lock only during reload. Audit log uses
//! a separate `Mutex` to avoid contention with permission checks.

use crate::security::access::subject::DistinguishedName;
use crate::security::SecurityError;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime};

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// Which action a permission rule applies to
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleAction {
    /// The rule applies to publishing
    Publish,
    /// The rule applies to subscribing
    Subscribe,
}

/// A permission rule for a topic/partition combination
#[derive(Debug, Clone, PartialEq)]
pub struct PermissionRule {
    /// Glob pattern for the topic (e.g. "sensors/*", "*", "data/raw")
    pub topic_pattern: String,
    /// Partition filter -- empty means all partitions
    pub partitions: Vec<String>,
    /// Which action this rule targets (publish or subscribe)
    pub action: RuleAction,
    /// Whether this rule allows (true) or denies (false) the action
    pub allow: bool,
}

/// A set of permission rules for a participant identified by X.509 subject name
#[derive(Debug, Clone)]
pub struct PermissionSet {
    /// X.509 subject name (e.g. "CN=sensor-node-1,O=HDDS")
    pub subject_name: String,
    /// Ordered list of rules (first match wins)
    pub rules: Vec<PermissionRule>,
    /// Default policy when no rule matches (true = deny)
    pub default_deny: bool,
}

/// A permission document loaded from file
#[derive(Debug, Clone)]
pub struct PermissionDocument {
    /// All participant permission grants
    pub grants: Vec<PermissionSet>,
    /// Timestamp when this document was loaded
    pub loaded_at: SystemTime,
}

/// Result of a reload operation
#[derive(Debug, Clone, PartialEq)]
pub enum ReloadResult {
    /// File was reloaded successfully
    Reloaded,
    /// File has not changed since last load (same mtime)
    Unchanged,
}

/// Audit entry for permission changes
#[derive(Debug, Clone)]
pub struct PermissionAuditEntry {
    /// When the change occurred
    pub timestamp: SystemTime,
    /// Type of change
    pub change_type: PermissionChangeType,
    /// Subject affected (or empty for file-level events)
    pub subject: String,
    /// Human-readable details
    pub details: String,
}

/// Types of permission changes tracked in the audit log
#[derive(Debug, Clone, PartialEq)]
pub enum PermissionChangeType {
    /// A new permission was granted
    Granted,
    /// A permission was revoked
    Revoked,
    /// The permission file was reloaded
    FileReloaded,
    /// An error occurred while reading the permission file
    FileError,
}

// ---------------------------------------------------------------------------
// Glob matching
// ---------------------------------------------------------------------------

/// Match a topic against a glob pattern.
///
/// Supported patterns:
/// - `*` at top level matches everything
/// - `prefix/*` matches anything starting with `prefix/`
/// - `**` at end matches everything (same as `*`)
/// - Exact match for non-pattern strings
fn topic_matches(pattern: &str, topic: &str) -> bool {
    // Universal wildcard
    if pattern == "*" || pattern == "**" {
        return true;
    }

    // Exact match
    if pattern == topic {
        return true;
    }

    // "prefix/*" -- matches prefix/ followed by anything
    if let Some(prefix) = pattern.strip_suffix("/*") {
        return topic.starts_with(prefix)
            && topic.len() > prefix.len()
            && topic.as_bytes()[prefix.len()] == b'/';
    }

    // "prefix/**" -- same as prefix/*
    if let Some(prefix) = pattern.strip_suffix("/**") {
        return topic.starts_with(prefix)
            && topic.len() > prefix.len()
            && topic.as_bytes()[prefix.len()] == b'/';
    }

    false
}

/// Check if a partition matches the rule's partition filter.
///
/// A rule with no `partitions=` clause is unscoped and matches every
/// partition, the default one included. A rule that NAMES partitions is
/// scoped to them, so it does not reach an endpoint that named none: the
/// operator wrote down which partitions the rule is about, and the default
/// partition is not one of them.
fn partition_matches(rule_partitions: &[String], partition: &str) -> bool {
    if rule_partitions.is_empty() {
        return true;
    }
    rule_partitions.iter().any(|p| p == partition)
}

// ---------------------------------------------------------------------------
// Parser (simple line-based format)
// ---------------------------------------------------------------------------

/// Parse a permission document from the line-based format.
///
/// Format:
/// ```text
/// [subject: CN=foo,O=bar]
/// default: deny
/// allow publish: sensors/*
/// allow subscribe: commands/* partitions=p1,p2
/// deny publish: admin/*
/// ```
pub fn parse_permission_file(content: &str) -> Result<PermissionDocument, SecurityError> {
    let mut grants: Vec<PermissionSet> = Vec::new();
    let mut current_subject: Option<String> = None;
    let mut current_rules: Vec<PermissionRule> = Vec::new();
    let mut current_default_deny = true;

    for (line_num, raw_line) in content.lines().enumerate() {
        let line = raw_line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Subject header: [subject: CN=foo,O=bar]
        if line.starts_with('[') && line.ends_with(']') {
            // Flush previous subject
            if let Some(subject) = current_subject.take() {
                grants.push(PermissionSet {
                    subject_name: subject,
                    rules: std::mem::take(&mut current_rules),
                    default_deny: current_default_deny,
                });
            }
            current_default_deny = true;

            let inner = &line[1..line.len() - 1];
            let subject = if let Some(stripped) = inner.strip_prefix("subject:") {
                stripped.trim().to_string()
            } else {
                return Err(SecurityError::ConfigError(format!(
                    "Line {}: expected [subject: ...], got: {}",
                    line_num + 1,
                    line
                )));
            };

            if subject.is_empty() {
                return Err(SecurityError::ConfigError(format!(
                    "Line {}: empty subject name",
                    line_num + 1
                )));
            }

            // Refused here rather than silently matching nothing later. This
            // file exists to TAKE PERMISSIONS AWAY, so a subject nobody can
            // parse would leave a topic open while the operator reads a rule
            // that says it is closed. The whole document is then rejected and
            // the previous one stays in force (see `watcher_poll_cycle`).
            if DistinguishedName::parse(&subject).is_none() {
                return Err(SecurityError::ConfigError(format!(
                    "Line {}: subject is not a readable RFC 4514 distinguished name: {}",
                    line_num + 1,
                    subject
                )));
            }

            current_subject = Some(subject);
            continue;
        }

        // Must be inside a subject block
        if current_subject.is_none() {
            return Err(SecurityError::ConfigError(format!(
                "Line {}: rule outside of [subject:] block: {}",
                line_num + 1,
                line
            )));
        }

        // Default policy: "default: deny" or "default: allow"
        if let Some(rest) = line.strip_prefix("default:") {
            let val = rest.trim();
            current_default_deny = match val {
                "deny" => true,
                "allow" => false,
                _ => {
                    return Err(SecurityError::ConfigError(format!(
                        "Line {}: invalid default value '{}', expected 'allow' or 'deny'",
                        line_num + 1,
                        val
                    )));
                }
            };
            continue;
        }

        // Permission rule: "allow publish: sensors/*" or "allow subscribe: * partitions=p1,p2"
        let rule = parse_rule_line(line, line_num)?;
        current_rules.push(rule);
    }

    // Flush last subject
    if let Some(subject) = current_subject.take() {
        grants.push(PermissionSet {
            subject_name: subject,
            rules: current_rules,
            default_deny: current_default_deny,
        });
    }

    Ok(PermissionDocument {
        grants,
        loaded_at: SystemTime::now(),
    })
}

/// Parse a single permission rule line like "allow publish: sensors/*"
/// or "deny subscribe: * partitions=p1,p2".
fn parse_rule_line(line: &str, line_num: usize) -> Result<PermissionRule, SecurityError> {
    let (is_allow, rest) = if let Some(r) = line.strip_prefix("allow ") {
        (true, r)
    } else if let Some(r) = line.strip_prefix("deny ") {
        (false, r)
    } else {
        return Err(SecurityError::ConfigError(format!(
            "Line {}: expected 'allow' or 'deny' rule, got: {}",
            line_num + 1,
            line
        )));
    };

    let (rule_action, pattern_and_rest) = if let Some(r) = rest.strip_prefix("publish:") {
        (RuleAction::Publish, r.trim())
    } else if let Some(r) = rest.strip_prefix("subscribe:") {
        (RuleAction::Subscribe, r.trim())
    } else {
        return Err(SecurityError::ConfigError(format!(
            "Line {}: expected 'publish:' or 'subscribe:', got: {}",
            line_num + 1,
            rest
        )));
    };

    let (pattern, partitions) = parse_pattern_and_partitions(pattern_and_rest);

    if pattern.is_empty() {
        return Err(SecurityError::ConfigError(format!(
            "Line {}: empty topic pattern",
            line_num + 1
        )));
    }

    Ok(PermissionRule {
        topic_pattern: pattern.to_string(),
        partitions,
        action: rule_action,
        allow: is_allow,
    })
}

/// Parse "topic_pattern partitions=p1,p2" into (pattern, partitions_vec)
fn parse_pattern_and_partitions(input: &str) -> (&str, Vec<String>) {
    if let Some(idx) = input.find("partitions=") {
        let pattern = input[..idx].trim();
        let parts_str = &input[idx + "partitions=".len()..];
        let partitions: Vec<String> = parts_str
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        (pattern, partitions)
    } else {
        (input.trim(), Vec::new())
    }
}

// ---------------------------------------------------------------------------
// Watcher stop gate
// ---------------------------------------------------------------------------

/// The watcher thread's sleep and its stop flag, as ONE object.
///
/// A plain flag plus `thread::sleep` makes `stop_watching` wait for the poll
/// interval to elapse before the thread notices - and `Drop` joins that
/// thread, so dropping a participant configured with a 30 s poll would stall
/// for up to 30 s. The condvar turns the wait into something a stop request
/// can interrupt at once.
struct StopGate {
    running: Mutex<bool>,
    wake: Condvar,
}

impl StopGate {
    fn new() -> Self {
        Self {
            running: Mutex::new(false),
            wake: Condvar::new(),
        }
    }

    fn is_running(&self) -> bool {
        *self.running.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn stop(&self) {
        *self.running.lock().unwrap_or_else(|e| e.into_inner()) = false;
        self.wake.notify_all();
    }

    /// Sleep up to `interval`, and report whether the watcher should keep
    /// going. Returns `false` the instant a stop is requested.
    fn sleep_then_continue(&self, interval: Duration) -> bool {
        let guard = self.running.lock().unwrap_or_else(|e| e.into_inner());
        if !*guard {
            return false;
        }
        let (guard, _) = self
            .wake
            .wait_timeout(guard, interval)
            .unwrap_or_else(|e| e.into_inner());
        *guard
    }
}

// ---------------------------------------------------------------------------
// Watcher reload debounce
// ---------------------------------------------------------------------------

/// `(length, mtime)` fingerprint of a file at the instant it was observed.
///
/// Cheap to compare, so most idle polls can be dismissed without ever
/// opening the file -- but on its own it is only ever a PRE-CHECK, never
/// the thing that decides a reload (see [`ReloadDebounce`]).
type FileStat = (u64, Option<SystemTime>);

fn file_stat(meta: &std::fs::Metadata) -> FileStat {
    (meta.len(), meta.modified().ok())
}

/// Debounce state for the background watcher thread (see
/// [`watcher_poll_cycle`]).
///
/// The watcher never applies a file's content just because its mtime
/// moved. A writer that rewrites the file non-atomically (truncate then
/// write, as most editors and `echo >` do) can be read mid-write, and the
/// torn result can easily still be a SYNTACTICALLY VALID document: an
/// empty file parses as zero grants, and a file cut after some lines can
/// parse as a valid subset of the final one. Since this file exists only
/// to TAKE PERMISSIONS AWAY (see the module doc), applying either one is
/// not a harmless no-op -- it can leave a deny rule un-applied, and if
/// mtime happens to land on the same tick for the torn read and the final
/// write (coarse filesystem granularity, or two writes close together),
/// relying on mtime alone means the complete content is never reloaded at
/// all, indefinitely.
///
/// So reload is decided on CONTENT, not mtime: a poll's read is first
/// discarded outright if the file's own `(len, mtime)` changed WHILE we
/// were reading it (not a coherent snapshot, might be a byte-level mix of
/// old and new), and otherwise is applied only once the SAME content has
/// been read back to back on two consecutive polls. A transient torn
/// state -- empty, or a cut prefix -- almost never survives two full poll
/// intervals unchanged, so it is seen at most once and never promoted;
/// the writer's real, final content is what eventually gets read twice in
/// a row. `settled` also remembers content that was REJECTED for a parse
/// error, so a malformed file that stops changing is logged once rather
/// than on every poll.
///
/// Residual contract: this is a debounce, not a lock. A writer that holds
/// the file in a torn state for longer than two poll intervals will
/// eventually have that state read twice in a row and applied, same as
/// any other content that stops changing. Operators who need a hard
/// guarantee, not just a realistic one, should still write a temp file
/// and `rename` it over the target -- a rename is atomic, so the watcher
/// only ever observes the old content or the complete new one. The other
/// side of the same residual contract: a file that is REGENERATED on
/// every poll (rewritten with fresh bytes continuously, rather than
/// settling once the writer is done) never reads identically twice in a
/// row and is therefore never applied, no matter how long it keeps being
/// regenerated. Operators must write the file once and leave it alone
/// (ideally via the atomic rename above), not regenerate it continuously.
///
/// Content is compared directly (the file is small), not through a hash:
/// a hash only ever buys speed at the cost of a collision question this
/// file does not need to carry.
#[derive(Default)]
struct ReloadDebounce {
    /// Content + stat of the content currently applied (or last rejected
    /// with a logged `FileError`). This is the ONLY place that records
    /// "content X is now applied" -- both `reload()` and the watcher go
    /// through [`Self::mark_settled`] so they can never disagree about
    /// what the other one already applied.
    settled: Option<(String, FileStat)>,
    /// Content + stat read on the immediately preceding poll, awaiting a
    /// second, matching read before it is trusted.
    pending: Option<(String, FileStat)>,
    /// Set once a read of the file has failed and a `FileError` has been
    /// logged for it; cleared the next time a read succeeds. Guards
    /// against logging a `FileError` on every poll of a file that stays
    /// unreadable -- the operator signal is the TRANSITION, not the
    /// ongoing state.
    unreadable: bool,
}

impl ReloadDebounce {
    /// Record `content` as the one now in force: applied to the live
    /// document, or the last content rejected with a logged parse-error
    /// `FileError`. Clears any in-flight pending candidate and any
    /// `unreadable` streak, since settling can only follow a successful
    /// read.
    fn mark_settled(&mut self, content: &str, stat: FileStat) {
        self.settled = Some((content.to_string(), stat));
        self.pending = None;
        self.unreadable = false;
    }
}

// ---------------------------------------------------------------------------
// DynamicPermissionManager
// ---------------------------------------------------------------------------

/// Dynamic permission manager with file-watching hot-reload.
///
/// Loads permissions from a file and periodically checks for changes.
/// When the file is modified, the new permissions are loaded atomically
/// and the old permissions are replaced. If the new file is malformed,
/// the old permissions are kept and an error is logged to the audit trail.
pub struct DynamicPermissionManager {
    /// Current permission document (read-heavy, write-rare)
    document: Arc<RwLock<PermissionDocument>>,
    /// Path to the permission file
    file_path: PathBuf,
    /// Content-based debounce state, shared by the background watcher
    /// thread AND the manual [`Self::reload`] API (see [`ReloadDebounce`]):
    /// there is exactly one record of "this content is now applied", so the
    /// two can never disagree about it.
    watch_debounce: Arc<Mutex<ReloadDebounce>>,
    /// Stop flag and interruptible sleep for the watcher thread
    stop: Arc<StopGate>,
    /// Watcher thread handle
    thread: Mutex<Option<JoinHandle<()>>>,
    /// Audit log of permission changes
    audit_log: Arc<Mutex<Vec<PermissionAuditEntry>>>,
    /// Bumped every time [`Self::document`] is actually replaced -- by
    /// [`Self::reload`] or by the watcher thread -- never on a poll that
    /// found nothing new. A caller that caches a verdict against this value
    /// (`Self::generation`) notices a reload without re-checking on every
    /// packet: DDS-Security v1.1 Sec.8.4.2.9 ties `check_remote_datawriter`/
    /// `check_remote_datareader` to the CURRENT permissions, and this is
    /// what lets a cache stay O(1) per packet while still reflecting a
    /// reload that revoked something.
    generation: Arc<AtomicU64>,
}

impl DynamicPermissionManager {
    /// Create a new manager by loading permissions from the given file.
    ///
    /// The file is read and parsed immediately. If the file cannot be read
    /// or parsed, an error is returned.
    pub fn new(file_path: PathBuf) -> Result<Self, SecurityError> {
        let content = std::fs::read_to_string(&file_path).map_err(|e| {
            SecurityError::ConfigError(format!(
                "Failed to read permission file '{}': {}",
                file_path.display(),
                e
            ))
        })?;

        let document = parse_permission_file(&content)?;
        let initial_stat = std::fs::metadata(&file_path)
            .as_ref()
            .map(file_stat)
            .unwrap_or((0, None));

        let audit_log = Arc::new(Mutex::new(Vec::new()));

        // Log initial load
        if let Ok(mut log) = audit_log.lock() {
            log.push(PermissionAuditEntry {
                timestamp: SystemTime::now(),
                change_type: PermissionChangeType::FileReloaded,
                subject: String::new(),
                details: format!(
                    "Initial load from '{}' ({} grants)",
                    file_path.display(),
                    document.grants.len()
                ),
            });
        }

        let mut debounce = ReloadDebounce::default();
        debounce.mark_settled(&content, initial_stat);

        Ok(Self {
            document: Arc::new(RwLock::new(document)),
            file_path,
            watch_debounce: Arc::new(Mutex::new(debounce)),
            stop: Arc::new(StopGate::new()),
            thread: Mutex::new(None),
            audit_log,
            generation: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Start the file watcher thread with the given poll interval.
    ///
    /// The thread checks the file's mtime at each interval and reloads
    /// if the file has been modified. If the file becomes unreadable or
    /// malformed, the old permissions are kept.
    ///
    /// # Errors
    ///
    /// Returns `SecurityError::ConfigError` if the watcher thread cannot be
    /// spawned. This is an error and not a log line: a caller that asked for
    /// hot-reload and silently got a frozen document would enforce yesterday's
    /// restrictions without anything saying so.
    pub fn start_watching(&self, poll_interval: Duration) -> Result<(), SecurityError> {
        // Don't start if already running
        {
            let mut running = self.stop.running.lock().unwrap_or_else(|e| e.into_inner());
            if *running {
                return Ok(());
            }
            *running = true;
        }

        let document = Arc::clone(&self.document);
        let file_path = self.file_path.clone();
        let watch_debounce = Arc::clone(&self.watch_debounce);
        let stop = Arc::clone(&self.stop);
        let audit_log = Arc::clone(&self.audit_log);
        let generation = Arc::clone(&self.generation);

        let spawned = std::thread::Builder::new()
            .name("hdds-perm-watch".to_string())
            .spawn(move || {
                while stop.sleep_then_continue(poll_interval) {
                    watcher_poll_cycle(
                        &file_path,
                        &watch_debounce,
                        &document,
                        &audit_log,
                        &generation,
                    );
                }
            });

        let handle = match spawned {
            Ok(h) => h,
            Err(e) => {
                self.stop.stop();
                return Err(SecurityError::ConfigError(format!(
                    "failed to spawn the permission watcher thread for '{}': {}",
                    self.file_path.display(),
                    e
                )));
            }
        };

        if let Ok(mut t) = self.thread.lock() {
            *t = Some(handle);
        }
        Ok(())
    }

    /// Stop the file watcher thread.
    pub fn stop_watching(&self) {
        self.stop.stop();
        if let Ok(mut guard) = self.thread.lock() {
            if let Some(handle) = guard.take() {
                let _ = handle.join();
            }
        }
    }

    /// Check if a subject can publish to a topic in the given partition.
    ///
    /// Returns `true` if publishing is allowed, `false` if denied. A subject
    /// this document never names is denied: read on its own, this engine is
    /// the whole policy, and a policy that has never heard of you does not
    /// let you through.
    pub fn check_publish(&self, subject: &str, topic: &str, partition: &str) -> bool {
        self.verdict(subject, topic, partition, RuleAction::Publish)
            .unwrap_or(false)
    }

    /// Check if a subject can subscribe to a topic in the given partition.
    ///
    /// Returns `true` if subscribing is allowed, `false` if denied. Same
    /// reading of an unnamed subject as [`Self::check_publish`].
    pub fn check_subscribe(&self, subject: &str, topic: &str, partition: &str) -> bool {
        self.verdict(subject, topic, partition, RuleAction::Subscribe)
            .unwrap_or(false)
    }

    /// What this document says about one action, or `None` if it names no
    /// grant for `subject` and therefore says nothing at all.
    ///
    /// A `subject` that is not a readable distinguished name is nobody, and
    /// this document has never granted anything to nobody: the answer is
    /// `Some(false)`, never `None`. Abstaining there would hand the caller
    /// the permissive reading of an unreadable identity.
    pub fn verdict(
        &self,
        subject: &str,
        topic: &str,
        partition: &str,
        action: RuleAction,
    ) -> Option<bool> {
        let Some(dn) = DistinguishedName::parse(subject) else {
            return Some(false);
        };
        self.verdict_for_name(&dn, topic, partition, action)
    }

    /// [`Self::verdict`] for a subject already read, from a certificate's DER
    /// (`access::subject::certificate_subject`): the production door never
    /// goes through a printed name.
    pub(crate) fn verdict_for_name(
        &self,
        subject: &DistinguishedName,
        topic: &str,
        partition: &str,
        action: RuleAction,
    ) -> Option<bool> {
        let doc = match self.document.read() {
            Ok(d) => d,
            Err(e) => e.into_inner(),
        };
        check_action(
            &doc,
            subject,
            topic,
            partition,
            action == RuleAction::Publish,
        )
    }

    /// The production door: apply this file as a RESTRICTION OVERLAY on top of
    /// a decision the signed permissions document has already taken.
    ///
    /// It can only take an action away. `Ok(())` means "no local objection",
    /// which is what a subject this file never names always gets - the signed
    /// document remains the only thing that GRANTS anything. DDS-Security
    /// v1.1 section 9.4.1.3 makes the Permissions CA the root of what a
    /// participant may do; an unsigned file that could widen that would be a
    /// way around the whole chain of trust. Narrowing it needs no signature:
    /// refusing more than you are allowed to refuse is not a thing.
    ///
    /// # Errors
    ///
    /// `SecurityError::PermissionsDenied` naming the subject, the action and
    /// the topic, when this file names the subject and its rules refuse.
    pub(crate) fn check_local_restriction(
        &self,
        subject: &DistinguishedName,
        topic: &str,
        partition: &str,
        action: RuleAction,
    ) -> Result<(), SecurityError> {
        match self.verdict_for_name(subject, topic, partition, action) {
            // The overlay abstains: either no grant names this subject, or
            // its rules allow the action.
            None | Some(true) => Ok(()),
            Some(false) => Err(SecurityError::PermissionsDenied(format!(
                "local permission file '{}' refuses {} on topic '{}'{} for subject '{}'",
                self.file_path.display(),
                match action {
                    RuleAction::Publish => "publish",
                    RuleAction::Subscribe => "subscribe",
                },
                topic,
                if partition.is_empty() {
                    String::new()
                } else {
                    format!(" in partition '{}'", partition)
                },
                subject
            ))),
        }
    }

    /// Whether this subject's rules for `action` on `topic` include at
    /// least one PARTITION-SCOPED rule (a non-empty `partitions`) whose
    /// topic expression matches `topic`.
    ///
    /// [`Self::check_local_restriction`] against the default partition
    /// alone is authoritative for `topic` only when this is `false`: a rule
    /// scoped to a partition other than the default is invisible to a probe
    /// against `""` (`partition_matches` on an empty `partition` string),
    /// so a verdict reached that way says nothing about what the same rule
    /// does in the partition a remote endpoint actually announces. A
    /// caller that sees `true` here must defer to
    /// [`Self::check_local_restriction`] with the endpoint's OWN announced
    /// partitions once they are known, rather than trust the default-only
    /// probe for every partition.
    pub(crate) fn has_partition_scoped_rule(
        &self,
        subject: &DistinguishedName,
        topic: &str,
        action: RuleAction,
    ) -> bool {
        let doc = match self.document.read() {
            Ok(d) => d,
            Err(e) => e.into_inner(),
        };
        topic_has_partition_scoped_rule(&doc, subject, topic, action)
    }

    /// Get a snapshot of the audit log entries.
    pub fn audit_log(&self) -> Vec<PermissionAuditEntry> {
        match self.audit_log.lock() {
            Ok(log) => log.clone(),
            Err(e) => e.into_inner().clone(),
        }
    }

    /// Manually trigger a reload of the permission file.
    ///
    /// Returns `Reloaded` if the file's content differs from what is
    /// currently applied, `Unchanged` if it is byte-for-byte the same.
    ///
    /// This is decided on CONTENT, the same rule the background watcher
    /// uses (see [`ReloadDebounce`]), through the SAME shared state
    /// (`watch_debounce`) -- not on mtime. A non-atomic rewrite (truncate
    /// then write) can land within one filesystem timestamp tick: mtime
    /// alone would then read as "unchanged" and the new content would
    /// never be applied, which for a file whose only job is to TAKE
    /// PERMISSIONS AWAY is a silently un-applied restriction, not a
    /// harmless no-op. Sharing `watch_debounce` with the watcher (rather
    /// than keeping a second, mtime-only copy of "what is applied") is
    /// also what keeps the two from disagreeing: a manual reload's
    /// `mark_settled` call is what tells the watcher this content is
    /// already in force, so it does not re-"confirm" and re-apply it two
    /// polls later and log a spurious second `FileReloaded`.
    ///
    /// Unlike the watcher's poll cycle, this does not wait for the same
    /// content to be read on two consecutive polls before trusting it:
    /// a manual reload is a deliberate, one-shot request made right now,
    /// not a continuous background sample that must debounce a torn
    /// read against itself.
    pub fn reload(&self) -> Result<ReloadResult, SecurityError> {
        let content = std::fs::read_to_string(&self.file_path).map_err(|e| {
            SecurityError::ConfigError(format!(
                "Failed to read '{}': {}",
                self.file_path.display(),
                e
            ))
        })?;
        let meta = std::fs::metadata(&self.file_path).map_err(|e| {
            SecurityError::ConfigError(format!(
                "Failed to stat '{}': {}",
                self.file_path.display(),
                e
            ))
        })?;
        let current_stat = file_stat(&meta);

        let already_settled = {
            let state = self
                .watch_debounce
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            state.settled.as_ref().map(|(c, _)| c.as_str()) == Some(content.as_str())
        };

        if already_settled {
            return Ok(ReloadResult::Unchanged);
        }

        let new_doc = parse_permission_file(&content)?;

        // Diff for audit
        if let Ok(old_doc) = self.document.read() {
            diff_and_audit(&old_doc, &new_doc, &self.audit_log);
        }

        // Swap
        if let Ok(mut doc) = self.document.write() {
            *doc = new_doc;
        }
        // Moved AFTER the swap: a reader of `generation` that sees the new
        // value is guaranteed to see the new document too (`Self::generation`).
        self.generation.fetch_add(1, Ordering::Release);

        if let Ok(mut log) = self.audit_log.lock() {
            log.push(PermissionAuditEntry {
                timestamp: SystemTime::now(),
                change_type: PermissionChangeType::FileReloaded,
                subject: String::new(),
                details: format!("Manual reload from '{}'", self.file_path.display()),
            });
        }

        // Record this content as the one now in force, through the same
        // single recorder the watcher uses (see the doc comment above).
        if let Ok(mut state) = self.watch_debounce.lock() {
            state.mark_settled(&content, current_stat);
        }

        Ok(ReloadResult::Reloaded)
    }

    /// Get a clone of the current permission document (for inspection/debugging).
    pub fn current_document(&self) -> PermissionDocument {
        match self.document.read() {
            Ok(d) => d.clone(),
            Err(e) => e.into_inner().clone(),
        }
    }

    /// Check whether the watcher thread is currently running.
    pub fn is_watching(&self) -> bool {
        self.stop.is_running()
    }

    /// How many times [`Self::document`] has actually been replaced, by
    /// [`Self::reload`] or by the watcher thread -- never by a poll that
    /// found nothing new. A caller holding a cached verdict and the
    /// generation it was reached under can skip re-checking as long as this
    /// value has not moved (one atomic load), and must re-check once it has.
    pub(crate) fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }
}

impl Drop for DynamicPermissionManager {
    fn drop(&mut self) {
        self.stop_watching();
    }
}

// ---------------------------------------------------------------------------
// Permission checking logic
// ---------------------------------------------------------------------------

/// Single poll cycle for the file watcher: content-debounced reload, audit
/// differences. See [`ReloadDebounce`] for why mtime alone never decides a
/// reload here.
fn watcher_poll_cycle(
    file_path: &std::path::Path,
    debounce: &Arc<Mutex<ReloadDebounce>>,
    document: &Arc<RwLock<PermissionDocument>>,
    audit_log: &Arc<Mutex<Vec<PermissionAuditEntry>>>,
    generation: &Arc<AtomicU64>,
) {
    let meta_before = match std::fs::metadata(file_path) {
        Ok(m) => m,
        Err(_) => return,
    };
    let stat_before = file_stat(&meta_before);

    // Cheap pre-check: nothing to do if the file looks exactly like what
    // we already settled on AND we are not mid-debounce on some other
    // candidate that still needs a second read to confirm or drop.
    {
        let state = debounce.lock().unwrap_or_else(|e| e.into_inner());
        if state.pending.is_none() && state.settled.as_ref().map(|(_, s)| *s) == Some(stat_before) {
            return;
        }
    }

    let content = match std::fs::read_to_string(file_path) {
        Ok(c) => c,
        Err(_) => {
            // Transient (e.g. mid-rename) or a real, lasting failure
            // (permission revoked, the file deleted and never replaced):
            // this poll cannot tell which. Log a `FileError` the first
            // time this is seen (the transition an operator needs to
            // know about), then stay quiet on every following poll of
            // the same outage -- `unreadable` is the one place that
            // remembers whether this was already reported, cleared the
            // next time a read succeeds so a later failure is reported
            // again. The old document, and the debounce's `settled`
            // content, are left exactly as they were: a read failure is
            // never treated as new content to debounce or apply.
            let mut state = debounce.lock().unwrap_or_else(|e| e.into_inner());
            if !state.unreadable {
                state.unreadable = true;
                drop(state);
                if let Ok(mut log) = audit_log.lock() {
                    log.push(PermissionAuditEntry {
                        timestamp: SystemTime::now(),
                        change_type: PermissionChangeType::FileError,
                        subject: String::new(),
                        details: format!(
                            "'{}' became unreadable (keeping old permissions)",
                            file_path.display()
                        ),
                    });
                }
            }
            return;
        }
    };

    let meta_after = match std::fs::metadata(file_path) {
        Ok(m) => m,
        Err(_) => return,
    };
    let stat_after = file_stat(&meta_after);

    let mut state = debounce.lock().unwrap_or_else(|e| e.into_inner());

    // The read succeeded: whatever `unreadable` streak was in progress is
    // over, regardless of what happens with this content below.
    state.unreadable = false;

    // The file's own (len, mtime) changed WHILE we were reading it: the
    // bytes we got are not a trustworthy snapshot (possibly a byte-level
    // mix of old and new content). Drop it rather than feed it into the
    // debounce count; the next poll gets a clean look.
    if stat_before != stat_after {
        state.pending = None;
        return;
    }

    if state.settled.as_ref().map(|(c, _)| c.as_str()) == Some(content.as_str()) {
        // Unchanged (or a benign `touch` with identical bytes): refresh
        // the cheap pre-check stat and drop any now-stale candidate.
        state.settled = Some((content, stat_after));
        state.pending = None;
        return;
    }

    let confirmed = state.pending.as_ref().map(|(c, _)| c.as_str()) == Some(content.as_str());
    if !confirmed {
        // First time this exact content has been seen: remember it, but
        // do not act on it. A transient torn read (empty, or a cut
        // prefix) almost never survives to match a second, later poll.
        state.pending = Some((content, stat_after));
        return;
    }

    // Read back to back, byte for byte, on two consecutive polls: settled.
    state.pending = None;
    drop(state);

    match parse_permission_file(&content) {
        Ok(new_doc) => {
            if let Ok(old_doc) = document.read() {
                diff_and_audit(&old_doc, &new_doc, audit_log);
            }
            if let Ok(mut doc) = document.write() {
                *doc = new_doc;
            }
            // Moved AFTER the swap, same as the manual `reload()` path.
            generation.fetch_add(1, Ordering::Release);
            if let Ok(mut log) = audit_log.lock() {
                log.push(PermissionAuditEntry {
                    timestamp: SystemTime::now(),
                    change_type: PermissionChangeType::FileReloaded,
                    subject: String::new(),
                    details: format!("Reloaded from '{}'", file_path.display()),
                });
            }
        }
        Err(e) => {
            if let Ok(mut log) = audit_log.lock() {
                log.push(PermissionAuditEntry {
                    timestamp: SystemTime::now(),
                    change_type: PermissionChangeType::FileError,
                    subject: String::new(),
                    details: format!(
                        "Parse error in '{}': {} (keeping old permissions)",
                        file_path.display(),
                        e
                    ),
                });
            }
        }
    }

    if let Ok(mut state) = debounce.lock() {
        state.mark_settled(&content, stat_after);
    }
}

/// Check whether an action (publish or subscribe) is allowed for a given
/// subject on a given topic/partition.
///
/// Returns `None` when the document says NOTHING about this subject - which
/// is not the same answer as "denied", and the two callers need to tell them
/// apart. Standing alone, the engine reads `None` as a refusal (see
/// [`DynamicPermissionManager::check_publish`]); used as a restriction
/// overlay on top of the signed document, `None` means the overlay abstains
/// and the signed decision stands (see
/// [`DynamicPermissionManager::check_local_restriction`]).
///
/// Evaluation order (deny takes precedence: the overlay's OWN format, a
/// local restriction file; the signed permissions document applies its rules
/// in document order instead, DDS-Security v1.1 Sec.9.4.1.3.2.3):
/// 1. Check all deny rules -- if any deny rule matches, return `Some(false)`
/// 2. Check all allow rules -- if any allow rule matches, return `Some(true)`
/// 3. Apply default policy
fn check_action(
    doc: &PermissionDocument,
    subject: &DistinguishedName,
    topic: &str,
    partition: &str,
    is_publish: bool,
) -> Option<bool> {
    let target_action = if is_publish {
        RuleAction::Publish
    } else {
        RuleAction::Subscribe
    };

    // No grant names this subject: the document has no opinion.
    //
    // Names are compared as distinguished names, not as strings, through the
    // SAME reader the signed permissions document is matched with
    // (`access::subject`). `x509_parser` prints `CN=a, O=b` and an operator
    // types `CN=a,O=b`; string equality would make the second one restrict
    // nothing at all, which is the one way this file must never fail.
    let perm_set = doc.grants.iter().find(|g| {
        DistinguishedName::parse(&g.subject_name).is_some_and(|dn| dn.matches(subject))
    })?;

    // Step 1: Check deny rules first (deny takes precedence)
    for rule in &perm_set.rules {
        if rule.action != target_action || rule.allow {
            continue;
        }
        if topic_matches(&rule.topic_pattern, topic)
            && partition_matches(&rule.partitions, partition)
        {
            return Some(false); // Explicit deny
        }
    }

    // Step 2: Check allow rules
    for rule in &perm_set.rules {
        if rule.action != target_action || !rule.allow {
            continue;
        }
        if topic_matches(&rule.topic_pattern, topic)
            && partition_matches(&rule.partitions, partition)
        {
            return Some(true); // Explicit allow
        }
    }

    // Step 3: No matching rule found -- apply this subject's default
    Some(!perm_set.default_deny)
}

/// Whether `subject`'s rules for `target_action` include at least one
/// PARTITION-SCOPED rule (non-empty `partitions`) whose topic expression
/// matches `topic` (see [`DynamicPermissionManager::has_partition_scoped_rule`]).
fn topic_has_partition_scoped_rule(
    doc: &PermissionDocument,
    subject: &DistinguishedName,
    topic: &str,
    target_action: RuleAction,
) -> bool {
    let Some(perm_set) = doc
        .grants
        .iter()
        .find(|g| DistinguishedName::parse(&g.subject_name).is_some_and(|dn| dn.matches(subject)))
    else {
        return false;
    };
    perm_set.rules.iter().any(|rule| {
        rule.action == target_action
            && !rule.partitions.is_empty()
            && topic_matches(&rule.topic_pattern, topic)
    })
}

// ---------------------------------------------------------------------------
// Audit diffing
// ---------------------------------------------------------------------------

/// Two subject spellings that name the same subject.
///
/// The same reader the decisions use, for the same reason: an operator who
/// reorders the attributes of a grant has not revoked it and granted it
/// again, and the change log should not say so.
fn same_subject(a: &str, b: &str) -> bool {
    match (DistinguishedName::parse(a), DistinguishedName::parse(b)) {
        (Some(a), Some(b)) => a.matches(&b),
        // Unparseable names never reach here from `parse_permission_file`,
        // which refuses them; fall back to the literal spelling rather than
        // calling two unreadable names equal.
        _ => a == b,
    }
}

/// Compare old and new documents and record grant/revoke audit entries.
fn diff_and_audit(
    old: &PermissionDocument,
    new: &PermissionDocument,
    audit_log: &Arc<Mutex<Vec<PermissionAuditEntry>>>,
) {
    let mut log = match audit_log.lock() {
        Ok(l) => l,
        Err(e) => e.into_inner(),
    };

    // Check for removed subjects
    for old_grant in &old.grants {
        if !new
            .grants
            .iter()
            .any(|g| same_subject(&g.subject_name, &old_grant.subject_name))
        {
            log.push(PermissionAuditEntry {
                timestamp: SystemTime::now(),
                change_type: PermissionChangeType::Revoked,
                subject: old_grant.subject_name.clone(),
                details: format!(
                    "Subject '{}' removed ({} rules revoked)",
                    old_grant.subject_name,
                    old_grant.rules.len()
                ),
            });
        }
    }

    // Check for added subjects
    for new_grant in &new.grants {
        if !old
            .grants
            .iter()
            .any(|g| same_subject(&g.subject_name, &new_grant.subject_name))
        {
            log.push(PermissionAuditEntry {
                timestamp: SystemTime::now(),
                change_type: PermissionChangeType::Granted,
                subject: new_grant.subject_name.clone(),
                details: format!(
                    "Subject '{}' added ({} rules granted)",
                    new_grant.subject_name,
                    new_grant.rules.len()
                ),
            });
        }
    }

    // Check for changed subjects (rules changed)
    for old_grant in &old.grants {
        if let Some(new_grant) = new
            .grants
            .iter()
            .find(|g| same_subject(&g.subject_name, &old_grant.subject_name))
        {
            if old_grant.rules != new_grant.rules
                || old_grant.default_deny != new_grant.default_deny
            {
                // Count additions and removals
                let old_count = old_grant.rules.len();
                let new_count = new_grant.rules.len();
                log.push(PermissionAuditEntry {
                    timestamp: SystemTime::now(),
                    change_type: PermissionChangeType::Granted,
                    subject: new_grant.subject_name.clone(),
                    details: format!(
                        "Subject '{}' rules changed ({} -> {} rules)",
                        new_grant.subject_name, old_count, new_count
                    ),
                });
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[path = "dynamic_tests.rs"]
mod tests;
