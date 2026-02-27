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

use crate::security::SecurityError;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
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
        return topic.starts_with(prefix) && topic.len() > prefix.len()
            && topic.as_bytes()[prefix.len()] == b'/';
    }

    // "prefix/**" -- same as prefix/*
    if let Some(prefix) = pattern.strip_suffix("/**") {
        return topic.starts_with(prefix) && topic.len() > prefix.len()
            && topic.as_bytes()[prefix.len()] == b'/';
    }

    false
}

/// Check if a partition matches the rule's partition filter.
/// Empty filter means "all partitions".
fn partition_matches(rule_partitions: &[String], partition: &str) -> bool {
    if rule_partitions.is_empty() {
        return true;
    }
    if partition.is_empty() {
        // No partition specified by caller -- match if rule allows all
        return rule_partitions.is_empty();
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

    let (rule_action, pattern_and_rest) =
        if let Some(r) = rest.strip_prefix("publish:") {
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
    /// Last known mtime of the file
    last_mtime: Arc<RwLock<Option<SystemTime>>>,
    /// Flag to stop the watcher thread
    running: Arc<AtomicBool>,
    /// Watcher thread handle
    thread: Mutex<Option<JoinHandle<()>>>,
    /// Audit log of permission changes
    audit_log: Arc<Mutex<Vec<PermissionAuditEntry>>>,
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
        let mtime = std::fs::metadata(&file_path)
            .and_then(|m| m.modified())
            .ok();

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

        Ok(Self {
            document: Arc::new(RwLock::new(document)),
            file_path,
            last_mtime: Arc::new(RwLock::new(mtime)),
            running: Arc::new(AtomicBool::new(false)),
            thread: Mutex::new(None),
            audit_log,
        })
    }

    /// Start the file watcher thread with the given poll interval.
    ///
    /// The thread checks the file's mtime at each interval and reloads
    /// if the file has been modified. If the file becomes unreadable or
    /// malformed, the old permissions are kept.
    pub fn start_watching(&self, poll_interval: Duration) {
        // Don't start if already running
        if self.running.load(Ordering::SeqCst) {
            return;
        }

        self.running.store(true, Ordering::SeqCst);

        let document = Arc::clone(&self.document);
        let file_path = self.file_path.clone();
        let last_mtime = Arc::clone(&self.last_mtime);
        let running = Arc::clone(&self.running);
        let audit_log = Arc::clone(&self.audit_log);

        let handle = std::thread::Builder::new()
            .name("hdds-perm-watch".to_string())
            .spawn(move || {
                while running.load(Ordering::SeqCst) {
                    std::thread::sleep(poll_interval);

                    if !running.load(Ordering::SeqCst) {
                        break;
                    }

                    watcher_poll_cycle(&file_path, &last_mtime, &document, &audit_log);
                }
            })
            .expect("Failed to spawn permission watcher thread");

        if let Ok(mut t) = self.thread.lock() {
            *t = Some(handle);
        }
    }

    /// Stop the file watcher thread.
    pub fn stop_watching(&self) {
        self.running.store(false, Ordering::SeqCst);
        if let Ok(mut guard) = self.thread.lock() {
            if let Some(handle) = guard.take() {
                let _ = handle.join();
            }
        }
    }

    /// Check if a subject can publish to a topic in the given partition.
    ///
    /// Returns `true` if publishing is allowed, `false` if denied.
    pub fn check_publish(&self, subject: &str, topic: &str, partition: &str) -> bool {
        let doc = match self.document.read() {
            Ok(d) => d,
            Err(e) => e.into_inner(),
        };
        check_action(&doc, subject, topic, partition, true)
    }

    /// Check if a subject can subscribe to a topic in the given partition.
    ///
    /// Returns `true` if subscribing is allowed, `false` if denied.
    pub fn check_subscribe(&self, subject: &str, topic: &str, partition: &str) -> bool {
        let doc = match self.document.read() {
            Ok(d) => d,
            Err(e) => e.into_inner(),
        };
        check_action(&doc, subject, topic, partition, false)
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
    /// Returns `Reloaded` if the file was loaded, `Unchanged` if the mtime
    /// has not changed since last load.
    pub fn reload(&self) -> Result<ReloadResult, SecurityError> {
        let current_mtime = std::fs::metadata(&self.file_path)
            .and_then(|m| m.modified())
            .map_err(|e| {
                SecurityError::ConfigError(format!(
                    "Failed to stat '{}': {}",
                    self.file_path.display(),
                    e
                ))
            })?;

        let should_reload = {
            let guard = self.last_mtime.read().unwrap_or_else(|e| e.into_inner());
            match *guard {
                Some(prev) => current_mtime != prev,
                None => true,
            }
        };

        if !should_reload {
            return Ok(ReloadResult::Unchanged);
        }

        let content = std::fs::read_to_string(&self.file_path).map_err(|e| {
            SecurityError::ConfigError(format!(
                "Failed to read '{}': {}",
                self.file_path.display(),
                e
            ))
        })?;

        let new_doc = parse_permission_file(&content)?;

        // Diff for audit
        if let Ok(old_doc) = self.document.read() {
            diff_and_audit(&old_doc, &new_doc, &self.audit_log);
        }

        // Swap
        if let Ok(mut doc) = self.document.write() {
            *doc = new_doc;
        }

        // Update mtime
        if let Ok(mut mt) = self.last_mtime.write() {
            *mt = Some(current_mtime);
        }

        if let Ok(mut log) = self.audit_log.lock() {
            log.push(PermissionAuditEntry {
                timestamp: SystemTime::now(),
                change_type: PermissionChangeType::FileReloaded,
                subject: String::new(),
                details: format!("Manual reload from '{}'", self.file_path.display()),
            });
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
        self.running.load(Ordering::SeqCst)
    }
}

impl Drop for DynamicPermissionManager {
    fn drop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        if let Ok(mut guard) = self.thread.lock() {
            if let Some(handle) = guard.take() {
                let _ = handle.join();
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Permission checking logic
// ---------------------------------------------------------------------------

/// Single poll cycle for the file watcher: check mtime, reload if changed, audit differences.
fn watcher_poll_cycle(
    file_path: &std::path::Path,
    last_mtime: &Arc<RwLock<Option<SystemTime>>>,
    document: &Arc<RwLock<PermissionDocument>>,
    audit_log: &Arc<Mutex<Vec<PermissionAuditEntry>>>,
) {
    let current_mtime = match std::fs::metadata(file_path).and_then(|m| m.modified()) {
        Ok(mt) => mt,
        Err(_) => return,
    };

    let should_reload = {
        let guard = last_mtime.read().unwrap_or_else(|e| e.into_inner());
        match *guard {
            Some(prev) => current_mtime != prev,
            None => true,
        }
    };

    if !should_reload {
        return;
    }

    let content = match std::fs::read_to_string(file_path) {
        Ok(c) => c,
        Err(e) => {
            if let Ok(mut log) = audit_log.lock() {
                log.push(PermissionAuditEntry {
                    timestamp: SystemTime::now(),
                    change_type: PermissionChangeType::FileError,
                    subject: String::new(),
                    details: format!("Failed to read '{}': {}", file_path.display(), e),
                });
            }
            return;
        }
    };

    match parse_permission_file(&content) {
        Ok(new_doc) => {
            if let Ok(old_doc) = document.read() {
                diff_and_audit(&old_doc, &new_doc, audit_log);
            }
            if let Ok(mut doc) = document.write() {
                *doc = new_doc;
            }
            if let Ok(mut mt) = last_mtime.write() {
                *mt = Some(current_mtime);
            }
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
            if let Ok(mut mt) = last_mtime.write() {
                *mt = Some(current_mtime);
            }
        }
    }
}

/// Check whether an action (publish or subscribe) is allowed for a given
/// subject on a given topic/partition.
///
/// Evaluation order (deny-takes-precedence, matching the existing RulesEngine):
/// 1. Check all deny rules -- if any deny rule matches, return false
/// 2. Check all allow rules -- if any allow rule matches, return true
/// 3. Apply default policy
fn check_action(
    doc: &PermissionDocument,
    subject: &str,
    topic: &str,
    partition: &str,
    is_publish: bool,
) -> bool {
    let target_action = if is_publish {
        RuleAction::Publish
    } else {
        RuleAction::Subscribe
    };

    // Find the permission set for this subject
    let perm_set = match doc.grants.iter().find(|g| g.subject_name == subject) {
        Some(ps) => ps,
        None => return false, // Unknown subject -- deny
    };

    // Step 1: Check deny rules first (deny takes precedence)
    for rule in &perm_set.rules {
        if rule.action != target_action || rule.allow {
            continue;
        }
        if topic_matches(&rule.topic_pattern, topic)
            && partition_matches(&rule.partitions, partition)
        {
            return false; // Explicit deny
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
            return true; // Explicit allow
        }
    }

    // Step 3: No matching rule found -- apply default
    !perm_set.default_deny
}

// ---------------------------------------------------------------------------
// Audit diffing
// ---------------------------------------------------------------------------

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
        if !new.grants.iter().any(|g| g.subject_name == old_grant.subject_name) {
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
        if !old.grants.iter().any(|g| g.subject_name == new_grant.subject_name) {
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
        if let Some(new_grant) = new.grants.iter().find(|g| g.subject_name == old_grant.subject_name) {
            if old_grant.rules != new_grant.rules || old_grant.default_deny != new_grant.default_deny {
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
