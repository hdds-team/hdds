// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::*;
use std::io::Write;
use std::time::Instant;

/// Helper: write content to a temp file and return its path
fn write_temp_file(content: &str) -> (tempfile::NamedTempFile, PathBuf) {
    let mut f = tempfile::NamedTempFile::new().expect("create temp file");
    f.write_all(content.as_bytes()).expect("write temp file");
    f.flush().expect("flush temp file");
    let path = f.path().to_owned();
    (f, path)
}

const BASIC_PERMS: &str = "\
# Test permission file
[subject: CN=sensor-node-1,O=HDDS]
default: deny
allow publish: sensors/*
deny publish: sensors/secret
allow subscribe: commands/*

[subject: CN=dashboard,O=HDDS]
default: deny
allow subscribe: *
allow publish: commands/*
";

// -----------------------------------------------------------------------
// 1. Load permission document from file
// -----------------------------------------------------------------------
#[test]
fn test_load_permission_document() {
    let doc = parse_permission_file(BASIC_PERMS).unwrap();
    assert_eq!(doc.grants.len(), 2);

    let sensor = &doc.grants[0];
    assert_eq!(sensor.subject_name, "CN=sensor-node-1,O=HDDS");
    assert!(sensor.default_deny);
    assert_eq!(sensor.rules.len(), 3);

    let dashboard = &doc.grants[1];
    assert_eq!(dashboard.subject_name, "CN=dashboard,O=HDDS");
    assert!(dashboard.default_deny);
    assert_eq!(dashboard.rules.len(), 2);
}

// -----------------------------------------------------------------------
// 2. Check publish allowed
// -----------------------------------------------------------------------
#[test]
fn test_check_publish_allowed() {
    let (_f, path) = write_temp_file(BASIC_PERMS);
    let mgr = DynamicPermissionManager::new(path).unwrap();

    assert!(mgr.check_publish("CN=sensor-node-1,O=HDDS", "sensors/temperature", ""));
    assert!(mgr.check_publish("CN=sensor-node-1,O=HDDS", "sensors/pressure", ""));
}

// -----------------------------------------------------------------------
// 3. Check publish denied
// -----------------------------------------------------------------------
#[test]
fn test_check_publish_denied() {
    let (_f, path) = write_temp_file(BASIC_PERMS);
    let mgr = DynamicPermissionManager::new(path).unwrap();

    // sensor-node-1 cannot publish to commands/*
    assert!(!mgr.check_publish("CN=sensor-node-1,O=HDDS", "commands/start", ""));
    // Unknown subject
    assert!(!mgr.check_publish("CN=unknown,O=HDDS", "sensors/temperature", ""));
    // Explicit deny
    assert!(!mgr.check_publish("CN=sensor-node-1,O=HDDS", "sensors/secret", ""));
}

// -----------------------------------------------------------------------
// 4. Check subscribe with glob pattern
// -----------------------------------------------------------------------
#[test]
fn test_check_subscribe_glob() {
    let (_f, path) = write_temp_file(BASIC_PERMS);
    let mgr = DynamicPermissionManager::new(path).unwrap();

    // dashboard can subscribe to anything (*)
    assert!(mgr.check_subscribe("CN=dashboard,O=HDDS", "sensors/temperature", ""));
    assert!(mgr.check_subscribe("CN=dashboard,O=HDDS", "commands/start", ""));
    assert!(mgr.check_subscribe("CN=dashboard,O=HDDS", "any/topic/here", ""));

    // sensor-node-1 can only subscribe to commands/*
    assert!(mgr.check_subscribe("CN=sensor-node-1,O=HDDS", "commands/start", ""));
    assert!(!mgr.check_subscribe("CN=sensor-node-1,O=HDDS", "other/topic", ""));
}

// -----------------------------------------------------------------------
// 5. Default deny works
// -----------------------------------------------------------------------
#[test]
fn test_default_deny() {
    let content = "\
[subject: CN=restricted,O=HDDS]
default: deny
allow publish: one/topic
";
    let (_f, path) = write_temp_file(content);
    let mgr = DynamicPermissionManager::new(path).unwrap();

    // Allowed topic
    assert!(mgr.check_publish("CN=restricted,O=HDDS", "one/topic", ""));
    // Everything else denied
    assert!(!mgr.check_publish("CN=restricted,O=HDDS", "other/topic", ""));
    assert!(!mgr.check_subscribe("CN=restricted,O=HDDS", "one/topic", ""));
}

// -----------------------------------------------------------------------
// 5b. Default allow works
// -----------------------------------------------------------------------
#[test]
fn test_default_allow() {
    let content = "\
[subject: CN=permissive,O=HDDS]
default: allow
deny publish: secret/topic
";
    let (_f, path) = write_temp_file(content);
    let mgr = DynamicPermissionManager::new(path).unwrap();

    // Explicit deny
    assert!(!mgr.check_publish("CN=permissive,O=HDDS", "secret/topic", ""));
    // Everything else allowed by default
    assert!(mgr.check_publish("CN=permissive,O=HDDS", "any/topic", ""));
    assert!(mgr.check_subscribe("CN=permissive,O=HDDS", "any/topic", ""));
}

// -----------------------------------------------------------------------
// 6. Reload detects file change
// -----------------------------------------------------------------------
#[test]
fn test_reload_detects_change() {
    let mut f = tempfile::NamedTempFile::new().expect("create temp file");
    f.write_all(BASIC_PERMS.as_bytes()).expect("write");
    f.flush().expect("flush");
    let path = f.path().to_owned();

    let mgr = DynamicPermissionManager::new(path.clone()).unwrap();

    // Initial: sensor can publish to sensors/*
    assert!(mgr.check_publish("CN=sensor-node-1,O=HDDS", "sensors/temperature", ""));

    // Unchanged reload
    let result = mgr.reload().unwrap();
    assert_eq!(result, ReloadResult::Unchanged);

    // Modify the file (sleep a bit to ensure mtime changes)
    std::thread::sleep(Duration::from_millis(50));
    let new_content = "\
[subject: CN=sensor-node-1,O=HDDS]
default: deny
allow publish: actuators/*
";
    std::fs::write(&path, new_content).expect("overwrite file");

    // Force a small sleep to let filesystem update mtime
    std::thread::sleep(Duration::from_millis(50));

    let result = mgr.reload().unwrap();
    assert_eq!(result, ReloadResult::Reloaded);

    // Now sensor can only publish to actuators/*
    assert!(!mgr.check_publish("CN=sensor-node-1,O=HDDS", "sensors/temperature", ""));
    assert!(mgr.check_publish("CN=sensor-node-1,O=HDDS", "actuators/motor", ""));
}

// -----------------------------------------------------------------------
// 7. Revoked permission blocks access
// -----------------------------------------------------------------------
#[test]
fn test_revoked_permission_blocks() {
    let mut f = tempfile::NamedTempFile::new().expect("create temp file");
    f.write_all(BASIC_PERMS.as_bytes()).expect("write");
    f.flush().expect("flush");
    let path = f.path().to_owned();

    let mgr = DynamicPermissionManager::new(path.clone()).unwrap();

    // Initially dashboard can subscribe to everything
    assert!(mgr.check_subscribe("CN=dashboard,O=HDDS", "sensors/temperature", ""));

    // Revoke dashboard permissions by removing it
    std::thread::sleep(Duration::from_millis(50));
    let new_content = "\
[subject: CN=sensor-node-1,O=HDDS]
default: deny
allow publish: sensors/*
";
    std::fs::write(&path, new_content).expect("overwrite file");
    std::thread::sleep(Duration::from_millis(50));

    let result = mgr.reload().unwrap();
    assert_eq!(result, ReloadResult::Reloaded);

    // Dashboard now has no permissions (unknown subject => deny)
    assert!(!mgr.check_subscribe("CN=dashboard,O=HDDS", "sensors/temperature", ""));
}

// -----------------------------------------------------------------------
// 8. Audit log records changes
// -----------------------------------------------------------------------
#[test]
fn test_audit_log_records_changes() {
    let mut f = tempfile::NamedTempFile::new().expect("create temp file");
    f.write_all(BASIC_PERMS.as_bytes()).expect("write");
    f.flush().expect("flush");
    let path = f.path().to_owned();

    let mgr = DynamicPermissionManager::new(path.clone()).unwrap();

    // Initial load audit
    let log = mgr.audit_log();
    assert!(!log.is_empty());
    assert_eq!(log[0].change_type, PermissionChangeType::FileReloaded);

    // Modify file to remove dashboard
    std::thread::sleep(Duration::from_millis(50));
    let new_content = "\
[subject: CN=sensor-node-1,O=HDDS]
default: deny
allow publish: sensors/*
";
    std::fs::write(&path, new_content).expect("overwrite");
    std::thread::sleep(Duration::from_millis(50));

    mgr.reload().unwrap();

    let log = mgr.audit_log();
    // Should have: initial FileReloaded, Revoked (dashboard removed), FileReloaded
    assert!(log.len() >= 3);

    let revoked_entries: Vec<_> = log
        .iter()
        .filter(|e| e.change_type == PermissionChangeType::Revoked)
        .collect();
    assert!(!revoked_entries.is_empty());
    assert!(revoked_entries[0].subject.contains("dashboard"));
}

// -----------------------------------------------------------------------
// 9. Malformed file keeps old permissions
// -----------------------------------------------------------------------
#[test]
fn test_malformed_file_keeps_old() {
    let mut f = tempfile::NamedTempFile::new().expect("create temp file");
    f.write_all(BASIC_PERMS.as_bytes()).expect("write");
    f.flush().expect("flush");
    let path = f.path().to_owned();

    let mgr = DynamicPermissionManager::new(path.clone()).unwrap();

    // Verify initial permissions work
    assert!(mgr.check_publish("CN=sensor-node-1,O=HDDS", "sensors/temperature", ""));

    // Write malformed content
    std::thread::sleep(Duration::from_millis(50));
    std::fs::write(&path, "this is not valid permission format at all!!!").expect("overwrite");
    std::thread::sleep(Duration::from_millis(50));

    // Reload should fail but not crash
    // (manual reload returns the parse error, but old perms remain)
    let result = mgr.reload();
    assert!(result.is_err());

    // Old permissions should still be in effect
    assert!(mgr.check_publish("CN=sensor-node-1,O=HDDS", "sensors/temperature", ""));
}

// -----------------------------------------------------------------------
// 10. Topic glob matching
// -----------------------------------------------------------------------
#[test]
fn test_topic_glob_matching() {
    assert!(topic_matches("*", "anything"));
    assert!(topic_matches("*", "multi/level/topic"));
    assert!(topic_matches("**", "anything"));
    assert!(topic_matches("sensors/*", "sensors/temp"));
    assert!(topic_matches("sensors/*", "sensors/pressure"));
    assert!(!topic_matches("sensors/*", "actuators/motor"));
    assert!(!topic_matches("sensors/*", "sensors")); // must have slash
    assert!(topic_matches("data/raw", "data/raw"));
    assert!(!topic_matches("data/raw", "data/cooked"));
    assert!(topic_matches("a/b/**", "a/b/c"));
    assert!(topic_matches("a/b/**", "a/b/c/d"));
}

// -----------------------------------------------------------------------
// 11. Partition filtering
// -----------------------------------------------------------------------
#[test]
fn test_partition_filtering() {
    let content = "\
[subject: CN=partitioned,O=HDDS]
default: deny
allow publish: data/* partitions=region-a,region-b
";
    let (_f, path) = write_temp_file(content);
    let mgr = DynamicPermissionManager::new(path).unwrap();

    // Allowed partitions
    assert!(mgr.check_publish("CN=partitioned,O=HDDS", "data/temperature", "region-a"));
    assert!(mgr.check_publish("CN=partitioned,O=HDDS", "data/temperature", "region-b"));
    // Denied partition
    assert!(!mgr.check_publish("CN=partitioned,O=HDDS", "data/temperature", "region-c"));
    // Empty partition -- rule has partitions, so empty does not match
    assert!(!mgr.check_publish("CN=partitioned,O=HDDS", "data/temperature", ""));
}

// -----------------------------------------------------------------------
// 12. File watcher thread start/stop
// -----------------------------------------------------------------------
#[test]
fn test_watcher_start_stop() {
    let (_f, path) = write_temp_file(BASIC_PERMS);
    let mgr = DynamicPermissionManager::new(path).unwrap();

    assert!(!mgr.is_watching());
    mgr.start_watching(Duration::from_millis(50))
        .expect("the watcher thread must start");
    assert!(mgr.is_watching());
    mgr.stop_watching();
    assert!(!mgr.is_watching());
}

// -----------------------------------------------------------------------
// 13. Parse error on empty subject
// -----------------------------------------------------------------------
#[test]
fn test_parse_error_empty_subject() {
    let content = "[subject: ]\ndefault: deny\n";
    let result = parse_permission_file(content);
    assert!(result.is_err());
}

// -----------------------------------------------------------------------
// 14. Parse error on rule outside subject block
// -----------------------------------------------------------------------
#[test]
fn test_parse_error_rule_outside_subject() {
    let content = "allow publish: sensors/*\n";
    let result = parse_permission_file(content);
    assert!(result.is_err());
}

// -----------------------------------------------------------------------
// 15. Watcher auto-reloads on file change
// -----------------------------------------------------------------------
#[test]
fn test_watcher_auto_reloads() {
    let mut f = tempfile::NamedTempFile::new().expect("create temp file");
    f.write_all(BASIC_PERMS.as_bytes()).expect("write");
    f.flush().expect("flush");
    let path = f.path().to_owned();

    let mgr = DynamicPermissionManager::new(path.clone()).unwrap();
    assert!(mgr.check_publish("CN=sensor-node-1,O=HDDS", "sensors/temperature", ""));

    mgr.start_watching(Duration::from_millis(50))
        .expect("the watcher thread must start");

    // Modify file
    std::thread::sleep(Duration::from_millis(100));
    let new_content = "\
[subject: CN=sensor-node-1,O=HDDS]
default: deny
allow publish: actuators/*
";
    std::fs::write(&path, new_content).expect("overwrite");

    // Wait for watcher to pick it up
    std::thread::sleep(Duration::from_millis(300));

    // Check new permissions
    assert!(!mgr.check_publish("CN=sensor-node-1,O=HDDS", "sensors/temperature", ""));
    assert!(mgr.check_publish("CN=sensor-node-1,O=HDDS", "actuators/motor", ""));

    mgr.stop_watching();
}

// -----------------------------------------------------------------------
// 16. Watcher keeps old perms on malformed file
// -----------------------------------------------------------------------
#[test]
fn test_watcher_keeps_old_on_malformed() {
    let mut f = tempfile::NamedTempFile::new().expect("create temp file");
    f.write_all(BASIC_PERMS.as_bytes()).expect("write");
    f.flush().expect("flush");
    let path = f.path().to_owned();

    let mgr = DynamicPermissionManager::new(path.clone()).unwrap();
    assert!(mgr.check_publish("CN=sensor-node-1,O=HDDS", "sensors/temperature", ""));

    mgr.start_watching(Duration::from_millis(50))
        .expect("the watcher thread must start");

    // Write malformed content ATOMICALLY: write to a sibling path, then
    // rename(2) it over the target. `std::fs::write` on the target path
    // directly is truncate-then-write as two separate syscalls on the very
    // file the watcher polls; under load the watcher thread can be
    // scheduled to read in between them and observe a transient EMPTY
    // file, which `parse_permission_file` accepts as a VALID document with
    // zero grants instead of erroring on it -- that is not the "malformed
    // file" scenario this test means to exercise, it is an artifact of a
    // racy write, and under load it would fail the "old permissions still
    // in effect" assertion because the watcher had swapped in that empty
    // document.
    // A rename is a single atomic step, so the watcher's read is always of
    // the old content or the fully-written new content, never a partial one.
    std::thread::sleep(Duration::from_millis(100));
    let tmp_path = path.with_extension("tmp-overwrite");
    std::fs::write(&tmp_path, "garbage content here!\n").expect("write temp overwrite");
    std::fs::rename(&tmp_path, &path).expect("atomically replace with malformed content");

    // Wait for the watcher to notice and reject it instead of sleeping a
    // fixed duration: on a loaded box a bound that is generous when idle
    // (300 ms, for a thread polling every 50 ms) is not generous at all
    // once the watcher thread itself has to wait its turn for a CPU.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let has_file_error = mgr
            .audit_log()
            .iter()
            .any(|e| e.change_type == PermissionChangeType::FileError);
        if has_file_error || Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    // Old permissions still in effect
    assert!(mgr.check_publish("CN=sensor-node-1,O=HDDS", "sensors/temperature", ""));

    // Audit log should have a FileError entry
    let log = mgr.audit_log();
    let errors: Vec<_> = log
        .iter()
        .filter(|e| e.change_type == PermissionChangeType::FileError)
        .collect();
    assert!(!errors.is_empty());

    mgr.stop_watching();
}

// -----------------------------------------------------------------------
// 17. A torn, non-atomic write must not get stuck on a partial document,
//     even when the final write lands on the SAME mtime as the torn read.
// -----------------------------------------------------------------------
//
// These two tests drive `watcher_poll_cycle` DIRECTLY instead of through
// `start_watching`'s background thread: the whole point is to control,
// byte for byte, exactly what the watcher observes at each discrete poll,
// which a timer-driven thread cannot give deterministically. Accessing
// the manager's private fields from here is normal Rust privacy: this
// module is a child of `dynamic`, declared with `#[path = ...] mod tests`
// inside it.
#[test]
fn test_torn_write_same_mtime_eventually_applies_complete_document() {
    let mut f = tempfile::NamedTempFile::new().expect("create temp file");
    f.write_all(BASIC_PERMS.as_bytes()).expect("write");
    f.flush().expect("flush");
    let path = f.path().to_owned();

    let mgr = DynamicPermissionManager::new(path.clone()).unwrap();
    assert!(mgr.check_publish("CN=sensor-node-1,O=HDDS", "sensors/temperature", ""));

    let full_content = "\
[subject: CN=sensor-node-1,O=HDDS]
default: deny
allow publish: actuators/*
allow subscribe: commands/*
";
    // A prefix of `full_content` that is ITSELF a syntactically valid,
    // parseable document -- a strict subset of the final grants. This is
    // the dangerous case named in the defect: a torn read that parses
    // fine but is not what the writer meant to land.
    let half_content = "\
[subject: CN=sensor-node-1,O=HDDS]
default: deny
allow publish: actuators/*
";
    assert_ne!(half_content, full_content);
    parse_permission_file(half_content).expect("fixture half must itself be valid");

    // Write the first half, non-atomically (plain truncate-then-write),
    // and let the watcher poll it.
    std::fs::write(&path, half_content).expect("write torn half");
    let half_mtime = std::fs::metadata(&path)
        .expect("stat half")
        .modified()
        .expect("mtime half");
    watcher_poll_cycle(
        &path,
        &mgr.watch_debounce,
        &mgr.document,
        &mgr.audit_log,
        &mgr.generation,
    );

    // Now write the rest, and force the SAME mtime the half-write landed
    // on -- simulating two writes close enough together to land in the
    // same filesystem mtime tick, which is the realistic trigger named in
    // the defect ("the complete content is NEVER reloaded" when mtime
    // alone drives the reload decision).
    std::fs::write(&path, full_content).expect("write torn rest");
    let f = std::fs::File::options()
        .write(true)
        .open(&path)
        .expect("reopen to force mtime");
    f.set_modified(half_mtime)
        .expect("force same mtime as the half-write");

    // Poll repeatedly (never a fixed sleep): the reload must converge within
    // a bounded number of polls even though mtime never moves again.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        watcher_poll_cycle(
            &path,
            &mgr.watch_debounce,
            &mgr.document,
            &mgr.audit_log,
            &mgr.generation,
        );
        let converged = !mgr.check_publish("CN=sensor-node-1,O=HDDS", "sensors/temperature", "")
            && mgr.check_publish("CN=sensor-node-1,O=HDDS", "actuators/motor", "")
            && mgr.check_subscribe("CN=sensor-node-1,O=HDDS", "commands/start", "");
        if converged || Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }

    assert!(
        !mgr.check_publish("CN=sensor-node-1,O=HDDS", "sensors/temperature", ""),
        "the complete document drops the old sensors/* grant"
    );
    assert!(
        mgr.check_publish("CN=sensor-node-1,O=HDDS", "actuators/motor", ""),
        "the COMPLETE document must end up in force, not the torn half"
    );
    assert!(
        mgr.check_subscribe("CN=sensor-node-1,O=HDDS", "commands/start", ""),
        "the complete document's second rule (absent from the torn half) must also apply"
    );
}

// -----------------------------------------------------------------------
// 18. A transient empty file between two valid documents must never be
//     applied, even though it parses as a perfectly valid zero-grant
//     document -- it would deny everything until the real content lands.
// -----------------------------------------------------------------------
#[test]
fn test_transient_empty_file_never_applied_between_two_valid_docs() {
    let mut f = tempfile::NamedTempFile::new().expect("create temp file");
    f.write_all(BASIC_PERMS.as_bytes()).expect("write");
    f.flush().expect("flush");
    let path = f.path().to_owned();

    let mgr = DynamicPermissionManager::new(path.clone()).unwrap();
    assert!(mgr.check_publish("CN=sensor-node-1,O=HDDS", "sensors/temperature", ""));
    let reloads_before = mgr
        .audit_log()
        .iter()
        .filter(|e| e.change_type == PermissionChangeType::FileReloaded)
        .count();
    assert_eq!(reloads_before, 1, "only the initial load so far");

    // Simulate a non-atomic rewrite: truncate to empty (most editors and
    // `echo >` do exactly this as two separate syscalls) and let the
    // watcher poll while the file is momentarily empty.
    std::fs::write(&path, "").expect("truncate to empty");
    watcher_poll_cycle(
        &path,
        &mgr.watch_debounce,
        &mgr.document,
        &mgr.audit_log,
        &mgr.generation,
    );

    // The empty read must never have been applied: a zero-grant document
    // denies the publish this subject was granted a moment ago, and no
    // reload should have been logged for it.
    assert!(
        mgr.check_publish("CN=sensor-node-1,O=HDDS", "sensors/temperature", ""),
        "a transient empty file must never be applied"
    );
    let reloads_after_empty = mgr
        .audit_log()
        .iter()
        .filter(|e| e.change_type == PermissionChangeType::FileReloaded)
        .count();
    assert_eq!(
        reloads_after_empty, 1,
        "no FileReloaded should be logged for a transient empty read"
    );

    // Now the writer finishes landing the real new content.
    let next_content = "\
[subject: CN=sensor-node-1,O=HDDS]
default: deny
allow publish: actuators/*
";
    std::fs::write(&path, next_content).expect("write the real content");

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        watcher_poll_cycle(
            &path,
            &mgr.watch_debounce,
            &mgr.document,
            &mgr.audit_log,
            &mgr.generation,
        );
        let converged = !mgr.check_publish("CN=sensor-node-1,O=HDDS", "sensors/temperature", "")
            && mgr.check_publish("CN=sensor-node-1,O=HDDS", "actuators/motor", "");
        if converged || Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }

    assert!(
        mgr.check_publish("CN=sensor-node-1,O=HDDS", "actuators/motor", ""),
        "the real final content must eventually be in force"
    );
    assert!(!mgr.check_publish("CN=sensor-node-1,O=HDDS", "sensors/temperature", ""));
}

// -----------------------------------------------------------------------
// 19. A manual `reload()` must update the SAME debounce state the
//     background watcher reads, not just `last_mtime`. Otherwise the
//     watcher still believes the content from BEFORE the manual reload
//     is settled, reads the content the manual reload just applied as if
//     it were unseen, and -- once it has read that same content on two
//     consecutive polls -- re-"confirms" and re-applies it, logging a
//     second `FileReloaded` for a change that was already in force.
// -----------------------------------------------------------------------
#[test]
fn test_manual_reload_then_noop_polls_logs_exactly_one_reload_per_change() {
    let (_f, path) = write_temp_file(BASIC_PERMS);
    let mgr = DynamicPermissionManager::new(path.clone()).unwrap();

    let reload_count = |mgr: &DynamicPermissionManager| {
        mgr.audit_log()
            .iter()
            .filter(|e| e.change_type == PermissionChangeType::FileReloaded)
            .count()
    };
    assert_eq!(reload_count(&mgr), 1, "only the initial load so far");

    let changed = "\
[subject: CN=sensor-node-1,O=HDDS]
default: deny
allow publish: actuators/*
allow subscribe: commands/*
";
    std::fs::write(&path, changed).expect("write changed content");

    assert_eq!(
        mgr.reload().unwrap(),
        ReloadResult::Reloaded,
        "mtime moved, so a manual reload must apply it"
    );
    assert_eq!(
        reload_count(&mgr),
        2,
        "the manual reload logs exactly one FileReloaded for this real change"
    );
    assert!(mgr.check_publish("CN=sensor-node-1,O=HDDS", "actuators/motor", ""));

    // The file does not change again. Several watcher polls over the
    // SAME content the manual reload already applied must never log a
    // second FileReloaded for it: one real change, one FileReloaded.
    for _ in 0..5 {
        watcher_poll_cycle(
            &path,
            &mgr.watch_debounce,
            &mgr.document,
            &mgr.audit_log,
            &mgr.generation,
        );
    }
    assert_eq!(
        reload_count(&mgr),
        2,
        "no-op watcher polls after a manual reload must not add a FileReloaded"
    );
}

// -----------------------------------------------------------------------
// 20. A file that becomes unreadable (permission denied, or deleted and
//     never replaced) must log exactly one FileError for the transition,
//     never one per poll, and must never disturb the document already in
//     force. Recovering (a read succeeds again) must not itself log
//     anything; a NEW failure after that recovery must log a second,
//     independent FileError.
// -----------------------------------------------------------------------
#[cfg(unix)]
#[test]
fn test_unreadable_file_logs_file_error_once_per_transition() {
    use std::os::unix::fs::PermissionsExt;

    // Root ignores file permission bits entirely, so chmod 000 would not
    // make the file unreadable and this test's premise would not hold.
    if unsafe { libc::geteuid() } == 0 {
        eprintln!(
            "skipping test_unreadable_file_logs_file_error_once_per_transition: \
             running as root, chmod 000 does not deny root a read"
        );
        return;
    }

    let (_f, path) = write_temp_file(BASIC_PERMS);
    let mgr = DynamicPermissionManager::new(path.clone()).unwrap();
    assert!(mgr.check_publish("CN=sensor-node-1,O=HDDS", "sensors/temperature", ""));

    let file_error_count = |mgr: &DynamicPermissionManager| {
        mgr.audit_log()
            .iter()
            .filter(|e| e.change_type == PermissionChangeType::FileError)
            .count()
    };
    let reload_count = |mgr: &DynamicPermissionManager| {
        mgr.audit_log()
            .iter()
            .filter(|e| e.change_type == PermissionChangeType::FileReloaded)
            .count()
    };
    assert_eq!(file_error_count(&mgr), 0, "nothing has failed yet");

    // A content change that, if it were ever (wrongly) applied while the
    // file is unreadable, would be visible: it drops the sensors/* grant
    // the initial document held. Written BEFORE the chmod, while the file
    // is still writable, so its mtime moves -- otherwise chmod alone
    // leaves (len, mtime) exactly as the already-settled content left it
    // and the watcher's cheap pre-check would skip the read entirely.
    let content_b = "\
[subject: CN=sensor-node-1,O=HDDS]
default: deny
allow publish: actuators/*
";
    std::fs::write(&path, content_b).expect("write content B");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).expect("chmod 000");

    // Several polls over the same unreadable file: exactly one FileError,
    // never one per poll, and the OLD document (content A) stays in
    // force -- content B is never applied, because it is never read.
    for _ in 0..4 {
        watcher_poll_cycle(
            &path,
            &mgr.watch_debounce,
            &mgr.document,
            &mgr.audit_log,
            &mgr.generation,
        );
    }
    assert_eq!(
        file_error_count(&mgr),
        1,
        "a read error logs FileError once per transition, not once per poll"
    );
    assert!(
        mgr.check_publish("CN=sensor-node-1,O=HDDS", "sensors/temperature", ""),
        "the old document must stay in force while the file is unreadable"
    );
    assert!(
        !mgr.check_publish("CN=sensor-node-1,O=HDDS", "actuators/motor", ""),
        "content B must never have been applied: it was never successfully read"
    );

    // Recover: the file becomes readable again, still holding content B
    // (never yet applied). The usual two-poll content debounce confirms
    // and applies it; recovering must not itself log a FileError.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod 644");
    watcher_poll_cycle(
        &path,
        &mgr.watch_debounce,
        &mgr.document,
        &mgr.audit_log,
        &mgr.generation,
    );
    watcher_poll_cycle(
        &path,
        &mgr.watch_debounce,
        &mgr.document,
        &mgr.audit_log,
        &mgr.generation,
    );
    assert_eq!(
        file_error_count(&mgr),
        1,
        "recovering (a read succeeding again) must not itself log a FileError"
    );
    assert!(
        mgr.check_publish("CN=sensor-node-1,O=HDDS", "actuators/motor", ""),
        "content B must apply once the file is readable and confirmed"
    );
    assert_eq!(
        reload_count(&mgr),
        2,
        "the initial load plus the recovered content B"
    );

    // A NEW failure after that recovery must log a SECOND, independent
    // FileError -- the first transition's guard must not swallow it.
    let content_c = "\
[subject: CN=sensor-node-1,O=HDDS]
default: deny
allow publish: actuators/*
allow subscribe: commands/*
";
    std::fs::write(&path, content_c).expect("write content C");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000))
        .expect("chmod 000 again");

    for _ in 0..4 {
        watcher_poll_cycle(
            &path,
            &mgr.watch_debounce,
            &mgr.document,
            &mgr.audit_log,
            &mgr.generation,
        );
    }
    assert_eq!(
        file_error_count(&mgr),
        2,
        "a new failure after a recovery logs a second FileError"
    );

    // A single successful read clears the `unreadable` streak right
    // away, even when it only reaches the first, unconfirmed candidate
    // and never the confirmed-and-applied content: recovery is "a read
    // succeeded", not "a reload happened". Recover (content C still on
    // disk from above), poll exactly once -- landing on the unconfirmed
    // first candidate, never reaching `mark_settled` -- then fail again
    // before a second poll could ever confirm it.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
        .expect("chmod 644 for the unconfirmed recovery");
    watcher_poll_cycle(
        &path,
        &mgr.watch_debounce,
        &mgr.document,
        &mgr.audit_log,
        &mgr.generation,
    );
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000))
        .expect("chmod 000 before the recovery is ever confirmed");
    watcher_poll_cycle(
        &path,
        &mgr.watch_debounce,
        &mgr.document,
        &mgr.audit_log,
        &mgr.generation,
    );
    assert_eq!(
        file_error_count(&mgr),
        3,
        "even an unconfirmed successful read must clear the unreadable streak, \
         so failing again right after logs a third, independent FileError"
    );

    // Restore a readable file so the temp file's own Drop can remove it.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
        .expect("restore permissions for cleanup");
}

// -----------------------------------------------------------------------
// 21. A manual `reload()` must apply a real content change even when the
//     rewrite lands on the SAME mtime as the content currently applied
//     (coarse filesystem timestamp granularity, or two writes close
//     together). Deciding on mtime alone would read
//     this as "nothing to do" and a permissions restriction would be silently
//     never applied. Unlike the torn-write tests above, this is not a
//     transient state settling over several polls: the new content is
//     real and final from the first read, so one `reload()` call must be
//     enough.
// -----------------------------------------------------------------------
#[test]
fn test_reload_applies_real_change_under_an_unmoved_mtime() {
    let (_f, path) = write_temp_file(BASIC_PERMS);
    let mgr = DynamicPermissionManager::new(path.clone()).unwrap();
    assert!(mgr.check_publish("CN=sensor-node-1,O=HDDS", "sensors/temperature", ""));

    let original_mtime = std::fs::metadata(&path)
        .expect("stat original")
        .modified()
        .expect("mtime original");

    let changed = "\
[subject: CN=sensor-node-1,O=HDDS]
default: deny
allow publish: actuators/*
";
    assert_ne!(changed, BASIC_PERMS);
    std::fs::write(&path, changed).expect("write changed content");

    // Force the mtime right back to what it was before this write -- the
    // realistic case of a filesystem whose timestamp tick is coarser than
    // the time between the two writes.
    let f = std::fs::File::options()
        .write(true)
        .open(&path)
        .expect("reopen to force mtime");
    f.set_modified(original_mtime)
        .expect("force the original mtime back onto the new content");
    assert_eq!(
        std::fs::metadata(&path)
            .expect("stat after forcing mtime")
            .modified()
            .expect("mtime after forcing"),
        original_mtime,
        "the fixture must actually land on an unmoved mtime, or this test proves nothing"
    );

    assert_eq!(
        mgr.reload().unwrap(),
        ReloadResult::Reloaded,
        "mtime did not move, but the content did: a manual reload must still apply it"
    );
    assert!(
        !mgr.check_publish("CN=sensor-node-1,O=HDDS", "sensors/temperature", ""),
        "the old sensors/* grant must be gone"
    );
    assert!(
        mgr.check_publish("CN=sensor-node-1,O=HDDS", "actuators/motor", ""),
        "the new actuators/* grant must be in force"
    );

    // Calling reload() again on the same, now-applied content must report
    // Unchanged -- the content comparison, not a one-shot side effect.
    assert_eq!(mgr.reload().unwrap(), ReloadResult::Unchanged);
}

// -----------------------------------------------------------------------
// 22. `generation()` moves exactly on a document replacement, by either
//     `reload()` or the watcher thread, and never on a no-op poll.
// -----------------------------------------------------------------------
//
// This is the counter a remote-admission cache (DiscoveryFsm) keys its
// verdicts on, so that a revoking reload is noticed without a per-packet
// re-check (DDS-Security v1.1 Sec.8.4.2.9). Mutant: delete either
// `generation.fetch_add` call (manual `reload()` or `watcher_poll_cycle`)
// and this test catches it -- the value stays frozen across a real
// content change on that path.
#[test]
fn generation_moves_only_on_an_actual_document_replacement() {
    let (_f, path) = write_temp_file(BASIC_PERMS);
    let mgr = DynamicPermissionManager::new(path.clone()).unwrap();
    let initial = mgr.generation();

    // A poll that changes nothing (same bytes) must not move it.
    watcher_poll_cycle(
        &path,
        &mgr.watch_debounce,
        &mgr.document,
        &mgr.audit_log,
        &mgr.generation,
    );
    assert_eq!(mgr.generation(), initial, "no content change, no move");

    // A manual reload of genuinely new content moves it by exactly one.
    let revoked = "\
[subject: CN=sensor-node-1,O=HDDS]
default: deny
deny publish: sensors/*
";
    std::fs::write(&path, revoked).expect("write revoked content");
    assert_eq!(mgr.reload().unwrap(), ReloadResult::Reloaded);
    assert_eq!(
        mgr.generation(),
        initial + 1,
        "reload() must move the generation by exactly one"
    );
    assert!(!mgr.check_publish("CN=sensor-node-1,O=HDDS", "sensors/temperature", ""));

    // A second manual reload with nothing new must not move it again.
    assert_eq!(mgr.reload().unwrap(), ReloadResult::Unchanged);
    assert_eq!(mgr.generation(), initial + 1, "unchanged reload, no move");

    // The watcher thread's own swap path moves it too, driven the same
    // way the earlier torn-write tests drive `watcher_poll_cycle` directly.
    let via_watcher = "\
[subject: CN=sensor-node-1,O=HDDS]
default: deny
allow publish: sensors/*
";
    std::fs::write(&path, via_watcher).expect("write content for the watcher path");
    // Two identical polls: the first only RECORDS the candidate (torn-read
    // protection), the second CONFIRMS and applies it (see `ReloadDebounce`).
    watcher_poll_cycle(
        &path,
        &mgr.watch_debounce,
        &mgr.document,
        &mgr.audit_log,
        &mgr.generation,
    );
    watcher_poll_cycle(
        &path,
        &mgr.watch_debounce,
        &mgr.document,
        &mgr.audit_log,
        &mgr.generation,
    );
    assert_eq!(
        mgr.generation(),
        initial + 2,
        "the watcher thread's own swap must move the generation too"
    );
    assert!(mgr.check_publish("CN=sensor-node-1,O=HDDS", "sensors/temperature", ""));
}
