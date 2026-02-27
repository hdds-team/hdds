// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

    use super::*;
    use std::io::Write;

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
        mgr.start_watching(Duration::from_millis(50));
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

        mgr.start_watching(Duration::from_millis(50));

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

        mgr.start_watching(Duration::from_millis(50));

        // Write malformed content
        std::thread::sleep(Duration::from_millis(100));
        std::fs::write(&path, "garbage content here!\n").expect("overwrite");

        // Wait for watcher
        std::thread::sleep(Duration::from_millis(300));

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
