// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Hot-reload watcher for QoS profile files.
//!
//! Uses a simple polling approach (checking file mtime) to detect changes
//! in YAML profile files and automatically reload them.
//!
//! # Example
//!
//! ```rust,ignore
//! use hdds::dds::qos::profiles::QosProfileRegistry;
//! use hdds::dds::qos::hot_reload::QosFileWatcher;
//! use std::path::PathBuf;
//! use std::sync::Arc;
//! use std::time::Duration;
//!
//! let registry = Arc::new(QosProfileRegistry::new());
//! registry.load_from_yaml(&PathBuf::from("qos.yaml")).unwrap();
//!
//! let mut watcher = QosFileWatcher::new(
//!     PathBuf::from("qos.yaml"),
//!     registry.clone(),
//!     Duration::from_secs(2),
//! );
//! watcher.start().unwrap();
//!
//! // ... profiles will be auto-reloaded on file changes ...
//!
//! watcher.stop();
//! ```

use super::profiles::{QosProfileRegistry, ReloadResult};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime};

/// Hot-reload watcher that monitors QoS profile files for changes.
///
/// Uses a simple polling approach: periodically checks the file's modification
/// time (mtime) and triggers a reload when it changes. This avoids requiring
/// the `notify` crate or OS-specific file watchers.
pub struct QosFileWatcher {
    /// Path to the YAML profile file being watched.
    path: PathBuf,
    /// Reference to the profile registry to reload.
    registry: Arc<QosProfileRegistry>,
    /// How often to check the file for changes.
    poll_interval: Duration,
    /// Flag to stop the watcher thread.
    running: Arc<AtomicBool>,
    /// Background polling thread handle.
    thread: Option<JoinHandle<()>>,
    /// Last reload result (shared with the watcher thread).
    last_result: Arc<Mutex<Option<ReloadResult>>>,
}

impl QosFileWatcher {
    /// Create a new file watcher (not yet started).
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the YAML profile file to watch
    /// * `registry` - The profile registry to reload on changes
    /// * `poll_interval` - How often to check the file (e.g. `Duration::from_secs(2)`)
    pub fn new(path: PathBuf, registry: Arc<QosProfileRegistry>, poll_interval: Duration) -> Self {
        Self {
            path,
            registry,
            poll_interval,
            running: Arc::new(AtomicBool::new(false)),
            thread: None,
            last_result: Arc::new(Mutex::new(None)),
        }
    }

    /// Start the file watcher in a background thread.
    ///
    /// Returns an error if the watcher is already running or if the file
    /// doesn't exist.
    pub fn start(&mut self) -> Result<(), String> {
        if self.running.load(Ordering::SeqCst) {
            return Err("Watcher is already running".to_string());
        }

        // Verify the file exists before starting
        if !self.path.exists() {
            return Err(format!("File not found: {}", self.path.display()));
        }

        self.running.store(true, Ordering::SeqCst);

        let path = self.path.clone();
        let registry = self.registry.clone();
        let poll_interval = self.poll_interval;
        let running = self.running.clone();
        let last_result = self.last_result.clone();

        // Get initial mtime
        let initial_mtime = get_mtime(&path);

        let handle = thread::Builder::new()
            .name("hdds-qos-watcher".to_string())
            .spawn(move || {
                let mut last_mtime = initial_mtime;

                while running.load(Ordering::SeqCst) {
                    thread::sleep(poll_interval);

                    if !running.load(Ordering::SeqCst) {
                        break;
                    }

                    let current_mtime = get_mtime(&path);

                    // Check if file was modified
                    if current_mtime != last_mtime {
                        last_mtime = current_mtime;

                        // Reload profiles
                        match registry.reload() {
                            Ok(result) => {
                                if result.has_changes() {
                                    log::info!(
                                        "QoS profiles reloaded: {} updated, {} added, {} removed",
                                        result.profiles_updated.len(),
                                        result.profiles_added.len(),
                                        result.profiles_removed.len(),
                                    );
                                }
                                if let Ok(mut guard) = last_result.lock() {
                                    *guard = Some(result);
                                }
                            }
                            Err(e) => {
                                log::warn!("QoS profile reload failed: {}", e);
                                if let Ok(mut guard) = last_result.lock() {
                                    *guard = Some(ReloadResult {
                                        profiles_updated: Vec::new(),
                                        profiles_added: Vec::new(),
                                        profiles_removed: Vec::new(),
                                        errors: vec![e],
                                    });
                                }
                            }
                        }
                    }
                }
            })
            .map_err(|e| format!("Failed to spawn watcher thread: {}", e))?;

        self.thread = Some(handle);
        Ok(())
    }

    /// Stop the file watcher.
    ///
    /// Signals the background thread to stop and waits for it to finish.
    pub fn stop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
    }

    /// Check if the watcher is currently running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Get the result of the last reload operation.
    ///
    /// Returns `None` if no reload has happened yet.
    pub fn last_reload_result(&self) -> Option<ReloadResult> {
        self.last_result.lock().ok().and_then(|guard| guard.clone())
    }
}

impl Drop for QosFileWatcher {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Get file modification time, returning None if the file doesn't exist or
/// metadata can't be read.
fn get_mtime(path: &PathBuf) -> Option<SystemTime> {
    fs::metadata(path).ok().and_then(|m| m.modified().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_temp_yaml(content: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().expect("create temp file");
        f.write_all(content.as_bytes()).expect("write temp file");
        f.flush().expect("flush temp file");
        f
    }

    #[test]
    fn test_watcher_create() {
        let registry = Arc::new(QosProfileRegistry::new());
        let watcher = QosFileWatcher::new(
            PathBuf::from("/tmp/nonexistent.yaml"),
            registry,
            Duration::from_millis(100),
        );
        assert!(!watcher.is_running());
    }

    #[test]
    fn test_watcher_start_nonexistent_file() {
        let registry = Arc::new(QosProfileRegistry::new());
        let mut watcher = QosFileWatcher::new(
            PathBuf::from("/tmp/definitely_not_a_real_file_12345.yaml"),
            registry,
            Duration::from_millis(100),
        );

        let result = watcher.start();
        assert!(result.is_err());
        assert!(!watcher.is_running());
    }

    #[test]
    fn test_watcher_start_stop() {
        let yaml = r#"
profiles:
  test:
    reliability: reliable
"#;
        let file = write_temp_yaml(yaml);
        let registry = Arc::new(QosProfileRegistry::new());
        registry.load_from_yaml(file.path()).expect("initial load");

        let mut watcher = QosFileWatcher::new(
            file.path().to_path_buf(),
            registry,
            Duration::from_millis(50),
        );

        watcher.start().expect("should start");
        assert!(watcher.is_running());

        // Let it run for a bit
        thread::sleep(Duration::from_millis(100));

        watcher.stop();
        assert!(!watcher.is_running());
    }

    #[test]
    fn test_watcher_detects_change() {
        let yaml_v1 = r#"
profiles:
  sensor:
    reliability: best_effort
    deadline_ms: 500
"#;
        let file = write_temp_yaml(yaml_v1);
        let registry = Arc::new(QosProfileRegistry::new());
        registry.load_from_yaml(file.path()).expect("initial load");

        let mut watcher = QosFileWatcher::new(
            file.path().to_path_buf(),
            registry.clone(),
            Duration::from_millis(50),
        );

        watcher.start().expect("should start");

        // Give the watcher time to start
        thread::sleep(Duration::from_millis(100));

        // Modify the file
        let yaml_v2 = r#"
profiles:
  sensor:
    reliability: reliable
    deadline_ms: 200
"#;
        fs::write(file.path(), yaml_v2).expect("write new content");

        // Wait for the watcher to detect the change
        thread::sleep(Duration::from_millis(200));

        // The registry should have been reloaded
        let qos = registry.get("sensor").expect("profile should exist");
        assert_eq!(qos.deadline.period, Duration::from_millis(200));

        watcher.stop();
    }

    #[test]
    fn test_watcher_double_start_fails() {
        let yaml = r#"
profiles:
  test:
    reliability: reliable
"#;
        let file = write_temp_yaml(yaml);
        let registry = Arc::new(QosProfileRegistry::new());
        registry.load_from_yaml(file.path()).expect("initial load");

        let mut watcher = QosFileWatcher::new(
            file.path().to_path_buf(),
            registry,
            Duration::from_millis(50),
        );

        watcher.start().expect("first start");
        let result = watcher.start();
        assert!(result.is_err());

        watcher.stop();
    }

    #[test]
    fn test_watcher_drop_stops_thread() {
        let yaml = r#"
profiles:
  test:
    reliability: reliable
"#;
        let file = write_temp_yaml(yaml);
        let registry = Arc::new(QosProfileRegistry::new());
        registry.load_from_yaml(file.path()).expect("initial load");

        let running_flag;
        {
            let mut watcher = QosFileWatcher::new(
                file.path().to_path_buf(),
                registry,
                Duration::from_millis(50),
            );
            watcher.start().expect("start");
            running_flag = watcher.running.clone();
            assert!(running_flag.load(Ordering::SeqCst));
            // watcher dropped here
        }

        // After drop, the running flag should be false
        assert!(!running_flag.load(Ordering::SeqCst));
    }

    #[test]
    fn test_watcher_last_reload_result_initially_none() {
        let registry = Arc::new(QosProfileRegistry::new());
        let watcher = QosFileWatcher::new(
            PathBuf::from("/tmp/test.yaml"),
            registry,
            Duration::from_millis(100),
        );
        assert!(watcher.last_reload_result().is_none());
    }

    #[test]
    fn test_get_mtime_existing_file() {
        let yaml = "profiles: {}";
        let file = write_temp_yaml(yaml);
        let mtime = get_mtime(&file.path().to_path_buf());
        assert!(mtime.is_some());
    }

    #[test]
    fn test_get_mtime_nonexistent_file() {
        let mtime = get_mtime(&PathBuf::from("/tmp/this_file_does_not_exist_xyz.yaml"));
        assert!(mtime.is_none());
    }
}
