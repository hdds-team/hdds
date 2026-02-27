// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Log output destinations: file (with rotation), stdout, syslog.

use crate::SyslogFacility;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};

/// Output configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum OutputConfig {
    /// Write to stdout.
    #[default]
    Stdout,
    /// Write to stderr.
    Stderr,
    /// Write to file with optional rotation.
    File {
        path: PathBuf,
        rotation: Option<FileRotation>,
    },
    /// Write to syslog daemon.
    Syslog { facility: SyslogFacility },
}

/// File rotation configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileRotation {
    /// Maximum file size in bytes before rotation.
    pub max_size: u64,
    /// Maximum number of rotated files to keep.
    pub max_files: u32,
    /// Compress rotated files (gzip).
    pub compress: bool,
}

impl Default for FileRotation {
    fn default() -> Self {
        Self {
            max_size: 10 * 1024 * 1024, // 10 MB
            max_files: 5,
            compress: false,
        }
    }
}

impl FileRotation {
    /// Create rotation config with size in megabytes.
    pub fn with_max_size_mb(mb: u64) -> Self {
        Self {
            max_size: mb * 1024 * 1024,
            ..Default::default()
        }
    }

    /// Set maximum number of backup files.
    pub fn max_files(mut self, count: u32) -> Self {
        self.max_files = count;
        self
    }

    /// Enable compression of rotated files.
    pub fn compressed(mut self) -> Self {
        self.compress = true;
        self
    }
}

/// Log output trait.
pub trait LogOutput: Send {
    /// Write a formatted log line.
    fn write(&mut self, line: &str) -> io::Result<()>;

    /// Flush output.
    fn flush(&mut self) -> io::Result<()>;
}

/// Stdout output.
pub struct StdoutOutput {
    handle: io::Stdout,
}

impl StdoutOutput {
    pub fn new() -> Self {
        Self {
            handle: io::stdout(),
        }
    }
}

impl Default for StdoutOutput {
    fn default() -> Self {
        Self::new()
    }
}

impl LogOutput for StdoutOutput {
    fn write(&mut self, line: &str) -> io::Result<()> {
        writeln!(self.handle, "{}", line)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.handle.flush()
    }
}

/// Stderr output.
pub struct StderrOutput {
    handle: io::Stderr,
}

impl StderrOutput {
    pub fn new() -> Self {
        Self {
            handle: io::stderr(),
        }
    }
}

impl Default for StderrOutput {
    fn default() -> Self {
        Self::new()
    }
}

impl LogOutput for StderrOutput {
    fn write(&mut self, line: &str) -> io::Result<()> {
        writeln!(self.handle, "{}", line)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.handle.flush()
    }
}

/// File output with optional rotation.
pub struct FileOutput {
    path: PathBuf,
    writer: BufWriter<File>,
    rotation: Option<FileRotation>,
    current_size: u64,
}

impl FileOutput {
    /// Open file for logging.
    pub fn open(path: impl AsRef<Path>, rotation: Option<FileRotation>) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();

        // Create parent directories if needed
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let file = OpenOptions::new().create(true).append(true).open(&path)?;

        let current_size = file.metadata()?.len();
        let writer = BufWriter::new(file);

        Ok(Self {
            path,
            writer,
            rotation,
            current_size,
        })
    }

    /// Check if rotation is needed and perform it.
    fn maybe_rotate(&mut self) -> io::Result<()> {
        let rotation = match &self.rotation {
            Some(r) if self.current_size >= r.max_size => r.clone(),
            _ => return Ok(()),
        };

        // Flush and close current file
        self.writer.flush()?;

        // Rotate files: .log.4 -> .log.5, .log.3 -> .log.4, etc.
        for i in (1..rotation.max_files).rev() {
            let old_path = rotated_path(&self.path, i);
            let new_path = rotated_path(&self.path, i + 1);
            if old_path.exists() {
                if i + 1 >= rotation.max_files {
                    std::fs::remove_file(&old_path)?;
                } else {
                    std::fs::rename(&old_path, &new_path)?;
                }
            }
        }

        // Rename current to .1
        let rotated = rotated_path(&self.path, 1);
        std::fs::rename(&self.path, &rotated)?;

        // Compress if enabled
        if rotation.compress {
            // Compression would require flate2 or similar - skip for now
            // compress_file(&rotated)?;
        }

        // Open new file
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;

        self.writer = BufWriter::new(file);
        self.current_size = 0;

        Ok(())
    }
}

impl LogOutput for FileOutput {
    fn write(&mut self, line: &str) -> io::Result<()> {
        self.maybe_rotate()?;

        let bytes = line.as_bytes();
        self.writer.write_all(bytes)?;
        self.writer.write_all(b"\n")?;
        self.current_size += bytes.len() as u64 + 1;

        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

/// Generate rotated file path.
fn rotated_path(base: &Path, index: u32) -> PathBuf {
    let stem = base.file_stem().unwrap_or_default().to_string_lossy();
    let ext = base
        .extension()
        .map(|e| e.to_string_lossy())
        .unwrap_or_default();

    let new_name = if ext.is_empty() {
        format!("{}.{}", stem, index)
    } else {
        format!("{}.{}.{}", stem, index, ext)
    };

    base.with_file_name(new_name)
}

/// Syslog output (Unix domain socket or UDP).
#[cfg(unix)]
pub struct SyslogOutput {
    socket: std::os::unix::net::UnixDatagram,
}

#[cfg(unix)]
impl SyslogOutput {
    /// Connect to local syslog daemon.
    pub fn connect() -> io::Result<Self> {
        let socket = std::os::unix::net::UnixDatagram::unbound()?;

        // Try common syslog socket paths
        let paths = ["/dev/log", "/var/run/syslog", "/var/run/log"];
        for path in &paths {
            if std::path::Path::new(path).exists() {
                socket.connect(path)?;
                return Ok(Self { socket });
            }
        }

        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "No syslog socket found",
        ))
    }
}

#[cfg(unix)]
impl LogOutput for SyslogOutput {
    fn write(&mut self, line: &str) -> io::Result<()> {
        self.socket.send(line.as_bytes())?;
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Stub syslog output for non-Unix systems.
#[cfg(not(unix))]
pub struct SyslogOutput;

#[cfg(not(unix))]
impl SyslogOutput {
    pub fn connect() -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Syslog not supported on this platform",
        ))
    }
}

#[cfg(not(unix))]
impl LogOutput for SyslogOutput {
    fn write(&mut self, _line: &str) -> io::Result<()> {
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Create output from configuration.
pub fn create_output(config: &OutputConfig) -> io::Result<Box<dyn LogOutput>> {
    match config {
        OutputConfig::Stdout => Ok(Box::new(StdoutOutput::new())),
        OutputConfig::Stderr => Ok(Box::new(StderrOutput::new())),
        OutputConfig::File { path, rotation } => {
            Ok(Box::new(FileOutput::open(path, rotation.clone())?))
        }
        OutputConfig::Syslog { .. } => Ok(Box::new(SyslogOutput::connect()?)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_stdout_output() {
        let mut output = StdoutOutput::new();
        // Just verify it doesn't panic
        output.write("test log line").unwrap();
        output.flush().unwrap();
    }

    #[test]
    fn test_file_output() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test.log");

        let mut output = FileOutput::open(&log_path, None).unwrap();
        output.write("line 1").unwrap();
        output.write("line 2").unwrap();
        output.flush().unwrap();

        let content = std::fs::read_to_string(&log_path).unwrap();
        assert!(content.contains("line 1"));
        assert!(content.contains("line 2"));
    }

    #[test]
    fn test_file_rotation() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test.log");

        let rotation = FileRotation {
            max_size: 50, // Very small for testing
            max_files: 3,
            compress: false,
        };

        let mut output = FileOutput::open(&log_path, Some(rotation)).unwrap();

        // Write enough to trigger rotation
        for i in 0..10 {
            output.write(&format!("This is line number {}", i)).unwrap();
        }
        output.flush().unwrap();

        // Should have rotated files
        assert!(log_path.exists());
        let rotated_1 = temp_dir.path().join("test.1.log");
        assert!(rotated_1.exists());
    }

    #[test]
    fn test_rotated_path() {
        let base = Path::new("/var/log/hdds.log");
        assert_eq!(rotated_path(base, 1), PathBuf::from("/var/log/hdds.1.log"));
        assert_eq!(rotated_path(base, 5), PathBuf::from("/var/log/hdds.5.log"));

        let no_ext = Path::new("/var/log/hdds");
        assert_eq!(rotated_path(no_ext, 1), PathBuf::from("/var/log/hdds.1"));
    }
}
