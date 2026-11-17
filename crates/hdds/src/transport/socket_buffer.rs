// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! UDP socket buffer configuration shared by participant-owned sockets.

use socket2::Socket;
use std::num::NonZeroUsize;

const RECV_BUFFER_ENV: &str = "HDDS_RCVBUF_BYTES";
const SEND_BUFFER_ENV: &str = "HDDS_SNDBUF_BYTES";

/// Fallback receive buffer when neither the builder nor the environment names
/// one.
///
/// Evaluated in CONST context on purpose. The previous shape was
/// `NonZeroUsize::new(SOCKET_RCVBUF_BYTES).expect(..)`, which turns a constant
/// someone might edit to zero into a runtime panic inside every participant
/// build. Here the same mistake refuses to compile, which is where a fact
/// known at compile time belongs.
const DEFAULT_RECEIVE_BUFFER_SIZE: NonZeroUsize =
    match NonZeroUsize::new(crate::config::SOCKET_RCVBUF_BYTES) {
        Some(size) => size,
        // This arm is evaluated at COMPILE time, in const context: it is a
        // static assertion, not a runtime panic path. Edit
        // SOCKET_RCVBUF_BYTES to zero and the crate stops BUILDING; no binary
        // containing this arm can ever execute it. A grep for `panic!` cannot
        // see that difference, hence the marker below (which the scanner only
        // reads within six lines of the finding, so it stays adjacent).
        // @audit-ok: const-context assertion, unreachable at runtime
        None => panic!("SOCKET_RCVBUF_BYTES must be non-zero"),
    };

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SocketBufferOptions {
    receive_buffer_size: Option<NonZeroUsize>,
    send_buffer_size: Option<NonZeroUsize>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ResolvedSocketBufferOptions {
    receive_buffer_size: NonZeroUsize,
    receive_is_explicit: bool,
    send_buffer_size: Option<NonZeroUsize>,
}

impl SocketBufferOptions {
    pub(crate) fn with_receive_buffer_size(mut self, bytes: NonZeroUsize) -> Self {
        self.receive_buffer_size = Some(bytes);
        self
    }

    pub(crate) fn with_send_buffer_size(mut self, bytes: NonZeroUsize) -> Self {
        self.send_buffer_size = Some(bytes);
        self
    }

    pub(crate) fn resolve(self) -> ResolvedSocketBufferOptions {
        let receive_env = std::env::var(RECV_BUFFER_ENV).ok();
        let send_env = std::env::var(SEND_BUFFER_ENV).ok();
        self.resolve_with_env(receive_env.as_deref(), send_env.as_deref())
    }

    pub(crate) fn resolve_with_env(
        self,
        receive_env: Option<&str>,
        send_env: Option<&str>,
    ) -> ResolvedSocketBufferOptions {
        let env_receive = parse_env_size(RECV_BUFFER_ENV, receive_env);
        let env_send = parse_env_size(SEND_BUFFER_ENV, send_env);
        let receive_buffer_size = self.receive_buffer_size.or(env_receive);

        ResolvedSocketBufferOptions {
            receive_buffer_size: receive_buffer_size.unwrap_or(DEFAULT_RECEIVE_BUFFER_SIZE),
            receive_is_explicit: receive_buffer_size.is_some(),
            send_buffer_size: self.send_buffer_size.or(env_send),
        }
    }
}

impl ResolvedSocketBufferOptions {
    /// The historical receive boost applies to user-data listener sockets.
    pub(crate) fn data_receive_buffer(self) -> (usize, bool) {
        (self.receive_buffer_size.get(), self.receive_is_explicit)
    }

    /// Metatraffic keeps the kernel default unless the operator opted in.
    pub(crate) fn metatraffic_receive_buffer(self) -> Option<usize> {
        self.receive_is_explicit
            .then_some(self.receive_buffer_size.get())
    }

    pub(crate) fn send_buffer(self) -> Option<usize> {
        self.send_buffer_size.map(NonZeroUsize::get)
    }
}

fn parse_env_size(name: &str, value: Option<&str>) -> Option<NonZeroUsize> {
    let value = value?;
    match value.parse::<usize>().ok().and_then(NonZeroUsize::new) {
        Some(bytes) => Some(bytes),
        None => {
            log::warn!("[Socket] ignoring invalid {name}={value:?}; expected a positive integer");
            None
        }
    }
}

pub(crate) fn apply_receive_buffer(socket: &Socket, requested: usize, explicit: bool, label: &str) {
    match socket.set_recv_buffer_size(requested) {
        Ok(()) => report_effective_size(
            socket.recv_buffer_size(),
            requested,
            explicit,
            label,
            "SO_RCVBUF",
        ),
        Err(error) => log_apply_failure(explicit, label, "SO_RCVBUF", requested, &error),
    }
}

pub(crate) fn apply_send_buffer(socket: &Socket, requested: usize, label: &str) {
    match socket.set_send_buffer_size(requested) {
        Ok(()) => report_effective_size(
            socket.send_buffer_size(),
            requested,
            true,
            label,
            "SO_SNDBUF",
        ),
        Err(error) => log_apply_failure(true, label, "SO_SNDBUF", requested, &error),
    }
}

fn report_effective_size(
    effective: std::io::Result<usize>,
    requested: usize,
    explicit: bool,
    label: &str,
    option: &str,
) {
    match effective {
        Ok(actual) if actual < requested && explicit => log::warn!(
            "[Socket] {label} {option} requested {requested} bytes but kernel granted {actual}"
        ),
        Ok(actual) if actual < requested => log::debug!(
            "[Socket] {label} {option} requested {requested} bytes but kernel granted {actual}"
        ),
        Ok(actual) => {
            log::debug!("[Socket] {label} {option} requested={requested} effective={actual}");
        }
        Err(error) => {
            log::debug!("[Socket] cannot read effective {label} {option}: {error}");
        }
    }
}

fn log_apply_failure(
    explicit: bool,
    label: &str,
    option: &str,
    requested: usize,
    error: &std::io::Error,
) {
    if explicit {
        log::warn!(
            "[Socket] failed to set {label} {option}={requested} (keeping kernel default): {error}"
        );
    } else {
        log::debug!(
            "[Socket] failed to set {label} {option}={requested} (keeping kernel default): {error}"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_values_win_over_environment() {
        let options = SocketBufferOptions::default()
            .with_receive_buffer_size(NonZeroUsize::new(65_536).unwrap())
            .with_send_buffer_size(NonZeroUsize::new(32_768).unwrap())
            .resolve_with_env(Some("131072"), Some("262144"));

        assert_eq!(options.data_receive_buffer(), (65_536, true));
        assert_eq!(options.metatraffic_receive_buffer(), Some(65_536));
        assert_eq!(options.send_buffer(), Some(32_768));
    }

    #[test]
    fn environment_is_a_fallback_and_zero_is_rejected() {
        let options = SocketBufferOptions::default().resolve_with_env(Some("0"), Some("65536"));

        assert_eq!(
            options.data_receive_buffer(),
            (crate::config::SOCKET_RCVBUF_BYTES, false)
        );
        assert_eq!(options.metatraffic_receive_buffer(), None);
        assert_eq!(options.send_buffer(), Some(65_536));
    }
}
