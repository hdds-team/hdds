// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Runtime ownership for synchronous RPC callers. No runtime enters a C thread.

use hdds::rpc::{RpcError, RpcResult, ServiceClient};
use hdds::Participant;
use std::rc::Rc;
use std::sync::{mpsc, Arc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc as async_mpsc, oneshot, watch, OwnedSemaphorePermit, Semaphore};

const MAX_IN_FLIGHT: usize = 64;

pub(crate) enum CallFailure {
    Rpc(RpcError),
    Busy,
}

struct Call {
    payload: Vec<u8>,
    permit: OwnedSemaphorePermit,
    deadline: Instant,
    reply: mpsc::SyncSender<RpcResult<Vec<u8>>>,
    cancelled: oneshot::Receiver<()>,
}

pub(crate) struct ClientWorker {
    calls: async_mpsc::UnboundedSender<Call>,
    capacity: Arc<Semaphore>,
    stop: watch::Sender<bool>,
    thread: Option<JoinHandle<()>>,
}

impl ClientWorker {
    pub(crate) fn start(
        participant: Arc<Participant>,
        name: String,
        default_timeout: Duration,
    ) -> Result<Self, String> {
        let (calls, mut requests) = async_mpsc::unbounded_channel::<Call>();
        let (stop, mut stopped) = watch::channel(false);
        let (ready, initialized) = mpsc::sync_channel(1);
        let thread = std::thread::Builder::new()
            .name(format!("hdds-rpc-client-{name}"))
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        let _ = ready.send(Err(error.to_string()));
                        return;
                    }
                };
                let local = tokio::task::LocalSet::new();
                local.block_on(&runtime, async move {
                    let client = match ServiceClient::with_timeout(&participant, &name, default_timeout) {
                        Ok(client) => Rc::new(client),
                        Err(error) => {
                            let _ = ready.send(Err(error.to_string()));
                            return;
                        }
                    };
                    let _ = ready.send(Ok(()));
                    let mut tasks = tokio::task::JoinSet::new();
                    loop {
                        tokio::select! {
                            biased;
                            _ = stopped.changed() => break,
                            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
                            Some(mut call) = requests.recv() => {
                                let client = client.clone();
                                tasks.spawn_local(async move {
                                    let _permit = call.permit;
                                    let result = match call.deadline.checked_duration_since(Instant::now()) {
                                        Some(remaining) if !remaining.is_zero() => {
                                            tokio::select! {
                                                biased;
                                                _ = &mut call.cancelled => Err(RpcError::Shutdown),
                                                result = tokio::time::timeout_at(
                                                    tokio::time::Instant::from_std(call.deadline),
                                                    client.call_raw(&call.payload, remaining),
                                                ) => result.unwrap_or(Err(RpcError::Timeout)),
                                            }
                                        }
                                        _ => Err(RpcError::Timeout),
                                    };
                                    // Capacity one: sending cannot block even if the C caller timed out.
                                    let _ = call.reply.send(result);
                                });
                            }
                        }
                    }
                    requests.close();
                    client.shutdown();
                    tasks.abort_all();
                    while tasks.join_next().await.is_some() {}
                });
            })
            .map_err(|error| error.to_string())?;
        match initialized.recv() {
            Ok(Ok(())) => Ok(Self {
                calls,
                capacity: Arc::new(Semaphore::new(MAX_IN_FLIGHT)),
                stop,
                thread: Some(thread),
            }),
            result => {
                let _ = thread.join();
                Err(format!("RPC client initialization failed: {result:?}"))
            }
        }
    }

    pub(crate) fn call(&self, payload: Vec<u8>, deadline: Instant) -> Result<Vec<u8>, CallFailure> {
        if *self.stop.borrow() {
            return Err(CallFailure::Rpc(RpcError::Shutdown));
        }
        if deadline <= Instant::now() {
            return Err(CallFailure::Rpc(RpcError::Timeout));
        }
        let permit = self
            .capacity
            .clone()
            .try_acquire_owned()
            .map_err(|_| CallFailure::Busy)?;
        let (reply, response) = mpsc::sync_channel(1);
        // Dropping this sender on every return cancels any remaining async work.
        let (_cancel_on_return, cancelled) = oneshot::channel();
        self.calls
            .send(Call {
                payload,
                permit,
                deadline,
                reply,
                cancelled,
            })
            .map_err(|_| CallFailure::Rpc(RpcError::Shutdown))?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        match response.recv_timeout(remaining) {
            Ok(result) => result.map_err(CallFailure::Rpc),
            Err(mpsc::RecvTimeoutError::Timeout) => Err(CallFailure::Rpc(RpcError::Timeout)),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(CallFailure::Rpc(RpcError::Shutdown)),
        }
    }

    pub(crate) fn shutdown(&self) {
        self.stop.send_replace(true);
    }
}

impl Drop for ClientWorker {
    fn drop(&mut self) {
        self.shutdown();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admission_is_bounded_and_shutdown_wakes_all_callers() {
        let participant = Participant::builder("rpc_admission")
            .domain_id(0)
            .with_transport(hdds::TransportMode::IntraProcess)
            .build()
            .unwrap();
        let worker = Arc::new(
            ClientWorker::start(participant, "rpc_no_server".into(), Duration::from_secs(30))
                .unwrap(),
        );
        let callers: Vec<_> = (0..MAX_IN_FLIGHT)
            .map(|_| {
                let worker = worker.clone();
                std::thread::spawn(move || {
                    worker.call(Vec::new(), Instant::now() + Duration::from_secs(30))
                })
            })
            .collect();
        let deadline = Instant::now() + Duration::from_secs(3);
        while worker.capacity.available_permits() != 0 && Instant::now() < deadline {
            std::thread::yield_now();
        }
        let saturated = worker.capacity.available_permits() == 0;
        let overflow = worker.call(Vec::new(), Instant::now() + Duration::from_millis(5));
        // Always release threads before asserting, including on an overloaded host.
        worker.shutdown();
        for caller in callers {
            assert!(matches!(
                caller.join().unwrap(),
                Err(CallFailure::Rpc(RpcError::Shutdown))
            ));
        }
        assert!(saturated, "callers did not reach the admission limit");
        assert!(matches!(overflow, Err(CallFailure::Busy)));
    }
}
