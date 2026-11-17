// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Cross-process lifecycle of the shared topic notify segment
//! (`hdds::transport::shm::TopicNotify`): released by its last live user,
//! crashed users reclaimed, and no user ever left on an unlinked object while
//! processes race to create it and to leave it.
//!
//! The "other processes" are this very test binary re-run filtered to
//! `child_process_entry`, driven over stdin/stdout.

#![cfg(target_os = "linux")]

use hdds::transport::shm::{reclaim_dead_notify_segments, ShmSegment, TopicNotify};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

const CHILD_ENV: &str = "HDDS_NOTIFY_LIFECYCLE_CHILD";
const REPLY: &str = "NTFY:";

fn unique_topic(tag: &str) -> String {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("lifecycle_{tag}_{}_{ts}", std::process::id())
}

/// The child's reply on `line`, if any. libtest prints `test <name> ... `
/// without a newline before running the test, so the first reply shares its
/// line with that banner: look for the marker anywhere on the line.
fn reply_of(line: &str) -> Option<String> {
    line.find(REPLY)
        .map(|at| line[at + REPLY.len()..].trim_end().to_string())
}

fn exists(name: &str) -> bool {
    ShmSegment::exists(name)
}

/// One child process holding (or not) a handle on one notify segment.
struct Peer {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl Peer {
    fn spawn(name: &str) -> Self {
        let exe = std::env::current_exe().expect("test binary");
        let mut child = Command::new(exe)
            .args([
                "--exact",
                "child_process_entry",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD_ENV, name)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn child");
        let stdin = child.stdin.take().expect("stdin");
        let stdout = BufReader::new(child.stdout.take().expect("stdout"));
        Self {
            child,
            stdin,
            stdout,
        }
    }

    /// Send one command and return the child's reply (after the prefix).
    fn ask(&mut self, cmd: &str) -> String {
        writeln!(self.stdin, "{cmd}").expect("write command");
        self.stdin.flush().expect("flush");
        let mut line = String::new();
        loop {
            line.clear();
            let n = self.stdout.read_line(&mut line).expect("read reply");
            assert!(n > 0, "child exited before answering {cmd:?}");
            if let Some(reply) = reply_of(&line) {
                return reply;
            }
        }
    }

    fn attach(&mut self) {
        assert_eq!(self.ask("attach"), "attached linked=true");
    }

    fn detach(&mut self) {
        assert_eq!(self.ask("detach"), "detached");
    }

    fn bump(&mut self, bucket: usize) {
        assert_eq!(self.ask(&format!("bump {bucket}")), "bumped");
    }

    fn read(&mut self, bucket: usize) -> u32 {
        let reply = self.ask(&format!("read {bucket}"));
        reply
            .strip_prefix("value ")
            .and_then(|v| v.parse().ok())
            .unwrap_or_else(|| panic!("bad read reply {reply:?}"))
    }

    fn sigkill(mut self) {
        let pid = i32::try_from(self.child.id()).expect("pid");
        // SAFETY: our own child's pid, a valid signal.
        unsafe { libc::kill(pid, libc::SIGKILL) };
        // Reap it: a zombie still answers kill(pid, 0).
        self.child.wait().expect("reap");
    }

    fn finish(mut self) {
        let _ = writeln!(self.stdin, "exit");
        let status = self.child.wait().expect("wait child");
        assert!(status.success(), "child failed: {status}");
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        // Never leak a child, whatever the test's outcome.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Child side. A no-op in a normal run (the env var is unset).
#[test]
fn child_process_entry() {
    let Ok(name) = std::env::var(CHILD_ENV) else {
        return;
    };
    let mut handle: Option<TopicNotify> = None;
    let mut holders: Option<ForkedHolders> = None;
    let stdin = std::io::stdin();
    let mut out = std::io::stdout();
    for line in stdin.lock().lines() {
        let line = line.expect("command");
        let mut words = line.split_whitespace();
        let reply = match words.next() {
            Some("attach") => {
                let h = TopicNotify::new(&name, true).expect("child attach");
                let linked = h.is_linked();
                handle = Some(h);
                format!("attached linked={linked}")
            }
            Some("umask_attach") => {
                // A restrictive umask (here: no owner write) must not leave
                // the created object unusable by the next process.
                // SAFETY: umask has no preconditions.
                unsafe { libc::umask(0o277) };
                let h = TopicNotify::new(&name, true).expect("child attach");
                let linked = h.is_linked();
                handle = Some(h);
                format!("attached linked={linked}")
            }
            Some("detach") => {
                handle = None;
                "detached".to_string()
            }
            Some("bump") => {
                let b: usize = words.next().unwrap().parse().unwrap();
                handle.as_ref().expect("attached").notify(b);
                "bumped".to_string()
            }
            Some("read") => {
                let b: usize = words.next().unwrap().parse().unwrap();
                let v = handle.as_ref().expect("attached").bucket(b).snapshot();
                format!("value {v}")
            }
            Some("stress") => {
                let iters: usize = words.next().unwrap().parse().unwrap();
                let mut violations = 0usize;
                for _ in 0..iters {
                    let h = TopicNotify::new(&name, true).expect("stress attach");
                    if !h.is_linked() {
                        violations += 1;
                    }
                    h.notify(1);
                    drop(h);
                }
                format!("violations {violations}")
            }
            Some("fork_hold") => {
                let n: usize = words.next().unwrap().parse().unwrap();
                let (h, attached) = ForkedHolders::spawn(&name, n);
                holders = Some(h);
                format!("held {attached}")
            }
            Some("kill_one") => {
                holders.as_mut().expect("holders").kill_one();
                "killed".to_string()
            }
            Some("kill_all") => {
                holders.as_mut().expect("holders").kill_all();
                "killed".to_string()
            }
            Some("exit") | None => break,
            Some(other) => format!("unknown {other}"),
        };
        writeln!(out, "{REPLY}{reply}").expect("reply");
        out.flush().expect("flush reply");
    }
    drop(handle);
    drop(holders);
}

/// Two real processes, every attach/detach interleaving: the segment exists
/// exactly while at least one of them is attached, and while both are, each
/// sees the other's notifications.
#[test]
fn two_processes_attach_detach_in_all_orders() {
    // (first to attach, first to detach) for peers 0 and 1.
    for (order, (first_in, first_out)) in [(0, 0), (0, 1), (1, 0), (1, 1)].iter().enumerate() {
        let name = TopicNotify::segment_name(4_100_001, &unique_topic(&format!("order{order}")));
        let mut peers = [Peer::spawn(&name), Peer::spawn(&name)];
        let second_in = 1 - first_in;
        let second_out = 1 - first_out;

        assert!(!exists(&name));
        peers[*first_in].attach();
        assert!(exists(&name));
        peers[second_in].attach();

        let before = peers[second_in].read(9);
        peers[*first_in].bump(9);
        assert_eq!(
            peers[second_in].read(9),
            before.wrapping_add(1),
            "order {order}"
        );
        peers[second_in].bump(9);
        assert_eq!(
            peers[*first_in].read(9),
            before.wrapping_add(2),
            "order {order}"
        );

        peers[*first_out].detach();
        assert!(exists(&name), "order {order}: one user is still attached");
        peers[second_out].detach();
        assert!(
            !exists(&name),
            "order {order}: both left, segment must be gone"
        );

        // Sequential use: attach/detach one after the other, never together.
        peers[0].attach();
        peers[0].detach();
        assert!(!exists(&name));
        peers[1].attach();
        peers[1].detach();
        assert!(
            !exists(&name),
            "order {order}: sequential use must not leak"
        );

        let [a, b] = peers;
        a.finish();
        b.finish();
    }
}

/// A user SIGKILLed while attached does not keep the segment alive: the next
/// detach of the other user reclaims its row and unlinks.
#[test]
fn a_killed_user_is_reclaimed_by_the_next_detach() {
    let name = TopicNotify::segment_name(4_100_002, &unique_topic("kill_detach"));
    let mut victim = Peer::spawn(&name);
    let mut survivor = Peer::spawn(&name);
    victim.attach();
    survivor.attach();
    victim.sigkill();
    assert!(exists(&name));
    survivor.detach();
    assert!(
        !exists(&name),
        "the killed user's row must have been reclaimed"
    );
    survivor.finish();
}

/// The sole user is SIGKILLed: the next process to attach and detach (or
/// the participant-startup sweep) releases the segment.
#[test]
fn a_killed_sole_user_is_reclaimed_by_the_next_attach_or_the_sweep() {
    // Next attach + detach.
    let name = TopicNotify::segment_name(4_100_003, &unique_topic("kill_attach"));
    let mut victim = Peer::spawn(&name);
    victim.attach();
    victim.sigkill();
    assert!(exists(&name));
    let mut next = Peer::spawn(&name);
    next.attach();
    next.detach();
    assert!(!exists(&name));
    next.finish();

    // Startup sweep, on a domain of its own.
    let domain = 4_100_004;
    let name = TopicNotify::segment_name(domain, &unique_topic("kill_sweep"));
    let mut victim = Peer::spawn(&name);
    victim.attach();
    victim.sigkill();
    assert!(exists(&name));
    assert_eq!(reclaim_dead_notify_segments(domain), 1);
    assert!(!exists(&name));
}

/// The sweep never releases a segment with a live user.
#[test]
fn the_sweep_leaves_a_live_users_segment_alone() {
    let domain = 4_100_005;
    let name = TopicNotify::segment_name(domain, &unique_topic("sweep_live"));
    let mut live = Peer::spawn(&name);
    live.attach();
    assert_eq!(reclaim_dead_notify_segments(domain), 0);
    assert!(exists(&name));
    let before = live.read(4);
    // The sweep's attach/detach must not have moved the live user off the name.
    let here = TopicNotify::new(&name, false).expect("still the same segment");
    assert!(here.is_linked());
    here.notify(4);
    assert_eq!(live.read(4), before.wrapping_add(1));
    drop(here);
    live.detach();
    assert!(!exists(&name));
    live.finish();
}

/// Processes and threads race open-or-create against last-detach on one
/// name. No user ever finds itself on an object the name no longer refers
/// to, and once everyone has left, the name is gone.
#[test]
fn create_vs_last_detach_race_processes_and_threads() {
    let name = TopicNotify::segment_name(4_100_006, &unique_topic("race"));
    let mut peers: Vec<Peer> = (0..4).map(|_| Peer::spawn(&name)).collect();
    for p in &mut peers {
        writeln!(p.stdin, "stress 400").expect("start stress");
        p.stdin.flush().expect("flush");
    }
    let threads: Vec<_> = (0..3)
        .map(|_| {
            let name = name.clone();
            std::thread::spawn(move || {
                let mut violations = 0;
                for _ in 0..400 {
                    let h = TopicNotify::new(&name, true).expect("attach");
                    if !h.is_linked() {
                        violations += 1;
                    }
                    h.notify(2);
                    drop(h);
                }
                violations
            })
        })
        .collect();
    let thread_violations: usize = threads.into_iter().map(|t| t.join().unwrap()).sum();
    let deadline = Instant::now() + Duration::from_secs(120);
    for p in &mut peers {
        let mut line = String::new();
        let reply = loop {
            line.clear();
            assert!(Instant::now() < deadline, "stress child timed out");
            let n = p.stdout.read_line(&mut line).expect("stress reply");
            assert!(n > 0, "stress child died");
            if let Some(r) = reply_of(&line) {
                break r;
            }
        };
        assert_eq!(
            reply, "violations 0",
            "a child registered on an unlinked object"
        );
    }
    assert_eq!(
        thread_violations, 0,
        "a thread registered on an unlinked object"
    );
    for p in peers {
        p.finish();
    }
    assert!(!exists(&name), "everyone left: the name must be gone");

    // And while several users overlap, they share one object: a held handle
    // here sees a child's notification.
    let held = TopicNotify::new(&name, true).expect("hold");
    let mut peer = Peer::spawn(&name);
    peer.attach();
    let before = held.bucket(6).snapshot();
    peer.bump(6);
    assert_eq!(held.bucket(6).snapshot(), before.wrapping_add(1));
    peer.detach();
    peer.finish();
    assert!(exists(&name));
    drop(held);
    assert!(!exists(&name));
}

/// A writer whose notify attach is refused (here: a foreign object under the
/// name) fails its transport and leaves nothing behind: neither its ring
/// segment nor the ring's owner record.
#[test]
fn a_refused_notify_attach_leaves_no_writer_ring() {
    use hdds::core::discovery::GUID;
    use hdds::transport::shm::{segment_name, ShmWriterTransport};
    let domain = 4_100_007;
    let topic = unique_topic("refused_ring");
    let notify = TopicNotify::segment_name(domain, &topic);
    let notify_path = format!("/dev/shm/{}", notify.trim_start_matches('/'));
    std::fs::write(&notify_path, b"not a notify segment").expect("squat");
    let guid_bytes = [0x5A; 16];
    let ring = segment_name(domain, &guid_bytes);
    let ring_path = format!("/dev/shm/{}", ring.trim_start_matches('/'));
    let writer = ShmWriterTransport::new(domain, GUID::from_bytes(guid_bytes), &topic);
    let refused = writer.is_err();
    drop(writer);
    let ring_left = std::path::Path::new(&ring_path).exists();
    let owner_left = std::path::Path::new(&format!("{ring_path}.owner")).exists();
    let _ = std::fs::remove_file(&notify_path);
    let _ = std::fs::remove_file(&ring_path);
    let _ = std::fs::remove_file(format!("{ring_path}.owner"));
    assert!(
        refused,
        "a squatted notify name must fail the writer transport"
    );
    assert!(!ring_left, "refused writer left its ring segment behind");
    assert!(
        !owner_left,
        "refused writer left its ring owner record behind"
    );
}

/// The creator sets mode 0600 exactly, whatever its umask: an object
/// created under a restrictive umask is still opened by the next process
/// (which refuses anything but this user's own mode-0600 object).
#[test]
fn an_object_created_under_a_restrictive_umask_is_still_shared() {
    let name = TopicNotify::segment_name(4_100_009, &unique_topic("umask"));
    let mut creator = Peer::spawn(&name);
    assert_eq!(creator.ask("umask_attach"), "attached linked=true");
    let here = TopicNotify::new(&name, false).expect("the next process opens it");
    assert!(here.is_linked());
    drop(here);
    creator.detach();
    assert!(!exists(&name));
    creator.finish();
}

/// The user table admits `NOTIFY_MAX_USERS` processes (at least 1024, so a
/// ROS 2 host's /rosout with hundreds of writing nodes fits) and refuses the
/// next one cleanly; when one of them dies, the next attach gets its row.
#[test]
fn the_user_table_admits_its_limit_and_refuses_one_more() {
    use hdds::transport::shm::NOTIFY_MAX_USERS;
    const _: () = assert!(NOTIFY_MAX_USERS >= 1024);
    let domain = 4_100_008;
    let name = TopicNotify::segment_name(domain, &unique_topic("limit"));
    let mut forker = Peer::spawn(&name);
    // The forker process itself holds no row: its children take all of them.
    assert_eq!(
        forker.ask(&format!("fork_hold {NOTIFY_MAX_USERS}")),
        format!("held {NOTIFY_MAX_USERS}"),
        "every holder up to the limit attaches"
    );
    let one_more = TopicNotify::new(&name, true);
    assert!(
        one_more.is_err(),
        "user {} must be refused",
        NOTIFY_MAX_USERS + 1
    );
    assert!(exists(&name), "a refusal never touches the segment");
    assert_eq!(forker.ask("kill_one"), "killed");
    let after = TopicNotify::new(&name, true).expect("a dead holder's row is reused");
    assert!(after.is_linked());
    drop(after);
    assert_eq!(forker.ask("kill_all"), "killed");
    forker.finish();
    assert_eq!(reclaim_dead_notify_segments(domain), 1);
    assert!(!exists(&name));
}

/// Light holders for the limit test, created inside a child process (never
/// in the multi-threaded test harness): `fork()`ed copies that each attach
/// once, report one byte on a pipe and pause. Each dies with its parent
/// (`PR_SET_PDEATHSIG`), so a failing test leaks none.
struct ForkedHolders {
    pids: Vec<libc::pid_t>,
}

impl ForkedHolders {
    fn spawn(name: &str, n: usize) -> (Self, usize) {
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: valid out-array of two fds.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let mut pids = Vec::with_capacity(n);
        for _ in 0..n {
            // SAFETY: the child only calls prctl, TopicNotify::new, write and
            // pause, then is killed; it never returns into the harness.
            let pid = unsafe { libc::fork() };
            assert!(pid >= 0, "fork failed");
            if pid == 0 {
                // SAFETY: plain prctl call.
                unsafe {
                    libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
                }
                let ok = TopicNotify::new(name, true);
                let byte: u8 = if ok.is_ok() { b'1' } else { b'0' };
                // SAFETY: valid fd and one-byte buffer.
                unsafe {
                    libc::write(fds[1], std::ptr::addr_of!(byte).cast(), 1);
                    loop {
                        libc::pause();
                    }
                }
            }
            pids.push(pid);
        }
        // SAFETY: closing our copy of the write end.
        unsafe { libc::close(fds[1]) };
        let mut attached = 0;
        for _ in 0..n {
            let mut byte = 0u8;
            // SAFETY: valid fd and one-byte buffer.
            let r = unsafe { libc::read(fds[0], std::ptr::addr_of_mut!(byte).cast(), 1) };
            assert_eq!(r, 1, "a holder died before reporting");
            if byte == b'1' {
                attached += 1;
            }
        }
        // SAFETY: closing the read end once.
        unsafe { libc::close(fds[0]) };
        (Self { pids }, attached)
    }

    fn kill_one(&mut self) {
        if let Some(pid) = self.pids.pop() {
            // SAFETY: our own forked child; reaped right after.
            unsafe {
                libc::kill(pid, libc::SIGKILL);
                libc::waitpid(pid, std::ptr::null_mut(), 0);
            }
        }
    }

    fn kill_all(&mut self) {
        while !self.pids.is_empty() {
            self.kill_one();
        }
    }
}

impl Drop for ForkedHolders {
    fn drop(&mut self) {
        self.kill_all();
    }
}
