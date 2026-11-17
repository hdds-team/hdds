// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! A/B of interface enumeration: the former `ip -4 addr show` text parse
//! (moved here verbatim, Linux only) against the `getifaddrs(3)` snapshot the
//! transport uses now.
//!
//! Prints both views, then the difference of the `(name, addr)` sets and of
//! the point-to-point address sets, then the ORDER of the non-loopback
//! addresses (order is load-bearing downstream: the multicast join and the
//! primary-IP fallback take the first entry). The old view's name is what
//! the `ip` header printed (`eth0@if31` for a veth, the device for an alias);
//! the new view's raw label is compared to it, with the normalised device
//! name shown next to it. Exit code 1 on any set difference, 3 when the sets
//! are equal but the order differs, 2 when `ip` cannot run.
//!
//! Known, expected differences: a veth's `@ifN` suffix (old only); a labelled
//! alias reported as `dev:label` (new) instead of `dev` (old); a point-to-point
//! link with a peer (`inet A peer B/32`), which the old parse dropped.
//!
//! ```text
//! cargo run -p hdds --example ifaces_ab --release
//! ```

use hdds::transport::ifaddrs::InterfaceSnapshot;
#[cfg(target_os = "linux")]
use std::collections::BTreeSet;
#[cfg(target_os = "linux")]
use std::net::Ipv4Addr;

/// Former Linux path of `get_interface_pairs_platform`, text parse only (the
/// `local_ip_address` fallback when `ip` is missing is not reproduced: this
/// tool reports that case as exit 2 instead).
#[cfg(target_os = "linux")]
fn old_interface_pairs() -> std::io::Result<Vec<(String, Ipv4Addr)>> {
    use std::process::Command;

    let output = Command::new("ip").args(["-4", "addr", "show"]).output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut pairs = Vec::new();
    let mut current_name = String::new();

    for line in stdout.lines() {
        // Interface header line: "2: eth0: <FLAGS,...> mtu 1500 ..."
        if line.starts_with(|c: char| c.is_ascii_digit()) {
            current_name = line
                .split(':')
                .nth(1)
                .map(|s| s.trim().to_string())
                .unwrap_or_default();
            continue;
        }
        if line.contains("127.0.0.1") || line.contains("host lo") {
            continue;
        }
        if let Some(inet_part) = line.trim().strip_prefix("inet ") {
            if let Some(addr_str) = inet_part.split('/').next() {
                if let Ok(addr) = addr_str.trim().parse::<Ipv4Addr>() {
                    pairs.push((current_name.clone(), addr));
                }
            }
        }
    }

    Ok(pairs)
}

/// Former Linux body of `is_tunnel_ip`: the POINTOPOINT address set.
#[cfg(target_os = "linux")]
fn old_tunnel_ips() -> std::io::Result<BTreeSet<Ipv4Addr>> {
    use std::process::Command;

    let output = Command::new("ip").args(["-4", "addr", "show"]).output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut tunnel_ips = BTreeSet::new();
    let mut iface_ptp = false;

    for line in stdout.lines() {
        if line.starts_with(|c: char| c.is_ascii_digit()) {
            iface_ptp = line.contains("POINTOPOINT");
            continue;
        }
        if !iface_ptp {
            continue;
        }
        if let Some(inet_part) = line.trim_start().strip_prefix("inet ") {
            if let Some(addr_str) = inet_part.split('/').next() {
                if let Ok(addr) = addr_str.trim().parse::<Ipv4Addr>() {
                    tunnel_ips.insert(addr);
                }
            }
        }
    }

    Ok(tunnel_ips)
}

fn print_snapshot(snapshot: &InterfaceSnapshot) {
    println!("# new: getifaddrs snapshot (all entries, loopback included)");
    for e in snapshot.entries() {
        let mut tags = Vec::new();
        if e.loopback {
            tags.push("LOOPBACK");
        }
        if e.point_to_point {
            tags.push("POINTOPOINT");
        }
        println!(
            "  {:16} name={:12} {:16} flags=0x{:x} {}{}",
            e.label,
            e.name,
            e.addr,
            e.flags,
            tags.join(","),
            e.peer.map(|p| format!(" peer={}", p)).unwrap_or_default()
        );
    }
}

#[cfg(target_os = "linux")]
fn print_set_diff<T: Ord + std::fmt::Debug>(
    title: &str,
    old: &BTreeSet<T>,
    new: &BTreeSet<T>,
) -> bool {
    println!("# diff {}", title);
    let mut differs = false;
    for item in old.difference(new) {
        println!("  - old only: {:?}", item);
        differs = true;
    }
    for item in new.difference(old) {
        println!("  + new only: {:?}", item);
        differs = true;
    }
    if !differs {
        println!("  identical ({} entries)", old.len());
    }
    differs
}

#[cfg(target_os = "linux")]
fn main() {
    let old_pairs = match old_interface_pairs() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("cannot run `ip -4 addr show`: {}", e);
            std::process::exit(2);
        }
    };
    let old_tunnels = old_tunnel_ips().unwrap_or_default();

    println!("# old: `ip -4 addr show` parse (non-loopback pairs)");
    for (name, addr) in &old_pairs {
        let ptp = if old_tunnels.contains(addr) {
            " POINTOPOINT"
        } else {
            ""
        };
        println!("  {:16} {:16}{}", name, addr, ptp);
    }

    let snapshot = match InterfaceSnapshot::capture() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("getifaddrs failed: {}", e);
            std::process::exit(2);
        }
    };
    print_snapshot(&snapshot);

    // (name, addr) as the former code saw it vs the raw OS label now.
    let old_set: BTreeSet<(String, Ipv4Addr)> = old_pairs.iter().cloned().collect();
    let new_label_set: BTreeSet<(String, Ipv4Addr)> = snapshot
        .entries()
        .iter()
        .filter(|e| !e.is_loopback())
        .map(|e| (e.label.clone(), e.addr))
        .collect();
    let new_name_set: BTreeSet<(String, Ipv4Addr)> =
        snapshot.pairs().map(|(n, a)| (n.to_string(), a)).collect();
    let new_tunnels: BTreeSet<Ipv4Addr> = snapshot
        .entries()
        .iter()
        .filter(|e| e.point_to_point && !e.is_loopback())
        .map(|e| e.addr)
        .collect();

    let d1 = print_set_diff("(label, addr) old vs new", &old_set, &new_label_set);
    let d2 = print_set_diff(
        "(device name, addr) old vs new (what allowlists match on)",
        &old_set,
        &new_name_set,
    );
    let d3 = print_set_diff("point-to-point addresses", &old_tunnels, &new_tunnels);

    // Order of the non-loopback addresses, old vs new. Only meaningful when
    // both sides list the same addresses; otherwise the set diff above
    // already explains the difference.
    let old_seq: Vec<Ipv4Addr> = old_pairs.iter().map(|(_, a)| *a).collect();
    let new_seq: Vec<Ipv4Addr> = snapshot.pairs().map(|(_, a)| a).collect();
    let old_addr_set: BTreeSet<Ipv4Addr> = old_seq.iter().copied().collect();
    let new_addr_set: BTreeSet<Ipv4Addr> = new_seq.iter().copied().collect();
    println!("# order of non-loopback addresses old vs new");
    let order_differs = if old_addr_set != new_addr_set {
        println!("  not comparable (address sets differ)");
        false
    } else if old_seq != new_seq {
        println!("  order differs:");
        println!("    old: {:?}", old_seq);
        println!("    new: {:?}", new_seq);
        true
    } else {
        println!("  identical ({} addresses)", old_seq.len());
        false
    };

    if d1 || d2 || d3 {
        println!("RESULT: DIFFERENT");
        std::process::exit(1);
    }
    if order_differs {
        println!("RESULT: DIFFERENT (order only)");
        std::process::exit(3);
    }
    println!("RESULT: identical");
}

#[cfg(not(target_os = "linux"))]
fn main() {
    // No `ip -4 addr show` to compare against off Linux: print the snapshot.
    match InterfaceSnapshot::capture() {
        Ok(s) => print_snapshot(&s),
        Err(e) => {
            eprintln!("interface enumeration failed: {}", e);
            std::process::exit(2);
        }
    }
    println!("RESULT: snapshot only (old parse is Linux-only)");
}
