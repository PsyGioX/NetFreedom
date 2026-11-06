// NetFreedom - open, local, reversible access to the open Internet.
// Copyright (C) 2026 Sergey (PsyGioX) <https://github.com/PsyGioX>
// Project home: https://github.com/PsyGioX/NetFreedom
//
// SPDX-License-Identifier: GPL-3.0-only
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation, version 3 of the License.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with
// this program. If not, see <https://www.gnu.org/licenses/>.

//! Latency / jitter / loss probe: ICMP through the OS API (no ping.exe, no PowerShell), with a
//! TCP-connect fallback for networks that drop ICMP.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use crate::stats::{self, Summary, Verdict};
pub use os::Pinger;
use crate::ui;
use crate::util::fmt_ms;

pub struct Options {
    pub count: u32,
    pub timeout_ms: u32,
    pub interval_ms: u64,
    pub warmup: bool,
    pub tunnel_stats: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self { count: 20, timeout_ms: 1000, interval_ms: 200, warmup: true, tunnel_stats: true }
    }
}

pub fn resolve_v4(host: &str) -> Option<Ipv4Addr> {
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return Some(ip);
    }
    (host, 0).to_socket_addrs().ok()?.find_map(|a| match a.ip() {
        IpAddr::V4(v4) => Some(v4),
        _ => None,
    })
}

// --------------------------------------------------------------------------- Windows pinger

#[cfg(windows)]
mod os {
    use std::ffi::c_void;
    use std::net::Ipv4Addr;

    use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::NetworkManagement::IpHelper::*;

    pub struct Pinger {
        handle: HANDLE,
        dest: u32,
        timeout_ms: u32,
        // 8-byte aligned reply buffer: ICMP_ECHO_REPLY + 32 bytes payload + ICMP error + IO_STATUS_BLOCK
        reply: Vec<u64>,
    }

    impl Pinger {
        pub fn new(ip: Ipv4Addr, timeout_ms: u32) -> Option<Self> {
            let handle = unsafe { IcmpCreateFile() };
            if handle == INVALID_HANDLE_VALUE || handle.is_null() {
                return None;
            }
            Some(Self { handle, dest: u32::from_ne_bytes(ip.octets()), timeout_ms, reply: vec![0u64; 64] })
        }

        /// Round-trip time in ms, or `None` on loss / error reply.
        pub fn ping(&mut self) -> Option<f64> {
            const PAYLOAD: &[u8; 32] = b"abcdefghijklmnopqrstuvwabcdefghi";
            let n = unsafe {
                IcmpSendEcho(
                    self.handle,
                    self.dest,
                    PAYLOAD.as_ptr() as *const c_void,
                    PAYLOAD.len() as u16,
                    std::ptr::null(),
                    self.reply.as_mut_ptr() as *mut c_void,
                    (self.reply.len() * 8) as u32,
                    self.timeout_ms,
                )
            };
            if n == 0 {
                return None;
            }
            let r = unsafe { &*(self.reply.as_ptr() as *const ICMP_ECHO_REPLY) };
            (r.Status == 0).then_some(r.RoundTripTime as f64)
        }
    }

    impl Drop for Pinger {
        fn drop(&mut self) {
            unsafe { IcmpCloseHandle(self.handle) };
        }
    }
}

// ---------------------------------------------------------------------------- Linux pinger

#[cfg(unix)]
mod os {
    use std::net::Ipv4Addr;
    use std::time::{Duration, Instant};

    /// ICMP echo over an unprivileged "ping" datagram socket, or a raw socket when running as root.
    pub struct Pinger {
        fd: i32,
        raw: bool,
        dest: libc::sockaddr_in,
        timeout: Duration,
        seq: u16,
        id: u16,
    }

    fn checksum(d: &[u8]) -> u16 {
        let mut sum = 0u32;
        for c in d.chunks(2) {
            sum += u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]) as u32;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    }

    impl Pinger {
        pub fn new(ip: Ipv4Addr, timeout_ms: u32) -> Option<Self> {
            let (fd, raw) = unsafe {
                let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, libc::IPPROTO_ICMP);
                if fd >= 0 {
                    (fd, false)
                } else {
                    (libc::socket(libc::AF_INET, libc::SOCK_RAW | libc::SOCK_CLOEXEC, libc::IPPROTO_ICMP), true)
                }
            };
            if fd < 0 {
                return None;
            }
            let mut dest: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            dest.sin_family = libc::AF_INET as u16;
            dest.sin_addr.s_addr = u32::from_ne_bytes(ip.octets());
            Some(Self { fd, raw, dest, timeout: Duration::from_millis(timeout_ms as u64), seq: 0, id: (std::process::id() & 0xFFFF) as u16 })
        }

        pub fn ping(&mut self) -> Option<f64> {
            self.seq = self.seq.wrapping_add(1);
            let mut pkt = [0u8; 40];
            pkt[0] = 8; // echo request
            pkt[4..6].copy_from_slice(&self.id.to_be_bytes());
            pkt[6..8].copy_from_slice(&self.seq.to_be_bytes());
            for (i, b) in pkt[8..].iter_mut().enumerate() {
                *b = b'a' + (i % 23) as u8;
            }
            let c = checksum(&pkt);
            pkt[2..4].copy_from_slice(&c.to_be_bytes());

            let t0 = Instant::now();
            let sent = unsafe {
                libc::sendto(self.fd, pkt.as_ptr().cast(), pkt.len(), 0, (&self.dest as *const libc::sockaddr_in).cast(), std::mem::size_of::<libc::sockaddr_in>() as u32)
            };
            if sent < 0 {
                return None;
            }
            let mut buf = [0u8; 256];
            loop {
                let left = self.timeout.checked_sub(t0.elapsed())?;
                let mut pfd = libc::pollfd { fd: self.fd, events: libc::POLLIN, revents: 0 };
                if unsafe { libc::poll(&mut pfd, 1, left.as_millis().max(1) as i32) } <= 0 {
                    return None;
                }
                let n = unsafe { libc::recv(self.fd, buf.as_mut_ptr().cast(), buf.len(), 0) };
                if n < 8 {
                    continue;
                }
                let icmp = if self.raw { &buf[((buf[0] & 0x0F) as usize) * 4..n as usize] } else { &buf[..n as usize] };
                if icmp.len() >= 8 && icmp[0] == 0 && icmp[6..8] == self.seq.to_be_bytes() && (!self.raw || icmp[4..6] == self.id.to_be_bytes()) {
                    return Some(t0.elapsed().as_secs_f64() * 1000.0);
                }
            }
        }
    }

    impl Drop for Pinger {
        fn drop(&mut self) {
            unsafe { libc::close(self.fd) };
        }
    }
}

// -------------------------------------------------------------------------------- measuring

/// Probes sent and discarded before measuring. One is not enough: a fresh QUIC/MASQUE tunnel needs
/// a few packets before the route, the neighbour and the NAT entries are all warm, and those
/// first round-trips made every run after a (re)start look worse than the steady state.
const WARMUP: u32 = 3;

/// Quiet measurement: round-trip times (ms) of the replies that arrived, in order.
/// `Err` only if the ICMP socket cannot be opened.
pub fn measure_icmp(ip: Ipv4Addr, o: &Options) -> Result<Vec<f64>, String> {
    let mut p = os::Pinger::new(ip, o.timeout_ms).ok_or("cannot open an ICMP socket (on Linux run as root or allow ping_group_range)")?;
    if o.warmup {
        // The first packet through a fresh tunnel pays route/cache setup and would inflate max/jitter.
        for _ in 0..WARMUP {
            let _ = p.ping();
            std::thread::sleep(Duration::from_millis(o.interval_ms.min(250)));
        }
    }
    let mut times = Vec::with_capacity(o.count as usize);
    for i in 1..=o.count {
        if let Some(t) = p.ping() {
            times.push(t);
        }
        if i < o.count {
            std::thread::sleep(Duration::from_millis(o.interval_ms));
        }
    }
    Ok(times)
}

/// TCP connect round-trips to `ip:port`; used when ICMP is filtered.
pub fn measure_tcp(ip: Ipv4Addr, port: u16, o: &Options) -> Vec<f64> {
    let addr = SocketAddr::new(IpAddr::V4(ip), port);
    let mut times = Vec::with_capacity(o.count as usize);
    if o.warmup {
        for _ in 0..WARMUP {
            let _ = TcpStream::connect_timeout(&addr, Duration::from_millis(o.timeout_ms as u64));
            std::thread::sleep(Duration::from_millis(o.interval_ms.min(250)));
        }
    }
    for i in 1..=o.count {
        let t0 = Instant::now();
        if TcpStream::connect_timeout(&addr, Duration::from_millis(o.timeout_ms as u64)).is_ok() {
            times.push(t0.elapsed().as_secs_f64() * 1000.0);
        }
        if i < o.count {
            std::thread::sleep(Duration::from_millis(o.interval_ms));
        }
    }
    times
}

/// Where the numbers came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Via {
    Icmp,
    Tcp443,
}

impl Via {
    pub fn label(self) -> &'static str {
        match self {
            Via::Icmp => "icmp",
            Via::Tcp443 => "tcp:443",
        }
    }
}

/// One probe of `ip:443` (used by the live monitor when ICMP is filtered).
pub fn tcp_sample(ip: Ipv4Addr, timeout_ms: u32) -> Option<f64> {
    let t0 = Instant::now();
    TcpStream::connect_timeout(&SocketAddr::new(IpAddr::V4(ip), 443), Duration::from_millis(timeout_ms as u64)).ok()?;
    Some(t0.elapsed().as_secs_f64() * 1000.0)
}

/// Consecutive silent ICMP probes after which the live monitor checks whether TCP 443 answers
/// instead (and then re-checks after every further run of this many).
pub const ICMP_GIVE_UP: u32 = 5;

/// Method state of the live monitor. Many game servers drop ICMP. Before, the monitor opened an
/// ICMP socket (which always works), got silence and drew "100% loss" for a perfectly healthy
/// server; only `tune` knew how to fall back to TCP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MethodSwitch {
    via: Via,
    icmp_misses: u32,
}

impl MethodSwitch {
    pub const fn new() -> Self {
        Self { via: Via::Icmp, icmp_misses: 0 }
    }

    pub const fn via(&self) -> Via {
        self.via
    }

    /// Records one ICMP probe. `true` = ICMP has been silent for a whole run, check TCP now.
    pub fn icmp_result(&mut self, answered: bool) -> bool {
        if answered {
            self.icmp_misses = 0;
            return false;
        }
        self.icmp_misses += 1;
        self.icmp_misses % ICMP_GIVE_UP == 0
    }
}

impl Default for MethodSwitch {
    fn default() -> Self {
        Self::new()
    }
}

/// One live sample. Returns the round-trip time (`None` = lost) and whether the method just
/// switched from ICMP to TCP (the caller drops the window: ICMP "losses" were not losses).
/// The probes are closures so that the decision is testable without a network.
pub fn live_sample(m: &mut MethodSwitch, icmp: impl FnOnce() -> Option<f64>, tcp: impl FnOnce() -> Option<f64>) -> (Option<f64>, bool) {
    match m.via {
        Via::Tcp443 => (tcp(), false),
        Via::Icmp => {
            let s = icmp();
            if !m.icmp_result(s.is_some()) {
                return (s, false);
            }
            match tcp() {
                Some(t) => {
                    m.via = Via::Tcp443;
                    (Some(t), true)
                }
                // both silent: the host (or the tunnel) really is down, keep ICMP and keep trying
                None => (None, false),
            }
        }
    }
}

/// Which probe a whole comparison uses. `tune` fixes one for ALL scenarios: ICMP and TCP-connect
/// numbers are not comparable, and a scenario that silently fell back to the other one used to be
/// ranked against the rest as if they were the same thing.
pub fn detect_method(target: &str) -> Option<Via> {
    let ip = resolve_v4(target)?;
    let o = Options { count: 4, interval_ms: 150, warmup: false, tunnel_stats: false, ..Options::default() };
    let icmp = measure_icmp(ip, &o).unwrap_or_default();
    if icmp.len() >= 2 {
        return Some(Via::Icmp);
    }
    (measure_tcp(ip, 443, &o).len() >= 2).then_some(Via::Tcp443)
}

/// Measures with `via` if given; otherwise ICMP first and, if nothing answers (filtered), TCP.
pub fn measure_with(target: &str, o: &Options, via: Option<Via>) -> Result<(Summary, Via), String> {
    let ip = resolve_v4(target).ok_or_else(|| format!("cannot resolve an IPv4 address for \"{target}\""))?;
    if via != Some(Via::Tcp443) {
        let icmp = measure_icmp(ip, o).unwrap_or_default();
        if let Some(s) = stats::summarize(&icmp, o.count) {
            return Ok((s, Via::Icmp));
        }
        if via == Some(Via::Icmp) {
            return Err(format!("no ICMP replies from {target}"));
        }
    }
    let tcp = measure_tcp(ip, 443, o);
    stats::summarize(&tcp, o.count).map(|s| (s, Via::Tcp443)).ok_or_else(|| format!("no replies from {target} (ICMP and TCP 443)"))
}

pub fn measure(target: &str, o: &Options) -> Result<(Summary, Via), String> {
    measure_with(target, o, None)
}

/// ICMP and TCP-connect to the same host should be in the same ballpark. When they are not, one of
/// them is answered by something in between (a router that owns the address, a captive portal, a
/// transparent proxy) and the latency is not the latency of the host.
pub fn methods_disagree(icmp_median: f64, tcp_median: f64) -> bool {
    let (lo, hi) = if icmp_median < tcp_median { (icmp_median, tcp_median) } else { (tcp_median, icmp_median) };
    hi - lo > 25.0 && hi > 2.5 * lo.max(1.0)
}

/// Interactive probe with the full report (`netfreedom check`).
pub fn run(target: &str, o: &Options) {
    let Some(ip) = resolve_v4(target) else {
        ui::error(&format!("cannot resolve an IPv4 address for \"{target}\""));
        return;
    };
    let extra = if o.warmup { " + warm-up" } else { "" };
    ui::cyan(&format!("Probing {target} ({ip}, {} packets{extra})...", o.count));
    let times = match measure_icmp(ip, o) {
        Ok(t) => t,
        Err(e) => {
            ui::error(&e);
            return;
        }
    };
    let Some(s) = stats::summarize(&times, o.count) else {
        ui::color("31", &format!("Result: no replies from {target}. 100% loss (the host may block ICMP, or the tunnel is down)."));
        return;
    };
    println!();
    println!("  Sent / received : {} / {}", s.sent, s.received);
    println!("  Packet loss     : {}%", s.loss_pct);
    println!("  Latency ms      : min {}  median {}  avg {}  p95 {}  max {}", fmt_ms(s.min), fmt_ms(s.median), fmt_ms(s.avg), fmt_ms(s.p95), fmt_ms(s.max));
    println!("  Std deviation   : {} ms", fmt_ms(s.stdev));
    println!("  Jitter ms       : {}", fmt_ms(s.jitter));
    println!();
    match stats::verdict(&s) {
        Verdict::Excellent => ui::color("32", "Verdict: excellent link (no loss, jitter <= 5 ms)."),
        Verdict::Good => ui::color("32", "Verdict: good link (no loss, jitter <= 10 ms). Fine for most games; very competitive shooters prefer jitter <= 5 ms."),
        Verdict::HighJitter => ui::color("33", "Verdict: no loss, but jitter is high - try another profile (`netfreedom tune` tests them all), close background downloads/Wi-Fi roaming, or re-run."),
        Verdict::Loss => ui::color("33", "Verdict: packet loss detected - try another profile (`netfreedom tune` tests them all), Compatibility mode, or re-run to rule out a one-off."),
    }
    if stats::long_tail(&s) {
        ui::color("33", &format!("Note: the tail is long (p95 {} ms vs median {} ms) - look for periodic spikes (Wi-Fi scans, background traffic, power saving).", s.p95, s.median));
    }
    if o.tunnel_stats {
        if let Some(w) = crate::warp::Warp::locate() {
            let t = w.tunnel_stats();
            if !t.is_empty() {
                println!();
                ui::cyan("WARP tunnel stats (warp-cli tunnel stats):");
                for l in t.lines() {
                    println!("  {l}");
                }
            }
        }
    }
}

#[cfg(test)]
mod method_tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn monitor_falls_back_to_tcp_when_icmp_is_filtered() {
        let mut m = MethodSwitch::new();
        let icmp_calls = Cell::new(0);
        let run = |m: &mut MethodSwitch| {
            live_sample(
                m,
                || {
                    icmp_calls.set(icmp_calls.get() + 1);
                    None
                },
                || Some(31.0),
            )
        };
        for _ in 0..4 {
            assert_eq!(run(&mut m), (None, false), "not yet: one dropped ping is not a verdict");
        }
        assert_eq!(run(&mut m), (Some(31.0), true), "5th silent ICMP probe, TCP answers: switch");
        assert_eq!(m.via(), Via::Tcp443);
        let before = icmp_calls.get();
        assert_eq!(run(&mut m), (Some(31.0), false));
        assert_eq!(icmp_calls.get(), before, "ICMP is not tried any more once TCP is the method");
    }

    #[test]
    fn a_real_outage_does_not_switch_the_method() {
        let mut m = MethodSwitch::new();
        for _ in 0..12 {
            let (s, switched) = live_sample(&mut m, || None, || None);
            assert_eq!((s, switched), (None, false));
        }
        assert_eq!(m.via(), Via::Icmp, "if TCP is silent too, the loss is real and is shown as loss");
    }

    #[test]
    fn occasional_icmp_loss_resets_the_counter() {
        let mut m = MethodSwitch::new();
        for i in 0..40 {
            let ans = i % 4 != 0; // every 4th probe dropped: ordinary loss, never 5 in a row
            let (s, switched) = live_sample(&mut m, || ans.then_some(20.0), || panic!("TCP must not be touched"));
            assert_eq!((s.is_some(), switched), (ans, false));
        }
        assert_eq!(m.via(), Via::Icmp);
    }

    #[test]
    fn icmp_tcp_disagreement() {
        assert!(!methods_disagree(20.0, 24.0));
        assert!(!methods_disagree(2.0, 12.0), "small absolute gaps are noise");
        assert!(methods_disagree(3.0, 90.0), "a local router answering ICMP for a distant host");
        assert!(methods_disagree(90.0, 3.0));
    }
}
