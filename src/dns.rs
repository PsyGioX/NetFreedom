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

//! Encrypted DNS for the length of a session: Cloudflare, Google or Quad9 (or "the fastest").
//!
//! Why it is here: a poisoned or slow provider resolver is the one block that no desync strategy
//! can fix (`tune` reports such sites as "not fixable by a strategy"), and a slow lookup is the
//! first thing a game launcher waits for.
//!
//! What it does, honestly, per platform:
//!
//!   * Windows 11 / Server 2022: real DNS-over-HTTPS. The provider's addresses are registered
//!     with their DoH template (`Add/Set-DnsClientDohServerAddress`, auto-upgrade on) and become the
//!     DNS servers of the active adapters. The OS then speaks HTTPS to them by itself.
//!   * Windows 10: the OS has no DoH client at all. Nothing is changed unless the player explicitly
//!     accepts plain (unencrypted) DNS of the same provider (`--plain`).
//!   * Linux: `systemd-resolved` has no DoH client either, only DNS-over-TLS, so that is what is
//!     configured (same providers, port 853). Without `systemd-resolved` nothing is changed.
//!
//! The project stays dependency-free, so there is no TLS stack and no local proxy in here: a proxy
//! that dies leaves the machine without DNS, the OS clients do not. Everything is reversible: the
//! previous settings are written to `utils/dns-backup.txt` BEFORE anything is changed, restored on
//! stop / Ctrl+C / crash / uninstall, and by the next start when the owner died abnormally.
//! The result is verified with a real lookup and rolled back if the resolver does not answer.

use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::config::Config;
use crate::paths::Layout;
use crate::ui::{self, tr};

// ------------------------------------------------------------------------------------ providers

#[derive(Debug, PartialEq, Eq)]
pub struct Provider {
    /// Key used in the settings file and on the command line.
    pub name: &'static str,
    pub title: &'static str,
    pub v4: [&'static str; 2],
    pub v6: [&'static str; 2],
    /// RFC 8484 DoH template.
    pub doh: &'static str,
    /// Certificate name (DoT server name).
    pub tls_name: &'static str,
}

pub const PROVIDERS: [Provider; 3] = [
    Provider {
        name: "cloudflare",
        title: "Cloudflare",
        v4: ["1.1.1.1", "1.0.0.1"],
        v6: ["2606:4700:4700::1111", "2606:4700:4700::1001"],
        doh: "https://cloudflare-dns.com/dns-query",
        tls_name: "cloudflare-dns.com",
    },
    Provider {
        name: "google",
        title: "Google Public DNS",
        v4: ["8.8.8.8", "8.8.4.4"],
        v6: ["2001:4860:4860::8888", "2001:4860:4860::8844"],
        doh: "https://dns.google/dns-query",
        tls_name: "dns.google",
    },
    Provider {
        name: "quad9",
        title: "Quad9",
        v4: ["9.9.9.9", "149.112.112.112"],
        v6: ["2620:fe::fe", "2620:fe::9"],
        doh: "https://dns.quad9.net/dns-query",
        tls_name: "dns.quad9.net",
    },
];

pub fn find(name: &str) -> Option<&'static Provider> {
    let n = name.trim().to_ascii_lowercase();
    let key = match n.as_str() {
        "cf" | "1.1.1.1" | "1.0.0.1" => "cloudflare",
        "8.8.8.8" | "8.8.4.4" | "google public dns" => "google",
        "9.9.9.9" | "149.112.112.112" => "quad9",
        other => other,
    };
    PROVIDERS.iter().find(|p| p.name == key)
}

/// What the player chose.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Choice {
    /// Do not touch the system's DNS.
    Off,
    /// Measure and take the fastest reachable provider at every start.
    Auto,
    Fixed(&'static Provider),
}

impl Choice {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "" | "off" | "none" | "system" | "default" | "0" => Ok(Self::Off),
            "auto" | "fastest" => Ok(Self::Auto),
            other => find(other).map(Self::Fixed).ok_or_else(|| format!("unknown DNS provider \"{other}\": use cloudflare, google, quad9, auto or off")),
        }
    }

    /// The value stored in the settings file.
    pub fn key(self) -> &'static str {
        match self {
            Self::Off => "",
            Self::Auto => "auto",
            Self::Fixed(p) => p.name,
        }
    }

    pub fn title(self) -> String {
        match self {
            Self::Off => tr("не менять", "leave as is").to_owned(),
            Self::Auto => tr("авто (самый быстрый)", "auto (fastest)").to_owned(),
            Self::Fixed(p) => p.title.to_owned(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    Doh,
    Dot,
    /// Unencrypted UDP/TCP 53, only when the player asked for it.
    Plain,
}

impl Transport {
    pub fn label(self) -> &'static str {
        match self {
            Self::Doh => "DoH",
            Self::Dot => "DoT",
            Self::Plain => "plain",
        }
    }

    fn from_label(s: &str) -> Option<Self> {
        match s {
            "DoH" => Some(Self::Doh),
            "DoT" => Some(Self::Dot),
            "plain" => Some(Self::Plain),
            _ => None,
        }
    }

    /// TCP port whose reachability decides whether the resolver can be used.
    pub fn port(self) -> u16 {
        match self {
            Self::Doh => 443,
            Self::Dot => 853,
            Self::Plain => 53,
        }
    }
}

/// The encrypted transport this operating system can speak by itself.
pub const fn native_transport() -> Transport {
    if cfg!(windows) { Transport::Doh } else { Transport::Dot }
}

// ------------------------------------------------------------------------------- DNS wire format

/// A recursive `A IN` query. `name` must consist of labels of at most 63 bytes (callers pass
/// constants).
pub fn build_query(id: u16, name: &str) -> Vec<u8> {
    let mut q = Vec::with_capacity(18 + name.len());
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00]); // flags: recursion desired
    q.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]); // one question
    for label in name.trim_end_matches('.').split('.') {
        q.push(label.len().min(63) as u8);
        q.extend_from_slice(&label.as_bytes()[..label.len().min(63)]);
    }
    q.push(0);
    q.extend_from_slice(&[0, 1, 0, 1]); // A, IN
    q
}

#[derive(Debug, PartialEq, Eq)]
pub struct Reply {
    pub rcode: u8,
    pub answers: u16,
}

/// Header of a response to query `id`; `None` for anything else (wrong id, not a response, short).
pub fn parse_reply(id: u16, buf: &[u8]) -> Option<Reply> {
    if buf.len() < 12 || u16::from_be_bytes([buf[0], buf[1]]) != id || buf[2] & 0x80 == 0 {
        return None;
    }
    Some(Reply { rcode: buf[3] & 0x0f, answers: u16::from_be_bytes([buf[6], buf[7]]) })
}

// ------------------------------------------------------------------------------------- measuring

/// Name asked of every resolver during a measurement (an IANA-reserved name that always exists).
const BENCH_NAME: &str = "example.com";

/// One UDP/53 lookup of `BENCH_NAME`; milliseconds, or `None` for no / a bad answer.
fn udp_probe(server: SocketAddr, id: u16, timeout: Duration) -> Option<f64> {
    let sock = UdpSocket::bind(if server.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }).ok()?;
    sock.set_read_timeout(Some(timeout)).ok()?;
    sock.connect(server).ok()?;
    let t0 = Instant::now();
    sock.send(&build_query(id, BENCH_NAME)).ok()?;
    let mut buf = [0u8; 512];
    let n = sock.recv(&mut buf).ok()?;
    let r = parse_reply(id, &buf[..n])?;
    (r.rcode == 0 && r.answers > 0).then(|| t0.elapsed().as_secs_f64() * 1000.0)
}

fn median(v: &mut [f64]) -> Option<f64> {
    if v.is_empty() {
        return None;
    }
    v.sort_by(|a, b| a.total_cmp(b));
    Some(if v.len() % 2 == 1 { v[v.len() / 2] } else { (v[v.len() / 2 - 1] + v[v.len() / 2]) / 2.0 })
}

/// Median TCP connect time to `addr:port` over `tries` attempts (the handshake costs one round trip,
/// the same one every DoH / DoT query pays after it). `None` when nothing connected.
fn tcp_probe(addr: Ipv4Addr, port: u16, tries: usize, timeout: Duration) -> Option<f64> {
    let mut ok = Vec::new();
    for _ in 0..tries {
        let t0 = Instant::now();
        if TcpStream::connect_timeout(&SocketAddr::new(IpAddr::V4(addr), port), timeout).is_ok() {
            ok.push(t0.elapsed().as_secs_f64() * 1000.0);
        }
    }
    median(&mut ok)
}

#[derive(Debug, Clone)]
pub struct Row {
    pub label: String,
    pub provider: Option<&'static Provider>,
    pub addr: Ipv4Addr,
    /// Successful UDP lookups, ms.
    pub udp: Vec<f64>,
    pub sent: usize,
    /// TCP connect to :443 (DoH) / :853 (DoT), ms; `None` = unreachable.
    pub doh: Option<f64>,
    pub dot: Option<f64>,
}

impl Row {
    pub fn udp_median(&self) -> Option<f64> {
        median(&mut self.udp.clone())
    }

    pub fn loss_pct(&self) -> f64 {
        if self.sent == 0 { 0.0 } else { 100.0 * (self.sent - self.udp.len()) as f64 / self.sent as f64 }
    }

    /// Lower is better; `None` = the encrypted transport of this platform cannot reach the provider.
    pub fn score(&self) -> Option<f64> {
        let t = if native_transport() == Transport::Doh { self.doh } else { self.dot }?;
        Some(t + 2.0 * self.loss_pct())
    }
}

/// The reachable provider with the best score.
pub fn best(rows: &[Row]) -> Option<&'static Provider> {
    rows.iter()
        .filter_map(|r| Some((r.provider?, r.score()?)))
        .min_by(|a, b| a.1.total_cmp(&b.1))
        .map(|(p, _)| p)
}

fn measure(label: String, provider: Option<&'static Provider>, addr: Ipv4Addr, count: usize, with_tls_ports: bool) -> Row {
    let seed = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.subsec_nanos()).unwrap_or(1);
    let mut udp = Vec::new();
    for i in 0..count {
        let id = (seed as u16).wrapping_add(i as u16).wrapping_mul(31).wrapping_add(7);
        if let Some(ms) = udp_probe(SocketAddr::new(IpAddr::V4(addr), 53), id, Duration::from_millis(1000)) {
            udp.push(ms);
        }
        std::thread::sleep(Duration::from_millis(60));
    }
    let (doh, dot) = if with_tls_ports {
        (tcp_probe(addr, 443, 3, Duration::from_millis(1500)), tcp_probe(addr, 853, 3, Duration::from_millis(1500)))
    } else {
        (None, None)
    };
    Row { label, provider, addr, udp, sent: count, doh, dot }
}

/// Measures every provider (in parallel) and, when it is a plain IPv4 address, the resolver the
/// system uses right now, for comparison.
pub fn bench(count: usize) -> Vec<Row> {
    let count = count.clamp(3, 50);
    let current = os::current_servers().iter().find_map(|l| first_public_or_private_v4(l));
    std::thread::scope(|s| {
        let mut jobs = Vec::new();
        for p in &PROVIDERS {
            let addr: Ipv4Addr = p.v4[0].parse().expect("constant address");
            jobs.push(s.spawn(move || measure(p.title.to_owned(), Some(p), addr, count, true)));
        }
        if let Some(ip) = current {
            jobs.push(s.spawn(move || measure(format!("{} ({ip})", tr("сейчас в системе", "current system DNS")), None, ip, count, false)));
        }
        jobs.into_iter().filter_map(|j| j.join().ok()).collect()
    })
}

/// First IPv4 address in a line such as `Ethernet<TAB>192.168.1.1,fe80::1` that is not loopback.
fn first_public_or_private_v4(line: &str) -> Option<Ipv4Addr> {
    line.split(|c: char| c.is_whitespace() || c == ',' || c == '#')
        .filter_map(|t| t.parse::<Ipv4Addr>().ok())
        .find(|ip| !ip.is_loopback() && !ip.is_unspecified())
}

pub fn print_bench(rows: &[Row]) {
    let port = native_transport().port();
    println!();
    println!(
        "  {:<34} {:>10} {:>8} {:>10} {:>10}",
        tr("Резолвер", "Resolver"),
        "UDP 53",
        tr("потери", "loss"),
        "TCP 443",
        "TCP 853"
    );
    for r in rows {
        let fmt = |v: Option<f64>| v.map(|x| format!("{} ms", crate::util::fmt_ms(x))).unwrap_or_else(|| "—".to_owned());
        let doh = if r.provider.is_some() { fmt(r.doh) } else { String::new() };
        let dot = if r.provider.is_some() { fmt(r.dot) } else { String::new() };
        println!("  {:<34} {:>10} {:>7.0}% {:>10} {:>10}", ui::clip(&r.label, 34), fmt(r.udp_median()), r.loss_pct(), doh, dot);
    }
    println!();
    match best(rows) {
        Some(p) => {
            ui::ok(&format!("{}: {} (TCP {port})", tr("Самый быстрый доступный", "Fastest reachable"), p.title));
            println!("  netfreedom dns set {}", p.name);
        }
        None => ui::warn(tr("Ни один провайдер не отвечает на порту шифрованного DNS: провайдер связи, вероятно, его фильтрует.", "No provider answers on the encrypted-DNS port: your ISP probably filters it.")),
    }
    println!("{}", tr("Это замер до самих серверов: реальный DoH/DoT-запрос стоит столько же, сколько один круг до них.", "This measures the path to the servers: a real DoH/DoT query costs one round trip to them."));
}

/// `name` resolved by the system within `limit`. The lookup runs on its own thread because the OS
/// resolver may block for ten seconds or more when nothing answers.
pub fn lookup_time(name: &str, limit: Duration) -> Option<Duration> {
    let (tx, rx) = mpsc::channel();
    let host = name.to_owned();
    std::thread::Builder::new()
        .name("dns-probe".into())
        .spawn(move || {
            let t0 = Instant::now();
            let ok = (host.as_str(), 0).to_socket_addrs().map(|mut a| a.next().is_some()).unwrap_or(false);
            let _ = tx.send(ok.then(|| t0.elapsed()));
        })
        .ok()?;
    rx.recv_timeout(limit).ok().flatten()
}

/// Names that really exist and are not wildcarded, asked after the cache was flushed.
const CANARIES: [&str; 2] = ["www.cloudflare.com", "www.wikipedia.org"];

fn verify(limit: Duration) -> Option<Duration> {
    CANARIES.iter().find_map(|h| lookup_time(h, limit))
}

// ------------------------------------------------------------------------------- saved settings

/// One thing that was changed, as it was before. The file holds only what is needed to undo it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Entry {
    /// Windows adapter: static servers it had (empty = automatic), and whether it had IPv6 DNS.
    Adapter { index: u32, name: String, v4: Vec<String>, v6: Vec<String>, v6_active: bool },
    /// Windows DoH table row: `None` = the row did not exist, else (template, auto-upgrade, fallback).
    Doh { ip: String, saved: Option<(String, bool, bool)> },
    /// systemd-resolved link.
    Link { name: String, dns: Vec<String>, tls: String, domains: Vec<String>, default_route: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Backup {
    pub pid: u32,
    pub provider: String,
    pub strict: bool,
    pub transport: Transport,
    pub entries: Vec<Entry>,
}

const BACKUP_HEADER: &str = "netfreedom-dns-backup 1";

fn clean(s: &str) -> String {
    s.replace(['\t', '\r', '\n'], " ")
}

fn is_ip(s: &str) -> bool {
    s.parse::<IpAddr>().is_ok()
}

/// A DoH template that is safe to put inside a quoted PowerShell string.
fn is_template(s: &str) -> bool {
    s.starts_with("https://") && s.len() < 200 && s.chars().all(|c| c.is_ascii_alphanumeric() || "-._~:/?=&%".contains(c))
}

/// An interface name for `resolvectl` (never an option, never shell-special).
fn is_link_name(s: &str) -> bool {
    !s.is_empty() && s.len() <= 15 && !s.starts_with('-') && s.chars().all(|c| c.is_ascii_alphanumeric() || "._:@-".contains(c))
}

/// `address` or `address#server.name`, as `resolvectl dns` prints and takes them.
fn is_dns_token(s: &str) -> bool {
    let (addr, name) = s.split_once('#').map_or((s, ""), |(a, n)| (a, n));
    let addr = addr.split('%').next().unwrap_or("");
    is_ip(addr) && name.chars().all(|c| c.is_ascii_alphanumeric() || "-.".contains(c))
}

fn is_domain_token(s: &str) -> bool {
    !s.is_empty() && !s.starts_with('-') && s.chars().all(|c| c.is_ascii_alphanumeric() || "-._~".contains(c))
}

fn words(s: &str, sep: impl Fn(char) -> bool) -> Vec<String> {
    s.split(sep).map(str::trim).filter(|t| !t.is_empty()).map(str::to_owned).collect()
}

impl Backup {
    pub fn render(&self) -> String {
        let b = |v: bool| if v { "1" } else { "0" };
        let mut s = format!("{BACKUP_HEADER}\npid\t{}\nprovider\t{}\nstrict\t{}\ntransport\t{}\n", self.pid, clean(&self.provider), b(self.strict), self.transport.label());
        for e in &self.entries {
            match e {
                Entry::Adapter { index, name, v4, v6, v6_active } => {
                    s.push_str(&format!("adapter\t{index}\t{}\t{}\t{}\t{}\n", clean(name), v4.join(","), v6.join(","), b(*v6_active)));
                }
                Entry::Doh { ip, saved: None } => s.push_str(&format!("doh\t{ip}\tabsent\n")),
                Entry::Doh { ip, saved: Some((t, au, fb)) } => s.push_str(&format!("doh\t{ip}\t{t}\t{}\t{}\n", b(*au), b(*fb))),
                Entry::Link { name, dns, tls, domains, default_route } => {
                    s.push_str(&format!("link\t{name}\t{}\t{}\t{}\t{default_route}\n", dns.join(" "), clean(tls), domains.join(" ")));
                }
            }
        }
        s
    }

    /// `None` for a file that is not ours or whose values would not be safe to hand to the OS tools.
    pub fn parse(text: &str) -> Option<Self> {
        let mut lines = text.lines();
        if lines.next()?.trim() != BACKUP_HEADER {
            return None;
        }
        let (mut pid, mut provider, mut strict, mut transport) = (None, String::new(), false, Transport::Plain);
        let mut entries = Vec::new();
        for line in lines {
            let f: Vec<&str> = line.split('\t').collect();
            match f[0] {
                "pid" => pid = f.get(1)?.trim().parse().ok(),
                "provider" => provider = f.get(1)?.trim().to_owned(),
                "strict" => strict = f.get(1)? == &"1",
                "transport" => transport = Transport::from_label(f.get(1)?.trim())?,
                "adapter" => {
                    let v4 = words(f.get(3)?, |c| c == ',');
                    let v6 = words(f.get(4)?, |c| c == ',');
                    if !v4.iter().chain(&v6).all(|a| is_ip(a)) {
                        return None;
                    }
                    entries.push(Entry::Adapter { index: f.get(1)?.trim().parse().ok()?, name: f.get(2)?.to_string(), v4, v6, v6_active: f.get(5)? == &"1" });
                }
                "doh" => {
                    let ip = f.get(1)?.trim().to_owned();
                    if !is_ip(&ip) {
                        return None;
                    }
                    let saved = if f.get(2)?.trim() == "absent" {
                        None
                    } else {
                        let t = f.get(2)?.trim().to_owned();
                        if !is_template(&t) {
                            return None;
                        }
                        Some((t, f.get(3)? == &"1", f.get(4)? == &"1"))
                    };
                    entries.push(Entry::Doh { ip, saved });
                }
                "link" => {
                    let name = f.get(1)?.trim().to_owned();
                    let dns = words(f.get(2)?, char::is_whitespace);
                    let domains = words(f.get(4)?, char::is_whitespace);
                    let tls = f.get(3)?.trim().to_owned();
                    let default_route = f.get(5)?.trim().to_owned();
                    let ok = is_link_name(&name)
                        && dns.iter().all(|d| is_dns_token(d))
                        && domains.iter().all(|d| is_domain_token(d))
                        && ["", "no", "yes", "opportunistic"].contains(&tls.as_str())
                        && ["", "no", "yes"].contains(&default_route.as_str());
                    if !ok {
                        return None;
                    }
                    entries.push(Entry::Link { name, dns, tls, domains, default_route });
                }
                _ => {}
            }
        }
        Some(Self { pid: pid?, provider, strict, transport, entries })
    }
}

enum Saved {
    Missing,
    /// Present but not ours / not safe: never acted upon.
    Corrupt,
    Found(Backup),
}

fn backup_path(layout: &Layout) -> PathBuf {
    layout.utils.join("dns-backup.txt")
}

fn read_backup(path: &Path) -> Saved {
    match fs::read_to_string(path) {
        Ok(t) => Backup::parse(t.trim_start_matches('\u{feff}')).map_or(Saved::Corrupt, Saved::Found),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Saved::Missing,
        Err(_) => Saved::Corrupt,
    }
}

fn write_backup(path: &Path, b: &Backup) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        let _ = fs::create_dir_all(dir);
    }
    crate::util::write_atomic(path, b.render().as_bytes()).map_err(|e| format!("cannot save the DNS backup ({}): {e}", path.display()))
}

// ---------------------------------------------------------------------------------- live state

struct Live {
    path: PathBuf,
    provider: &'static Provider,
    strict: bool,
    transport: Transport,
    /// Round trip to the resolver's encrypted-DNS port at the last check.
    rtt: Option<f64>,
    fails: u32,
}

static LIVE: Mutex<Option<Live>> = Mutex::new(None);

fn live_lock() -> std::sync::MutexGuard<'static, Option<Live>> {
    LIVE.lock().unwrap_or_else(|e| e.into_inner())
}

/// For the status panel: (provider, transport, last round trip in ms, consecutive failed checks).
pub fn summary() -> Option<(&'static Provider, Transport, Option<f64>, u32)> {
    live_lock().as_ref().map(|l| (l.provider, l.transport, l.rtt, l.fails))
}

pub fn is_applied() -> bool {
    live_lock().is_some()
}

#[cfg(unix)]
fn pid_alive(pid: u32) -> bool {
    // SAFETY: signal 0 only checks for existence / permission.
    unsafe { libc::kill(pid as i32, 0) == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM) }
}

#[cfg(windows)]
fn pid_alive(pid: u32) -> bool {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{GetExitCodeProcess, OpenProcess};
    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    const STILL_ACTIVE: u32 = 259;
    // SAFETY: plain handle calls; the handle is closed before returning.
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return false;
        }
        let mut code = 0u32;
        let ok = GetExitCodeProcess(h, &mut code) != 0 && code == STILL_ACTIVE;
        CloseHandle(h);
        ok
    }
}

// ---------------------------------------------------------------------------- apply / restore

#[derive(Debug)]
pub struct Applied {
    pub provider: &'static Provider,
    pub transport: Transport,
    pub strict: bool,
    pub warnings: Vec<String>,
    /// First real lookup through the new resolver, ms.
    pub first_lookup_ms: f64,
}

#[derive(Debug)]
pub struct Snapshot {
    pub entries: Vec<Entry>,
    /// The OS has an encrypted-DNS client (Windows 11+ / systemd-resolved).
    pub encrypted: bool,
    pub warnings: Vec<String>,
}

fn plain_needed_msg() -> String {
    tr(
        "В этой версии Windows нет клиента DNS-over-HTTPS (он есть в Windows 11 и Server 2022). DNS не изменён. Чтобы всё равно использовать быстрый DNS этого провайдера без шифрования: `netfreedom dns set <имя> --plain`.",
        "This version of Windows has no DNS-over-HTTPS client (Windows 11 and Server 2022 have one). DNS was NOT changed. To use this provider's fast DNS without encryption anyway: `netfreedom dns set <name> --plain`.",
    )
    .to_owned()
}

fn pick_auto() -> Result<&'static Provider, String> {
    best(&bench(6)).ok_or_else(|| {
        tr("ни один из DNS-провайдеров недоступен на порту шифрованного DNS", "none of the DNS providers is reachable on the encrypted-DNS port").to_owned()
    })
}

/// Undoes a backup (and forgets it). The file is kept when the undo fails, so that it can be retried.
fn undo(path: &Path, b: &Backup) -> Result<(), String> {
    os::restore(&b.entries)?;
    os::flush();
    let _ = fs::remove_file(path);
    *live_lock() = None;
    Ok(())
}

/// Applies `choice` system-wide, verifies it with a real lookup and rolls back if that fails.
pub fn apply(layout: &Layout, choice: Choice, strict: bool, allow_plain: bool) -> Result<Applied, String> {
    if is_applied() {
        return Err(tr("DNS уже применён в этой сессии", "DNS is already applied in this session").to_owned());
    }
    let path = backup_path(layout);
    match read_backup(&path) {
        Saved::Missing => {}
        Saved::Corrupt => return Err(format!("{} {}", path.display(), tr("повреждён или не наш: DNS не менялся. Удалите файл или исправьте DNS вручную.", "is damaged or not ours: DNS was not touched. Delete it or fix DNS by hand."))),
        Saved::Found(b) => {
            if b.pid != std::process::id() && pid_alive(b.pid) {
                return Err(format!("{} (pid {})", tr("DNS уже изменён другим запущенным NetFreedom", "DNS is already managed by another running NetFreedom"), b.pid));
            }
            undo(&path, &b)?; // what a crashed run left behind
        }
    }

    let provider = match choice {
        Choice::Fixed(p) => p,
        Choice::Auto => pick_auto()?,
        Choice::Off => return Err(tr("DNS не меняется (выбрано «не менять»)", "DNS is left alone (set to “leave as is”)").to_owned()),
    };
    let snap = os::snapshot()?;
    if !snap.entries.iter().any(|e| matches!(e, Entry::Adapter { .. } | Entry::Link { .. })) {
        return Err(tr("не найдено активного сетевого подключения со шлюзом", "no active network connection with a gateway was found").to_owned());
    }
    let transport = if snap.encrypted {
        native_transport()
    } else if allow_plain {
        Transport::Plain
    } else {
        return Err(plain_needed_msg());
    };

    let backup = Backup { pid: std::process::id(), provider: provider.name.to_owned(), strict, transport, entries: snap.entries };
    write_backup(&path, &backup)?; // BEFORE the first change: a crash from here on is recoverable
    if let Err(e) = os::apply(&backup.entries, provider, strict, transport) {
        let _ = undo(&path, &backup);
        return Err(e);
    }
    os::flush();
    let first = verify(Duration::from_secs(4)).or_else(|| {
        std::thread::sleep(Duration::from_millis(1200));
        os::flush();
        verify(Duration::from_secs(4))
    });
    let Some(first) = first else {
        let _ = undo(&path, &backup);
        return Err(format!(
            "{} {} ({}): {}",
            tr("Резолвер", "The resolver"),
            provider.title,
            transport.label(),
            tr("не отвечает, настройки DNS возвращены как были. Возможно, провайдер связи его фильтрует: `netfreedom dns bench` покажет, что доступно.", "does not answer, DNS settings are back as they were. Your ISP may filter it: `netfreedom dns bench` shows what is reachable.")
        ));
    };
    *live_lock() = Some(Live { path, provider, strict, transport, rtt: None, fails: 0 });
    Ok(Applied { provider, transport, strict, warnings: snap.warnings, first_lookup_ms: first.as_secs_f64() * 1000.0 })
}

/// Moves a running session to another provider (menu choice, failover). The original settings stay
/// in the backup; only the provider in it changes.
pub fn switch(to: &'static Provider) -> Result<Applied, String> {
    let (path, from, strict, transport) = {
        let g = live_lock();
        let l = g.as_ref().ok_or_else(|| tr("DNS не применён", "DNS is not applied").to_owned())?;
        (l.path.clone(), l.provider, l.strict, l.transport)
    };
    let Saved::Found(mut b) = read_backup(&path) else {
        return Err(tr("файл резервной копии DNS пропал", "the DNS backup file is gone").to_owned());
    };
    let back = |e: String| {
        let _ = os::apply(&b.entries, from, strict, transport);
        os::flush();
        e
    };
    os::apply(&b.entries, to, strict, transport).map_err(&back)?;
    os::flush();
    let first = verify(Duration::from_secs(4)).ok_or_else(|| back(format!("{} {}", to.title, tr("не отвечает", "does not answer"))))?;
    b.provider = to.name.to_owned();
    write_backup(&path, &b)?;
    if let Some(l) = live_lock().as_mut() {
        l.provider = to;
        l.rtt = None;
        l.fails = 0;
    }
    Ok(Applied { provider: to, transport, strict, warnings: Vec::new(), first_lookup_ms: first.as_secs_f64() * 1000.0 })
}

/// Explicit restore (`netfreedom dns restore`, `stop`, uninstall). `Ok(false)` = nothing to undo.
pub fn restore(layout: &Layout) -> Result<bool, String> {
    let path = backup_path(layout);
    match read_backup(&path) {
        Saved::Missing => Ok(false),
        Saved::Corrupt => Err(format!("{} {}", path.display(), tr("повреждён или не наш: не трогаю DNS. Удалите файл, если настройки уже в порядке.", "is damaged or not ours: DNS is not touched. Delete the file if your settings are fine."))),
        Saved::Found(b) => undo(&path, &b).map(|()| true),
    }
}

/// What the session cleanup (Ctrl+C, closing the window, shutdown) runs. Quiet and idempotent; acts
/// only on a DNS change made by this process.
pub fn cleanup() {
    let Some(l) = live_lock().take() else { return };
    if let Saved::Found(b) = read_backup(&l.path) {
        match os::restore(&b.entries) {
            Ok(()) => {
                os::flush();
                let _ = fs::remove_file(&l.path);
            }
            Err(e) => eprintln!("DNS: {e} ({})", tr("настройки сохранены в utils/dns-backup.txt; `netfreedom dns restore`", "settings are kept in utils/dns-backup.txt; run `netfreedom dns restore`")),
        }
    }
}

/// The pid of a dead NetFreedom that left changed DNS behind.
pub fn stale_owner(layout: &Layout) -> Option<u32> {
    match read_backup(&backup_path(layout)) {
        Saved::Found(b) if b.pid != std::process::id() && !pid_alive(b.pid) => Some(b.pid),
        _ => None,
    }
}

/// At the start of an elevated command: undo what a crashed or killed run left behind. The owner's
/// pid is checked, so a second window never undoes the DNS of a session that is still running.
pub fn recover_stale(layout: &Layout) {
    if stale_owner(layout).is_some() {
        match restore(layout) {
            Ok(true) => ui::ok(tr("DNS возвращён: прошлый запуск завершился аварийно", "DNS restored: the previous run ended abnormally")),
            Ok(false) => {}
            Err(e) => ui::warn(&e),
        }
    }
}

// ------------------------------------------------------------------------------------- watchdog

/// Consecutive failed checks (one per ~15 s) before a lookup test and a possible failover.
const FAILS_BEFORE_TEST: u32 = 3;

/// One health step of the applied resolver. Returns an event line when something changed.
/// With `failover`, an unreachable provider is replaced by the next one that works; if none does,
/// the original DNS is restored (a dead resolver must never leave the player offline).
pub fn health_step(layout: &Layout, failover: bool) -> Option<String> {
    let (provider, transport, fails) = {
        let g = live_lock();
        let l = g.as_ref()?;
        (l.provider, l.transport, l.fails)
    };
    let port = transport.port();
    let rtt = provider.v4.iter().find_map(|a| a.parse().ok().and_then(|ip| tcp_probe(ip, port, 1, Duration::from_millis(1500))));
    {
        let mut g = live_lock();
        let l = g.as_mut()?;
        l.fails = if rtt.is_some() { 0 } else { fails + 1 };
        if rtt.is_some() {
            l.rtt = rtt;
        }
    }
    if rtt.is_some() || fails + 1 < FAILS_BEFORE_TEST || !failover {
        return None;
    }
    // the endpoint stays silent: does the system still resolve (the other address, a cached path)?
    os::flush();
    if verify(Duration::from_secs(3)).is_some() {
        if let Some(l) = live_lock().as_mut() {
            l.fails = 0;
        }
        return None;
    }
    let order: Vec<&'static Provider> = PROVIDERS.iter().cycle().skip_while(|p| p.name != provider.name).skip(1).take(PROVIDERS.len() - 1).collect();
    for next in order {
        if tcp_probe(next.v4[0].parse().ok()?, port, 1, Duration::from_millis(1500)).is_none() {
            continue;
        }
        if switch(next).is_ok() {
            return Some(format!("{} {} → {}", tr("DNS: нет ответа от", "DNS: no answer from"), provider.title, next.title));
        }
    }
    match restore(layout) {
        Ok(_) => Some(tr("DNS: ни один резолвер не отвечает, возвращён прежний DNS", "DNS: no resolver answers, the original DNS is back").to_owned()),
        Err(e) => Some(format!("DNS: {e}")),
    }
}

// ------------------------------------------------------------------------ Windows: PowerShell

/// Scripts and parsers for the Windows side. Pure strings, tested on every OS. The scripts are
/// ASCII only and handed over with `-EncodedCommand`: no temporary file that another process could
/// swap, no quoting. Every value that comes from the backup file was validated on parsing.
pub mod ps {
    use super::*;

    const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    fn base64(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
        for c in bytes.chunks(3) {
            let n = (u32::from(c[0]) << 16) | (u32::from(*c.get(1).unwrap_or(&0)) << 8) | u32::from(*c.get(2).unwrap_or(&0));
            for i in 0..4 {
                if i <= c.len() {
                    out.push(B64[(n >> (18 - 6 * i) & 63) as usize] as char);
                } else {
                    out.push('=');
                }
            }
        }
        out
    }

    /// The `-EncodedCommand` form of a script (base64 of UTF-16LE).
    pub fn encoded_command(script: &str) -> String {
        let bytes: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
        base64(&bytes)
    }

    const HEAD: &str = "$ErrorActionPreference = 'Stop'\n[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false\n$t = [char]9\n";
    const CATCH: &str = "} catch { 'ERR' + $t + $_.Exception.Message; exit 1 }\n";

    fn quoted_list(items: &[String]) -> String {
        items.iter().map(|a| format!("'{a}'")).collect::<Vec<_>>().join(",")
    }

    fn all_provider_ips() -> Vec<&'static str> {
        PROVIDERS.iter().flat_map(|p| p.v4.iter().chain(p.v6.iter()).copied()).collect()
    }

    /// Read-only: the active adapters (those with a default route, without tunnels and virtual
    /// switches), their STATIC servers from the registry (empty = automatic), and the DoH table rows
    /// of every provider address. Prints `NODOH` when the OS has no DoH client.
    pub fn snapshot_script() -> String {
        let ips = all_provider_ips().iter().map(|a| format!("'{a}'")).collect::<Vec<_>>().join(",");
        format!(
            "{HEAD}try {{
  $doh = [bool](Get-Command Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue)
  if (-not $doh) {{ 'NODOH' }}
  $skip = 'WARP|Wintun|WireGuard|TAP-|OpenVPN|vEthernet|VMware|VirtualBox|Loopback|Bluetooth|Hyper-V|Npcap|Tailscale|ZeroTier'
  $idx = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0','::/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -ExpandProperty InterfaceIndex -Unique)
  foreach ($i in $idx) {{
    $a = Get-NetAdapter -InterfaceIndex $i -ErrorAction SilentlyContinue
    if (-not $a -or $a.Status -ne 'Up') {{ continue }}
    if ($a.Name -match $skip -or $a.InterfaceDescription -match $skip) {{ continue }}
    $g = $a.InterfaceGuid
    $n4 = ''; $n6 = ''
    $k4 = Get-ItemProperty -Path ('HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\' + $g) -ErrorAction SilentlyContinue
    if ($k4 -and $k4.NameServer) {{ $n4 = ($k4.NameServer -replace '[\\s;]+', ',').Trim(',') }}
    $k6 = Get-ItemProperty -Path ('HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\Interfaces\\' + $g) -ErrorAction SilentlyContinue
    if ($k6 -and $k6.NameServer) {{ $n6 = ($k6.NameServer -replace '[\\s;]+', ',').Trim(',') }}
    $c6 = @((Get-DnsClientServerAddress -InterfaceIndex $i -AddressFamily IPv6).ServerAddresses | Where-Object {{ $_ -notlike 'fec0:*' }}) -join ','
    'IF' + $t + $i + $t + $a.Name + $t + $n4 + $t + $n6 + $t + $c6
  }}
  if ($doh) {{
    foreach ($ip in @({ips})) {{
      $d = Get-DnsClientDohServerAddress -ServerAddress $ip -ErrorAction SilentlyContinue
      if ($d) {{ 'DOH' + $t + $ip + $t + $d.DohTemplate + $t + [int][bool]$d.AutoUpgrade + $t + [int][bool]$d.AllowFallbackToUdp }}
      else {{ 'DOH' + $t + $ip + $t + 'absent' }}
    }}
  }}
{CATCH}"
        )
    }

    pub fn parse_snapshot(out: &str) -> Result<Snapshot, String> {
        let mut entries = Vec::new();
        let mut encrypted = true;
        for line in out.lines() {
            let line = line.trim_start_matches('\u{feff}').trim_end_matches('\r');
            let f: Vec<&str> = line.split('\t').collect();
            match f[0] {
                "NODOH" => encrypted = false,
                "ERR" => return Err(format!("PowerShell: {}", f.get(1).unwrap_or(&""))),
                "IF" if f.len() >= 6 => {
                    let v4 = words(f[3], |c| c == ',');
                    let v6 = words(f[4], |c| c == ',');
                    if !v4.iter().chain(&v6).all(|a| is_ip(a)) {
                        return Err("an adapter reports DNS servers that are not IP addresses; nothing was changed".into());
                    }
                    let index = f[1].trim().parse().map_err(|_| "bad adapter index".to_owned())?;
                    entries.push(Entry::Adapter { index, name: clean(f[2]), v4, v6, v6_active: !f[5].trim().is_empty() });
                }
                "DOH" if f.len() >= 3 => {
                    let ip = f[1].trim().to_owned();
                    if !is_ip(&ip) {
                        continue;
                    }
                    let saved = if f[2].trim() == "absent" {
                        None
                    } else if f.len() >= 5 && is_template(f[2].trim()) {
                        Some((f[2].trim().to_owned(), f[3].trim() == "1", f[4].trim() == "1"))
                    } else {
                        return Err("the DoH table holds an entry that cannot be saved safely; nothing was changed".into());
                    };
                    entries.push(Entry::Doh { ip, saved });
                }
                _ => {}
            }
        }
        Ok(Snapshot { entries, encrypted, warnings: Vec::new() })
    }

    /// Registers the provider's DoH templates (unless `Plain`) and makes its addresses the servers of
    /// every adapter in `entries`. IPv6 servers only on adapters that had IPv6 DNS: a resolver that
    /// the adapter cannot reach would only add timeouts.
    pub fn apply_script(entries: &[Entry], p: &Provider, strict: bool, t: Transport) -> String {
        let mut s = format!("{HEAD}try {{\n");
        if t != Transport::Plain {
            let fb = if strict { "$false" } else { "$true" };
            s.push_str(
                "  function SetDoh($ip, $tpl, $fb) {
    $e = Get-DnsClientDohServerAddress -ServerAddress $ip -ErrorAction SilentlyContinue
    if ($e) { Set-DnsClientDohServerAddress -ServerAddress $ip -DohTemplate $tpl -AutoUpgrade $true -AllowFallbackToUdp $fb | Out-Null }
    else { Add-DnsClientDohServerAddress -ServerAddress $ip -DohTemplate $tpl -AutoUpgrade $true -AllowFallbackToUdp $fb | Out-Null }
  }\n",
            );
            for ip in p.v4.iter().chain(p.v6.iter()) {
                s.push_str(&format!("  SetDoh '{ip}' '{}' {fb}\n", p.doh));
            }
        }
        for e in entries {
            if let Entry::Adapter { index, v6_active, .. } = e {
                let mut list: Vec<String> = p.v4.iter().map(|a| (*a).to_owned()).collect();
                if *v6_active {
                    list.extend(p.v6.iter().map(|a| (*a).to_owned()));
                }
                s.push_str(&format!("  Set-DnsClientServerAddress -InterfaceIndex {index} -ServerAddresses @({})\n", quoted_list(&list)));
            }
        }
        s.push_str("  Clear-DnsClientCache\n  'OK'\n");
        s.push_str(CATCH);
        s
    }

    /// Puts every adapter back (`FAIL` lines for the ones that could not be restored; an adapter
    /// that no longer exists counts as restored) and the DoH table rows (best effort: `WARN`).
    pub fn restore_script(entries: &[Entry]) -> String {
        let mut s = format!("{HEAD}try {{\n");
        for e in entries {
            match e {
                Entry::Adapter { index, v4, v6, .. } => {
                    let statics: Vec<String> = v4.iter().chain(v6).cloned().collect();
                    let set = if statics.is_empty() {
                        format!("Set-DnsClientServerAddress -InterfaceIndex {index} -ResetServerAddresses")
                    } else {
                        format!("Set-DnsClientServerAddress -InterfaceIndex {index} -ServerAddresses @({})", quoted_list(&statics))
                    };
                    s.push_str(&format!(
                        "  if (Get-NetAdapter -InterfaceIndex {index} -ErrorAction SilentlyContinue) {{\n    try {{ {set}; 'OK' + $t + {index} }} catch {{ 'FAIL' + $t + {index} + $t + $_.Exception.Message }}\n  }}\n"
                    ));
                }
                Entry::Doh { ip, saved: None } => {
                    s.push_str(&format!("  try {{ Remove-DnsClientDohServerAddress -ServerAddress '{ip}' -Confirm:$false }} catch {{ 'WARN' + $t + $_.Exception.Message }}\n"));
                }
                Entry::Doh { ip, saved: Some((tpl, au, fb)) } => {
                    let b = |v: &bool| if *v { "$true" } else { "$false" };
                    s.push_str(&format!(
                        "  try {{ Set-DnsClientDohServerAddress -ServerAddress '{ip}' -DohTemplate '{tpl}' -AutoUpgrade {} -AllowFallbackToUdp {} | Out-Null }} catch {{ 'WARN' + $t + $_.Exception.Message }}\n",
                        b(au),
                        b(fb)
                    ));
                }
                Entry::Link { .. } => {}
            }
        }
        s.push_str("  Clear-DnsClientCache\n");
        s.push_str(CATCH);
        s
    }

    /// `adapter<TAB>servers` for every adapter that has IPv4 DNS servers (for `dns status` and the
    /// comparison row of the benchmark).
    pub fn current_script() -> String {
        format!("{HEAD}Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object {{ $_.ServerAddresses.Count -gt 0 }} | ForEach-Object {{ $_.InterfaceAlias + $t + ($_.ServerAddresses -join ',') }}\n")
    }
}

// --------------------------------------------------------------------- Linux: systemd-resolved

/// Parsers and argument builders for `resolvectl`. Pure, tested on every OS.
pub mod resolved {
    use super::*;

    /// Names that are tunnels, bridges or containers, never the uplink.
    const NOT_UPLINK: [&str; 11] = ["lo", "CloudflareWARP", "tun", "tap", "wg", "ppp", "docker", "veth", "br-", "virbr", "tailscale"];

    /// The interface of the best default route in `ip -o route show default` output.
    pub fn uplink(routes: &str) -> Option<String> {
        routes
            .lines()
            .filter_map(|l| {
                let t: Vec<&str> = l.split_whitespace().collect();
                let dev = t.iter().position(|x| *x == "dev").and_then(|i| t.get(i + 1))?;
                let metric = t.iter().position(|x| *x == "metric").and_then(|i| t.get(i + 1)).and_then(|m| m.parse::<u32>().ok()).unwrap_or(0);
                (!NOT_UPLINK.iter().any(|p| dev.starts_with(p))).then(|| (metric, (*dev).to_owned()))
            })
            .min_by_key(|(m, _)| *m)
            .map(|(_, d)| d)
    }

    /// The value in `Link 2 (eth0): a b c` (text after the first colon; empty when there is none).
    pub fn link_value(out: &str) -> String {
        out.lines().next().and_then(|l| l.split_once(':')).map(|(_, v)| v.trim().to_owned()).unwrap_or_default()
    }

    /// True when one of the servers is a non-link-local IPv6 address.
    pub fn has_global_v6(dns: &[String]) -> bool {
        dns.iter().any(|d| {
            let addr = d.split('#').next().unwrap_or("").split('%').next().unwrap_or("");
            addr.parse::<std::net::Ipv6Addr>().is_ok_and(|a| a.segments()[0] & 0xffc0 != 0xfe80)
        })
    }

    /// `address#server.name` for every address of the provider (IPv6 only when `v6`).
    pub fn dns_args(p: &Provider, v6: bool) -> Vec<String> {
        let mut a: Vec<&str> = p.v4.to_vec();
        if v6 {
            a.extend(p.v6);
        }
        a.into_iter().map(|x| format!("{x}#{}", p.tls_name)).collect()
    }

    /// The link's own domains plus `~.` (route every name to this link), once.
    pub fn domain_args(current: &[String]) -> Vec<String> {
        let mut d: Vec<String> = current.to_vec();
        if !d.iter().any(|x| x == "~.") {
            d.push("~.".to_owned());
        }
        d
    }

    pub const fn tls_mode(strict: bool) -> &'static str {
        if strict { "yes" } else { "opportunistic" }
    }
}

// ---------------------------------------------------------------------------- the OS back ends

#[cfg(windows)]
mod os {
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};

    use super::*;

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    fn run(script: &str) -> Result<String, String> {
        let out = Command::new(crate::util::system_tool("powershell"))
            .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", &ps::encoded_command(script)])
            .creation_flags(CREATE_NO_WINDOW)
            .stdin(Stdio::null())
            .output()
            .map_err(|e| format!("cannot run PowerShell: {e}"))?;
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        if let Some(l) = text.lines().find(|l| l.trim_start_matches('\u{feff}').starts_with("ERR\t")) {
            return Err(format!("PowerShell: {}", l.split('\t').nth(1).unwrap_or("")));
        }
        if !out.status.success() && text.trim().is_empty() {
            return Err(format!("PowerShell: {}", String::from_utf8_lossy(&out.stderr).lines().next().unwrap_or("failed")));
        }
        Ok(text)
    }

    pub fn snapshot() -> Result<Snapshot, String> {
        ps::parse_snapshot(&run(&ps::snapshot_script())?)
    }

    pub fn apply(entries: &[Entry], p: &Provider, strict: bool, t: Transport) -> Result<(), String> {
        let out = run(&ps::apply_script(entries, p, strict, t))?;
        if out.lines().any(|l| l.trim() == "OK") { Ok(()) } else { Err("PowerShell did not confirm the change".into()) }
    }

    pub fn restore(entries: &[Entry]) -> Result<(), String> {
        let out = run(&ps::restore_script(entries))?;
        match out.lines().find(|l| l.trim_start_matches('\u{feff}').starts_with("FAIL\t")) {
            Some(l) => Err(format!("adapter {}: {}", l.split('\t').nth(1).unwrap_or("?"), l.split('\t').nth(2).unwrap_or(""))),
            None => Ok(()),
        }
    }

    pub fn flush() {
        let _ = Command::new(crate::util::system_tool("ipconfig")).arg("/flushdns").creation_flags(CREATE_NO_WINDOW).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).status();
    }

    pub fn current_servers() -> Vec<String> {
        run(&ps::current_script()).map(|t| t.lines().map(|l| l.trim_start_matches('\u{feff}').trim().to_owned()).filter(|l| !l.is_empty()).collect()).unwrap_or_default()
    }
}

#[cfg(unix)]
mod os {
    use std::process::{Command, Stdio};

    use super::*;

    fn rc(args: &[&str]) -> Result<String, String> {
        let out = Command::new(crate::util::system_tool("resolvectl")).args(args).stdin(Stdio::null()).output().map_err(|e| format!("cannot run resolvectl: {e}"))?;
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).into_owned())
        } else {
            let err = String::from_utf8_lossy(&out.stderr);
            Err(format!("resolvectl {}: {}", args.join(" "), err.lines().next().unwrap_or("failed")))
        }
    }

    fn default_routes() -> String {
        let ip = crate::util::system_tool("ip");
        let run = |extra: &[&str]| Command::new(&ip).args(extra).args(["-o", "route", "show", "default"]).stdin(Stdio::null()).output().map(|o| String::from_utf8_lossy(&o.stdout).into_owned()).unwrap_or_default();
        format!("{}{}", run(&[]), run(&["-6"]))
    }

    pub fn snapshot() -> Result<Snapshot, String> {
        if !crate::util::system_tool("resolvectl").is_absolute() {
            return Err(no_resolved());
        }
        rc(&["dns"]).map_err(|e| format!("{}\n{e}", no_resolved()))?;
        let link = resolved::uplink(&default_routes()).ok_or_else(|| tr("нет маршрута по умолчанию: подключитесь к сети", "no default route: connect to a network first").to_owned())?;
        if !is_link_name(&link) {
            return Err(format!("unexpected interface name \"{link}\""));
        }
        let value = |what: &str| rc(&[what, &link]).map(|o| resolved::link_value(&o));
        let entry = Entry::Link {
            dns: words(&value("dns")?, char::is_whitespace),
            domains: words(&value("domain")?, char::is_whitespace),
            tls: value("dnsovertls")?,
            default_route: value("default-route").unwrap_or_default(),
            name: link,
        };
        let mut warnings = Vec::new();
        let managed = std::fs::read_link("/etc/resolv.conf").map(|p| p.to_string_lossy().contains("systemd/resolve")).unwrap_or(false);
        if !managed {
            warnings.push(tr(
                "/etc/resolv.conf не ведёт на systemd-resolved: программы, которые читают его напрямую, обойдут этот DNS (ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf)",
                "/etc/resolv.conf does not point to systemd-resolved: programs that read it directly bypass this DNS (ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf)",
            )
            .to_owned());
        }
        Ok(Snapshot { entries: vec![entry], encrypted: true, warnings })
    }

    fn no_resolved() -> String {
        tr(
            "systemd-resolved не запущен. Он нужен для шифрованного DNS на Linux (в Debian: sudo apt install systemd-resolved && sudo systemctl enable --now systemd-resolved). DNS не изменён.",
            "systemd-resolved is not running. Encrypted DNS on Linux needs it (Debian: sudo apt install systemd-resolved && sudo systemctl enable --now systemd-resolved). DNS was NOT changed.",
        )
        .to_owned()
    }

    pub fn apply(entries: &[Entry], p: &Provider, strict: bool, _t: Transport) -> Result<(), String> {
        for e in entries {
            let Entry::Link { name, dns, domains, .. } = e else { continue };
            let servers = resolved::dns_args(p, resolved::has_global_v6(dns));
            let mut a: Vec<&str> = vec!["dns", name];
            a.extend(servers.iter().map(String::as_str));
            rc(&a)?;
            rc(&["dnsovertls", name, resolved::tls_mode(strict)])?;
            let doms = resolved::domain_args(domains);
            let mut a: Vec<&str> = vec!["domain", name];
            a.extend(doms.iter().map(String::as_str));
            rc(&a)?;
            rc(&["default-route", name, "yes"])?;
        }
        Ok(())
    }

    pub fn restore(entries: &[Entry]) -> Result<(), String> {
        for e in entries {
            let Entry::Link { name, dns, tls, domains, default_route } = e else { continue };
            if dns.is_empty() {
                rc(&["revert", name])?;
                continue;
            }
            let mut a: Vec<&str> = vec!["dns", name];
            a.extend(dns.iter().map(String::as_str));
            rc(&a)?;
            let mut a: Vec<&str> = vec!["domain", name];
            if domains.is_empty() {
                a.push("");
            }
            a.extend(domains.iter().map(String::as_str));
            rc(&a)?;
            if !tls.is_empty() {
                rc(&["dnsovertls", name, tls])?;
            }
            if !default_route.is_empty() {
                rc(&["default-route", name, default_route])?;
            }
        }
        Ok(())
    }

    pub fn flush() {
        let _ = rc(&["flush-caches"]);
    }

    pub fn current_servers() -> Vec<String> {
        rc(&["dns"]).map(|t| t.lines().map(str::trim).filter(|l| l.split_once(':').is_some_and(|(_, v)| !v.trim().is_empty())).map(str::to_owned).collect()).unwrap_or_default()
    }
}

// ---------------------------------------------------------------------------------- commands

fn usage() -> String {
    "usage:\n  netfreedom dns [status]                 what is chosen and what the system uses now\n  netfreedom dns list                     the providers and their addresses\n  netfreedom dns bench [probes]           measure every provider on this connection\n  netfreedom dns set <cloudflare|google|quad9|auto|off> [--strict|--fallback] [--plain|--no-plain]\n  netfreedom dns restore                  undo a DNS change that is still applied (needs admin rights)".to_owned()
}

/// What `start` and the menu print after a successful `apply` / `switch`.
pub fn print_applied(a: &Applied) {
    let how = match a.transport {
        Transport::Doh => tr("шифрование DoH", "DoH encryption"),
        Transport::Dot => tr("шифрование DoT (DoH на Linux недоступен в systemd-resolved)", "DoT encryption (systemd-resolved has no DoH)"),
        Transport::Plain => tr("БЕЗ шифрования (обычный DNS)", "NO encryption (plain DNS)"),
    };
    let mode = if a.transport == Transport::Plain {
        ""
    } else if a.strict {
        tr(", строго: без обычного DNS", ", strict: no plain-DNS fallback")
    } else {
        tr(", при сбое — обычный DNS того же провайдера", ", falls back to the same provider's plain DNS if it fails")
    };
    ui::ok(&format!("DNS: {} · {how}{mode} · {} {:.0} ms", a.provider.title, tr("первый запрос", "first lookup"), a.first_lookup_ms));
    for w in &a.warnings {
        ui::warn(w);
    }
}

fn describe_saved(cfg: &Config) -> String {
    let choice = Choice::parse(&cfg.dns).unwrap_or(Choice::Off);
    let mut s = choice.title();
    if choice != Choice::Off {
        s.push_str(if cfg.dns_strict { tr(" · строгий режим", " · strict") } else { "" });
        s.push_str(if cfg.dns_plain { tr(" · разрешён обычный DNS", " · plain DNS allowed") } else { "" });
    }
    s
}

/// The saved choice and flags of `cfg`.
pub fn saved(cfg: &Config) -> (Choice, bool, bool) {
    (Choice::parse(&cfg.dns).unwrap_or(Choice::Off), cfg.dns_strict, cfg.dns_plain)
}

fn status(layout: &Layout) -> Result<(), String> {
    let cfg = Config::load_with_legacy(&layout.cfg, &layout.cfg_legacy);
    ui::heading(tr("DNS", "DNS"));
    println!("  {:<14}{}", tr("Выбор", "Chosen"), describe_saved(&cfg));
    println!(
        "  {:<14}{}",
        tr("Шифрование", "Encryption"),
        if cfg!(windows) { tr("DoH (нужна Windows 11 / Server 2022)", "DoH (needs Windows 11 / Server 2022)") } else { tr("DoT через systemd-resolved", "DoT through systemd-resolved") }
    );
    match read_backup(&backup_path(layout)) {
        Saved::Found(b) => {
            let who = if b.pid == std::process::id() { tr("этот запуск", "this run").to_owned() } else if pid_alive(b.pid) { format!("{} {}", tr("запущенный NetFreedom, pid", "a running NetFreedom, pid"), b.pid) } else { tr("ЗАВЕРШИВШИЙСЯ запуск (нужен `netfreedom dns restore`)", "a run that has ENDED (run `netfreedom dns restore`)").to_owned() };
            println!("  {:<14}{} · {} · {}", tr("Применён", "Applied"), find(&b.provider).map_or(b.provider.as_str(), |p| p.title), b.transport.label(), who);
        }
        Saved::Corrupt => ui::warn(tr("utils/dns-backup.txt повреждён или не наш", "utils/dns-backup.txt is damaged or not ours")),
        Saved::Missing => println!("  {:<14}{}", tr("Применён", "Applied"), tr("нет (DNS системы не менялся)", "no (the system's DNS is untouched)")),
    }
    println!("  {}", tr("Сейчас в системе:", "The system uses now:"));
    let now = os::current_servers();
    if now.is_empty() {
        println!("    —");
    }
    for l in now {
        println!("    {l}");
    }
    Ok(())
}

fn list() {
    println!();
    for p in &PROVIDERS {
        println!("  {:<11} {}", p.name, p.title);
        println!("              IPv4  {}", p.v4.join(", "));
        println!("              IPv6  {}", p.v6.join(", "));
        println!("              DoH   {}", p.doh);
        println!("              DoT   {}:853", p.tls_name);
    }
    println!();
}

fn set(layout: &Layout, args: &[String]) -> Result<(), String> {
    let mut name = None;
    let mut cfg = Config::load_with_legacy(&layout.cfg, &layout.cfg_legacy);
    for a in args {
        match a.as_str() {
            "--strict" => cfg.dns_strict = true,
            "--fallback" => cfg.dns_strict = false,
            "--plain" => cfg.dns_plain = true,
            "--no-plain" => cfg.dns_plain = false,
            x if x.starts_with('-') => return Err(format!("unknown option {x}\n{}", usage())),
            x => name = Some(x),
        }
    }
    let choice = Choice::parse(name.ok_or_else(usage)?)?;
    cfg.dns = choice.key().to_owned();
    let _ = fs::create_dir_all(&layout.utils);
    cfg.save(&layout.cfg).map_err(|e| format!("cannot save {}: {e}", layout.cfg.display()))?;
    ui::ok(&format!("DNS: {}", describe_saved(&cfg)));
    if choice != Choice::Off {
        println!("{}", tr("Применяется при каждом запуске режима (игры через WARP или обход) и возвращается при остановке.", "Applied at every start (games via WARP or bypass) and put back when it stops."));
    }
    Ok(())
}

/// `netfreedom dns ...`
pub fn command(layout: &Layout, args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str).unwrap_or("status") {
        "status" => status(layout),
        "list" => {
            list();
            Ok(())
        }
        "bench" => {
            let n = args.get(1).and_then(|x| x.parse().ok()).unwrap_or(10);
            println!("{}", tr("Измеряю провайдеров (около 5 с)…", "Measuring the providers (about 5 s)..."));
            print_bench(&bench(n));
            Ok(())
        }
        "set" => set(layout, &args[1..]),
        "restore" => match restore(layout)? {
            true => {
                ui::ok(tr("DNS возвращён как был", "DNS is back as it was"));
                Ok(())
            }
            false => {
                println!("{}", tr("Нечего возвращать: NetFreedom DNS не менял.", "Nothing to undo: NetFreedom has not changed DNS."));
                Ok(())
            }
        },
        _ => Err(usage()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(label: &str, p: Option<&'static Provider>, udp: &[f64], sent: usize, doh: Option<f64>, dot: Option<f64>) -> Row {
        Row { label: label.into(), provider: p, addr: Ipv4Addr::new(1, 1, 1, 1), udp: udp.to_vec(), sent, doh, dot }
    }

    #[test]
    fn providers_are_well_formed() {
        for p in &PROVIDERS {
            assert!(p.v4.iter().all(|a| a.parse::<Ipv4Addr>().is_ok()), "{}", p.name);
            assert!(p.v6.iter().all(|a| a.parse::<std::net::Ipv6Addr>().is_ok()), "{}", p.name);
            assert!(is_template(p.doh), "{}", p.name);
            assert!(p.doh.contains(p.tls_name), "the DoH host is the certificate name: {}", p.name);
            assert_eq!(find(p.name), Some(p));
        }
        assert_eq!(find("CF").map(|p| p.name), Some("cloudflare"));
        assert_eq!(find("8.8.4.4").map(|p| p.name), Some("google"));
        assert_eq!(find("9.9.9.9").map(|p| p.name), Some("quad9"));
        assert!(find("yandex").is_none());
    }

    #[test]
    fn choices_parse_and_roundtrip() {
        assert_eq!(Choice::parse("").unwrap(), Choice::Off);
        assert_eq!(Choice::parse("OFF").unwrap(), Choice::Off);
        assert_eq!(Choice::parse("Auto").unwrap(), Choice::Auto);
        for p in &PROVIDERS {
            let c = Choice::parse(p.name).unwrap();
            assert_eq!(c, Choice::Fixed(p));
            assert_eq!(Choice::parse(c.key()).unwrap(), c);
        }
        assert!(Choice::parse("dns.example").unwrap_err().contains("cloudflare, google, quad9"));
        assert_eq!(Choice::Off.key(), "");
    }

    #[test]
    fn query_and_reply_on_the_wire() {
        let q = build_query(0xBEEF, "example.com");
        assert_eq!(&q[..12], &[0xBE, 0xEF, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(&q[12..], b"\x07example\x03com\x00\x00\x01\x00\x01");
        assert_eq!(build_query(1, "example.com.")[12..], q[12..], "a trailing dot changes nothing");

        let mut r = vec![0xBE, 0xEF, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0];
        assert_eq!(parse_reply(0xBEEF, &r), Some(Reply { rcode: 0, answers: 2 }));
        assert_eq!(parse_reply(0xBEEE, &r), None, "another query's answer");
        r[2] = 0x01; // a query, not a response
        assert_eq!(parse_reply(0xBEEF, &r), None);
        assert_eq!(parse_reply(0xBEEF, &[0; 5]), None);
        assert_eq!(parse_reply(0xBEEF, &[0xBE, 0xEF, 0x81, 0x83, 0, 1, 0, 0, 0, 0, 0, 0]).map(|r| r.rcode), Some(3), "NXDOMAIN");
    }

    #[test]
    fn udp_probe_talks_to_a_local_server_and_rejects_bad_answers() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = server.local_addr().unwrap();
        let t = std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            for answer in [true, false, true] {
                let (n, from) = server.recv_from(&mut buf).unwrap();
                if !answer {
                    continue; // stay silent: the probe must time out
                }
                let mut r = buf[..n].to_vec();
                r[2] = 0x81;
                r[3] = 0x80;
                r[7] = 1; // one answer
                server.send_to(&r, from).unwrap();
            }
        });
        let ms = udp_probe(addr, 7, Duration::from_millis(500)).expect("answered");
        assert!((0.0..500.0).contains(&ms));
        assert!(udp_probe(addr, 8, Duration::from_millis(150)).is_none(), "silence is a loss");
        assert!(udp_probe(addr, 9, Duration::from_millis(500)).is_some());
        t.join().unwrap();
    }

    #[test]
    fn tcp_probe_reaches_a_listener_and_not_a_closed_port() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        assert!(tcp_probe(Ipv4Addr::LOCALHOST, port, 2, Duration::from_millis(500)).is_some());
        drop(l);
        assert!(tcp_probe(Ipv4Addr::LOCALHOST, port, 1, Duration::from_millis(300)).is_none());
    }

    #[test]
    fn medians_scores_and_the_choice_of_the_best_provider() {
        assert_eq!(median(&mut [3.0, 1.0, 2.0]), Some(2.0));
        assert_eq!(median(&mut [4.0, 1.0, 2.0, 3.0]), Some(2.5));
        assert_eq!(median(&mut []), None);

        let (cf, g, q9) = (&PROVIDERS[0], &PROVIDERS[1], &PROVIDERS[2]);
        // the port that decides on this platform
        let on = |ms: Option<f64>| if native_transport() == Transport::Doh { (ms, None) } else { (None, ms) };
        let (a, b) = on(Some(20.0));
        let fast_but_lossy = row("cf", Some(cf), &[10.0; 5], 10, a, b); // 50% lost: 20 + 100
        let (a, b) = on(Some(35.0));
        let steady = row("google", Some(g), &[30.0; 10], 10, a, b);
        let (a, b) = on(None);
        let filtered = row("quad9", Some(q9), &[9.0; 10], 10, a, b); // fast on UDP, but the encrypted port is blocked
        let current = row("isp", None, &[2.0; 10], 10, None, None);
        let rows = [fast_but_lossy, steady, filtered, current];
        assert_eq!(best(&rows).map(|p| p.name), Some("google"));
        assert_eq!(rows[2].score(), None, "an unreachable transport is never chosen, however fast UDP is");
        assert_eq!(rows[0].loss_pct(), 50.0);
        assert!(best(&[rows[2].clone(), rows[3].clone()]).is_none());
        assert_eq!(rows[1].udp_median(), Some(30.0));
    }

    fn sample_entries() -> Vec<Entry> {
        vec![
            Entry::Adapter { index: 12, name: "Ethernet 2".into(), v4: vec!["192.168.1.1".into()], v6: vec![], v6_active: false },
            Entry::Adapter { index: 7, name: "Беспроводная сеть".into(), v4: vec![], v6: vec![], v6_active: true },
            Entry::Doh { ip: "1.1.1.1".into(), saved: Some(("https://cloudflare-dns.com/dns-query".into(), false, true)) },
            Entry::Doh { ip: "2620:fe::9".into(), saved: None },
            Entry::Link { name: "enp3s0".into(), dns: vec!["192.168.1.1".into(), "fe80::1%2".into(), "1.1.1.1#cloudflare-dns.com".into()], tls: "no".into(), domains: vec!["lan".into(), "~corp.example".into()], default_route: "yes".into() },
            Entry::Link { name: "wlan0".into(), dns: vec![], tls: String::new(), domains: vec![], default_route: String::new() },
        ]
    }

    #[test]
    fn the_backup_roundtrips() {
        let b = Backup { pid: 4242, provider: "quad9".into(), strict: true, transport: Transport::Doh, entries: sample_entries() };
        assert_eq!(Backup::parse(&b.render()), Some(b.clone()));
        // a text editor that adds a BOM or CRLF must not make the file unusable
        assert_eq!(Backup::parse(&b.render().replace('\n', "\r\n").replace("\r\n", "\n")), Some(b));
    }

    #[test]
    fn a_tampered_backup_is_never_acted_upon() {
        let good = Backup { pid: 1, provider: "google".into(), strict: false, transport: Transport::Dot, entries: sample_entries() }.render();
        assert!(Backup::parse(&good).is_some());
        let tamper = |from: &str, to: &str| Backup::parse(&good.replace(from, to));
        assert!(Backup::parse("not our file\npid\t1\n").is_none());
        // code injected through a value that ends up inside a PowerShell string or a command line
        assert!(tamper("https://cloudflare-dns.com/dns-query", "https://x/'; calc; '").is_none());
        assert!(tamper("doh\t1.1.1.1", "doh\t1.1.1.1'; calc; '").is_none());
        assert!(tamper("192.168.1.1\t\t0", "192.168.1.1'),(calc\t\t0").is_none());
        assert!(tamper("link\tenp3s0", "link\t--help").is_none());
        assert!(tamper("link\tenp3s0", "link\tenp3s0; reboot").is_none());
        assert!(tamper("\tlan ~corp.example\t", "\t$(reboot)\t").is_none());
        assert!(tamper("\tno\t", "\tmaybe\t").is_none());
        assert!(tamper("transport\tDoT", "transport\tcarrier-pigeon").is_none());
        assert!(Backup::parse(&good.replace("pid\t1\n", "")).is_none(), "no owner, no restore");
    }

    #[test]
    fn base64_and_encoded_commands() {
        assert_eq!(ps::encoded_command("A"), "QQA=");
        assert_eq!(ps::encoded_command("Get-Date"), "RwBlAHQALQBEAGEAdABlAA==");
    }

    const SNAPSHOT_OUT: &str = "\u{feff}NODOH\r\nIF\t12\tEthernet 2\t192.168.1.1,192.168.1.2\t\t\r\nIF\t7\tWi-Fi\t\t\t2001:db8::53\r\nDOH\t1.1.1.1\thttps://cloudflare-dns.com/dns-query\t0\t0\r\nDOH\t9.9.9.9\tabsent\r\nSOMETHING\telse\r\n";

    #[test]
    fn a_snapshot_is_parsed_and_noticed_as_having_no_doh_client() {
        let s = ps::parse_snapshot(SNAPSHOT_OUT).unwrap();
        assert!(!s.encrypted, "NODOH means Windows 10");
        assert_eq!(s.entries.len(), 4);
        assert_eq!(s.entries[0], Entry::Adapter { index: 12, name: "Ethernet 2".into(), v4: vec!["192.168.1.1".into(), "192.168.1.2".into()], v6: vec![], v6_active: false });
        assert!(matches!(&s.entries[1], Entry::Adapter { index: 7, v4, v6_active: true, .. } if v4.is_empty()));
        assert_eq!(s.entries[3], Entry::Doh { ip: "9.9.9.9".into(), saved: None });
        assert!(ps::parse_snapshot(&SNAPSHOT_OUT.replace("NODOH\r\n", "")).unwrap().encrypted);
        assert!(ps::parse_snapshot("ERR\taccess denied").unwrap_err().contains("access denied"));
        assert!(ps::parse_snapshot("IF\t1\tX\tnot-an-ip\t\t").is_err(), "garbage in the DNS list is refused, not passed on");
    }

    #[test]
    fn powershell_scripts_are_ascii_balanced_and_say_what_they_should() {
        let entries = sample_entries();
        let cf = &PROVIDERS[0];
        let scripts = [
            ps::snapshot_script(),
            ps::apply_script(&entries, cf, false, Transport::Doh),
            ps::apply_script(&entries, cf, true, Transport::Doh),
            ps::apply_script(&entries, cf, false, Transport::Plain),
            ps::restore_script(&entries),
            ps::current_script(),
        ];
        for s in &scripts {
            assert!(s.is_ascii(), "-EncodedCommand scripts must not depend on a code page:\n{s}");
            assert_eq!(s.matches('{').count(), s.matches('}').count(), "braces:\n{s}");
            assert_eq!(s.matches('\'').count() % 2, 0, "quotes:\n{s}");
            assert_eq!(s.matches('(').count(), s.matches(')').count(), "parentheses:\n{s}");
        }
        let snap = &scripts[0];
        assert!(snap.contains("Get-NetRoute") && snap.contains("Tcpip6") && snap.contains("NODOH") && snap.contains("'9.9.9.9'") && snap.contains("'2620:fe::9'"));
        assert!(snap.contains("WARP|Wintun"), "the WARP adapter is never touched");

        let relaxed = &scripts[1];
        assert!(relaxed.contains("SetDoh '1.1.1.1' 'https://cloudflare-dns.com/dns-query' $true"));
        assert!(relaxed.contains("SetDoh '2606:4700:4700::1001'"));
        assert!(relaxed.contains("Set-DnsClientServerAddress -InterfaceIndex 12 -ServerAddresses @('1.1.1.1','1.0.0.1')\n"), "no IPv6 where the adapter had none");
        assert!(relaxed.contains("-InterfaceIndex 7 -ServerAddresses @('1.1.1.1','1.0.0.1','2606:4700:4700::1111','2606:4700:4700::1001')"));
        assert!(relaxed.contains("Clear-DnsClientCache"));
        assert!(scripts[2].contains("'https://cloudflare-dns.com/dns-query' $false"), "strict: no fallback to UDP");
        assert!(!scripts[3].contains("DohServerAddress"), "plain DNS registers no DoH template");

        let undo = &scripts[4];
        assert!(undo.contains("-InterfaceIndex 12 -ServerAddresses @('192.168.1.1')"), "a static server comes back as static");
        assert!(undo.contains("-InterfaceIndex 7 -ResetServerAddresses"), "an automatic adapter goes back to automatic");
        assert!(undo.contains("Remove-DnsClientDohServerAddress -ServerAddress '2620:fe::9'"));
        assert!(undo.contains("Set-DnsClientDohServerAddress -ServerAddress '1.1.1.1' -DohTemplate 'https://cloudflare-dns.com/dns-query' -AutoUpgrade $false -AllowFallbackToUdp $true"));
        assert!(undo.contains("Get-NetAdapter -InterfaceIndex 12"), "an adapter that is gone is skipped, not an error");
    }

    #[test]
    fn resolved_helpers() {
        let routes = "default via 10.8.0.1 dev tun0 proto static metric 50\ndefault via 192.168.1.1 dev wlp3s0 proto dhcp metric 600\ndefault via 192.168.1.1 dev enp3s0 proto dhcp src 192.168.1.20 metric 100\ndefault dev CloudflareWARP scope link\n";
        assert_eq!(resolved::uplink(routes).as_deref(), Some("enp3s0"), "tunnels are skipped, the lowest metric wins");
        assert_eq!(resolved::uplink("default dev wg0 scope link\n"), None);
        assert_eq!(resolved::uplink(""), None);

        assert_eq!(resolved::link_value("Link 2 (enp3s0): 192.168.1.1 fe80::1%2\n"), "192.168.1.1 fe80::1%2");
        assert_eq!(resolved::link_value("Link 2 (enp3s0):\n"), "");
        assert_eq!(resolved::link_value(""), "");

        assert!(resolved::has_global_v6(&["192.168.1.1".into(), "2001:db8::1".into()]));
        assert!(!resolved::has_global_v6(&["192.168.1.1".into(), "fe80::1%2".into()]));
        let g = &PROVIDERS[1];
        assert_eq!(resolved::dns_args(g, false), ["8.8.8.8#dns.google", "8.8.4.4#dns.google"]);
        assert_eq!(resolved::dns_args(g, true).len(), 4);
        assert_eq!(resolved::domain_args(&["lan".into()]), ["lan", "~."]);
        assert_eq!(resolved::domain_args(&["~.".into()]), ["~."], "never twice");
        assert_eq!((resolved::tls_mode(true), resolved::tls_mode(false)), ("yes", "opportunistic"));
        assert!(resolved::dns_args(g, true).iter().all(|a| is_dns_token(a)), "what we pass to resolvectl passes our own validation");
    }

    #[test]
    fn the_pid_check_knows_a_live_and_a_dead_process() {
        assert!(pid_alive(std::process::id()));
        assert!(!pid_alive(u32::MAX - 1));
    }

    #[test]
    fn stale_and_foreign_backups_are_told_apart() {
        let root = std::env::temp_dir().join(format!("nf-dns-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let l = Layout::at(root.clone());
        fs::create_dir_all(&l.utils).unwrap();
        assert_eq!(stale_owner(&l), None);
        assert!(!restore(&l).unwrap(), "nothing to undo");

        let mine = Backup { pid: std::process::id(), provider: "google".into(), strict: false, transport: Transport::Doh, entries: vec![] };
        write_backup(&backup_path(&l), &mine).unwrap();
        assert_eq!(stale_owner(&l), None, "our own run is not stale");
        let dead = Backup { pid: u32::MAX - 1, ..mine };
        write_backup(&backup_path(&l), &dead).unwrap();
        assert_eq!(stale_owner(&l), Some(u32::MAX - 1));

        fs::write(backup_path(&l), "junk").unwrap();
        assert_eq!(stale_owner(&l), None, "a file that is not ours is never treated as a stale backup");
        assert!(restore(&l).is_err());
        assert!(apply(&l, Choice::Fixed(&PROVIDERS[0]), false, false).unwrap_err().contains("dns-backup.txt"));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn the_first_usable_address_of_a_status_line() {
        assert_eq!(first_public_or_private_v4("Ethernet\t192.168.1.1,fe80::1"), Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(first_public_or_private_v4("Link 2 (eth0): 127.0.0.53 10.0.0.1"), Some(Ipv4Addr::new(10, 0, 0, 1)), "the local stub is not a resolver to compare");
        assert_eq!(first_public_or_private_v4("Global: "), None);
    }
}
