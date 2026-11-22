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

//! SNI-block detection and a per-site bypass search (no WARP).
//!
//! The signature of an SNI block is simple: to the SAME address and port, a TLS ClientHello that
//! names the blocked site gets no answer (reset, silence, close), while a ClientHello with another
//! name, or with no name, is answered by the server. Only the server name differs, so only the name
//! is being filtered. That is exactly what packet strategies (split, fake, disorder) can fix.
//! Everything else (no TCP connection, nothing answers whatever the name, poisoned DNS) is told
//! apart, because no strategy can fix it and trying them all would only waste minutes.
//!
//! The probe is a hand-built ClientHello over `std::net`: no TLS library, no dependency, no root.

use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use crate::web;

/// Neutral control name: answered by any server, listed nowhere.
pub const CONTROL_NEUTRAL: &str = "example.com";
/// Control name typical for "white list" regimes (only some names pass).
pub const CONTROL_WHITELISTED: &str = "yandex.ru";

// ------------------------------------------------------------------------------ ClientHello

fn xorshift(s: &mut u32) -> u8 {
    *s ^= *s << 13;
    *s ^= *s >> 17;
    *s ^= *s << 5;
    (*s >> 8) as u8
}

/// A small, valid TLS 1.3 ClientHello. `sni == None` leaves the server_name extension out.
/// Any 32 bytes are a valid X25519 public key, so a real server answers with a ServerHello.
pub fn build_hello(sni: Option<&str>, seed: u32) -> Vec<u8> {
    let mut s = seed | 1;
    let mut rnd = |n: usize| -> Vec<u8> { (0..n).map(|_| xorshift(&mut s)).collect() };
    let mut ext: Vec<u8> = Vec::new();
    if let Some(h) = sni {
        let n = h.len();
        ext.extend_from_slice(&[0, 0]);
        ext.extend_from_slice(&((n + 5) as u16).to_be_bytes());
        ext.extend_from_slice(&((n + 3) as u16).to_be_bytes());
        ext.push(0);
        ext.extend_from_slice(&(n as u16).to_be_bytes());
        ext.extend_from_slice(h.as_bytes());
    }
    ext.extend_from_slice(&[0, 0x0a, 0, 4, 0, 2, 0, 0x1d]); // supported_groups: x25519
    ext.extend_from_slice(&[0, 0x0d, 0, 8, 0, 6, 4, 3, 8, 4, 4, 1]); // signature_algorithms
    ext.extend_from_slice(&[0, 0x2b, 0, 3, 2, 3, 4]); // supported_versions: TLS 1.3
    ext.extend_from_slice(&[0, 0x33, 0, 38, 0, 36, 0, 0x1d, 0, 32]); // key_share x25519
    ext.extend_from_slice(&rnd(32));
    let mut body = vec![3, 3];
    body.extend_from_slice(&rnd(32));
    body.push(32);
    body.extend_from_slice(&rnd(32)); // legacy session id
    body.extend_from_slice(&[0, 6, 0x13, 1, 0x13, 2, 0x13, 3]);
    body.extend_from_slice(&[1, 0]);
    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext);
    let mut hs = vec![1, (body.len() >> 16) as u8, (body.len() >> 8) as u8, body.len() as u8];
    hs.extend_from_slice(&body);
    let mut rec = vec![0x16, 3, 1];
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

// ------------------------------------------------------------------------------ one probe

/// What came back after the ClientHello.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reply {
    /// A TLS handshake record (the ServerHello) or an alert: the server itself answered.
    Answered,
    /// RST: the typical active SNI block.
    Reset,
    /// FIN without data.
    Closed,
    /// Nothing within the time limit: the typical silent drop.
    Silence,
    /// Something that is not TLS (an injected block page).
    Injected,
}

impl Reply {
    pub fn answered(self) -> bool {
        self == Reply::Answered
    }

    pub fn word(self) -> &'static str {
        match self {
            Reply::Answered => "answered",
            Reply::Reset => "connection reset",
            Reply::Closed => "connection closed",
            Reply::Silence => "no answer (dropped)",
            Reply::Injected => "non-TLS data injected",
        }
    }
}

/// Classifies the first bytes the server sent back (pure).
pub fn classify(first: &[u8]) -> Reply {
    match first.first() {
        None => Reply::Closed,
        Some(0x16) | Some(0x15) if first.len() < 2 || first[1] == 3 => Reply::Answered,
        Some(_) => Reply::Injected,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Conn {
    Ok(Reply),
    Refused,
    NoSyn,
}

/// One TCP connection, one ClientHello, the first answer.
pub fn probe(ip: Ipv4Addr, sni: Option<&str>, timeout: Duration) -> Conn {
    let addr = SocketAddr::new(IpAddr::V4(ip), 443);
    let mut st = match TcpStream::connect_timeout(&addr, timeout) {
        Ok(s) => s,
        Err(e) if e.kind() == ErrorKind::ConnectionRefused => return Conn::Refused,
        Err(_) => return Conn::NoSyn,
    };
    let _ = st.set_nodelay(true);
    let _ = st.set_read_timeout(Some(timeout));
    let _ = st.set_write_timeout(Some(timeout));
    let seed = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.subsec_nanos()).unwrap_or(7) ^ u32::from(ip);
    if let Err(e) = st.write_all(&build_hello(sni, seed)) {
        return Conn::Ok(if matches!(e.kind(), ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted | ErrorKind::BrokenPipe) { Reply::Reset } else { Reply::Silence });
    }
    let mut buf = [0u8; 8];
    match st.read(&mut buf) {
        Ok(n) => Conn::Ok(classify(&buf[..n])),
        Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => Conn::Ok(Reply::Silence),
        Err(_) => Conn::Ok(Reply::Reset),
    }
}

// ------------------------------------------------------------------------------ decision

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Handshake and transfer work: nothing to fix.
    Open,
    /// The handshake works, then the connection is cut after about 16 KB.
    Throttled(u64),
    /// Only the server name is filtered. Packet strategies can fix this.
    SniBlocked(Reply),
    /// Only some names pass (white-list regime); a fake allowed name may help.
    Whitelist,
    /// No name gets through: address- or fingerprint-level block. Strategies cannot help.
    AddressBlocked,
    /// The system resolver gives a wrong address; the trusted resolver gives the right one.
    DnsPoisoned(Ipv4Addr, Ipv4Addr),
    /// The system resolver gives nothing, the trusted one does.
    DnsBlocked,
    /// No TCP connection to the address, while the reference host answers.
    NoConnection,
    /// Not even the reference host answers.
    Offline,
    Inconclusive,
}

impl Verdict {
    /// Can `netfreedom sni --fix` do something about it?
    pub fn fixable(&self) -> bool {
        matches!(self, Verdict::SniBlocked(_) | Verdict::Throttled(_) | Verdict::Whitelist)
    }
}

/// Evidence about one address (pure input of `decide`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Evidence {
    pub real: Conn,
    pub no_sni: Conn,
    pub neutral: Conn,
    pub whitelisted: Conn,
}

fn ans(c: Conn) -> bool {
    matches!(c, Conn::Ok(r) if r.answered())
}

pub fn decide(e: &Evidence) -> Verdict {
    if let Conn::Ok(r) = e.real {
        if r.answered() {
            return Verdict::Open;
        }
        if ans(e.no_sni) || ans(e.neutral) {
            return Verdict::SniBlocked(r);
        }
        if ans(e.whitelisted) {
            return Verdict::Whitelist;
        }
        return Verdict::AddressBlocked;
    }
    // the very first packet is not answered
    Verdict::NoConnection
}

/// IPs that no real site has: a block page host, a null route.
pub fn bogus(ip: Ipv4Addr) -> bool {
    ip.is_unspecified() || ip.is_loopback() || ip.is_private() || ip.is_link_local() || ip.is_broadcast()
}

/// `"data":"1.2.3.4"` values of a DNS-over-HTTPS JSON answer (type A only).
pub fn parse_doh(text: &str) -> Vec<Ipv4Addr> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(i) = rest.find("\"data\"") {
        rest = &rest[i + 6..];
        let Some(q1) = rest.find('"') else { break };
        let after = &rest[q1 + 1..];
        let Some(q2) = after.find('"') else { break };
        if let Ok(ip) = after[..q2].parse::<Ipv4Addr>() {
            if !out.contains(&ip) {
                out.push(ip);
            }
        }
        rest = &after[q2..];
    }
    out
}

/// A host name that is safe to put into a URL, a list file and a ClientHello.
pub fn valid_host(h: &str) -> bool {
    let h = h.trim_end_matches('.');
    !h.is_empty() && h.len() <= 253 && h.contains('.') && h.split('.').all(|l| !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-') && l.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-'))
}

/// `https://www.Example.com/path` -> `www.example.com`.
pub fn normalize_host(s: &str) -> Option<String> {
    let s = s.trim().to_ascii_lowercase();
    let s = s.as_str();
    let s = s.strip_prefix("https://").or_else(|| s.strip_prefix("http://")).unwrap_or(s);
    let h = s.split(['/', '?', '#']).next().unwrap_or("").split(':').next().unwrap_or("").trim_end_matches('.').to_ascii_lowercase();
    valid_host(&h).then_some(h)
}

/// What goes into the hostlist: `www.` is dropped so the whole site (zapret matches subdomains).
pub fn list_entry(host: &str) -> &str {
    host.strip_prefix("www.").filter(|r| r.contains('.')).unwrap_or(host)
}

// ------------------------------------------------------------------------------ network parts

pub fn resolve_system(host: &str) -> Vec<Ipv4Addr> {
    let mut v: Vec<Ipv4Addr> = (host, 443).to_socket_addrs().map(|it| it.filter_map(|a| if let IpAddr::V4(x) = a.ip() { Some(x) } else { None }).collect()).unwrap_or_default();
    v.dedup();
    v
}

/// Trusted answer over DoH, asked by IP (no name to filter), through curl.
pub fn resolve_trusted(host: &str) -> Vec<Ipv4Addr> {
    for url in [format!("https://1.1.1.1/dns-query?name={host}&type=A"), format!("https://8.8.8.8/resolve?name={host}&type=A")] {
        let out = web::curl_command().args(["-sS", "--ssl-no-revoke", "--connect-timeout", "4", "-m", "7", "-H", "accept: application/dns-json", &url]).output();
        if let Ok(o) = out {
            if o.status.success() {
                let v = parse_doh(&String::from_utf8_lossy(&o.stdout));
                if !v.is_empty() {
                    return v;
                }
            }
        }
    }
    Vec::new()
}

pub fn gather(ip: Ipv4Addr, host: &str, t: Duration) -> Evidence {
    std::thread::scope(|s| {
        let a = s.spawn(|| probe(ip, Some(host), t));
        let b = s.spawn(|| probe(ip, None, t));
        let c = s.spawn(|| probe(ip, Some(CONTROL_NEUTRAL), t));
        let d = s.spawn(|| probe(ip, Some(CONTROL_WHITELISTED), t));
        let j = |h: std::thread::ScopedJoinHandle<'_, Conn>| h.join().unwrap_or(Conn::NoSyn);
        Evidence { real: j(a), no_sni: j(b), neutral: j(c), whitelisted: j(d) }
    })
}

/// Page download pinned to `ip` (real SNI, real HTTP): the browser-grade second opinion, and the
/// only way to see the ~16 KB cut-off that happens AFTER a good handshake.
pub fn transfer(host: &str, ip: Ipv4Addr, secs: u64) -> Result<(u64, f64), (u64, String)> {
    if !web::curl_available() {
        return Err((0, "curl not found".into()));
    }
    let resolve = format!("{host}:443:{ip}");
    let url = format!("https://{host}/");
    let o = web::curl_command()
        .args(["-sS", "--ssl-no-revoke", "-L", "--max-redirs", "3", "--resolve", &resolve, "-o", web::null_device(), "--connect-timeout", "5", "-m", &secs.to_string()])
        .args(["-w", "%{http_code} %{size_download} %{time_total}", &url])
        .output();
    let Ok(o) = o else { return Err((0, "cannot run curl".into())) };
    let parsed = web::parse_write_out(&String::from_utf8_lossy(&o.stdout));
    let why = web::explain_exit(o.status.code().unwrap_or(-1), &String::from_utf8_lossy(&o.stderr));
    match parsed {
        Some((code, bytes, t)) if o.status.success() && code > 0 => Ok((bytes, t)),
        Some((_, bytes, _)) => Err((bytes, why)),
        None => Err((0, why)),
    }
}

/// Was a download cut in the ~16 KB band that TSPU uses?
pub fn is_cut(bytes: u64) -> bool {
    (12_000..=24_000).contains(&bytes)
}

pub struct Report {
    pub host: String,
    pub system_ips: Vec<Ipv4Addr>,
    pub trusted_ips: Vec<Ipv4Addr>,
    pub ip: Option<Ipv4Addr>,
    pub evidence: Option<Evidence>,
    pub verdict: Verdict,
    pub detail: String,
}

fn offline_check(t: Duration) -> bool {
    !matches!(probe(Ipv4Addr::new(1, 1, 1, 1), None, t), Conn::NoSyn)
}

/// Full detection for one site.
pub fn detect(host: &str, t: Duration) -> Report {
    let system_ips = resolve_system(host);
    let trusted_ips = resolve_trusted(host);
    let mut r = Report { host: host.to_owned(), system_ips: system_ips.clone(), trusted_ips: trusted_ips.clone(), ip: None, evidence: None, verdict: Verdict::Inconclusive, detail: String::new() };

    let sys_ok: Vec<Ipv4Addr> = system_ips.iter().copied().filter(|i| !bogus(*i)).collect();
    if sys_ok.is_empty() {
        if let Some(good) = trusted_ips.first() {
            r.verdict = match system_ips.first() {
                Some(bad) => Verdict::DnsPoisoned(*bad, *good),
                None => Verdict::DnsBlocked,
            };
        } else {
            r.detail = "neither the system resolver nor DNS-over-HTTPS knows this name".into();
        }
        return r;
    }
    let ip = sys_ok[0];
    r.ip = Some(ip);
    let e = gather(ip, host, t);
    r.evidence = Some(e);
    let mut v = decide(&e);

    // the system answer may be a poisoned one that merely looks normal
    if !matches!(v, Verdict::Open) && !trusted_ips.is_empty() && !trusted_ips.contains(&ip) {
        let tip = trusted_ips[0];
        let e2 = gather(tip, host, t);
        if matches!(decide(&e2), Verdict::Open) {
            r.verdict = Verdict::DnsPoisoned(ip, tip);
            r.evidence = Some(e2);
            return r;
        }
    }
    if matches!(v, Verdict::NoConnection) && !offline_check(t) {
        v = Verdict::Offline;
    }
    // second opinion with a real TLS stack, and the 16 KB cut-off
    match (&v, transfer(host, ip, 10)) {
        (Verdict::Open, Ok((bytes, _))) => r.detail = format!("{bytes} bytes downloaded"),
        (Verdict::Open, Err((bytes, why))) => {
            if is_cut(bytes) {
                v = Verdict::Throttled(bytes);
            } else {
                r.detail = format!("handshake works, the page did not load: {why}");
            }
        }
        (Verdict::SniBlocked(_) | Verdict::AddressBlocked, Ok((bytes, _))) => {
            // a browser-grade client got through: the raw probe was the one being filtered
            v = Verdict::Open;
            r.detail = format!("the raw probe was filtered, but a real TLS client downloaded {bytes} bytes");
        }
        _ => {}
    }
    r.verdict = v;
    r
}

// ------------------------------------------------------------------------------ output

pub fn print(r: &Report) {
    use crate::ui::{self, tr};
    println!("\n{}", ui::paint(ui::BOLD, &r.host));
    if !r.system_ips.is_empty() || !r.trusted_ips.is_empty() {
        println!("  DNS: system {:?}, DoH {:?}", r.system_ips.iter().map(|i| i.to_string()).collect::<Vec<_>>(), r.trusted_ips.iter().map(|i| i.to_string()).collect::<Vec<_>>());
    }
    if let Some(e) = &r.evidence {
        let w = |c: Conn| match c {
            Conn::Ok(x) => x.word().to_owned(),
            Conn::Refused => "port closed".into(),
            Conn::NoSyn => "no TCP connection".into(),
        };
        println!("  {:<34} {}", format!("TLS with the name {}:", r.host), w(e.real));
        println!("  {:<34} {}", "TLS without any name:", w(e.no_sni));
        println!("  {:<34} {}", format!("TLS with the name {CONTROL_NEUTRAL}:"), w(e.neutral));
        println!("  {:<34} {}", format!("TLS with the name {CONTROL_WHITELISTED}:"), w(e.whitelisted));
    }
    let (mark, text): (&str, String) = match &r.verdict {
        Verdict::Open => ("OK", tr("не заблокирован: рукопожатие и загрузка проходят", "not blocked: handshake and download work").into()),
        Verdict::Throttled(b) => ("SNI", format!("{} {b} {}", tr("рукопожатие проходит, но соединение обрывается после", "the handshake works, but the connection is cut after"), tr("байт (лимит ~16 КБ): режут по SNI/IP", "bytes (~16 KB limit): SNI/IP throttling"))),
        Verdict::SniBlocked(x) => ("SNI", format!("{} ({})", tr("ограничен по SNI: тот же адрес отвечает на другое имя, на это нет", "restricted by SNI: the same address answers another name, not this one"), x.word())),
        Verdict::Whitelist => ("SNI", tr("пропускаются только отдельные имена (режим белого списка): поможет подмена SNI", "only some names pass (white-list regime): a fake SNI may help").into()),
        Verdict::AddressBlocked => ("IP", tr("ни одно имя не проходит: блокировка по адресу или отпечатку TLS; стратегии не помогут", "no name gets through: address or TLS-fingerprint block; strategies cannot help").into()),
        Verdict::DnsPoisoned(bad, good) => ("DNS", format!("{} {bad}, {} {good}", tr("DNS подменён: система отдаёт", "DNS is poisoned: the system returns"), tr("а настоящий адрес", "the real address is"))),
        Verdict::DnsBlocked => ("DNS", tr("системный DNS не отдаёт адрес, DoH отдаёт: DNS заблокирован", "the system DNS returns nothing, DoH does: DNS is blocked").into()),
        Verdict::NoConnection => ("IP", tr("нет TCP-соединения с адресом (блокировка по IP или узел выключен)", "no TCP connection to the address (IP block, or the host is down)").into()),
        Verdict::Offline => ("NET", tr("нет связи вообще: проверьте подключение", "no connectivity at all: check your connection").into()),
        Verdict::Inconclusive => ("?", if r.detail.is_empty() { tr("вывод сделать нельзя", "cannot conclude").to_owned() } else { r.detail.clone() }),
    };
    println!("  => [{mark}] {text}");
    if !r.detail.is_empty() && !matches!(r.verdict, Verdict::Inconclusive) {
        println!("     {}", ui::paint(ui::DIM, &r.detail));
    }
    match &r.verdict {
        Verdict::DnsPoisoned(..) | Verdict::DnsBlocked => println!("     {}", tr("Исправление: `netfreedom dns set cloudflare` (шифрованный DNS), затем проверьте снова.", "Fix: `netfreedom dns set cloudflare` (encrypted DNS), then check again.")),
        v if v.fixable() => println!("     {}", tr("Обход без WARP: `netfreedom sni <сайт> --fix`", "Bypass without WARP: `netfreedom sni <site> --fix`")),
        Verdict::AddressBlocked | Verdict::NoConnection => println!("     {}", tr("Нужен другой маршрут (WARP, VPN, прокси): пакетные стратегии здесь бессильны.", "A different route is needed (WARP, VPN, proxy): packet strategies cannot help here.")),
        _ => {}
    }
}

// ------------------------------------------------------------------------------ the fix

/// Adds the site to `lists/list-general-user.txt` (every bypass strategy reads it). `Ok(true)` =
/// added, `Ok(false)` = it was there already.
pub fn add_to_user_list(layout: &crate::paths::Layout, host: &str) -> Result<bool, String> {
    let path = std::path::PathBuf::from(&layout.lists).join("list-general-user.txt");
    let entry = list_entry(host);
    let text = std::fs::read_to_string(&path).unwrap_or_default();
    if crate::hostlist::HostList::parse(&text).contains(entry) {
        return Ok(false);
    }
    let mut new = text;
    if !new.is_empty() && !new.ends_with('\n') {
        new.push('\n');
    }
    new.push_str(entry);
    new.push('\n');
    crate::util::write_atomic(&path, new.as_bytes()).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    Ok(true)
}

/// Does the site really open now? Handshake with the real name, then a download.
pub fn works_now(host: &str, ip: Ipv4Addr) -> bool {
    if !matches!(probe(ip, Some(host), Duration::from_secs(4)), Conn::Ok(Reply::Answered)) {
        return false;
    }
    match transfer(host, ip, 10) {
        Ok(_) => true,
        Err((b, _)) => !is_cut(b) && b > 0,
    }
}

/// Finds the first strategy that opens `host`, saves it as the bypass default. `all`: test every
/// strategy, not only the likeliest ones. Returns the strategy name.
pub fn fix(layout: &crate::paths::Layout, r: &Report, all: bool) -> Result<String, String> {
    use crate::{backend, config::Config, run, session, sys, tune, ui};
    let ip = r.ip.ok_or("no address to test")?;
    if backend::engine_running() {
        return Err("The packet engine is already running: stop it first (`netfreedom stop`).".into());
    }
    backend::check_engine(layout)?;
    layout.ensure_user_lists().map_err(|e| format!("cannot prepare lists: {e}"))?;
    if add_to_user_list(layout, &r.host)? {
        ui::ok(&format!("{} {}", list_entry(&r.host), ui::tr("добавлен в lists/list-general-user.txt", "added to lists/list-general-user.txt")));
    }
    let args = tune::TuneArgs { bypass: true, quick: !all, no_baseline: true, ..Default::default() };
    let list = tune::scenarios(&args);
    println!("{} {} {}", ui::tr("Проверяю стратегии:", "Testing strategies:"), list.len(), ui::tr("(Ctrl+C прервёт)", "(Ctrl+C stops)"));
    session::set_warp_owned(false);
    sys::arm_cleanup(true);
    sys::set_graceful(true);
    let mut found: Option<String> = None;
    for sc in &list {
        if sys::interrupted() {
            break;
        }
        tune::teardown(None);
        let Some(plan) = sc.plan() else { continue };
        if let Err(e) = run::launch(layout, &plan, &run::StartArgs::default(), true) {
            println!("  - {:<14} {}", sc.label, e.lines().next().unwrap_or(""));
            continue;
        }
        std::thread::sleep(Duration::from_millis(1200));
        // two good results in a row: one lucky packet is not a bypass
        let ok = backend::engine_running() && works_now(&r.host, ip) && works_now(&r.host, ip);
        println!("  {} {}", if ok { "+" } else { "-" }, sc.label);
        if ok {
            found = Some(sc.label.clone());
            break;
        }
    }
    tune::teardown(None);
    sys::arm_cleanup(false);
    sys::set_graceful(false);
    let name = found.ok_or_else(|| "no strategy opened the site on this connection. The block may be beyond the SNI (try `--all`, or use WARP/VPN).".to_owned())?;
    let mut cfg = Config::load_with_legacy(&layout.cfg, &layout.cfg_legacy);
    cfg.bypass = name.clone();
    let _ = cfg.save(&layout.cfg);
    Ok(name)
}

// ------------------------------------------------------------------------------ tests

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(real: Conn, no_sni: Conn, neutral: Conn, wl: Conn) -> Evidence {
        Evidence { real, no_sni, neutral, whitelisted: wl }
    }
    const A: Conn = Conn::Ok(Reply::Answered);
    const RST: Conn = Conn::Ok(Reply::Reset);
    const DROP: Conn = Conn::Ok(Reply::Silence);

    #[test]
    fn hello_is_parsed_by_the_engines_own_parser() {
        let p = build_hello(Some("blocked.example.org"), 42);
        let h = crate::tls::parse(&p).unwrap();
        assert_eq!(crate::tls::sni(&p, &h), Some("blocked.example.org"));
        assert_eq!(crate::tls::record_total(&p), Some(p.len()));
        let n = build_hello(None, 42);
        assert!(crate::tls::parse(&n).unwrap().host.is_none());
        assert_ne!(build_hello(None, 1), build_hello(None, 2), "random and session id differ");
    }

    #[test]
    fn replies_are_classified() {
        assert_eq!(classify(&[0x16, 3, 3, 0, 90, 2]), Reply::Answered);
        assert_eq!(classify(&[0x15, 3, 3, 0, 2]), Reply::Answered, "an alert is the server speaking");
        assert_eq!(classify(b"HTTP/1.1 403"), Reply::Injected);
        assert_eq!(classify(&[]), Reply::Closed);
    }

    #[test]
    fn the_sni_signature_is_same_address_other_name() {
        assert_eq!(decide(&ev(RST, A, A, A)), Verdict::SniBlocked(Reply::Reset));
        assert_eq!(decide(&ev(DROP, DROP, A, A)), Verdict::SniBlocked(Reply::Silence));
        assert_eq!(decide(&ev(A, A, A, A)), Verdict::Open);
        assert_eq!(decide(&ev(DROP, DROP, DROP, A)), Verdict::Whitelist);
        assert_eq!(decide(&ev(DROP, DROP, DROP, DROP)), Verdict::AddressBlocked);
        assert_eq!(decide(&ev(Conn::NoSyn, Conn::NoSyn, Conn::NoSyn, Conn::NoSyn)), Verdict::NoConnection);
        assert!(Verdict::SniBlocked(Reply::Reset).fixable() && Verdict::Whitelist.fixable());
        assert!(!Verdict::AddressBlocked.fixable() && !Verdict::NoConnection.fixable() && !Verdict::Open.fixable());
    }

    #[test]
    fn doh_json_is_read() {
        let j = r#"{"Status":0,"Answer":[{"name":"a.com","type":5,"TTL":1,"data":"b.a.com."},{"name":"b.a.com","type":1,"TTL":9,"data":"93.184.216.34"},{"type":1,"data":"93.184.216.35"}]}"#;
        assert_eq!(parse_doh(j), vec![Ipv4Addr::new(93, 184, 216, 34), Ipv4Addr::new(93, 184, 216, 35)]);
        assert!(parse_doh("{}").is_empty());
        assert!(bogus(Ipv4Addr::new(127, 0, 0, 1)) && bogus(Ipv4Addr::new(10, 0, 0, 1)) && !bogus(Ipv4Addr::new(93, 184, 216, 34)));
    }

    #[test]
    fn hosts_are_validated_and_normalised() {
        assert_eq!(normalize_host("HTTPS://Www.Example.com:8443/a?b#c").as_deref(), Some("www.example.com"));
        assert_eq!(normalize_host("example.com.").as_deref(), Some("example.com"));
        assert_eq!(normalize_host("bad host.com"), None);
        assert_eq!(normalize_host("a;rm -rf.com"), None);
        assert_eq!(normalize_host("localhost"), None);
        assert_eq!(list_entry("www.example.com"), "example.com");
        assert_eq!(list_entry("www.com"), "www.com");
        assert_eq!(list_entry("m.example.com"), "m.example.com");
        assert!(is_cut(16_384) && !is_cut(300_000) && !is_cut(0));
    }

    #[test]
    fn user_list_gets_the_site_once() {
        let root = std::env::temp_dir().join(format!("nf-sni-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let l = crate::paths::Layout::at(root.clone());
        l.ensure_user_lists().unwrap();
        assert!(add_to_user_list(&l, "www.blocked.example").unwrap());
        assert!(!add_to_user_list(&l, "blocked.example").unwrap(), "already covered");
        assert!(!add_to_user_list(&l, "cdn.blocked.example").unwrap(), "subdomains are covered by the parent");
        let t = std::fs::read_to_string(root.join("lists").join("list-general-user.txt")).unwrap();
        assert_eq!(t.lines().filter(|x| *x == "blocked.example").count(), 1);
        assert!(t.contains("domain.example.abc"), "existing lines stay");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_local_server_that_resets_one_name_is_detected() {
        use std::net::TcpListener;
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for s in l.incoming().flatten() {
                let mut s = s;
                let mut b = [0u8; 2048];
                let n = s.read(&mut b).unwrap_or(0);
                let blocked = crate::tls::parse(&b[..n]).and_then(|h| crate::tls::sni(&b[..n], &h).map(|x| x.to_owned())).is_some_and(|x| x == "blocked.test");
                if blocked { drop(s); } else { let _ = s.write_all(&[0x16, 3, 3, 0, 4, 2, 0, 0, 0]); }
            }
        });
        // the probe always uses port 443, so the pure parts are what this test can cover end to end:
        // the same hello bytes a server would parse
        let p = build_hello(Some("blocked.test"), 5);
        let mut st = TcpStream::connect(("127.0.0.1", port)).unwrap();
        st.write_all(&p).unwrap();
        let mut b = [0u8; 8];
        let n = st.read(&mut b).unwrap_or(0);
        assert_eq!(classify(&b[..n]), Reply::Closed, "the blocked name gets a closed connection");
        let mut st = TcpStream::connect(("127.0.0.1", port)).unwrap();
        st.write_all(&build_hello(Some("fine.test"), 5)).unwrap();
        let n = st.read(&mut b).unwrap();
        assert_eq!(classify(&b[..n]), Reply::Answered);
    }
}
