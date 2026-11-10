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

//! Native (in-process) replacement for winws, EXPERIMENTAL.
//!
//! It reproduces what winws does for the LEAN profiles, whose rules are only
//! `--dpi-desync=fake` on outbound UDP: build N copies of a fake payload with the same
//! addresses/ports/TTL as the real packet, send them, then send the real packet untouched.
//!
//! Behaviour was checked against the zapret v72.9 sources (the version bundled in `bin\winws.exe`):
//!  * `cutoff=nN`: the per-flow counter is incremented *before* the check, so `n2` means that only
//!    the FIRST packet of a flow is desynchronised;
//!  * fakes use the original TTL / DF / TOS, IPv4 ID = original ID (random if 0), no fooling;
//!  * UDP flows expire after 60 s of silence (zapret `CTRACK_T_UDP`).
//!
//! Known differences from winws (see README): no SNI check for QUIC Initials, no delaying of
//! fragmented ClientHellos (fakes go out before the first Initial instead of after reassembly),
//! no built-in default fake blobs. Anything outside this subset makes `Plan::from_args` fail, and
//! the launcher falls back to winws.

use std::collections::HashMap;
use std::io;

use crate::faketls::{self, TlsMod, DEFAULT_FAKE_TLS};
use crate::hostlist::{self, HostList};
use crate::http;
use crate::ipset::IpSet;
use crate::quic::is_quic_initial;
use crate::quic_sni;
use crate::tcp::{self, Split, Tcp, TcpRule};
use crate::tls::{self, Pos};

/// Opaque `WINDIVERT_ADDRESS` (80 bytes, 8-aligned). Copied from the original packet for fakes.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Addr(pub [u64; 10]);

// must match sizeof(WINDIVERT_ADDRESS) of WinDivert 2.2
const _: () = assert!(std::mem::size_of::<Addr>() == 80);

/// Where packets come from and go to (WinDivert in production, a mock in tests).
pub trait PacketIo {
    /// Blocks for the next packet. `None` means the handle was closed: stop the loop.
    fn recv(&mut self, buf: &mut [u8]) -> Option<(usize, Addr)>;
    fn send(&mut self, pkt: &[u8], addr: &Addr);
    /// Let the driver recompute checksums / checksum flags of a packet we built.
    fn finalize(&mut self, _pkt: &mut [u8], _addr: &mut Addr) {}
}

// ------------------------------------------------------------------------------ rules

/// What a UDP payload is, in zapret's detection order (`desync.c`, UDP path).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum U7 {
    Quic = 0,
    Wireguard = 1,
    Dht = 2,
    Discord = 3,
    Stun = 4,
    Unknown = 5,
}

impl U7 {
    fn from_name(s: &str) -> Option<U7> {
        Some(match s {
            "quic" => U7::Quic,
            "wireguard" => U7::Wireguard,
            "dht" => U7::Dht,
            "discord" => U7::Discord,
            "stun" => U7::Stun,
            _ => return None,
        })
    }
}

/// `None` = nothing recognised (only rules with `--dpi-desync-any-protocol` act on those).
fn classify_udp(p: &[u8]) -> Option<U7> {
    if is_quic_initial(p) {
        Some(U7::Quic)
    } else if p.len() == 148 && p[0] == 1 {
        Some(U7::Wireguard) // IsWireguardHandshakeInitiation
    } else if p.len() >= 7 && p[0] == b'd' && p[1] == b'1' && p[p.len() - 1] == b'e' {
        Some(U7::Dht)
    } else if p.len() == 74 && p[..4] == [0, 1, 0, 70] && p[8..72].iter().all(|&b| b == 0) {
        Some(U7::Discord) // IsDiscordIpDiscoveryRequest
    } else if p.len() >= 20 && p[0] & 0xC0 == 0 && p[3] & 3 == 0 && p[4..8] == [0x21, 0x12, 0xA4, 0x42] && u16::from_be_bytes([p[2], p[3]]) as usize == p.len() - 20 {
        Some(U7::Stun) // IsStunMessage
    } else {
        None
    }
}

#[derive(Debug, Default, Clone)]
pub struct Rule {
    pub ports: Vec<(u16, u16)>,
    pub any_protocol: bool,
    pub repeats: u32,
    /// Fake payloads per protocol, in send order (index = [`U7`]). `finish` fills the empty ones
    /// with zapret's built-in defaults.
    pub fakes: [Vec<Vec<u8>>; 6],
    /// `--filter-l7` as a bit set over [`U7`] (0 = any).
    pub l7: u8,
    pub ttl: Option<u8>,
    pub ttl6: Option<u8>,
    /// `Some(n)`: desync only while the flow's packet counter (incremented first) is < n.
    pub cutoff: Option<u32>,
    /// `--ipset` / `--ipset-exclude`: select by destination address.
    pub ips: Option<IpSet>,
    pub ips_exclude: Option<IpSet>,
    /// `--hostlist` / `--hostlist-exclude`: matched against the SNI of a QUIC Initial.
    pub include: Option<HostList>,
    pub exclude: Option<HostList>,
}

impl Rule {
    fn matches_port(&self, p: u16) -> bool {
        self.ports.iter().any(|&(a, b)| (a..=b).contains(&p))
    }

    fn matches_ip(&self, dst: &[u8; 16], v6: bool) -> bool {
        self.ips.as_ref().map_or(true, |s| s.contains(dst, v6)) && !self.ips_exclude.as_ref().is_some_and(|s| s.contains(dst, v6))
    }

    fn matches_host(&self, host: Option<&str>) -> bool {
        hostlist::applies(self.include.as_ref(), self.exclude.as_ref(), host)
    }

    fn matches_l7(&self, c: Option<U7>) -> bool {
        self.l7 == 0 || c.is_some_and(|c| self.l7 & (1 << c as u8) != 0)
    }

    /// zapret's built-in fakes for protocols the rule gave none for (`dp_fake_defaults`).
    fn fill_defaults(&mut self) {
        for (i, f) in self.fakes.iter_mut().enumerate() {
            if f.is_empty() {
                let mut b = vec![0u8; if i == U7::Quic as usize { 620 } else { 64 }];
                if i == U7::Quic as usize {
                    b[0] = 0x40;
                }
                f.push(b);
            }
        }
    }
}

/// Which application protocol a TCP rule is for (`--filter-l7`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L7 {
    Any,
    Tls,
    Http,
}

/// `--dpi-desync-autottl=delta[:min[-max]]` (zapret `parse_autottl`, `autottl_eval`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AutoTtl {
    pub delta: i8,
    pub min: u8,
    pub max: u8,
}

impl AutoTtl {
    /// `Ok(None)` for "-" (disabled). Defaults are zapret's for the desync TTL: -1, 3, 20; a bare
    /// number is a *negative* delta unless it starts with `+`.
    pub fn parse(s: &str) -> Result<Option<AutoTtl>, String> {
        if s == "-" {
            return Ok(None);
        }
        let bad = || format!("bad --dpi-desync-autottl \"{s}\"");
        let (neg, rest) = match s.as_bytes().first() {
            Some(b'+') => (false, &s[1..]),
            Some(b'-') => (true, &s[1..]),
            _ => (true, s),
        };
        let (d, tail) = rest.split_once(':').map_or((rest, None), |(d, t)| (d, Some(t)));
        let delta: u32 = d.parse().map_err(|_| bad())?;
        let (mut min, mut max) = (3u32, 20u32);
        if let Some(t) = tail {
            let (m, x) = t.split_once('-').map_or((t, None), |(m, x)| (m, Some(x)));
            min = m.parse().map_err(|_| bad())?;
            if let Some(x) = x {
                max = x.parse().map_err(|_| bad())?;
                if (delta != 0 && max == 0) || max > 255 {
                    return Err(bad());
                }
            }
            if (delta != 0 && min == 0) || min > 255 || min > max {
                return Err(bad());
            }
        }
        if delta > 127 {
            return Err(bad());
        }
        let delta = if neg { -(delta as i32) } else { delta as i32 } as i8;
        Ok(Some(AutoTtl { delta, min: min as u8, max: max as u8 }))
    }

    /// The fake TTL for a server `hops` away, or `None` when it cannot be chosen sensibly.
    pub fn eval(&self, hops: u8) -> Option<u8> {
        let d = hops as i32 + self.delta as i32;
        let fake = d.clamp(self.min as i32, self.max as i32) as u8;
        if (self.delta < 0 && fake >= hops) || (self.delta >= 0 && fake < hops) {
            None
        } else {
            Some(fake)
        }
    }
}

/// zapret `hop_count_guess`: assume the sender started from 64, 128 or 255.
pub fn hop_count_guess(ttl: u8) -> u8 {
    let orig = if ttl > 223 {
        255
    } else if ttl < 128 && ttl > 96 {
        128
    } else if ttl < 64 && ttl > 32 {
        64
    } else {
        return 0;
    };
    orig - ttl
}

/// One TCP segment of a profile (`--filter-tcp ... --new`).
#[derive(Debug)]
pub struct TcpSpec {
    pub ports: Vec<(u16, u16)>,
    pub l7: L7,
    pub include: Option<HostList>,
    pub exclude: Option<HostList>,
    pub ips: Option<IpSet>,
    pub ips_exclude: Option<IpSet>,
    pub rule: TcpRule,
    /// `fake` is among the desync modes (the blob itself is chosen per packet).
    pub fake: bool,
    /// Fake ClientHellos in send order: blob already prepared (`sni=`, `rndsni`) + per-packet mod.
    pub fake_tls: Vec<(Vec<u8>, TlsMod)>,
    pub fake_unknown: Vec<Vec<u8>>,
    /// A rule that can never desync anything (see `Seg::finish`): matched, then passed untouched.
    pub inert: bool,
    pub autottl: Option<AutoTtl>,
    /// `syndata`: the payload put into the SYN. Only set for rules that can match a SYN, i.e. that
    /// have no host list.
    pub syndata: Option<Vec<u8>>,
}

impl TcpSpec {
    fn matches(&self, t: &Tcp, l7: L7, host: Option<&str>) -> bool {
        (self.l7 == L7::Any || self.l7 == l7)
            && self.ports.iter().any(|&(a, b)| (a..=b).contains(&t.dport))
            && hostlist::applies(self.include.as_ref(), self.exclude.as_ref(), host)
            && self.ips.as_ref().map_or(true, |s| s.contains(&t.dst, t.v6))
            && !self.ips_exclude.as_ref().is_some_and(|s| s.contains(&t.dst, t.v6))
    }
}

/// zapret's built-in fake HTTP request (`fake_http_request_default`, MIT licence).
const FAKE_HTTP: &[u8] = b"GET / HTTP/1.1\r\nHost: www.iana.org\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/109.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\nAccept-Encoding: gzip, deflate, br\r\n\r\n";

#[derive(Debug)]
pub struct Plan {
    /// WinDivert filter: the profile's `--wf-raw` (UDP) and/or one generated for the TCP rules.
    pub filter: String,
    pub rules: Vec<Rule>,
    pub tcp: Vec<TcpSpec>,
}

fn parse_ports(s: &str) -> Result<Vec<(u16, u16)>, String> {
    let mut v = Vec::new();
    for item in s.split(',') {
        let (a, b) = item.split_once('-').unwrap_or((item, item));
        let a: u16 = a.parse().map_err(|_| format!("bad port list \"{s}\""))?;
        let b: u16 = b.parse().map_err(|_| format!("bad port list \"{s}\""))?;
        if a > b {
            return Err(format!("bad port range in \"{s}\""));
        }
        v.push((a, b));
    }
    Ok(v)
}

fn port_clause(proto: &str, ports: &[(u16, u16)]) -> String {
    let items: Vec<String> = ports
        .iter()
        .map(|&(a, b)| if a == b { format!("{proto}.DstPort=={a}") } else { format!("({proto}.DstPort>={a} and {proto}.DstPort<={b})") })
        .collect();
    format!("({})", items.join(" or "))
}

/// Options and state of the segment being parsed.
struct Seg {
    udp_ports: Option<Vec<(u16, u16)>>,
    tcp_ports: Option<Vec<(u16, u16)>>,
    modes: Vec<String>,
    udp: Rule,
    tcp: TcpRule,
    l7_raw: Option<String>,
    inc: Option<HostList>,
    exc: Option<HostList>,
    ips: Option<IpSet>,
    ipx: Option<IpSet>,
    fake_tls: Vec<(Vec<u8>, Option<TlsMod>)>,
    tls_mod_last: Option<TlsMod>,
    fake_unknown: Vec<Vec<u8>>,
    autottl: Option<AutoTtl>,
    fake_syndata: Option<Vec<u8>>,
    udp_only: Option<String>,
    tcp_only: Option<String>,
}

impl Seg {
    fn new() -> Seg {
        Seg {
            udp_ports: None,
            tcp_ports: None,
            modes: Vec::new(),
            udp: Rule { repeats: 1, ..Default::default() },
            tcp: TcpRule { fake_repeats: 1, ..Default::default() },
            l7_raw: None,
            inc: None,
            exc: None,
            ips: None,
            ipx: None,
            fake_tls: Vec::new(),
            tls_mod_last: None,
            fake_unknown: Vec::new(),
            autottl: None,
            fake_syndata: None,
            udp_only: None,
            tcp_only: None,
        }
    }

    fn finish(self, rules: &mut Vec<Rule>, tcp: &mut Vec<TcpSpec>) -> Result<(), String> {
        match (self.udp_ports, self.tcp_ports) {
            (Some(_), Some(_)) => Err("a rule with both --filter-udp and --filter-tcp".into()),
            (None, None) => Err("a rule without --filter-udp / --filter-tcp".into()),
            (Some(ports), None) => {
                if let Some(o) = self.tcp_only {
                    return Err(format!("unsupported option {o}"));
                }
                if self.modes != ["fake"] {
                    return Err("a rule without --dpi-desync=fake".into());
                }
                let mut r = self.udp;
                if let Some(raw) = &self.l7_raw {
                    for n in raw.split(',') {
                        let c = U7::from_name(n).ok_or_else(|| format!("unsupported option --filter-l7={raw}"))?;
                        r.l7 |= 1 << c as u8;
                    }
                }
                r.fill_defaults();
                r.ports = ports;
                if self.inc.is_some() && self.ips.is_some() {
                    return Err("both --hostlist and --ipset in one rule".into());
                }
                r.include = self.inc;
                r.exclude = self.exc;
                r.ips = self.ips;
                r.ips_exclude = self.ipx;
                rules.push(r);
                Ok(())
            }
            (None, Some(ports)) => {
                if let Some(o) = self.udp_only {
                    return Err(format!("unsupported option {o}"));
                }
                // winws creates a TCP flow record only on SYN and counts every captured packet,
                // SYN included, so with --dpi-desync-cutoff=n1/n2 the first data packet is already
                // past the cut-off (and a flow without SYN has no record: zapret then refuses to
                // desync). Such a rule never changes a packet.
                let inert = match self.udp.cutoff {
                    Some(n) if n <= 2 => true,
                    Some(_) => return Err("TCP --dpi-desync-cutoff above n2 needs flow tracking".into()),
                    None => false,
                };
                if self.udp.any_protocol && !inert {
                    return Err("--dpi-desync-any-protocol on TCP needs flow tracking".into());
                }
                let l7 = match self.l7_raw.as_deref() {
                    None => L7::Any,
                    Some("tls") => L7::Tls,
                    Some("http") => L7::Http,
                    Some(o) => return Err(format!("unsupported option --filter-l7={o}")),
                };
                let mut rule = self.tcp;
                rule.fool.ttl = self.udp.ttl;
                rule.fool.ttl6 = self.udp.ttl6;
                // `syndata` acts on the SYN, where the host name is still unknown. winws then cannot
                // match a rule that has a host list (its IP-to-name cache is off by default), so
                // with a list the mode never fires and only the data-stage mode remains
                let want_syn = self.modes.iter().any(|m| m == "syndata");
                let syndata = (want_syn && self.inc.is_none()).then(|| self.fake_syndata.clone().unwrap_or_else(|| vec![0u8; 16]));
                if self.l7_raw.is_some() && syndata.is_some() {
                    return Err("syndata together with --filter-l7".into()); // no L7 is known at the SYN
                }
                let fake = self.modes.iter().any(|m| m == "fake");
                let splits: Vec<Split> = self
                    .modes
                    .iter()
                    .filter_map(|m| match m.as_str() {
                        "multisplit" => Some(Split::Multisplit),
                        "multidisorder" => Some(Split::Multidisorder),
                        "fakedsplit" => Some(Split::FakedSplit),
                        "fakeddisorder" => Some(Split::FakedDisorder),
                        "hostfakesplit" => Some(Split::HostFakeSplit),
                        _ => None,
                    })
                    .collect();
                if self.modes.is_empty() || splits.len() > 1 {
                    return Err("this --dpi-desync combination is not supported".into());
                }
                rule.split = splits.first().copied().unwrap_or(Split::None);
                if rule.split != Split::None && rule.split != Split::HostFakeSplit && rule.positions.is_empty() {
                    rule.positions.push(Pos::parse("2")?); // zapret's default split position
                }
                if rule.split == Split::HostFakeSplit && rule.seqovl > 0 {
                    return Err("--dpi-desync-split-seqovl with hostfakesplit".into());
                }
                if rule.split == Split::None && (rule.seqovl > 0 || !rule.positions.is_empty()) {
                    return Err("split options without multisplit / multidisorder".into());
                }
                if self.inc.is_some() && self.ips.is_some() {
                    return Err("both --hostlist and --ipset in one rule".into());
                }
                // zapret: the built-in blob gets rnd,rndsni,dupsid unless a --dpi-desync-fake-tls-mod
                // was given; blobs given with --dpi-desync-fake-tls get only the mod that was set
                // when they were added (or the one that came right after the last of them)
                let mut seed = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(1, |d| d.subsec_nanos()) | 1;
                let mut fake_tls = Vec::new();
                if fake && l7 != L7::Http {
                    if self.fake_tls.is_empty() {
                        let m = self.tls_mod_last.unwrap_or_else(TlsMod::builtin_default);
                        fake_tls.push((faketls::prepare(DEFAULT_FAKE_TLS, &m, &mut seed)?, m.runtime()));
                    }
                    for (blob, m) in self.fake_tls {
                        let m = m.unwrap_or_default();
                        fake_tls.push((faketls::prepare(&blob, &m, &mut seed)?, m.runtime()));
                    }
                }
                let fake_unknown = if self.fake_unknown.is_empty() { vec![vec![0u8; 256]] } else { self.fake_unknown };
                tcp.push(TcpSpec {
                    ports,
                    l7,
                    include: self.inc,
                    exclude: self.exc,
                    ips: self.ips,
                    ips_exclude: self.ipx,
                    rule,
                    fake,
                    fake_tls,
                    fake_unknown,
                    inert,
                    autottl: self.autottl,
                    syndata,
                });
                Ok(())
            }
        }
    }
}

impl Plan {
    /// Builds a plan from an expanded winws command line. Fails (with the reason) on anything the
    /// native engine does not reproduce exactly, so the caller can fall back to winws.
    pub fn from_args(args: &[String], read: &dyn Fn(&str) -> io::Result<Vec<u8>>) -> Result<Plan, String> {
        let mut raw = None;
        let mut rules = Vec::new();
        let mut tcp = Vec::new();
        let mut seg = Seg::new();

        let blob = |p: &str| -> Result<Vec<u8>, String> {
            let b = read(p).map_err(|e| format!("cannot read {p}: {e}"))?;
            if b.is_empty() || b.len() > 1400 {
                return Err(format!("{p}: fake payload must be 1..1400 bytes"));
            }
            Ok(b)
        };
        let text = |p: &str| -> Result<String, String> {
            let b = read(p).map_err(|e| format!("cannot read {p}: {e}"))?;
            Ok(String::from_utf8_lossy(&b).into_owned())
        };

        for a in args {
            if a == "--new" {
                std::mem::replace(&mut seg, Seg::new()).finish(&mut rules, &mut tcp)?;
                continue;
            }
            let (k, v) = a.split_once('=').unwrap_or((a.as_str(), ""));
            let mut tcp_only = || {
                seg.tcp_only.get_or_insert_with(|| a.clone());
            };
            match k {
                "--wf-raw" => raw = Some(v.to_owned()),
                "--wf-tcp" | "--wf-udp" => {} // capture is derived from the rules themselves
                "--filter-udp" => seg.udp_ports = Some(parse_ports(v)?),
                "--filter-tcp" => seg.tcp_ports = Some(parse_ports(v)?),
                "--dpi-desync" => {
                    for m in v.split(',') {
                        if !["fake", "multisplit", "multidisorder", "fakedsplit", "fakeddisorder", "hostfakesplit", "syndata"].contains(&m) {
                            return Err(format!("unsupported option {a}"));
                        }
                        seg.modes.push(m.to_owned());
                    }
                }
                "--dpi-desync-repeats" => {
                    let n = v.parse().ok().filter(|n| (1..=64).contains(n)).ok_or("bad --dpi-desync-repeats")?;
                    seg.udp.repeats = n;
                    seg.tcp.fake_repeats = n;
                }
                // ---- UDP only
                "--dpi-desync-any-protocol" => seg.udp.any_protocol = v == "1",
                "--dpi-desync-fake-quic" | "--dpi-desync-fake-wireguard" | "--dpi-desync-fake-dht" | "--dpi-desync-fake-discord" | "--dpi-desync-fake-stun" | "--dpi-desync-fake-unknown-udp" => {
                    let c = match k {
                        "--dpi-desync-fake-quic" => U7::Quic,
                        "--dpi-desync-fake-wireguard" => U7::Wireguard,
                        "--dpi-desync-fake-dht" => U7::Dht,
                        "--dpi-desync-fake-discord" => U7::Discord,
                        "--dpi-desync-fake-stun" => U7::Stun,
                        _ => U7::Unknown,
                    };
                    seg.udp.fakes[c as usize].push(blob(v)?);
                    seg.udp_only.get_or_insert_with(|| a.clone());
                }
                "--dpi-desync-cutoff" => {
                    let n = v.strip_prefix('n').and_then(|n| n.parse().ok()).filter(|n| *n >= 1);
                    seg.udp.cutoff = Some(n.ok_or("only --dpi-desync-cutoff=nN is supported")?);
                }
                // ---- TCP only
                "--filter-l7" => seg.l7_raw = Some(v.to_owned()),
                "--hostlist" | "--hostlist-exclude" => {
                    let l = HostList::parse(&text(v)?);
                    let slot = if k == "--hostlist" { &mut seg.inc } else { &mut seg.exc };
                    slot.get_or_insert_with(HostList::default).merge(l);
                }
                "--hostlist-domains" => {
                    let l = HostList::parse(&v.replace(',', "\n"));
                    seg.inc.get_or_insert_with(HostList::default).merge(l);
                }
                "--ipset" | "--ipset-exclude" => {
                    let l = IpSet::parse(&text(v)?);
                    let slot = if k == "--ipset" { &mut seg.ips } else { &mut seg.ipx };
                    slot.get_or_insert_with(IpSet::default).merge(l);
                }
                "--dpi-desync-split-pos" => {
                    seg.tcp.positions = v.split(',').map(Pos::parse).collect::<Result<_, _>>()?;
                    tcp_only();
                }
                "--dpi-desync-split-seqovl" => {
                    seg.tcp.seqovl = v.parse().ok().filter(|n| *n < 4096).ok_or("bad --dpi-desync-split-seqovl")?;
                    tcp_only();
                }
                "--dpi-desync-split-seqovl-pattern" => {
                    seg.tcp.seqovl_pattern = blob(v)?;
                    tcp_only();
                }
                "--dpi-desync-fakedsplit-pattern" => {
                    seg.tcp.fs_pattern = match v.strip_prefix("0x") {
                        Some(h) if !h.is_empty() && h.len() % 2 == 0 && h.chars().all(|c| c.is_ascii_hexdigit()) => {
                            (0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect()
                        }
                        Some(_) => return Err(format!("bad hex pattern in {a}")),
                        None => blob(v)?,
                    };
                    tcp_only();
                }
                "--dpi-desync-fakedsplit-mod" => {
                    for item in v.split(',') {
                        match item.strip_prefix("altorder=") {
                            Some(n) => seg.tcp.fs_order = n.parse().ok().filter(|n| *n <= 3).ok_or("unsupported altorder")?,
                            None if item == "none" => {}
                            None => return Err(format!("unsupported option {a}")),
                        }
                    }
                    tcp_only();
                }
                "--dpi-desync-hostfakesplit-mod" => {
                    for item in v.split(',') {
                        if let Some(n) = item.strip_prefix("altorder=") {
                            seg.tcp.hfs_order = n.parse().ok().filter(|n| *n <= 1).ok_or("bad altorder")?;
                        } else if let Some(h) = item.strip_prefix("host=") {
                            if h.is_empty() || !h.is_ascii() || h.len() > 200 {
                                return Err(format!("bad host in {a}"));
                            }
                            seg.tcp.hfs_host = Some(h.to_owned());
                        } else if item != "none" {
                            return Err(format!("unsupported option {a}"));
                        }
                    }
                    tcp_only();
                }
                "--dpi-desync-fooling" => {
                    for f in v.split(',') {
                        match f {
                            "ts" => seg.tcp.fool.ts = true,
                            "badseq" => seg.tcp.fool.badseq = true,
                            "md5sig" => seg.tcp.fool.md5sig = true,
                            _ => return Err(format!("unsupported fooling \"{f}\"")),
                        }
                    }
                    tcp_only();
                }
                "--dpi-desync-badseq-increment" => {
                    seg.tcp.fool.badseq_inc = Some(v.parse().map_err(|_| "bad --dpi-desync-badseq-increment")?);
                    tcp_only();
                }
                "--dpi-desync-fake-unknown" => {
                    seg.fake_unknown.push(blob(v)?);
                    tcp_only();
                }
                "--dpi-desync-fake-tls" => {
                    let b = blob(v)?;
                    let m = seg.tls_mod_last.clone();
                    seg.fake_tls.push((b, m));
                    tcp_only();
                }
                "--dpi-desync-fake-tls-mod" => {
                    let m = TlsMod::parse(v)?;
                    if let Some(last) = seg.fake_tls.last_mut() {
                        last.1 = Some(m.clone());
                    }
                    seg.tls_mod_last = Some(m);
                    tcp_only();
                }
                "--dpi-desync-autottl" => {
                    seg.autottl = AutoTtl::parse(v)?;
                    tcp_only();
                }
                "--dpi-desync-fake-syndata" => {
                    seg.fake_syndata = Some(blob(v)?);
                    tcp_only();
                }
                "--dpi-desync-ttl" => seg.udp.ttl = Some(v.parse().ok().filter(|n| *n >= 1).ok_or("bad --dpi-desync-ttl")?),
                "--dpi-desync-ttl6" => seg.udp.ttl6 = Some(v.parse().ok().filter(|n| *n >= 1).ok_or("bad --dpi-desync-ttl6")?),
                "--ip-id" if v == "zero" => {
                    seg.tcp.ip_id_zero = true;
                    tcp_only();
                }
                _ => return Err(format!("unsupported option {a}")),
            }
        }
        seg.finish(&mut rules, &mut tcp)?;

        let mut clauses: Vec<String> = Vec::new();
        for s in tcp.iter().filter(|s| !s.inert) {
            if s.syndata.is_some() {
                clauses.push(format!("{} and tcp.Syn and tcp.Ack==0 and tcp.PayloadLength==0", port_clause("tcp", &s.ports)));
            }
            if s.l7 != L7::Http {
                clauses.push(format!("{} and tcp.PayloadLength>=6 and tcp.Payload[0]==0x16 and tcp.Payload[5]==0x01", port_clause("tcp", &s.ports)));
            }
            let http_ports: Vec<(u16, u16)> = if s.l7 == L7::Http { s.ports.clone() } else { s.ports.iter().copied().filter(|&(a, b)| (a..=b).contains(&80)).map(|_| (80, 80)).collect() };
            if !http_ports.is_empty() && s.l7 != L7::Tls {
                clauses.push(format!("{} and tcp.PayloadLength>=4 and tcp.Payload[0]>=0x41 and tcp.Payload[0]<=0x5A", port_clause("tcp", &http_ports)));
            }
        }
        let mut seen = std::collections::HashSet::new();
        clauses.retain(|c| seen.insert(c.clone()));
        let mut tcp_filter = (!clauses.is_empty()).then(|| format!("not impostor and not loopback and outbound and tcp and ({})", clauses.join(" or ")));
        // autottl learns the server's distance from its SYN-ACK
        let mut synack_ports: Vec<(u16, u16)> = tcp.iter().filter(|s| !s.inert && s.autottl.is_some()).flat_map(|s| s.ports.iter().copied()).collect();
        synack_ports.sort_unstable();
        synack_ports.dedup();
        if let (Some(f), false) = (&tcp_filter, synack_ports.is_empty()) {
            tcp_filter = Some(format!("({f}) or (not impostor and not loopback and inbound and tcp and tcp.Syn and tcp.Ack and {})", port_clause("tcp", &synack_ports).replace("DstPort", "SrcPort")));
        }
        let udp_filter = if rules.is_empty() {
            None
        } else if let Some(r) = raw {
            Some(r)
        } else {
            // a rule with a host list can only ever act on a QUIC Initial (long header, 256+ bytes);
            // the others look at every datagram on their ports
            let mut uc: Vec<String> = Vec::new();
            for r in &rules {
                let shape = if r.include.is_some() { "udp.PayloadLength>=256 and udp.Payload[0]>=0xC0" } else { "udp.PayloadLength>0" };
                uc.push(format!("{} and {shape}", port_clause("udp", &r.ports)));
            }
            let mut seen = std::collections::HashSet::new();
            uc.retain(|c| seen.insert(c.clone()));
            Some(format!("not impostor and not loopback and outbound and udp and ({})", uc.join(" or ")))
        };
        let filter = match (udp_filter, tcp_filter) {
            (Some(u), None) => u,
            (None, Some(t)) => t,
            (Some(u), Some(t)) => format!("({u}) or ({t})"),
            (None, None) => return Err("the profile has no rules".into()),
        };
        Ok(Plan { filter, rules, tcp })
    }
}

// ------------------------------------------------------------------------------ packets

struct Udp {
    v6: bool,
    payload_off: usize,
    ttl: u8,
    src: [u8; 16],
    dst: [u8; 16],
    sport: u16,
    dport: u16,
}

fn parse_udp(p: &[u8]) -> Option<Udp> {
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    let (v6, ip_len, ttl) = match p.first()? >> 4 {
        4 => {
            let ihl = (p[0] & 0x0F) as usize * 4;
            if ihl < 20 || p.len() < ihl + 8 || p[9] != 17 {
                return None;
            }
            if u16::from_be_bytes([p[6], p[7]]) & 0x3FFF != 0 {
                return None; // fragment
            }
            src[..4].copy_from_slice(&p[12..16]);
            dst[..4].copy_from_slice(&p[16..20]);
            (false, ihl, p[8])
        }
        6 => {
            if p.len() < 48 || p[6] != 17 {
                return None; // extension headers are passed through untouched
            }
            src.copy_from_slice(&p[8..24]);
            dst.copy_from_slice(&p[24..40]);
            (true, 40, p[7])
        }
        _ => return None,
    };
    let u = &p[ip_len..];
    Some(Udp {
        v6,
        payload_off: ip_len + 8,
        ttl,
        src,
        dst,
        sport: u16::from_be_bytes([u[0], u[1]]),
        dport: u16::from_be_bytes([u[2], u[3]]),
    })
}

pub(crate) fn csum_add(mut sum: u32, data: &[u8]) -> u32 {
    #[allow(unknown_lints, clippy::manual_as_chunks)]
    let mut it = data.chunks_exact(2);
    for w in &mut it {
        sum += u16::from_be_bytes([w[0], w[1]]) as u32;
    }
    if let [b] = it.remainder() {
        sum += (*b as u32) << 8;
    }
    sum
}

pub(crate) fn csum_fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Builds a complete IP+UDP packet carrying `payload`, modelled on `orig`.
/// Returns the length written into `out`.
fn build_fake(orig: &[u8], u: &Udp, ip_id: u16, ttl: u8, payload: &[u8], out: &mut Vec<u8>) {
    out.clear();
    let udp_len = 8 + payload.len();
    if u.v6 {
        out.extend_from_slice(&orig[..4]); // version, traffic class, flow label
        out.extend_from_slice(&(udp_len as u16).to_be_bytes());
        out.push(17);
        out.push(ttl);
        out.extend_from_slice(&u.src);
        out.extend_from_slice(&u.dst);
    } else {
        out.push(0x45);
        out.push(orig[1]); // TOS
        out.extend_from_slice(&((20 + udp_len) as u16).to_be_bytes());
        out.extend_from_slice(&ip_id.to_be_bytes());
        out.push(orig[6] & 0x40); // keep DF, clear MF / offset
        out.push(0);
        out.push(ttl);
        out.push(17);
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(&u.src[..4]);
        out.extend_from_slice(&u.dst[..4]);
        let c = csum_fold(csum_add(0, &out[..20]));
        out[10..12].copy_from_slice(&c.to_be_bytes());
    }
    let ip_len = out.len();
    out.extend_from_slice(&u.sport.to_be_bytes());
    out.extend_from_slice(&u.dport.to_be_bytes());
    out.extend_from_slice(&(udp_len as u16).to_be_bytes());
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(payload);

    let mut sum = if u.v6 {
        let s = csum_add(0, &u.src);
        let s = csum_add(s, &u.dst);
        s + udp_len as u32 + 17
    } else {
        let s = csum_add(0, &u.src[..4]);
        let s = csum_add(s, &u.dst[..4]);
        s + 17 + udp_len as u32
    };
    sum = csum_add(sum, &out[ip_len..]);
    let mut c = csum_fold(sum);
    if c == 0 {
        c = 0xFFFF;
    }
    out[ip_len + 6..ip_len + 8].copy_from_slice(&c.to_be_bytes());
}

// ------------------------------------------------------------------------------ engine

#[derive(Hash, PartialEq, Eq, Clone, Copy)]
struct FlowKey {
    v6: bool,
    src: [u8; 16],
    dst: [u8; 16],
    sport: u16,
    dport: u16,
}

struct Flow {
    packets: u32,
    last_ms: u64,
    last_quic_fake_ms: Option<u64>,
}

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    pub packets: u64,
    pub desynced: u64,
    pub fakes_sent: u64,
    pub passed: u64,
}

const FLOW_TTL_MS: u64 = 60_000;
/// zapret `IPCACHE_LIFETIME`: 7200 s.
const IPCACHE_LIFETIME_MS: u64 = 7_200_000;
const MAX_FLOWS: usize = 4096;
/// A repeated Initial within this window belongs to the same ClientHello (fragmentation) or is a
/// quick retransmit: the DPI state is already primed, so no new fakes.
const QUIC_REFAKE_MS: u64 = 1000;

pub struct Engine {
    rules: Vec<Rule>,
    tcp: Vec<TcpSpec>,
    /// Server IPv4 -> (hops, last seen ms), learned from inbound SYN-ACKs, for `autottl`.
    hops: HashMap<[u8; 4], (u8, u64)>,
    flows: HashMap<FlowKey, Flow>,
    scratch: Vec<u8>,
    rng: u32,
    pub stats: Stats,
}

impl Engine {
    pub fn new(rules: Vec<Rule>, seed: u32) -> Self {
        Self { rules, tcp: Vec::new(), hops: HashMap::new(), flows: HashMap::new(), scratch: Vec::with_capacity(2048), rng: seed | 1, stats: Stats::default() }
    }

    /// Adds the TCP rules. TCP needs no per-flow state: the capture filter hands over only the
    /// first data segment of a handshake (a ClientHello or an HTTP request), so there is nothing
    /// to count or expire.
    pub fn with_tcp(mut self, tcp: Vec<TcpSpec>) -> Self {
        self.tcp = tcp;
        self
    }

    fn rand16(&mut self) -> u16 {
        let mut x = self.rng;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.rng = x;
        (x >> 8) as u16 | 1
    }

    fn purge(&mut self, now: u64) {
        if self.flows.len() >= MAX_FLOWS / 2 {
            self.flows.retain(|_, f| now.saturating_sub(f.last_ms) < FLOW_TTL_MS);
            if self.flows.len() >= MAX_FLOWS {
                self.flows.clear(); // flows are short-lived; losing the counters is harmless
            }
        }
    }

    /// Processes one captured outbound packet: fakes first (if any), then the original, unmodified.
    pub fn handle(&mut self, pkt: &[u8], addr: &Addr, now_ms: u64, io: &mut dyn PacketIo) {
        self.stats.packets += 1;
        if let Some(t) = tcp::parse_tcp(pkt) {
            if t.flags & 0x12 == 0x02 && self.handle_syn(pkt, &t, addr, io) {
                return;
            }
            if t.flags & 0x12 == 0x12 && t.payload_off == t.end {
                self.note_synack(&t, now_ms);
                io.send(pkt, addr);
                return;
            }
            if !self.handle_tcp(pkt, &t, addr, now_ms, io) {
                self.stats.passed += 1;
                io.send(pkt, addr);
            }
            return;
        }
        let fakes = self.plan_fakes(pkt, now_ms);
        if let Some((rule_idx, class, ip_id)) = fakes {
            let u = parse_udp(pkt).expect("parsed above");
            let r = &self.rules[rule_idx];
            let ttl = if u.v6 { r.ttl6 } else { r.ttl }.unwrap_or(u.ttl);
            let repeats = r.repeats;
            let mut buf = std::mem::take(&mut self.scratch);
            let mut id = ip_id;
            let mut sent = 0u64;
            for blob in &r.fakes[class as usize] {
                build_fake(pkt, &u, id, ttl, blob, &mut buf);
                let mut a = *addr;
                io.finalize(&mut buf, &mut a);
                for _ in 0..repeats {
                    io.send(&buf, &a);
                }
                sent += repeats as u64;
                id = id.wrapping_add(1);
            }
            self.stats.fakes_sent += sent;
            self.stats.desynced += 1;
            self.scratch = buf;
        } else {
            self.stats.passed += 1;
        }
        io.send(pkt, addr);
    }

    /// Desynchronises one captured TCP data segment. Returns `false` when the packet is not
    /// ours to change (the caller then forwards it untouched).
    /// `syndata`: the SYN is replaced by one carrying junk (the server ignores data in a SYN
    /// that is not Fast Open). The first rule whose port and address filters match decides, as in
    /// zapret; host lists cannot match yet because the name is unknown at this point.
    fn handle_syn(&mut self, pkt: &[u8], t: &Tcp, addr: &Addr, io: &mut dyn PacketIo) -> bool {
        if t.payload_off != t.end {
            return false; // zapret: a SYN that already carries data is left alone
        }
        let Some(spec) = self.tcp.iter().find(|s| s.matches(t, L7::Any, None)) else { return false };
        let Some(data) = &spec.syndata else { return false };
        let opts = &pkt[t.ip_len + 20..t.payload_off];
        let mut i = 0;
        while i < opts.len() {
            match opts[i] {
                0 => break,
                1 => i += 1,
                k => {
                    let l = *opts.get(i + 1).unwrap_or(&0) as usize;
                    // TCP Fast Open (RFC 7413, or the old experimental form): never break it
                    if k == 34 || (k == 254 && l >= 4 && opts.get(i + 2..i + 4) == Some(&[0xF9, 0x89])) {
                        return false;
                    }
                    if l < 2 {
                        break;
                    }
                    i += l;
                }
            }
        }
        let id = if t.v6 { 0 } else { u16::from_be_bytes([pkt[4], pkt[5]]) };
        let mut out = Vec::new();
        tcp::build(pkt, t, t.seq, data, tcp::Fool::default(), if spec.rule.ip_id_zero { 0 } else { id }, &mut out);
        let mut a = *addr;
        io.finalize(&mut out, &mut a);
        for _ in 0..spec.rule.fake_repeats.max(1) {
            io.send(&out, &a);
        }
        self.stats.desynced += 1;
        true
    }

    /// An inbound SYN-ACK tells how far the server is (its TTL); only kept when a rule uses autottl.
    fn note_synack(&mut self, t: &Tcp, now: u64) {
        if t.v6 || !self.tcp.iter().any(|s| s.autottl.is_some()) {
            return;
        }
        let h = hop_count_guess(t.ttl);
        if h == 0 {
            return;
        }
        if self.hops.len() >= 4096 {
            self.hops.retain(|_, v| now.saturating_sub(v.1) < IPCACHE_LIFETIME_MS);
            if self.hops.len() >= 4096 {
                self.hops.clear();
            }
        }
        self.hops.insert([t.src[0], t.src[1], t.src[2], t.src[3]], (h, now));
    }

    fn handle_tcp(&mut self, pkt: &[u8], t: &Tcp, addr: &Addr, now: u64, io: &mut dyn PacketIo) -> bool {
        if self.tcp.is_empty() {
            return false;
        }
        let payload = &pkt[t.payload_off..t.end];
        let (l7, hello) = if tls::is_client_hello(payload) {
            (L7::Tls, tls::parse(payload))
        } else if http::is_request(payload) {
            (L7::Http, http::parse(payload))
        } else {
            return false;
        };
        let host = hello.as_ref().and_then(|h| tls::sni(payload, h));
        let Some(idx) = self.tcp.iter().position(|s| s.matches(t, l7, host)) else {
            return false;
        };
        let spec = &self.tcp[idx];
        if spec.inert {
            return false;
        }
        let fakes: Vec<Vec<u8>> = match (spec.fake, l7) {
            (false, _) => Vec::new(),
            (true, L7::Http) => vec![FAKE_HTTP.to_vec()],
            (true, _) => spec.fake_tls.iter().map(|(b, m)| faketls::apply(b, m, payload, &mut self.rng)).collect(),
        };
        let ttl_fake = spec.autottl.filter(|_| !t.v6).and_then(|a| {
            let (h, seen) = *self.hops.get(&[t.dst[0], t.dst[1], t.dst[2], t.dst[3]])?;
            (now.saturating_sub(seen) < IPCACHE_LIFETIME_MS).then_some(h).and_then(|h| a.eval(h))
        });
        let orig_id = if t.v6 { 0 } else { u16::from_be_bytes([pkt[4], pkt[5]]) };
        let out = tcp::desync_with(&spec.rule, &fakes, ttl_fake, pkt, t, hello.as_ref(), orig_id);
        if out.len() == 1 && out[0] == pkt {
            return false;
        }
        self.stats.fakes_sent += fakes.len() as u64 * spec.rule.fake_repeats.max(1) as u64;
        self.stats.desynced += 1;
        for mut p in out {
            let mut a = *addr;
            io.finalize(&mut p, &mut a);
            io.send(&p, &a);
        }
        true
    }

    /// Decides whether fakes are needed: (rule index, is_quic, repeats, ipv4 id).
    fn plan_fakes(&mut self, pkt: &[u8], now: u64) -> Option<(usize, U7, u16)> {
        let u = parse_udp(pkt)?;
        let payload = pkt.get(u.payload_off..)?;
        let class = classify_udp(payload);
        // the SNI is only read (an AES-GCM decrypt) when a rule actually has a host list
        let host = if class == Some(U7::Quic) && self.rules.iter().any(|r| r.include.is_some() || r.exclude.is_some()) { quic_sni::host(payload) } else { None };
        let ri = self.rules.iter().position(|r| r.matches_port(u.dport) && r.matches_ip(&u.dst, u.v6) && r.matches_l7(class) && r.matches_host(host.as_deref()))?;

        let key = FlowKey { v6: u.v6, src: u.src, dst: u.dst, sport: u.sport, dport: u.dport };
        if self.flows.len() >= MAX_FLOWS / 2 && !self.flows.contains_key(&key) {
            self.purge(now);
        }
        let flow = self.flows.entry(key).or_insert(Flow { packets: 0, last_ms: now, last_quic_fake_ms: None });
        if now.saturating_sub(flow.last_ms) >= FLOW_TTL_MS {
            flow.packets = 0;
            flow.last_quic_fake_ms = None;
        }
        flow.packets = flow.packets.saturating_add(1); // zapret increments before testing the cutoff
        flow.last_ms = now;
        let count = flow.packets;

        let rule = &self.rules[ri];
        if rule.cutoff.is_some_and(|n| count >= n) || payload.is_empty() {
            return None;
        }
        let class = match class {
            Some(c) => c,
            None if rule.any_protocol => U7::Unknown,
            None => return None,
        };
        if class == U7::Quic {
            if flow.last_quic_fake_ms.is_some_and(|t| now.saturating_sub(t) < QUIC_REFAKE_MS) {
                return None;
            }
            flow.last_quic_fake_ms = Some(now);
        }
        let orig_id = if u.v6 { 0 } else { u16::from_be_bytes([pkt[4], pkt[5]]) };
        let ip_id = if u.v6 { 0 } else if orig_id != 0 { orig_id } else { self.rand16() };
        Some((ri, class, ip_id))
    }

    /// Main loop: runs until `recv` reports that the handle is closed.
    pub fn run(&mut self, io: &mut dyn PacketIo, clock: &dyn Fn() -> u64) {
        let mut buf = vec![0u8; 65_600]; // one allocation for the whole session
        while let Some((n, addr)) = io.recv(&mut buf) {
            let now = clock();
            self.handle(&buf[..n], &addr, now, io);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quic::sample_initial;

    #[derive(Default)]
    struct Mock {
        sent: Vec<Vec<u8>>,
    }
    impl PacketIo for Mock {
        fn recv(&mut self, _: &mut [u8]) -> Option<(usize, Addr)> {
            None
        }
        fn send(&mut self, p: &[u8], _: &Addr) {
            self.sent.push(p.to_vec());
        }
    }

    fn udp4(sport: u16, dport: u16, ttl: u8, id: u16, payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0x45, 0x28, 0, 0, (id >> 8) as u8, id as u8, 0x40, 0, ttl, 17, 0, 0, 10, 0, 0, 2, 162, 159, 197, 5];
        let total = (28 + payload.len()) as u16;
        p[2..4].copy_from_slice(&total.to_be_bytes());
        p.extend_from_slice(&sport.to_be_bytes());
        p.extend_from_slice(&dport.to_be_bytes());
        p.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        p.extend_from_slice(&[0, 0]);
        p.extend_from_slice(payload);
        p
    }

    fn udp6(dport: u16, payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0x60, 0x01, 0x23, 0x45, 0, 0, 17, 55];
        p.truncate(4);
        p.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        p.push(17);
        p.push(55);
        let mut src = [0u8; 16];
        src[0] = 0x20;
        src[15] = 1;
        let mut dst = [0u8; 16];
        dst[0] = 0x26;
        dst[1] = 0x06;
        dst[2] = 0x47;
        dst[3] = 0x00;
        dst[15] = 9;
        p.extend_from_slice(&src);
        p.extend_from_slice(&dst);
        p.extend_from_slice(&5000u16.to_be_bytes());
        p.extend_from_slice(&dport.to_be_bytes());
        p.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        p.extend_from_slice(&[0, 0]);
        p.extend_from_slice(payload);
        p
    }

    fn fakes_of(c: U7, blob: Vec<u8>) -> [Vec<Vec<u8>>; 6] {
        let mut f: [Vec<Vec<u8>>; 6] = Default::default();
        f[c as usize].push(blob);
        f
    }

    fn rules() -> Vec<Rule> {
        vec![
            Rule { ports: vec![(443, 443)], repeats: 6, fakes: fakes_of(U7::Quic, vec![0xAB; 300]), ..Default::default() },
            Rule {
                ports: vec![(500, 500), (8443, 8443)],
                any_protocol: true,
                repeats: 12,
                fakes: fakes_of(U7::Unknown, vec![0xCD; 200]),
                cutoff: Some(2),
                ..Default::default()
            },
        ]
    }

    /// Internet checksum over pseudo header + UDP segment must be zero.
    fn udp_checksum_ok(p: &[u8]) -> bool {
        let u = parse_udp(p).unwrap();
        let seg = &p[u.payload_off - 8..];
        let mut sum = if u.v6 {
            csum_add(csum_add(0, &u.src), &u.dst) + seg.len() as u32 + 17
        } else {
            csum_add(csum_add(0, &u.src[..4]), &u.dst[..4]) + 17 + seg.len() as u32
        };
        sum = csum_add(sum, seg);
        csum_fold(sum) == 0
    }

    #[test]
    fn quic_initial_gets_six_fakes_before_the_original() {
        let mut e = Engine::new(rules(), 1);
        let mut io = Mock::default();
        let orig = udp4(50000, 443, 128, 0x1234, &sample_initial(1200));
        e.handle(&orig, &Addr::default(), 0, &mut io);
        assert_eq!(io.sent.len(), 7);
        assert_eq!(io.sent[6], orig, "the original goes last and is untouched");
        let f = &io.sent[0];
        assert!(io.sent[..6].iter().all(|x| x == f));
        let u = parse_udp(f).unwrap();
        assert_eq!((u.sport, u.dport, u.ttl), (50000, 443, 128));
        assert_eq!(&f[4..6], &[0x12, 0x34], "ip id = original id");
        assert_eq!(f[6] & 0x40, 0x40, "DF kept");
        assert_eq!(f[1], 0x28, "TOS kept");
        assert_eq!(&f[u.payload_off..], &[0xAB; 300][..]);
        assert_eq!(csum_fold(csum_add(0, &f[..20])), 0, "ipv4 header checksum");
        assert!(udp_checksum_ok(f));
    }

    #[test]
    fn repeated_initial_in_the_same_flow_is_not_refaked_until_the_window_passes() {
        let mut e = Engine::new(rules(), 1);
        let mut io = Mock::default();
        let p = udp4(50000, 443, 64, 7, &sample_initial(1200));
        e.handle(&p, &Addr::default(), 0, &mut io);
        e.handle(&p, &Addr::default(), 200, &mut io); // second fragment / quick retransmit
        assert_eq!(io.sent.len(), 7 + 1);
        e.handle(&p, &Addr::default(), 1500, &mut io); // real retransmit later
        assert_eq!(io.sent.len(), 7 + 1 + 7);
        let other_flow = udp4(50001, 443, 64, 8, &sample_initial(1200));
        e.handle(&other_flow, &Addr::default(), 1600, &mut io);
        assert_eq!(io.sent.len(), 7 + 1 + 7 + 7);
    }

    #[test]
    fn non_initial_quic_traffic_on_443_is_passed() {
        let mut e = Engine::new(rules(), 1);
        let mut io = Mock::default();
        let mut hs = sample_initial(1200);
        hs[0] = 0xE3;
        e.handle(&udp4(1, 443, 64, 1, &hs), &Addr::default(), 0, &mut io);
        assert_eq!(io.sent.len(), 1);
        assert_eq!(e.stats.passed, 1);
    }

    #[test]
    fn cutoff_n2_means_only_the_first_packet_of_a_flow() {
        let mut e = Engine::new(rules(), 1);
        let mut io = Mock::default();
        let p = udp4(4000, 8443, 64, 9, &[0xC5; 120]);
        e.handle(&p, &Addr::default(), 0, &mut io);
        assert_eq!(io.sent.len(), 13); // 12 fakes + original
        e.handle(&p, &Addr::default(), 10, &mut io);
        assert_eq!(io.sent.len(), 14); // second packet: counter reached 2 -> passed
        // a new flow starts again; so does the same flow after 60 s of silence
        e.handle(&udp4(4001, 8443, 64, 9, &[0xC5; 120]), &Addr::default(), 20, &mut io);
        assert_eq!(io.sent.len(), 14 + 13);
        e.handle(&p, &Addr::default(), 70_000, &mut io);
        assert_eq!(io.sent.len(), 14 + 13 + 13);
    }

    #[test]
    fn unmatched_ports_and_garbage_pass_untouched() {
        let mut e = Engine::new(rules(), 1);
        let mut io = Mock::default();
        e.handle(&udp4(1, 9999, 64, 1, &[0xC5; 100]), &Addr::default(), 0, &mut io);
        e.handle(&[0x45, 0, 0], &Addr::default(), 0, &mut io);
        assert_eq!(io.sent.len(), 2);
        assert_eq!(e.stats.fakes_sent, 0);
    }

    #[test]
    fn ipv6_fake_keeps_flow_label_hop_limit_and_valid_checksum() {
        let mut e = Engine::new(rules(), 1);
        let mut io = Mock::default();
        let p = udp6(8443, &[0xC5; 100]);
        e.handle(&p, &Addr::default(), 0, &mut io);
        assert_eq!(io.sent.len(), 13);
        let f = &io.sent[0];
        assert_eq!(&f[..4], &p[..4]);
        assert_eq!(f[7], 55);
        assert_eq!(f.len(), 40 + 8 + 200);
        assert!(udp_checksum_ok(f));
    }

    #[test]
    fn zero_ipv4_id_gets_a_random_nonzero_one() {
        let mut e = Engine::new(rules(), 99);
        let mut io = Mock::default();
        e.handle(&udp4(1, 8443, 64, 0, &[0xC5; 100]), &Addr::default(), 0, &mut io);
        assert_ne!(&io.sent[0][4..6], &[0, 0]);
    }

    fn read_stub(p: &str) -> io::Result<Vec<u8>> {
        Ok(vec![p.len() as u8; 100])
    }
    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn plan_from_the_real_warp_lean_profile() {
        use crate::capture::{expand, Vars};
        use crate::profiles::{find, WFRAW};
        let p = find("warp").unwrap();
        let args = expand(p.lean.unwrap(), &Vars { bin: "B\\", lists: "L\\", wfraw: WFRAW, gf_tcp: "12", gf_udp: "500,1701,4443,4500,8095,8443" });
        let plan = Plan::from_args(&args, &read_stub).unwrap();
        assert_eq!(plan.filter, WFRAW);
        assert_eq!(plan.rules.len(), 2);
        assert_eq!(plan.rules[0].repeats, 6);
        assert!(plan.rules[0].fakes[U7::Quic as usize].len() == 1 && plan.rules[0].cutoff.is_none());
        assert_eq!(plan.rules[1].repeats, 12);
        assert!(plan.rules[1].any_protocol && plan.rules[1].fakes[U7::Unknown as usize].len() == 1);
        assert_eq!(plan.rules[1].cutoff, Some(2));
        assert!(plan.rules[1].matches_port(4500) && !plan.rules[1].matches_port(443));
    }

    #[test]
    fn strategies_that_need_lists_tcp_or_ttl_are_refused() {
        use crate::capture::{expand, Vars};
        use crate::profiles::{PROFILES, WFRAW};
        let v = Vars { bin: "B\\", lists: "L\\", wfraw: WFRAW, gf_tcp: "12", gf_udp: "500" };
        let supported: Vec<_> = PROFILES
            .iter()
            .filter(|p| p.lean.is_some_and(|l| Plan::from_args(&expand(l, &v), &read_stub).is_ok()))
            .map(|p| p.name)
            .collect();
        assert!(supported.contains(&"warp"), "the default WARP strategy must run on the native engine: {supported:?}");
        assert!(supported.contains(&"warp-esports") && supported.contains(&"warp-lowburst"), "{supported:?}");
        assert!(supported.contains(&"warp-esports-ttl") && supported.contains(&"warp-ttl"), "UDP TTL fakes are native now: {supported:?}");
        assert!(Plan::from_args(&s(&["--wf-raw=x", "--filter-udp=443", "--dpi-desync=fake", "--dpi-desync-autottl=2"]), &read_stub).is_err());
        assert!(Plan::from_args(&s(&["--filter-tcp=443", "--dpi-desync=disorder2"]), &read_stub).is_err());
        let g = Plan::from_args(&s(&["--wf-udp=443", "--filter-udp=443", "--dpi-desync=fake"]), &read_stub).unwrap();
        assert!(g.filter.contains("udp.DstPort==443") && g.filter.contains("udp.PayloadLength>0"), "{}", g.filter);
    }

    // ------------------------------------------------------------------------- TCP

    fn tcp_reader(p: &str) -> io::Result<Vec<u8>> {
        use crate::tls::tests::hello;
        Ok(match p {
            "FAKE" => hello(Some("www.example.org")),
            "PAT" => vec![0xAB; 20],
            "BLOCKED" => b"blocked.test\n".to_vec(),
            "IPS" => b"104.16.0.0/16\n".to_vec(),
            _ => vec![1],
        })
    }

    fn tls_args() -> Vec<String> {
        s(&[
            "--filter-tcp=443",
            "--hostlist=BLOCKED",
            "--dpi-desync=fake,multisplit",
            "--dpi-desync-split-pos=1,midsld",
            "--dpi-desync-split-seqovl=10",
            "--dpi-desync-split-seqovl-pattern=PAT",
            "--dpi-desync-fooling=ts",
            "--dpi-desync-repeats=2",
            "--dpi-desync-fake-tls=FAKE",
            "--dpi-desync-fake-tls-mod=rnd,dupsid,sni=ya.ru",
            "--ip-id=zero",
        ])
    }

    #[test]
    fn tcp_plan_collects_rule_lists_and_builds_a_kernel_side_filter() {
        let plan = Plan::from_args(&tls_args(), &tcp_reader).unwrap();
        assert!(plan.rules.is_empty() && plan.tcp.len() == 1);
        let t = &plan.tcp[0];
        assert!(t.fake && t.rule.split == Split::Multisplit && t.rule.seqovl == 10 && t.rule.fake_repeats == 2);
        assert!(t.rule.fool.ts && t.rule.ip_id_zero && t.include.as_ref().unwrap().contains("a.blocked.test"));
        assert!(plan.filter.contains("outbound and tcp") && plan.filter.contains("tcp.DstPort==443"));
        assert!(plan.filter.contains("tcp.Payload[0]==0x16") && !plan.filter.contains("udp"));
    }

    #[test]
    fn http_rule_adds_a_port_80_clause_and_default_split() {
        let plan = Plan::from_args(&s(&["--filter-tcp=80", "--filter-l7=http", "--dpi-desync=fake,multisplit", "--dpi-desync-split-pos=method+2", "--dpi-desync-fooling=ts"]), &tcp_reader).unwrap();
        assert!(plan.filter.contains("tcp.DstPort==80") && plan.filter.contains("tcp.Payload[0]>=0x41"));
        assert!(!plan.filter.contains("0x16"), "an HTTP-only rule does not capture TLS");
        let mixed = Plan::from_args(&s(&["--wf-raw=udp", "--filter-udp=443", "--dpi-desync=fake", "--new", "--filter-tcp=443", "--dpi-desync=multisplit"]), &tcp_reader).unwrap();
        assert!(mixed.filter.starts_with("(udp) or (not impostor"), "{}", mixed.filter);
    }

    #[test]
    fn unsupported_tcp_features_are_refused_so_the_launcher_falls_back() {
        let bad = |extra: &[&str]| {
            let mut a = s(&["--filter-tcp=443", "--dpi-desync=multisplit"]);
            a.extend(s(extra));
            Plan::from_args(&a, &tcp_reader).is_err()
        };
        assert!(bad(&["--dpi-desync-fooling=badsum"]));
        assert!(bad(&["--dpi-desync-cutoff=n3"]));
        assert!(bad(&["--dpi-desync-autottl6=2"]));
        assert!(bad(&["--filter-l7=discord"]));
        assert!(bad(&["--hostlist=BLOCKED", "--ipset=IPS"]));
        assert!(bad(&["--dpi-desync-fake-tls-mod=padencap"]));
        assert!(Plan::from_args(&s(&["--filter-tcp=443", "--dpi-desync=fake,fakedsplit,multisplit"]), &tcp_reader).is_err(), "two split modes");
        assert!(bad(&["--dpi-desync-hostfakesplit-midhost=host+1"]));
        assert!(Plan::from_args(&s(&["--filter-tcp=443", "--dpi-desync=rst"]), &tcp_reader).is_err());
        let b = Plan::from_args(&s(&["--filter-tcp=443", "--dpi-desync=fake"]), &tcp_reader).unwrap();
        let (blob, m) = &b.tcp[0].fake_tls[0];
        assert_eq!((blob.len(), m.rnd, m.dupsid), (680, true, true), "built-in blob with zapret's default mods");
        let sni = |x: &[u8]| tls::sni(x, &tls::parse(x).unwrap()).unwrap().to_owned();
        assert_ne!(sni(blob), "www.microsoft.com", "rndsni ran once at plan time");
        let c = Plan::from_args(&s(&["--filter-tcp=443", "--dpi-desync=fake", "--dpi-desync-fake-tls=FAKE"]), &tcp_reader).unwrap();
        assert!(!c.tcp[0].fake_tls[0].1.rnd, "a custom blob gets no default mods");
        // two blobs, the mod written after them belongs to the last one only (zapret: tls_fake_last)
        let two = Plan::from_args(&s(&["--filter-tcp=443", "--dpi-desync=fake", "--dpi-desync-fake-tls=PAT", "--dpi-desync-fake-tls=FAKE", "--dpi-desync-fake-tls-mod=rnd"]), &tcp_reader).unwrap();
        assert_eq!(two.tcp[0].fake_tls.len(), 2);
        assert!(!two.tcp[0].fake_tls[0].1.rnd && two.tcp[0].fake_tls[1].1.rnd);
    }

    #[test]
    fn client_hello_for_a_listed_host_is_faked_and_split_and_the_original_is_not_sent() {
        use crate::tcp::tests::mk4;
        use crate::tls::tests::hello;
        let plan = Plan::from_args(&tls_args(), &tcp_reader).unwrap();
        let ch = hello(Some("www.blocked.test"));
        let pkt = mk4(5000, 7, &ch);
        let mut e = Engine::new(Vec::new(), 5).with_tcp(plan.tcp);
        let mut io = Mock::default();
        e.handle(&pkt, &Addr::default(), 0, &mut io);
        assert_eq!(io.sent.len(), 2 + 3, "2 fakes + 3 split segments");
        assert!(!io.sent.contains(&pkt));
        let f = crate::tcp::parse_tcp(&io.sent[0]).unwrap();
        assert_eq!(f.seq, 5000, "a ts-fooled fake keeps the SEQ");
        assert_eq!(&io.sent[0][4..6], &[0, 0], "--ip-id=zero");
        let fake_hello = &io.sent[0][f.payload_off..f.end];
        assert_eq!(tls::sni(fake_hello, &tls::parse(fake_hello).unwrap()), Some("ya.ru"));
        let first = crate::tcp::parse_tcp(&io.sent[2]).unwrap();
        assert_eq!(first.seq, 4990, "seqovl 10 in front of the first segment");
        assert_eq!((e.stats.desynced, e.stats.fakes_sent, e.stats.passed), (1, 2, 0));
    }

    #[test]
    fn other_hosts_other_ports_and_other_payloads_pass_untouched() {
        use crate::tcp::tests::mk4;
        use crate::tls::tests::hello;
        let plan = Plan::from_args(&tls_args(), &tcp_reader).unwrap();
        let mut e = Engine::new(Vec::new(), 5).with_tcp(plan.tcp);
        let mut io = Mock::default();
        let allowed = mk4(1, 1, &hello(Some("fine.example")));
        let no_sni = mk4(1, 1, &hello(None));
        let app_data = mk4(1, 1, &[0x17, 3, 3, 0, 5, 1, 2, 3, 4, 5]);
        let mut other_port = mk4(1, 1, &hello(Some("a.blocked.test")));
        other_port[22..24].copy_from_slice(&8443u16.to_be_bytes());
        for p in [&allowed, &no_sni, &app_data, &other_port] {
            e.handle(p, &Addr::default(), 0, &mut io);
        }
        assert_eq!(io.sent, vec![allowed, no_sni, app_data, other_port]);
        assert_eq!((e.stats.desynced, e.stats.passed), (0, 4));
    }

    #[test]
    fn ipset_include_and_exclude_select_by_destination() {
        use crate::tcp::tests::mk4;
        use crate::tls::tests::hello;
        let inc = Plan::from_args(&s(&["--filter-tcp=443", "--ipset=IPS", "--dpi-desync=multisplit", "--dpi-desync-split-pos=1"]), &tcp_reader).unwrap();
        let exc = Plan::from_args(&s(&["--filter-tcp=443", "--ipset-exclude=IPS", "--dpi-desync=multisplit", "--dpi-desync-split-pos=1"]), &tcp_reader).unwrap();
        let pkt = mk4(1, 1, &hello(Some("x.test"))); // destination 104.16.1.1
        for (plan, expect) in [(inc, 2), (exc, 1)] {
            let mut e = Engine::new(Vec::new(), 5).with_tcp(plan.tcp);
            let mut io = Mock::default();
            e.handle(&pkt, &Addr::default(), 0, &mut io);
            assert_eq!(io.sent.len(), expect);
        }
    }

    #[test]
    fn http_request_is_split_after_two_bytes_of_the_method() {
        use crate::tcp::tests::mk4;
        let plan = Plan::from_args(&s(&["--filter-tcp=80", "--filter-l7=http", "--dpi-desync=fake,multisplit", "--dpi-desync-split-pos=method+2", "--dpi-desync-fooling=ts", "--dpi-desync-repeats=4"]), &tcp_reader).unwrap();
        let req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let mut pkt = mk4(100, 1, req);
        pkt[22..24].copy_from_slice(&80u16.to_be_bytes());
        let mut e = Engine::new(Vec::new(), 5).with_tcp(plan.tcp);
        let mut io = Mock::default();
        e.handle(&pkt, &Addr::default(), 0, &mut io);
        assert_eq!(io.sent.len(), 4 + 2);
        let t = crate::tcp::parse_tcp(&io.sent[4]).unwrap();
        assert_eq!(&io.sent[4][t.payload_off..t.end], b"GE");
        let t = crate::tcp::parse_tcp(&io.sent[5]).unwrap();
        assert_eq!((t.seq, &io.sent[5][t.payload_off..t.end]), (102, &req[2..]));
    }

    #[test]
    fn the_udp_path_is_unaffected_by_tcp_rules() {
        let plan = Plan::from_args(&tls_args(), &tcp_reader).unwrap();
        let mut e = Engine::new(rules(), 1).with_tcp(plan.tcp);
        let mut io = Mock::default();
        let p = udp4(50000, 443, 64, 7, &sample_initial(1200));
        e.handle(&p, &Addr::default(), 0, &mut io);
        assert_eq!(io.sent.len(), 7, "six fakes and the original");
    }

    // ------------------------------------------------------------------------- UDP, per protocol

    fn udp_plan(extra: &[&str]) -> Vec<Rule> {
        let mut a = s(&["--wf-raw=x"]);
        a.extend(s(extra));
        Plan::from_args(&a, &tcp_reader).unwrap().rules
    }

    fn run_udp(rules: Vec<Rule>, pkt: &[u8]) -> Vec<Vec<u8>> {
        let mut e = Engine::new(rules, 3);
        let mut io = Mock::default();
        e.handle(pkt, &Addr::default(), 0, &mut io);
        io.sent
    }

    fn udp_payload(p: &[u8]) -> &[u8] {
        &p[28..]
    }

    #[test]
    fn several_fake_quic_blobs_go_out_in_order_each_repeated() {
        let rules = udp_plan(&["--filter-udp=443", "--dpi-desync=fake", "--dpi-desync-repeats=2", "--dpi-desync-fake-quic=PAT", "--dpi-desync-fake-quic=FAKE"]);
        let orig = udp4(50000, 443, 64, 7, &sample_initial(1200));
        let sent = run_udp(rules, &orig);
        assert_eq!(sent.len(), 5, "2 blobs x 2 repeats + the original");
        let first = udp_payload(&sent[0]).len();
        assert_eq!((udp_payload(&sent[1]).len(), udp_payload(&sent[2]).len()), (first, tls_reader_len("FAKE")));
        assert_eq!(sent[4], orig);
    }

    fn tls_reader_len(p: &str) -> usize {
        tcp_reader(p).unwrap().len()
    }

    #[test]
    fn a_rule_without_fakes_uses_zaprets_defaults_per_protocol() {
        let rules = udp_plan(&["--filter-udp=443,4500", "--dpi-desync=fake", "--dpi-desync-any-protocol=1", "--dpi-desync-fake-unknown-udp=PAT"]);
        // QUIC Initial: built-in 620 bytes, first byte 0x40
        let q = run_udp(rules.clone(), &udp4(50000, 443, 64, 7, &sample_initial(1200)));
        assert_eq!(udp_payload(&q[0]).len(), 620);
        assert_eq!(udp_payload(&q[0])[0], 0x40);
        // WireGuard handshake initiation (148 bytes, first byte 1): the *wireguard* fake (64 zeros),
        // not the unknown-protocol blob
        let mut wg = vec![0u8; 148];
        wg[0] = 1;
        let w = run_udp(rules.clone(), &udp4(50000, 4500, 64, 7, &wg));
        assert_eq!(udp_payload(&w[0]), &[0u8; 64][..]);
        // anything else: the unknown-protocol blob from the rule
        let u = run_udp(rules, &udp4(50000, 4500, 64, 7, &[9u8; 100]));
        assert_eq!(udp_payload(&u[0]), &[0xABu8; 20][..]);
    }

    #[test]
    fn udp_ttl_applies_to_ipv4_fakes_only_not_to_the_original() {
        let rules = udp_plan(&["--filter-udp=443", "--dpi-desync=fake", "--dpi-desync-repeats=1", "--dpi-desync-ttl=5", "--dpi-desync-fake-quic=FAKE"]);
        let orig = udp4(50000, 443, 64, 7, &sample_initial(1200));
        let sent = run_udp(rules, &orig);
        assert_eq!((sent[0][8], sent[1][8]), (5, 64));
        assert_eq!(csum_fold(csum_add(0, &sent[0][..20])), 0, "IP checksum is valid with the new TTL");
    }

    #[test]
    fn l7_filter_selects_discord_and_stun_and_ignores_everything_else() {
        let rules = udp_plan(&["--filter-udp=1000-65535", "--filter-l7=discord,stun", "--dpi-desync=fake", "--dpi-desync-repeats=3", "--dpi-desync-fake-discord=PAT", "--dpi-desync-fake-stun=FAKE"]);
        let mut discord = vec![0u8; 74];
        discord[1] = 1;
        discord[3] = 70;
        let mut stun = vec![0u8; 28];
        stun[3] = 8;
        stun[4..8].copy_from_slice(&[0x21, 0x12, 0xA4, 0x42]);
        let d = run_udp(rules.clone(), &udp4(50000, 50010, 64, 7, &discord));
        assert_eq!((d.len(), udp_payload(&d[0]).len()), (4, 20));
        let t = run_udp(rules.clone(), &udp4(50000, 3478, 64, 7, &stun));
        assert_eq!((t.len(), udp_payload(&t[0]).len()), (4, tls_reader_len("FAKE")));
        let other = udp4(50000, 50010, 64, 7, &[5u8; 80]);
        assert_eq!(run_udp(rules.clone(), &other), vec![other.clone()]);
        discord[10] = 1; // not an IP discovery request any more
        let nd = udp4(50000, 50010, 64, 7, &discord);
        assert_eq!(run_udp(rules, &nd), vec![nd]);
    }

    #[test]
    fn udp_ipset_selects_by_destination() {
        let inc = udp_plan(&["--filter-udp=443", "--ipset=IPS", "--dpi-desync=fake", "--dpi-desync-fake-quic=PAT"]);
        let exc = udp_plan(&["--filter-udp=443", "--ipset-exclude=IPS", "--dpi-desync=fake", "--dpi-desync-fake-quic=PAT"]);
        let to_listed = udp4(50000, 443, 64, 7, &sample_initial(1200));
        let mut to_other = to_listed.clone();
        to_other[16..20].copy_from_slice(&[8, 8, 8, 8]);
        to_listed.len(); // 162.159.197.5 is outside 104.16.0.0/16, so make a listed one too
        let mut listed = to_listed.clone();
        listed[16..20].copy_from_slice(&[104, 16, 9, 9]);
        assert_eq!((run_udp(inc.clone(), &listed).len(), run_udp(inc, &to_other).len()), (2, 1));
        assert_eq!((run_udp(exc.clone(), &listed).len(), run_udp(exc, &to_other).len()), (1, 2));
    }

    // ------------------------------------------------------------------------- QUIC host lists

    const QV1: &[u8] = include_bytes!("data/quic_initial_v1.bin");
    const QSPLIT: &[u8] = include_bytes!("data/quic_initial_v1_split.bin");
    const QTAIL: &[u8] = include_bytes!("data/quic_initial_v1_tail.bin");

    #[test]
    fn quic_hostlist_rule_fakes_only_listed_hosts_and_builds_a_narrow_filter() {
        let a = &["--filter-udp=443", "--hostlist-domains=example.com", "--dpi-desync=fake", "--dpi-desync-repeats=2", "--dpi-desync-fake-quic=PAT"];
        let plan = Plan::from_args(&s(a), &tcp_reader).unwrap();
        assert!(plan.filter.contains("udp.DstPort==443") && plan.filter.contains("udp.Payload[0]>=0xC0"), "{}", plan.filter);
        let listed = udp4(50000, 443, 64, 7, QV1);
        let other = udp4(50000, 443, 64, 7, QSPLIT);
        let no_name = udp4(50000, 443, 64, 7, QTAIL);
        assert_eq!(run_udp(plan.rules.clone(), &listed).len(), 3, "2 fakes + the original");
        assert_eq!(run_udp(plan.rules.clone(), &other), vec![other.clone()], "www.blocked.test is not listed");
        assert_eq!(run_udp(plan.rules.clone(), &no_name), vec![no_name.clone()], "no SNI in this datagram: an include list cannot match");
        assert_eq!(run_udp(plan.rules, &udp4(50000, 443, 64, 7, &[1u8; 300])).len(), 1);
    }

    #[test]
    fn quic_hostlist_exclude_now_works_on_the_decrypted_sni() {
        let exc = Plan::from_args(&s(&["--filter-udp=443", "--hostlist-exclude-domains=x", "--dpi-desync=fake", "--dpi-desync-fake-quic=PAT"]), &tcp_reader);
        assert!(exc.is_err(), "unknown option");
        let mut a = s(&["--filter-udp=443", "--hostlist-exclude=BLOCKED", "--dpi-desync=fake", "--dpi-desync-fake-quic=PAT"]);
        a.insert(0, "--wf-raw=x".into());
        let rules = Plan::from_args(&a, &tcp_reader).unwrap().rules;
        let blocked = udp4(50000, 443, 64, 7, QSPLIT); // www.blocked.test: subdomain of the excluded blocked.test
        let fine = udp4(50000, 443, 64, 7, QV1);
        assert_eq!(run_udp(rules.clone(), &blocked), vec![blocked.clone()]);
        assert_eq!(run_udp(rules, &fine).len(), 2);
    }

    // ------------------------------------------------------------------------- autottl, syndata

    #[test]
    fn autottl_parse_and_eval_follow_zapret() {
        assert_eq!(AutoTtl::parse("2").unwrap(), Some(AutoTtl { delta: -2, min: 3, max: 20 }));
        assert_eq!(AutoTtl::parse("+2").unwrap(), Some(AutoTtl { delta: 2, min: 3, max: 20 }));
        assert_eq!(AutoTtl::parse("3:5-9").unwrap(), Some(AutoTtl { delta: -3, min: 5, max: 9 }));
        assert_eq!(AutoTtl::parse("-").unwrap(), None);
        assert!(AutoTtl::parse("x").is_err() && AutoTtl::parse("200").is_err() && AutoTtl::parse("2:9-4").is_err());
        let a = AutoTtl::parse("2").unwrap().unwrap();
        assert_eq!(a.eval(10), Some(8));
        assert_eq!(a.eval(3), None, "min 3 is not below 3 hops: the fake would reach the server");
        assert_eq!(a.eval(40), Some(20), "clamped to max");
        let p = AutoTtl::parse("+2").unwrap().unwrap();
        assert_eq!(p.eval(10), Some(12));
    }

    #[test]
    fn hop_count_is_guessed_from_the_usual_initial_ttls() {
        assert_eq!([hop_count_guess(57), hop_count_guess(117), hop_count_guess(250)], [7, 11, 5]);
        assert_eq!([hop_count_guess(64), hop_count_guess(128), hop_count_guess(20)], [0, 0, 0]);
    }

    fn synack_from(server: [u8; 4], ttl: u8) -> Vec<u8> {
        use crate::tcp::tests::mk4;
        let mut p = mk4(777, 1, &[]);
        p[8] = ttl;
        p[12..16].copy_from_slice(&server);
        p[16..20].copy_from_slice(&[10, 0, 0, 2]);
        p[20..22].copy_from_slice(&443u16.to_be_bytes());
        p[22..24].copy_from_slice(&40000u16.to_be_bytes());
        p[33] = 0x12;
        p
    }

    #[test]
    fn autottl_fakes_use_the_hop_count_learned_from_the_syn_ack() {
        use crate::tcp::tests::mk4;
        use crate::tls::tests::hello;
        let args = s(&["--filter-tcp=443", "--dpi-desync=fake,multisplit", "--dpi-desync-split-pos=1", "--dpi-desync-fake-tls=FAKE", "--dpi-desync-autottl=2", "--dpi-desync-fooling=ts"]);
        let plan = Plan::from_args(&args, &tcp_reader).unwrap();
        assert!(plan.filter.contains("inbound and tcp and tcp.Syn and tcp.Ack") && plan.filter.contains("tcp.SrcPort==443"), "{}", plan.filter);
        let mut e = Engine::new(Vec::new(), 5).with_tcp(plan.tcp);
        let mut io = Mock::default();
        let ch = mk4(5000, 1, &hello(Some("x.example.com"))); // destination 104.16.1.1
        // no SYN-ACK seen yet: the fake keeps the original TTL
        e.handle(&ch, &Addr::default(), 0, &mut io);
        assert_eq!(io.sent[0][8], 64);
        // server TTL 52 -> 12 hops -> fake TTL 10; real segments are untouched
        let sa = synack_from([104, 16, 1, 1], 52);
        e.handle(&sa, &Addr::default(), 1_000, &mut io);
        assert_eq!(io.sent.last().unwrap(), &sa, "the SYN-ACK itself passes through");
        io.sent.clear();
        e.handle(&ch, &Addr::default(), 2_000, &mut io);
        assert_eq!((io.sent[0][8], io.sent[1][8], io.sent[2][8]), (10, 64, 64));
        // the entry expires after zapret's two hours
        io.sent.clear();
        e.handle(&ch, &Addr::default(), 2_000 + 7_300_000, &mut io);
        assert_eq!(io.sent[0][8], 64);
    }

    #[test]
    fn syndata_with_a_host_list_never_fires_on_the_syn_so_only_the_data_stage_remains() {
        let ok = Plan::from_args(&s(&["--filter-tcp=2053,8443", "--hostlist-domains=discord.media", "--dpi-desync=syndata,multidisorder"]), &tcp_reader).unwrap();
        assert!(ok.tcp[0].rule.split == Split::Multidisorder && !ok.tcp[0].fake);
        assert!(!ok.filter.contains("tcp.Syn and tcp.PayloadLength"), "no SYN capture is needed: {}", ok.filter);
        let any = Plan::from_args(&s(&["--filter-tcp=2053", "--dpi-desync=syndata,multidisorder"]), &tcp_reader).unwrap();
        assert_eq!(any.tcp[0].syndata, Some(vec![0u8; 16]), "zapret's default is 16 zero bytes");
        assert!(any.filter.contains("tcp.Syn and tcp.Ack==0"), "{}", any.filter);
        assert!(Plan::from_args(&s(&["--filter-tcp=2053", "--filter-l7=tls", "--dpi-desync=syndata"]), &tcp_reader).is_err());
    }

    fn syn_packet(options: &[u8]) -> Vec<u8> {
        use crate::tcp::tests::mk4;
        let mut p = mk4(4000, 0, &[]);
        p.truncate(20 + 20); // IP + a bare TCP header
        p[20 + 12] = ((20 + options.len()) as u8 / 4) << 4;
        p[20 + 13] = 0x02; // SYN
        p.extend_from_slice(options);
        let total = p.len() as u16;
        p[2..4].copy_from_slice(&total.to_be_bytes());
        p
    }

    #[test]
    fn syndata_replaces_the_syn_with_one_that_carries_junk_and_repeats_it() {
        let plan = Plan::from_args(&s(&["--filter-tcp=443", "--dpi-desync=syndata,multisplit", "--dpi-desync-split-pos=1", "--dpi-desync-repeats=3"]), &tcp_reader).unwrap();
        let mut e = Engine::new(Vec::new(), 5).with_tcp(plan.tcp);
        let mut io = Mock::default();
        let syn = syn_packet(&[2, 4, 5, 0xb4, 1, 3, 3, 8]); // MSS 1460, NOP, WS 8
        e.handle(&syn, &Addr::default(), 0, &mut io);
        assert_eq!(io.sent.len(), 3, "the original is dropped; the replacement goes out 3 times");
        let t = crate::tcp::parse_tcp(&io.sent[0]).unwrap();
        assert_eq!((t.flags, t.seq, t.end - t.payload_off), (0x02, 4000, 16));
        assert_eq!(&io.sent[0][t.ip_len + 20..t.payload_off], &[2, 4, 5, 0xb4, 1, 3, 3, 8], "options are kept");
        // Fast Open and SYNs that already have data are not touched
        let tfo = syn_packet(&[34, 2, 1, 1]);
        io.sent.clear();
        e.handle(&tfo, &Addr::default(), 0, &mut io);
        assert_eq!(io.sent, vec![tfo]);
        let mut with_data = syn_packet(&[]);
        with_data.extend_from_slice(&[9; 5]);
        let total = with_data.len() as u16;
        with_data[2..4].copy_from_slice(&total.to_be_bytes());
        io.sent.clear();
        e.handle(&with_data, &Addr::default(), 0, &mut io);
        assert_eq!(io.sent, vec![with_data]);
    }
}
