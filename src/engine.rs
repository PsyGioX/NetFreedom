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

use crate::quic::is_quic_initial;

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

#[derive(Debug, Default, Clone)]
pub struct Rule {
    pub ports: Vec<(u16, u16)>,
    pub any_protocol: bool,
    pub repeats: u32,
    pub fake_quic: Option<Vec<u8>>,
    pub fake_unknown: Option<Vec<u8>>,
    /// `Some(n)`: desync only while the flow's packet counter (incremented first) is < n.
    pub cutoff: Option<u32>,
}

impl Rule {
    fn matches_port(&self, p: u16) -> bool {
        self.ports.iter().any(|&(a, b)| (a..=b).contains(&p))
    }
}

#[derive(Debug)]
pub struct Plan {
    /// WinDivert filter (`--wf-raw`).
    pub filter: String,
    pub rules: Vec<Rule>,
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

impl Plan {
    /// Builds a plan from an expanded winws command line. Fails (with the reason) on anything the
    /// native engine does not reproduce exactly, so the caller can fall back to winws.
    pub fn from_args(args: &[String], read: &dyn Fn(&str) -> io::Result<Vec<u8>>) -> Result<Plan, String> {
        let mut filter = None;
        let mut rules = Vec::new();
        let mut cur = Rule { repeats: 1, ..Default::default() };
        let mut cur_has_filter = false;
        let mut mode_fake = false;

        let finish = |cur: &mut Rule, has_filter: &mut bool, fake: &mut bool, rules: &mut Vec<Rule>| -> Result<(), String> {
            if !*has_filter {
                return Err("a rule without --filter-udp".into());
            }
            if !*fake {
                return Err("a rule without --dpi-desync=fake".into());
            }
            rules.push(std::mem::replace(cur, Rule { repeats: 1, ..Default::default() }));
            *has_filter = false;
            *fake = false;
            Ok(())
        };

        for a in args {
            if a == "--new" {
                finish(&mut cur, &mut cur_has_filter, &mut mode_fake, &mut rules)?;
                continue;
            }
            let (k, v) = a.split_once('=').unwrap_or((a.as_str(), ""));
            let load = |p: &str| -> Result<Vec<u8>, String> {
                let b = read(p).map_err(|e| format!("cannot read {p}: {e}"))?;
                if b.is_empty() || b.len() > 1400 {
                    return Err(format!("{p}: fake payload must be 1..1400 bytes"));
                }
                Ok(b)
            };
            match k {
                "--wf-raw" => filter = Some(v.to_owned()),
                "--filter-udp" => {
                    cur.ports = parse_ports(v)?;
                    cur_has_filter = true;
                }
                "--dpi-desync" if v == "fake" => mode_fake = true,
                "--dpi-desync-repeats" => {
                    cur.repeats = v.parse().ok().filter(|n| (1..=64).contains(n)).ok_or("bad --dpi-desync-repeats")?
                }
                "--dpi-desync-any-protocol" => cur.any_protocol = v == "1",
                "--dpi-desync-fake-quic" => cur.fake_quic = Some(load(v)?),
                "--dpi-desync-fake-unknown-udp" => cur.fake_unknown = Some(load(v)?),
                "--dpi-desync-cutoff" => {
                    let n = v.strip_prefix('n').and_then(|n| n.parse().ok()).filter(|n| *n >= 1);
                    cur.cutoff = Some(n.ok_or("only --dpi-desync-cutoff=nN is supported")?);
                }
                _ => return Err(format!("unsupported option {a}")),
            }
        }
        finish(&mut cur, &mut cur_has_filter, &mut mode_fake, &mut rules)?;
        let filter = filter.ok_or("the profile has no --wf-raw filter (port-based capture)")?;
        Ok(Plan { filter, rules })
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

fn csum_add(mut sum: u32, data: &[u8]) -> u32 {
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

fn csum_fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Builds a complete IP+UDP packet carrying `payload`, modelled on `orig`.
/// Returns the length written into `out`.
fn build_fake(orig: &[u8], u: &Udp, ip_id: u16, payload: &[u8], out: &mut Vec<u8>) {
    out.clear();
    let udp_len = 8 + payload.len();
    if u.v6 {
        out.extend_from_slice(&orig[..4]); // version, traffic class, flow label
        out.extend_from_slice(&(udp_len as u16).to_be_bytes());
        out.push(17);
        out.push(u.ttl);
        out.extend_from_slice(&u.src);
        out.extend_from_slice(&u.dst);
    } else {
        out.push(0x45);
        out.push(orig[1]); // TOS
        out.extend_from_slice(&((20 + udp_len) as u16).to_be_bytes());
        out.extend_from_slice(&ip_id.to_be_bytes());
        out.push(orig[6] & 0x40); // keep DF, clear MF / offset
        out.push(0);
        out.push(u.ttl);
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
const MAX_FLOWS: usize = 4096;
/// A repeated Initial within this window belongs to the same ClientHello (fragmentation) or is a
/// quick retransmit: the DPI state is already primed, so no new fakes.
const QUIC_REFAKE_MS: u64 = 1000;

pub struct Engine {
    rules: Vec<Rule>,
    flows: HashMap<FlowKey, Flow>,
    scratch: Vec<u8>,
    rng: u32,
    pub stats: Stats,
}

impl Engine {
    pub fn new(rules: Vec<Rule>, seed: u32) -> Self {
        Self { rules, flows: HashMap::new(), scratch: Vec::with_capacity(2048), rng: seed | 1, stats: Stats::default() }
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
        let fakes = self.plan_fakes(pkt, now_ms);
        if let Some((rule_idx, quic, repeats, ip_id)) = fakes {
            let u = parse_udp(pkt).expect("parsed above");
            let blob = {
                let r = &self.rules[rule_idx];
                if quic { r.fake_quic.as_deref() } else { r.fake_unknown.as_deref() }
            };
            if let Some(blob) = blob {
                let mut buf = std::mem::take(&mut self.scratch);
                build_fake(pkt, &u, ip_id, blob, &mut buf);
                let mut a = *addr;
                io.finalize(&mut buf, &mut a);
                for _ in 0..repeats {
                    io.send(&buf, &a);
                }
                self.stats.fakes_sent += repeats as u64;
                self.stats.desynced += 1;
                self.scratch = buf;
            } else {
                self.stats.passed += 1; // winws would use a built-in blob here: not reproduced
            }
        } else {
            self.stats.passed += 1;
        }
        io.send(pkt, addr);
    }

    /// Decides whether fakes are needed: (rule index, is_quic, repeats, ipv4 id).
    fn plan_fakes(&mut self, pkt: &[u8], now: u64) -> Option<(usize, bool, u32, u16)> {
        let u = parse_udp(pkt)?;
        let ri = self.rules.iter().position(|r| r.matches_port(u.dport))?;

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
        if rule.cutoff.is_some_and(|n| count >= n) {
            return None;
        }
        let payload = pkt.get(u.payload_off..)?;
        if payload.is_empty() {
            return None;
        }
        let quic = is_quic_initial(payload);
        if !quic && !rule.any_protocol {
            return None;
        }
        let repeats = rule.repeats;
        if quic {
            if flow.last_quic_fake_ms.is_some_and(|t| now.saturating_sub(t) < QUIC_REFAKE_MS) {
                return None;
            }
            flow.last_quic_fake_ms = Some(now);
        }
        let orig_id = if u.v6 { 0 } else { u16::from_be_bytes([pkt[4], pkt[5]]) };
        let ip_id = if u.v6 { 0 } else if orig_id != 0 { orig_id } else { self.rand16() };
        Some((ri, quic, repeats, ip_id))
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

    fn rules() -> Vec<Rule> {
        vec![
            Rule { ports: vec![(443, 443)], repeats: 6, fake_quic: Some(vec![0xAB; 300]), ..Default::default() },
            Rule {
                ports: vec![(500, 500), (8443, 8443)],
                any_protocol: true,
                repeats: 12,
                fake_unknown: Some(vec![0xCD; 200]),
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
        assert!(plan.rules[0].fake_quic.is_some() && plan.rules[0].cutoff.is_none());
        assert_eq!(plan.rules[1].repeats, 12);
        assert!(plan.rules[1].any_protocol && plan.rules[1].fake_unknown.is_some());
        assert_eq!(plan.rules[1].cutoff, Some(2));
        assert!(plan.rules[1].matches_port(4500) && !plan.rules[1].matches_port(443));
    }

    #[test]
    fn strategies_that_need_lists_tcp_or_ttl_are_refused() {
        use crate::capture::{expand, Vars};
        use crate::profiles::{find, PROFILES, WFRAW};
        let v = Vars { bin: "B\\", lists: "L\\", wfraw: WFRAW, gf_tcp: "12", gf_udp: "500" };
        let supported: Vec<_> = PROFILES
            .iter()
            .filter(|p| p.lean.is_some_and(|l| Plan::from_args(&expand(l, &v), &read_stub).is_ok()))
            .map(|p| p.name)
            .collect();
        assert!(supported.contains(&"warp"), "the default WARP strategy must run on the native engine: {supported:?}");
        let ttl = expand(find("warp-ttl").unwrap().lean.unwrap(), &v);
        let err = Plan::from_args(&ttl, &read_stub).unwrap_err();
        assert!(err.contains("unsupported option"), "{err}");
        assert!(Plan::from_args(&s(&["--filter-tcp=443", "--dpi-desync=fake"]), &read_stub).is_err());
        assert!(Plan::from_args(&s(&["--wf-tcp=80", "--filter-udp=443", "--dpi-desync=fake"]), &read_stub).is_err());
    }
}
