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

//! TCP side of the native engine: parsing, building fooled segments, and the split / fake
//! actions for a TLS ClientHello. Everything here is a pure function from a captured packet to
//! the list of packets to inject, so it is unit-tested on any OS without a driver.
//!
//! Implemented: `fake`, `multisplit` (with `seqovl`), `multidisorder`; fooling `ts`, `badseq`,
//! `md5sig`, `badsum`, explicit TTL; a ClientHello cut into several segments is desynchronised as
//! one message (`desync_payload`, `chunk_to_mss`). Not implemented yet (the launcher keeps using the old engine
//! for profiles that need them): `fakedsplit`, `fakeddisorder`, `hostfakesplit`, `syndata`,
//! `autottl`, fake-tls-mod.

use crate::engine::{csum_add, csum_fold};
use crate::tls::{Hello, Pos};

/// zapret defaults: `--dpi-desync-ts-increment`, `--dpi-desync-badseq-increment`,
/// `--dpi-desync-badseq-ack-increment`.
pub const TS_INC: i32 = -600_000;
pub const BADSEQ_INC: i32 = -10_000;
pub const BADSEQ_ACK_INC: i32 = -66_000;

const ACK: u8 = 0x10;

#[derive(Debug, Clone, Copy)]
pub struct Tcp {
    pub v6: bool,
    pub ip_len: usize,
    pub hdr_len: usize,
    pub payload_off: usize,
    /// End of the IP datagram (trailing Ethernet padding is not payload).
    pub end: usize,
    pub ttl: u8,
    pub src: [u8; 16],
    pub dst: [u8; 16],
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
}

pub fn parse_tcp(p: &[u8]) -> Option<Tcp> {
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    let (v6, ip_len, ttl, end) = match p.first()? >> 4 {
        4 => {
            let ihl = (p[0] & 0x0F) as usize * 4;
            if ihl < 20 || p.len() < ihl + 20 || p[9] != 6 {
                return None;
            }
            if u16::from_be_bytes([p[6], p[7]]) & 0x3FFF != 0 {
                return None; // fragment
            }
            src[..4].copy_from_slice(&p[12..16]);
            dst[..4].copy_from_slice(&p[16..20]);
            (false, ihl, p[8], (u16::from_be_bytes([p[2], p[3]]) as usize).min(p.len()))
        }
        6 => {
            if p.len() < 60 || p[6] != 6 {
                return None; // extension headers are passed through untouched
            }
            src.copy_from_slice(&p[8..24]);
            dst.copy_from_slice(&p[24..40]);
            (true, 40, p[7], (40 + u16::from_be_bytes([p[4], p[5]]) as usize).min(p.len()))
        }
        _ => return None,
    };
    if end < ip_len + 20 {
        return None;
    }
    let t = &p[ip_len..end];
    let hdr_len = (t[12] >> 4) as usize * 4;
    if hdr_len < 20 || hdr_len > t.len() {
        return None;
    }
    Some(Tcp {
        v6,
        ip_len,
        hdr_len,
        payload_off: ip_len + hdr_len,
        end,
        ttl,
        src,
        dst,
        sport: u16::from_be_bytes([t[0], t[1]]),
        dport: u16::from_be_bytes([t[2], t[3]]),
        seq: u32::from_be_bytes([t[4], t[5], t[6], t[7]]),
        ack: u32::from_be_bytes([t[8], t[9], t[10], t[11]]),
        flags: t[13],
        window: u16::from_be_bytes([t[14], t[15]]),
    })
}

/// How an injected packet is made invisible to the server (but not to the DPI).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Fool {
    /// Decrease the TCP timestamp so PAWS rejects the segment.
    pub ts: bool,
    /// Move SEQ (and ACK) out of the window.
    pub badseq: bool,
    /// Add a bogus TCP-MD5 option; servers without a configured key ignore the segment.
    pub md5sig: bool,
    pub badsum: bool,
    /// Low TTL: dies before reaching the server.
    pub ttl: Option<u8>,
    /// `--dpi-desync-ttl6`: the TTL for IPv6 (zapret does not reuse `ttl` there).
    pub ttl6: Option<u8>,
    /// `--dpi-desync-badseq-increment`; `None` means zapret's default.
    pub badseq_inc: Option<i32>,
}

fn options(orig: &[u8], f: Fool, salt: u32) -> Vec<u8> {
    let mut o = orig.to_vec();
    let (mut i, mut real_end) = (0usize, 0usize);
    while i < o.len() {
        match o[i] {
            0 => break,
            1 => i += 1,
            k => {
                if i + 1 >= o.len() {
                    break;
                }
                let l = o[i + 1] as usize;
                if l < 2 || i + l > o.len() {
                    break;
                }
                if k == 8 && l == 10 && f.ts {
                    let v = u32::from_be_bytes([o[i + 2], o[i + 3], o[i + 4], o[i + 5]]).wrapping_add(TS_INC as u32);
                    o[i + 2..i + 6].copy_from_slice(&v.to_be_bytes());
                }
                i += l;
                real_end = i;
            }
        }
    }
    if f.md5sig {
        o.truncate(real_end);
        if o.len() + 18 <= 40 {
            o.extend_from_slice(&[19, 18]);
            let mut x = salt | 1;
            for _ in 0..16 {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                o.push(x as u8);
            }
        }
    }
    while o.len() % 4 != 0 {
        o.push(0);
    }
    o
}

/// Builds a complete IP+TCP packet modelled on `orig` (same addresses, ports, flags, window, DF,
/// TOS, flow label) carrying `payload` at sequence number `seq`.
pub fn build(orig: &[u8], t: &Tcp, seq: u32, payload: &[u8], f: Fool, ip_id: u16, out: &mut Vec<u8>) {
    out.clear();
    let opts = options(&orig[t.ip_len + 20..t.ip_len + t.hdr_len], f, seq ^ ((ip_id as u32) << 16));
    let hl = 20 + opts.len();
    let tcp_len = hl + payload.len();
    let ttl = if t.v6 { f.ttl6 } else { f.ttl }.unwrap_or(t.ttl);
    if t.v6 {
        out.extend_from_slice(&orig[..4]);
        out.extend_from_slice(&(tcp_len as u16).to_be_bytes());
        out.push(6);
        out.push(ttl);
        out.extend_from_slice(&t.src);
        out.extend_from_slice(&t.dst);
    } else {
        out.push(0x45);
        out.push(orig[1]);
        out.extend_from_slice(&((20 + tcp_len) as u16).to_be_bytes());
        out.extend_from_slice(&ip_id.to_be_bytes());
        out.push(orig[6] & 0x40);
        out.push(0);
        out.push(ttl);
        out.push(6);
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(&t.src[..4]);
        out.extend_from_slice(&t.dst[..4]);
        let c = csum_fold(csum_add(0, &out[..20]));
        out[10..12].copy_from_slice(&c.to_be_bytes());
    }
    let ip_len = out.len();
    let (mut s, mut a) = (seq, t.ack);
    if f.badseq {
        s = s.wrapping_add(f.badseq_inc.unwrap_or(BADSEQ_INC) as u32);
        if t.flags & ACK != 0 {
            a = a.wrapping_add(BADSEQ_ACK_INC as u32);
        }
    }
    out.extend_from_slice(&t.sport.to_be_bytes());
    out.extend_from_slice(&t.dport.to_be_bytes());
    out.extend_from_slice(&s.to_be_bytes());
    out.extend_from_slice(&a.to_be_bytes());
    out.push(((hl / 4) as u8) << 4);
    out.push(t.flags);
    out.extend_from_slice(&t.window.to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]); // checksum, urgent pointer
    out.extend_from_slice(&opts);
    out.extend_from_slice(payload);

    let sum = if t.v6 {
        csum_add(csum_add(0, &t.src), &t.dst) + tcp_len as u32 + 6
    } else {
        csum_add(csum_add(0, &t.src[..4]), &t.dst[..4]) + 6 + tcp_len as u32
    };
    let mut c = csum_fold(csum_add(sum, &out[ip_len..]));
    if f.badsum {
        c = c.wrapping_add(1);
    }
    out[ip_len + 16..ip_len + 18].copy_from_slice(&c.to_be_bytes());
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Split {
    #[default]
    None,
    Multisplit,
    Multidisorder,
    /// Real halves interleaved with fake halves made of a pattern (`fakedsplit`).
    FakedSplit,
    /// Same, with the second half first (`fakeddisorder`).
    FakedDisorder,
    /// Splits the host name out and puts a fake host in its place on the wire (`hostfakesplit`).
    HostFakeSplit,
}

#[derive(Debug, Clone, Default)]
pub struct TcpRule {
    /// Fake ClientHello sent before the real one, same SEQ, fooled.
    pub fake: Option<Vec<u8>>,
    pub fake_repeats: u32,
    pub split: Split,
    pub positions: Vec<Pos>,
    /// Bytes of overlap in front of the first segment (`--dpi-desync-split-seqovl`).
    pub seqovl: usize,
    pub seqovl_pattern: Vec<u8>,
    pub fool: Fool,
    /// `--ip-id=zero`: every injected IPv4 packet gets ID 0.
    pub ip_id_zero: bool,
    /// `--dpi-desync-fakedsplit-pattern`, repeated to fill; empty means 64 zero bytes.
    pub fs_pattern: Vec<u8>,
    /// `altorder` of `--dpi-desync-fakedsplit-mod` (0 = zapret's default order).
    pub fs_order: u32,
    /// `host=` and `altorder=` of `--dpi-desync-hostfakesplit-mod`.
    pub hfs_host: Option<String>,
    pub hfs_order: u32,
}

fn fill(pattern: &[u8], n: usize) -> Vec<u8> {
    let pat: &[u8] = if pattern.is_empty() { &[0] } else { pattern };
    pat.iter().cycle().take(n).copied().collect()
}

/// zapret's `--dpi-desync-split-pos` choice for fakedsplit / fakeddisorder: the first marker that
/// is not a plain number and resolves, else the first plain number that resolves, else 1.
fn pick_split_pos(rule: &TcpRule, payload: &[u8], hello: Option<&Hello>) -> usize {
    use crate::tls::Marker;
    let pick = |abs: bool| {
        rule.positions.iter().filter(|p| (p.marker == Marker::Abs) == abs).find_map(|p| p.resolve(payload, hello))
    };
    let sp = pick(false).or_else(|| pick(true)).unwrap_or(1);
    if sp > 0 && sp < payload.len() { sp } else { 0 }
}

/// The packets to send *instead of* the captured ClientHello, in send order.
/// Positions that do not exist in this payload are skipped; if none remain the original goes out
/// whole (after the fakes).
pub fn desync(rule: &TcpRule, orig: &[u8], t: &Tcp, hello: Option<&Hello>, base_id: u16) -> Vec<Vec<u8>> {
    let fakes: Vec<Vec<u8>> = rule.fake.iter().cloned().collect();
    desync_with(rule, &fakes, None, orig, t, hello, base_id)
}

/// Same, with the fake payloads supplied by the caller (already adapted to this connection). Like
/// zapret, each fake is sent `fake_repeats` times in a row before the next one, and the IP ID moves
/// on once per fake, not per copy.
/// `ttl_fake` (from autottl) overrides the rule's fixed TTL for the fake packets.
pub fn desync_with(rule: &TcpRule, fakes: &[Vec<u8>], ttl_fake: Option<u8>, orig: &[u8], t: &Tcp, hello: Option<&Hello>, base_id: u16) -> Vec<Vec<u8>> {
    let payload = &orig[t.payload_off..t.end];
    let (mut out, keep_original) = desync_payload(rule, fakes, ttl_fake, orig, t, payload, hello, base_id);
    if keep_original {
        out.push(orig[..t.end].to_vec());
    }
    out
}

/// The general form of [`desync_with`]: `payload` is the stream data the rule acts on, `orig` / `t`
/// only supply the addresses, ports, options and the sequence number of its first byte. That lets
/// a ClientHello that the OS cut into several segments (see `engine::TcpReasm`) be treated as one
/// message. Returns the packets to send and whether the caller must still send the original
/// packet(s) untouched after them (no split applied).
#[allow(clippy::too_many_arguments)]
pub fn desync_payload(rule: &TcpRule, fakes: &[Vec<u8>], ttl_fake: Option<u8>, orig: &[u8], t: &Tcp, payload: &[u8], hello: Option<&Hello>, base_id: u16) -> (Vec<Vec<u8>>, bool) {
    let fooling = Fool { ttl: ttl_fake.or(rule.fool.ttl), ..rule.fool };
    let mut out: Vec<Vec<u8>> = Vec::new();
    let mut id = base_id;
    let zero = rule.ip_id_zero;
    let mut next_id = || {
        id = id.wrapping_add(1);
        if zero {
            0
        } else {
            id
        }
    };
    for fake in fakes {
        let mut b = Vec::new();
        build(orig, t, t.seq, fake, fooling, next_id(), &mut b);
        for _ in 0..rule.fake_repeats.max(1) {
            out.push(b.clone());
        }
    }
    let seg = |out: &mut Vec<Vec<u8>>, seq: u32, data: &[u8], fool: Fool, repeats: u32, id: u16| {
        let mut b = Vec::new();
        build(orig, t, seq, data, fool, id, &mut b);
        for _ in 0..repeats.max(1) {
            out.push(b.clone());
        }
    };
    let real = Fool::default();
    let n = payload.len();
    match rule.split {
        Split::None => {}
        Split::Multisplit | Split::Multidisorder => {
            let mut cuts: Vec<usize> = rule.positions.iter().filter_map(|p| p.resolve(payload, hello)).collect();
            cuts.sort_unstable();
            cuts.dedup();
            if !cuts.is_empty() {
                let mut bounds = vec![0usize];
                bounds.extend(cuts);
                bounds.push(n);
                let disorder = rule.split == Split::Multidisorder;
                let mut segs = Vec::with_capacity(bounds.len() - 1);
                for (i, w) in bounds.windows(2).enumerate() {
                    let (from, to) = (w[0], w[1]);
                    // multisplit: the overlap goes in front of the first segment; multidisorder: in
                    // front of the second one, and only if it is shorter than its start (zapret)
                    let ovl = if disorder { i == 1 && rule.seqovl > 0 && rule.seqovl < from } else { i == 0 && rule.seqovl > 0 };
                    let mut data = Vec::new();
                    let mut seq = t.seq.wrapping_add(from as u32);
                    if ovl {
                        seq = seq.wrapping_sub(rule.seqovl as u32);
                        data.extend(fill(&rule.seqovl_pattern, rule.seqovl));
                    }
                    data.extend_from_slice(&payload[from..to]);
                    let mut b = Vec::new();
                    build(orig, t, seq, &data, real, next_id(), &mut b);
                    segs.push(b);
                }
                if disorder {
                    segs.reverse();
                }
                out.extend(segs);
                return (out, false);
            }
        }
        Split::FakedSplit | Split::FakedDisorder if n >= 2 => {
            let sp = pick_split_pos(rule, payload, hello);
            if sp > 0 {
                let pat = fill(&rule.fs_pattern, n);
                let order = rule.fs_order & 3;
                let rep = rule.fake_repeats;
                let ovl = |data: &[u8]| -> Vec<u8> {
                    let mut v = fill(&rule.seqovl_pattern, rule.seqovl);
                    v.extend_from_slice(data);
                    v
                };
                if rule.split == Split::FakedSplit {
                    if order == 0 {
                        seg(&mut out, t.seq, &pat[..sp], fooling, rep, next_id());
                    }
                    if rule.seqovl > 0 {
                        seg(&mut out, t.seq.wrapping_sub(rule.seqovl as u32), &ovl(&payload[..sp]), real, 1, next_id());
                    } else {
                        seg(&mut out, t.seq, &payload[..sp], real, 1, next_id());
                    }
                    if order <= 1 {
                        seg(&mut out, t.seq, &pat[..sp], fooling, rep, next_id());
                    }
                    let s2 = t.seq.wrapping_add(sp as u32);
                    seg(&mut out, s2, &pat[sp..], fooling, rep, next_id());
                    seg(&mut out, s2, &payload[sp..], real, 1, next_id());
                    if order <= 2 {
                        seg(&mut out, s2, &pat[sp..], fooling, rep, next_id());
                    }
                } else {
                    let s2 = t.seq.wrapping_add(sp as u32);
                    let use_ovl = rule.seqovl > 0 && rule.seqovl < sp;
                    if order == 0 {
                        seg(&mut out, s2, &pat[sp..], fooling, rep, next_id());
                    }
                    if use_ovl {
                        seg(&mut out, s2.wrapping_sub(rule.seqovl as u32), &ovl(&payload[sp..]), real, 1, next_id());
                    } else {
                        seg(&mut out, s2, &payload[sp..], real, 1, next_id());
                    }
                    if order <= 1 {
                        seg(&mut out, s2, &pat[sp..], fooling, rep, next_id());
                    }
                    seg(&mut out, t.seq, &pat[..sp], fooling, rep, next_id());
                    seg(&mut out, t.seq, &payload[..sp], real, 1, next_id());
                    if order <= 2 {
                        seg(&mut out, t.seq, &pat[..sp], fooling, rep, next_id());
                    }
                }
                return (out, false);
            }
        }
        Split::HostFakeSplit => {
            if let Some((o, hn)) = hello.and_then(|h| h.host) {
                let (host, end) = (o, o + hn);
                if host > 0 && end < n && hn > 0 {
                    let fake_host = fake_host(rule.hfs_host.as_deref(), hn, &mut (t.seq ^ 0x9E37_79B9 | 1));
                    let rep = rule.fake_repeats;
                    let at = |p: usize| t.seq.wrapping_add(p as u32);
                    seg(&mut out, t.seq, &payload[..host], real, 1, next_id());
                    seg(&mut out, at(host), &fake_host, fooling, rep, next_id());
                    if rule.hfs_order == 1 {
                        seg(&mut out, at(end), &payload[end..], real, 1, next_id());
                    }
                    seg(&mut out, at(host), &payload[host..end], real, 1, next_id());
                    if rule.hfs_order == 0 {
                        seg(&mut out, at(host), &fake_host, fooling, rep, next_id());
                        seg(&mut out, at(end), &payload[end..], real, 1, next_id());
                    }
                    return (out, false);
                }
            }
        }
        _ => {}
    }
    (out, true)
}

/// Cuts every TCP packet in `out` whose payload is longer than `mss` into consecutive packets of
/// at most `mss` bytes (same flags, options, TTL, fooling and window; sequence numbers continue,
/// the IPv4 ID moves on). A ClientHello that the OS sent in several segments is desynchronised as
/// one message, so a part of it (everything after a split position, say) can be larger than one
/// segment; an injected packet above the path MTU would be fragmented or dropped.
pub fn chunk_to_mss(out: Vec<Vec<u8>>, mss: usize) -> Vec<Vec<u8>> {
    let mut res = Vec::with_capacity(out.len() + 2);
    for p in out {
        let Some(t) = parse_tcp(&p) else {
            res.push(p);
            continue;
        };
        let n = t.end - t.payload_off;
        if mss == 0 || n <= mss {
            res.push(p);
            continue;
        }
        let id0 = if t.v6 { 0 } else { u16::from_be_bytes([p[4], p[5]]) };
        let (mut off, mut k) = (0usize, 0u16);
        while off < n {
            let e = (off + mss).min(n);
            let mut b = Vec::with_capacity(t.payload_off + mss);
            let id = if id0 == 0 { 0 } else { id0.wrapping_add(k) };
            build(&p, &t, t.seq.wrapping_add(off as u32), &p[t.payload_off + off..t.payload_off + e], Fool::default(), id, &mut b);
            res.push(b);
            off = e;
            k = k.wrapping_add(1);
        }
    }
    res
}

/// The made-up host name of `hostfakesplit`, `host_size` bytes long (zapret `desync.c`).
fn fake_host(mod_host: Option<&str>, host_size: usize, rng: &mut u32) -> Vec<u8> {
    let next = |r: &mut u32| {
        let mut x = *r | 1;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        *r = x;
        (x >> 11) as usize
    };
    let az = |r: &mut u32| b'a' + (next(r) % 26) as u8;
    let az09 = |r: &mut u32| {
        let k = next(r) % 36;
        if k < 26 { b'a' + k as u8 } else { b'0' + (k - 26) as u8 }
    };
    let mut f = vec![0u8; host_size];
    match mod_host {
        Some(h) if host_size <= h.len() => f.copy_from_slice(&h.as_bytes()[h.len() - host_size..]),
        Some(h) => {
            let mut sz = host_size - h.len();
            f[sz..].copy_from_slice(h.as_bytes());
            sz -= 1;
            f[sz] = b'.';
            if sz > 0 {
                f[0] = az(rng);
                sz -= 1;
            }
            for i in 0..sz {
                f[1 + i] = az09(rng);
            }
        }
        None => {
            f[0] = az(rng);
            for i in 1..host_size {
                f[i] = az09(rng);
            }
            if host_size >= 7 {
                f[host_size - 4] = b'.';
                let tld = [b"com", b"org", b"net", b"edu", b"gov", b"biz"][next(rng) % 6];
                f[host_size - 3..].copy_from_slice(tld);
            }
        }
    }
    f
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::tls::tests::hello;
    use crate::tls::{parse, Pos};

    pub fn mk4(seq: u32, ack: u32, payload: &[u8]) -> Vec<u8> {
        let opts = [1, 1, 8, 10, 0, 0, 0x10, 0, 0, 0, 0, 5]; // NOP NOP TS(val=0x1000)
        let tcp_len = 20 + opts.len() + payload.len();
        let mut p = vec![0x45, 0, 0, 0, 0x12, 0x34, 0x40, 0, 64, 6, 0, 0, 10, 0, 0, 2, 104, 16, 1, 1];
        p[2..4].copy_from_slice(&((20 + tcp_len) as u16).to_be_bytes());
        p.extend_from_slice(&40000u16.to_be_bytes());
        p.extend_from_slice(&443u16.to_be_bytes());
        p.extend_from_slice(&seq.to_be_bytes());
        p.extend_from_slice(&ack.to_be_bytes());
        p.push(((20 + opts.len()) as u8 / 4) << 4);
        p.push(0x18); // PSH|ACK
        p.extend_from_slice(&[0x20, 0, 0, 0, 0, 0]);
        p.extend_from_slice(&opts);
        p.extend_from_slice(payload);
        p
    }

    fn mk6(seq: u32, payload: &[u8]) -> Vec<u8> {
        let tcp_len = 20 + payload.len();
        let mut p = vec![0x60, 1, 2, 3];
        p.extend_from_slice(&(tcp_len as u16).to_be_bytes());
        p.extend_from_slice(&[6, 60]);
        p.extend_from_slice(&[0x20, 1, 0xdb, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        p.extend_from_slice(&[0x26, 6, 0x47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 1]);
        p.extend_from_slice(&[0x9c, 0x40, 1, 0xbb]);
        p.extend_from_slice(&seq.to_be_bytes());
        p.extend_from_slice(&[0, 0, 0, 9, 0x50, 0x18, 0x20, 0, 0, 0, 0, 0]);
        p.extend_from_slice(payload);
        p
    }

    fn checksum_ok(p: &[u8]) -> bool {
        let t = parse_tcp(p).unwrap();
        let tcp = &p[t.ip_len..t.end];
        let pseudo = if t.v6 {
            csum_add(csum_add(0, &t.src), &t.dst) + tcp.len() as u32 + 6
        } else {
            csum_add(csum_add(0, &t.src[..4]), &t.dst[..4]) + 6 + tcp.len() as u32
        };
        let ip_ok = t.v6 || csum_fold(csum_add(0, &p[..t.ip_len])) == 0;
        ip_ok && csum_fold(csum_add(pseudo, tcp)) == 0
    }

    fn rule(split: Split, pos: &[&str]) -> TcpRule {
        TcpRule { split, positions: pos.iter().map(|s| Pos::parse(s).unwrap()).collect(), ..Default::default() }
    }

    fn payload_of(p: &[u8]) -> (u32, Vec<u8>) {
        let t = parse_tcp(p).unwrap();
        (t.seq, p[t.payload_off..t.end].to_vec())
    }

    #[test]
    fn parse_and_rebuild_roundtrip_has_valid_checksums() {
        let ch = hello(Some("www.example.com"));
        for orig in [mk4(1000, 77, &ch), mk6(1000, &ch)] {
            let t = parse_tcp(&orig).unwrap();
            assert_eq!((t.sport, t.dport, t.seq), (40000, 443, 1000));
            let mut b = Vec::new();
            build(&orig, &t, t.seq, &ch, Fool::default(), 9, &mut b);
            assert!(checksum_ok(&b));
            assert_eq!(&b[b.len() - ch.len()..], &ch[..]);
        }
    }

    #[test]
    fn multisplit_reassembles_in_order_with_contiguous_seq() {
        let ch = hello(Some("www.example.com"));
        let orig = mk4(5000, 1, &ch);
        let t = parse_tcp(&orig).unwrap();
        let h = parse(&ch);
        let out = desync(&rule(Split::Multisplit, &["1", "midsld"]), &orig, &t, h.as_ref(), 100);
        assert_eq!(out.len(), 3);
        assert!(out.iter().all(|p| checksum_ok(p)));
        let mut joined = Vec::new();
        let mut expect_seq = 5000;
        for p in &out {
            let (s, d) = payload_of(p);
            assert_eq!(s, expect_seq);
            expect_seq += d.len() as u32;
            joined.extend(d);
        }
        assert_eq!(joined, ch);
        assert_eq!(payload_of(&out[0]).1.len(), 1);
    }

    #[test]
    fn multidisorder_sends_the_same_segments_backwards() {
        let ch = hello(Some("www.example.com"));
        let orig = mk4(5000, 1, &ch);
        let t = parse_tcp(&orig).unwrap();
        let h = parse(&ch);
        let fwd = desync(&rule(Split::Multisplit, &["1", "midsld"]), &orig, &t, h.as_ref(), 7);
        let rev = desync(&rule(Split::Multidisorder, &["1", "midsld"]), &orig, &t, h.as_ref(), 7);
        let seqs = |v: &[Vec<u8>]| v.iter().map(|p| payload_of(p).0).collect::<Vec<_>>();
        let mut r = seqs(&rev);
        r.reverse();
        assert_eq!(r, seqs(&fwd));
    }

    #[test]
    fn seqovl_prepends_pattern_before_the_stream_start() {
        let ch = hello(Some("www.example.com"));
        let orig = mk4(5000, 1, &ch);
        let t = parse_tcp(&orig).unwrap();
        let mut r = rule(Split::Multisplit, &["2"]);
        r.seqovl = 10;
        r.seqovl_pattern = vec![0xAA, 0xBB, 0xCC];
        let out = desync(&r, &orig, &t, parse(&ch).as_ref(), 1);
        let (s0, d0) = payload_of(&out[0]);
        assert_eq!(s0, 4990);
        assert_eq!(d0.len(), 12);
        assert_eq!(&d0[..4], &[0xAA, 0xBB, 0xCC, 0xAA]);
        assert_eq!(&d0[10..], &ch[..2]);
        assert_eq!(payload_of(&out[1]).0, 5002);
        assert!(out.iter().all(|p| checksum_ok(p)));
    }

    #[test]
    fn fake_goes_first_with_same_seq_and_is_fooled() {
        let ch = hello(Some("www.example.com"));
        let fake = hello(Some("www.google.com"));
        let orig = mk4(5000, 900_000, &ch);
        let t = parse_tcp(&orig).unwrap();
        let r = TcpRule {
            fake: Some(fake.clone()),
            fake_repeats: 2,
            fool: Fool { badseq: true, ts: true, md5sig: true, ttl: Some(3), ..Default::default() },
            ..Default::default()
        };
        let out = desync(&r, &orig, &t, parse(&ch).as_ref(), 1);
        assert_eq!(out.len(), 3);
        assert_eq!(out[2], orig);
        let f = parse_tcp(&out[0]).unwrap();
        assert_eq!(f.seq, 5000u32.wrapping_add(BADSEQ_INC as u32));
        assert_eq!(f.ack, 900_000u32.wrapping_add(BADSEQ_ACK_INC as u32));
        assert_eq!(f.ttl, 3);
        assert_eq!(&out[0][f.payload_off..f.end], &fake[..]);
        assert!(checksum_ok(&out[0]));
        let o = &out[0][f.ip_len + 20..f.payload_off];
        assert_eq!(o.len() % 4, 0);
        assert_eq!(&o[2..4], &[8, 10]);
        assert_eq!(u32::from_be_bytes([o[4], o[5], o[6], o[7]]), 0x1000u32.wrapping_add(TS_INC as u32));
        assert_eq!(&o[12..14], &[19, 18]);
    }

    #[test]
    fn badsum_and_plain_fake_without_ack_flag() {
        let ch = hello(Some("a.example.com"));
        let orig = mk4(1, 2, &ch);
        let t = parse_tcp(&orig).unwrap();
        let r = TcpRule { fake: Some(ch.clone()), fool: Fool { badsum: true, ..Default::default() }, ..Default::default() };
        let out = desync(&r, &orig, &t, None, 1);
        assert!(!checksum_ok(&out[0]));
        let mut good = Vec::new();
        build(&orig, &t, t.seq, &ch, Fool::default(), 1, &mut good);
        assert!(checksum_ok(&good), "same packet without badsum is valid");
        assert_eq!(out[1], orig, "the original follows untouched");
    }

    #[test]
    fn unresolvable_positions_pass_the_original_whole() {
        let ch = hello(None);
        let orig = mk4(1, 2, &ch);
        let t = parse_tcp(&orig).unwrap();
        let out = desync(&rule(Split::Multisplit, &["method+2", "midsld", "sniext+1"]), &orig, &t, parse(&ch).as_ref(), 1);
        assert_eq!(out, vec![orig]);
    }

    #[test]
    fn ipv6_split_has_valid_checksums() {
        let ch = hello(Some("www.example.com"));
        let orig = mk6(777, &ch);
        let t = parse_tcp(&orig).unwrap();
        let out = desync(&rule(Split::Multisplit, &["1", "midsld"]), &orig, &t, parse(&ch).as_ref(), 0);
        assert_eq!(out.len(), 3);
        assert!(out.iter().all(|p| checksum_ok(p)));
        let total: usize = out.iter().map(|p| payload_of(p).1.len()).sum();
        assert_eq!(total, ch.len());
    }

    #[test]
    fn garbage_and_trailing_padding_do_not_panic() {
        assert!(parse_tcp(&[]).is_none());
        assert!(parse_tcp(&[0x45; 10]).is_none());
        let ch = hello(Some("x.example.com"));
        let mut orig = mk4(1, 2, &ch);
        let real = orig.len();
        orig.extend_from_slice(&[0; 6]); // Ethernet padding
        let t = parse_tcp(&orig).unwrap();
        assert_eq!(t.end, real);
    }

    fn plan_rule(split: Split, pos: &[&str]) -> TcpRule {
        TcpRule { split, positions: pos.iter().map(|s| Pos::parse(s).unwrap()).collect(), fake_repeats: 2, fool: Fool { ts: true, ..Default::default() }, ..Default::default() }
    }

    fn describe(out: &[Vec<u8>], base: u32) -> Vec<(u32, usize, bool)> {
        // (seq offset, payload length, looks like a fooled fake i.e. has no valid-looking ts)
        out.iter()
            .map(|p| {
                let t = parse_tcp(p).unwrap();
                (t.seq.wrapping_sub(base), t.end - t.payload_off, p[t.ip_len + 20..t.payload_off].len() > 0 && p[t.ip_len + 20 + 4..t.ip_len + 20 + 8] != [0, 0, 0x10, 0])
            })
            .collect()
    }

    #[test]
    fn fakedsplit_interleaves_fake_halves_around_the_real_ones() {
        let ch = hello(Some("www.example.com"));
        let orig = mk4(1000, 1, &ch);
        let t = parse_tcp(&orig).unwrap();
        let mut r = plan_rule(Split::FakedSplit, &["1"]);
        r.fs_pattern = vec![0xEE];
        let out = desync(&r, &orig, &t, parse(&ch).as_ref(), 1);
        let n = ch.len();
        // order 0, 2 repeats: F1 F1 R1 F1 F1 F2 F2 R2 F2 F2
        let d = describe(&out, 1000);
        let expect: Vec<(u32, usize, bool)> = vec![(0, 1, true), (0, 1, true), (0, 1, false), (0, 1, true), (0, 1, true), (1, n - 1, true), (1, n - 1, true), (1, n - 1, false), (1, n - 1, true), (1, n - 1, true)];
        assert_eq!(d, expect);
        assert_eq!(&out[0][parse_tcp(&out[0]).unwrap().payload_off..parse_tcp(&out[0]).unwrap().end], &[0xEE]);
        assert!(out.iter().all(|p| checksum_ok(p)));
        // the real halves reassemble to the original payload
        let real: Vec<_> = out.iter().filter(|p| payload_of(p).1 != vec![0xEE; payload_of(p).1.len()]).map(|p| payload_of(p)).collect();
        assert_eq!(real.iter().map(|(_, d)| d.len()).sum::<usize>(), n);
    }

    #[test]
    fn fakeddisorder_sends_the_second_half_first() {
        let ch = hello(Some("www.example.com"));
        let orig = mk4(1000, 1, &ch);
        let t = parse_tcp(&orig).unwrap();
        let out = desync(&plan_rule(Split::FakedDisorder, &["1", "midsld"]), &orig, &t, parse(&ch).as_ref(), 1);
        let h = parse(&ch).unwrap();
        let sp = Pos::parse("midsld").unwrap().resolve(&ch, Some(&h)).unwrap(); // non-absolute marker wins over "1"
        let n = ch.len();
        let d: Vec<_> = describe(&out, 1000).into_iter().map(|(a, b, _)| (a as usize, b)).collect();
        // F2 F2 R2 F2 F2 F1 F1 R1 F1 F1
        let expect = vec![(sp, n - sp), (sp, n - sp), (sp, n - sp), (sp, n - sp), (sp, n - sp), (0, sp), (0, sp), (0, sp), (0, sp), (0, sp)];
        assert_eq!(d, expect);
        assert_eq!(payload_of(&out[2]).1, ch[sp..].to_vec(), "the real second half");
        assert_eq!(payload_of(&out[7]).1, ch[..sp].to_vec(), "the real first half");
    }

    #[test]
    fn multidisorder_puts_the_overlap_on_the_second_segment() {
        let ch = hello(Some("www.example.com"));
        let orig = mk4(5000, 1, &ch);
        let t = parse_tcp(&orig).unwrap();
        let mut r = rule(Split::Multidisorder, &["10", "20"]);
        r.seqovl = 4;
        r.seqovl_pattern = vec![0xAA];
        let out = desync(&r, &orig, &t, parse(&ch).as_ref(), 1);
        assert_eq!(out.len(), 3);
        // sent backwards: [20..], [10..20 with overlap], [0..10]
        assert_eq!(payload_of(&out[0]), (5020, ch[20..].to_vec()));
        let (s, d) = payload_of(&out[1]);
        assert_eq!((s, d.len()), (5010 - 4, 4 + 10));
        assert_eq!(&d[..4], &[0xAA; 4]);
        assert_eq!(payload_of(&out[2]), (5000, ch[..10].to_vec()));
        // an overlap that reaches back past the segment start is cancelled
        r.seqovl = 10;
        let out = desync(&r, &orig, &t, parse(&ch).as_ref(), 1);
        assert_eq!(payload_of(&out[1]), (5010, ch[10..20].to_vec()));
    }

    #[test]
    fn hostfakesplit_hides_the_real_host_between_a_fake_one() {
        let ch = hello(Some("www.example.com"));
        let orig = mk4(2000, 1, &ch);
        let t = parse_tcp(&orig).unwrap();
        let h = parse(&ch).unwrap();
        let (o, n) = h.host.unwrap();
        let mut r = plan_rule(Split::HostFakeSplit, &[]);
        r.hfs_host = Some("ya.ru".into());
        let out = desync(&r, &orig, &t, Some(&h), 1);
        // before_host, fake host x2, real host, fake host x2, after_host
        assert_eq!(out.len(), 1 + 2 + 1 + 2 + 1);
        assert_eq!(payload_of(&out[0]), (2000, ch[..o].to_vec()));
        let (fs, fd) = payload_of(&out[1]);
        assert_eq!((fs, fd.len()), (2000 + o as u32, n));
        assert!(fd.ends_with(b".ya.ru") || fd.ends_with(b"ya.ru"), "{:?}", String::from_utf8_lossy(&fd));
        assert_eq!(payload_of(&out[3]), (2000 + o as u32, ch[o..o + n].to_vec()));
        assert_eq!(payload_of(&out[6]), (2000 + (o + n) as u32, ch[o + n..].to_vec()));
        assert!(out.iter().all(|p| checksum_ok(p)));
        // altorder=1: the tail goes out before the real host
        r.hfs_order = 1;
        let out = desync(&r, &orig, &t, Some(&h), 1);
        assert_eq!(out.len(), 1 + 2 + 1 + 1);
        assert_eq!(payload_of(&out[3]).0, 2000 + (o + n) as u32);
        assert_eq!(payload_of(&out[4]), (2000 + o as u32, ch[o..o + n].to_vec()));
        // no SNI: nothing to hide, the packet goes out whole
        let bare = hello(None);
        let p2 = mk4(1, 1, &bare);
        let t2 = parse_tcp(&p2).unwrap();
        assert_eq!(desync(&r, &p2, &t2, parse(&bare).as_ref(), 1), vec![p2]);
    }

    #[test]
    fn fake_host_shapes_follow_zaprets_rules() {
        let mut rng = 77u32;
        assert_eq!(fake_host(Some("google.com"), 7, &mut rng), b"gle.com".to_vec());
        assert_eq!(fake_host(Some("google.com"), 10, &mut rng), b"google.com".to_vec());
        let f = fake_host(Some("google.com"), 18, &mut rng);
        assert!(f.ends_with(b".google.com") && f.len() == 18);
        let r = fake_host(None, 15, &mut rng);
        assert_eq!((r.len(), r[11]), (15, b'.'));
        assert!(r[0].is_ascii_lowercase());
    }
}
