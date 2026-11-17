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

//! Traffic masking: decoy packets that look like a real browser's, not like a tool's.
//!
//! A desync strategy sends fake packets in front of (or between) the real ones. A fake that is
//! the same byte string for every connection is a signature in its own right: one fixed
//! ClientHello with one fixed key share, one fixed ECH blob, one SNI, repeated thousands of times
//! from one address, is exactly what a filter that has seen the tool can learn to recognise
//! (the project is open, so the filter can read it too). With `--nf-mask=<hosts>` the engine
//! builds every fake from scratch instead:
//!
//!   * TLS: a ClientHello shaped like Chrome's (GREASE values, extensions in a fresh random order,
//!     as Chrome has done since version 110) or like Firefox's (fixed order, its own cipher and
//!     group lists), with a new Random, session id, key shares and ECH GREASE blob each time and
//!     the server name taken at random from the host list;
//!   * QUIC: a real, correctly encrypted Initial packet (new connection id, new keys, header
//!     protection applied) whose CRYPTO frame carries such a hello, padded to the size the browser
//!     pads to, so a filter that decrypts Initials reads an ordinary HTTP/3 handshake;
//!   * HTTP: a browser-like GET with a Host from the list and a current-looking User-Agent.
//!
//! What this is not: the real traffic is not touched or tunnelled by it. The real handshake is
//! the browser's own and already looks like web traffic; masking only makes the *decoys* sent
//! around it indistinguishable from other people's. It is a statistical mask, not a proof against
//! a filter that compares the decoy with the connection that follows it.
//!
//! Only the built-in (Windows) engine builds masked fakes. On Linux the `--nf-*` arguments are
//! stripped before nfqws starts (`nftrules::split_args`), and nfqws sends the strategy's static
//! fakes: the strategy still works, it is just not masked.

use crate::crypto::{Aes128, aes128_gcm_encrypt};
use crate::quic_sni::initial_keys;

/// xorshift32, the generator the rest of the engine uses.
pub fn next32(r: &mut u32) -> u32 {
    let mut x = *r | 1;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *r = x;
    x
}

fn below(r: &mut u32, n: usize) -> usize {
    (next32(r) >> 8) as usize % n.max(1)
}

fn fill(r: &mut u32, out: &mut [u8]) {
    for b in out {
        *b = (next32(r) >> 11) as u8;
    }
}

fn random_bytes(r: &mut u32, n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    fill(r, &mut v);
    v
}

/// Which browser a fake imitates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Browser {
    Chrome,
    Firefox,
}

/// The masking settings of one rule: the host names fakes may carry and, optionally, a browser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mask {
    pub hosts: Vec<String>,
    /// `None`: a browser is chosen at random for every fake (a mixed population, like real life).
    pub browser: Option<Browser>,
}

pub const MAX_HOSTS: usize = 64;

fn valid_host(h: &str) -> bool {
    h.len() >= 4
        && h.len() <= 100
        && h.contains('.')
        && h.split('.').all(|l| !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-') && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
}

impl Mask {
    /// `a.example,b.example` plus optionally `chrome`, `firefox` or `mixed` anywhere in the list.
    pub fn parse(s: &str) -> Result<Mask, String> {
        let mut hosts = Vec::new();
        let mut browser = None;
        for item in s.split(',').map(|i| i.trim().to_ascii_lowercase()).filter(|i| !i.is_empty()) {
            match item.as_str() {
                "chrome" => browser = Some(Browser::Chrome),
                "firefox" => browser = Some(Browser::Firefox),
                "mixed" => browser = None,
                _ if valid_host(&item) => hosts.push(item),
                _ => return Err(format!("bad host name \"{item}\" in --nf-mask")),
            }
        }
        if hosts.is_empty() || hosts.len() > MAX_HOSTS {
            return Err(format!("--nf-mask needs 1..{MAX_HOSTS} host names"));
        }
        Ok(Mask { hosts, browser })
    }

    pub fn host(&self, r: &mut u32) -> &str {
        &self.hosts[below(r, self.hosts.len())]
    }

    fn browser(&self, r: &mut u32) -> Browser {
        self.browser.unwrap_or(if below(r, 100) < 65 { Browser::Chrome } else { Browser::Firefox })
    }
}

// ----------------------------------------------------------------------------- ClientHello

fn put16(v: &mut Vec<u8>, x: usize) {
    v.extend_from_slice(&(x as u16).to_be_bytes());
}

fn ext(ty: u16, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + body.len());
    v.extend_from_slice(&ty.to_be_bytes());
    put16(&mut v, body.len());
    v.extend_from_slice(body);
    v
}

/// A 2-byte length followed by the 16-bit items.
fn list16(items: &[u16]) -> Vec<u8> {
    let mut v = Vec::with_capacity(2 + items.len() * 2);
    put16(&mut v, items.len() * 2);
    for i in items {
        v.extend_from_slice(&i.to_be_bytes());
    }
    v
}

/// RFC 8701 GREASE value: 0x0A0A, 0x1A1A, ... 0xFAFA.
fn grease(r: &mut u32) -> u16 {
    below(r, 16) as u16 * 0x1010 + 0x0A0A
}

fn server_name(host: &str) -> Vec<u8> {
    let mut b = Vec::with_capacity(5 + host.len());
    put16(&mut b, 3 + host.len());
    b.push(0);
    put16(&mut b, host.len());
    b.extend_from_slice(host.as_bytes());
    ext(0, &b)
}

/// An outer ECH extension with random contents: what browsers send when they have no ECH
/// configuration for the server ("GREASE ECH").
fn ech_grease(r: &mut u32, payload_len: usize) -> Vec<u8> {
    let mut b = vec![0, 0, 1, 0, 1, next32(r) as u8];
    put16(&mut b, 32);
    b.extend(random_bytes(r, 32));
    put16(&mut b, payload_len);
    b.extend(random_bytes(r, payload_len));
    ext(0xfe0d, &b)
}

fn x25519_share(r: &mut u32) -> Vec<u8> {
    let mut v = vec![0x00, 0x1d, 0x00, 0x20];
    v.extend(random_bytes(r, 32));
    v
}

fn alpn(protos: &[&str]) -> Vec<u8> {
    let mut b = Vec::new();
    put16(&mut b, protos.iter().map(|p| 1 + p.len()).sum());
    for p in protos {
        b.push(p.len() as u8);
        b.extend_from_slice(p.as_bytes());
    }
    ext(0x0010, &b)
}

fn varint(v: &mut Vec<u8>, x: u64) {
    match x {
        0..=0x3f => v.push(x as u8),
        0x40..=0x3fff => v.extend_from_slice(&(0x4000 | x as u16).to_be_bytes()),
        0x4000..=0x3fff_ffff => v.extend_from_slice(&(0x8000_0000 | x as u32).to_be_bytes()),
        _ => v.extend_from_slice(&(0xC000_0000_0000_0000 | x).to_be_bytes()),
    }
}

fn tparam(out: &mut Vec<u8>, id: u64, val: &[u8]) {
    varint(out, id);
    varint(out, val.len() as u64);
    out.extend_from_slice(val);
}

fn tparam_int(out: &mut Vec<u8>, id: u64, val: u64) {
    let mut v = Vec::new();
    varint(&mut v, val);
    tparam(out, id, &v);
}

/// `quic_transport_parameters` as quiche (Chrome) and neqo (Firefox) send them, close enough that
/// a filter reading them sees a browser: the usual flow-control limits, a GREASE parameter.
fn quic_params(b: Browser, scid: &[u8], r: &mut u32) -> Vec<u8> {
    let mut p = Vec::new();
    match b {
        Browser::Chrome => {
            tparam_int(&mut p, 0x04, 15_728_640);
            tparam_int(&mut p, 0x05, 6_291_456);
            tparam_int(&mut p, 0x06, 6_291_456);
            tparam_int(&mut p, 0x07, 6_291_456);
            tparam_int(&mut p, 0x08, 100);
            tparam_int(&mut p, 0x09, 103);
            tparam_int(&mut p, 0x01, 30_000);
            tparam_int(&mut p, 0x03, 1472);
            tparam_int(&mut p, 0x0e, 4);
            tparam(&mut p, 0x0f, scid);
            tparam(&mut p, 0x11, &[0, 0, 0, 1, 0, 0, 0, 1]);
        }
        Browser::Firefox => {
            tparam_int(&mut p, 0x01, 30_000);
            tparam_int(&mut p, 0x04, 25_165_824);
            tparam_int(&mut p, 0x05, 12_582_912);
            tparam_int(&mut p, 0x06, 1_048_576);
            tparam_int(&mut p, 0x07, 1_048_576);
            tparam_int(&mut p, 0x08, 16);
            tparam_int(&mut p, 0x09, 16);
            tparam_int(&mut p, 0x0e, 8);
            tparam(&mut p, 0x0f, scid);
        }
    }
    let n = below(r, 4) + 1;
    tparam(&mut p, 27 + 31 * (1 + below(r, 400) as u64), &random_bytes(r, n));
    ext(0x0039, &p)
}

/// Fisher-Yates.
fn shuffle<T>(v: &mut [T], r: &mut u32) {
    for i in (1..v.len()).rev() {
        v.swap(i, below(r, i + 1));
    }
}

/// The handshake message (type 1 and its 3-byte length, no record header) of a ClientHello for
/// `host`. `quic_scid` is `Some` for the hello inside a QUIC Initial: TLS 1.3 only, ALPN h3, no
/// session id, transport parameters, as the browsers' HTTP/3 stacks send it.
pub fn client_hello(b: Browser, host: &str, quic_scid: Option<&[u8]>, r: &mut u32) -> Vec<u8> {
    let quic = quic_scid.is_some();
    let mut random = [0u8; 32];
    fill(r, &mut random);

    let (ciphers, exts): (Vec<u16>, Vec<u8>) = match b {
        Browser::Chrome => {
            let (g_cs, g_grp, g_ver, g_ks) = (grease(r), grease(r), grease(r), grease(r));
            let g1 = grease(r);
            let mut g2 = grease(r);
            if g2 == g1 {
                g2 ^= 0x1010; // Chrome never sends the same GREASE extension type twice
            }
            let mut ciphers = vec![g_cs, 0x1301, 0x1302, 0x1303];
            let mut keyshare = vec![];
            put16(&mut keyshare, 5 + 36);
            keyshare.extend_from_slice(&g_ks.to_be_bytes());
            keyshare.extend_from_slice(&[0, 1, 0]);
            keyshare.extend(x25519_share(r));
            let sigalgs = list16(&[0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]);
            let ech_len = [144, 176, 208, 240][below(r, 4)];
            let ech = ech_grease(r, ech_len);
            let mut mid: Vec<Vec<u8>> = vec![
                server_name(host),
                ext(0x000a, &list16(&[g_grp, 0x001d, 0x0017, 0x0018])),
                ext(0x000d, &sigalgs),
                ext(0x0033, &keyshare),
                ext(0x002d, &[1, 1]),
                ext(0x001b, &[2, 0, 2]),
                ech,
            ];
            if quic {
                mid.push(alpn(&["h3"]));
                mid.push(ext(0x002b, &[4, (g_ver >> 8) as u8, g_ver as u8, 3, 4]));
                mid.push(ext(0x4469, &[0, 3, 2, b'h', b'3']));
                mid.push(quic_params(b, quic_scid.unwrap_or(&[]), r));
            } else {
                ciphers.extend_from_slice(&[0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035]);
                mid.push(ext(0x0017, &[]));
                mid.push(ext(0xff01, &[0]));
                mid.push(ext(0x000b, &[1, 0]));
                mid.push(ext(0x0023, &[]));
                mid.push(alpn(&["h2", "http/1.1"]));
                mid.push(ext(0x0005, &[1, 0, 0, 0, 0]));
                mid.push(ext(0x0012, &[]));
                mid.push(ext(0x002b, &[6, (g_ver >> 8) as u8, g_ver as u8, 3, 4, 3, 3]));
                mid.push(ext(0x4469, &[0, 3, 2, b'h', b'2']));
            }
            shuffle(&mut mid, r);
            let mut all = ext(g1, &[]);
            for e in mid {
                all.extend(e);
            }
            all.extend(ext(g2, &[0]));
            (ciphers, all)
        }
        Browser::Firefox => {
            let mut keyshare = vec![];
            let mut p256 = vec![0x00, 0x17, 0x00, 0x41, 0x04];
            p256.extend(random_bytes(r, 64));
            let x = x25519_share(r);
            put16(&mut keyshare, x.len() + p256.len());
            keyshare.extend(x);
            keyshare.extend(p256);
            let mut e: Vec<Vec<u8>> = vec![server_name(host)];
            let ciphers;
            if quic {
                ciphers = vec![0x1301, 0x1303, 0x1302];
                e.push(ext(0x000a, &list16(&[0x001d, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101])));
                e.push(ext(0x0033, &keyshare));
                e.push(ext(0x002b, &[4, 3, 4, 3, 3]));
                e.push(ext(0x000d, &list16(&[0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201])));
                e.push(alpn(&["h3"]));
                e.push(ext(0x002d, &[1, 1]));
                e.push(ext(0x001c, &[0x40, 0x01]));
                e.push(quic_params(b, quic_scid.unwrap_or(&[]), r));
            } else {
                ciphers = vec![0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc00a, 0xc009, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035];
                e.push(ext(0x0017, &[]));
                e.push(ext(0xff01, &[0]));
                e.push(ext(0x000a, &list16(&[0x001d, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101])));
                e.push(ext(0x000b, &[1, 0]));
                e.push(ext(0x0023, &[]));
                e.push(alpn(&["h2", "http/1.1"]));
                e.push(ext(0x0005, &[1, 0, 0, 0, 0]));
                e.push(ext(0x0022, &list16(&[0x0403, 0x0503, 0x0603, 0x0203])));
                e.push(ext(0x0012, &[]));
                e.push(ext(0x0033, &keyshare));
                e.push(ext(0x002b, &[4, 3, 4, 3, 3]));
                e.push(ext(0x000d, &list16(&[0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201])));
                e.push(ext(0x002d, &[1, 1]));
                e.push(ext(0x001c, &[0x40, 0x01]));
                e.push(ext(0x001b, &[6, 0, 1, 0, 2, 0, 3]));
            }
            e.push(ech_grease(r, 239));
            (ciphers, e.concat())
        }
    };

    let mut body = vec![3, 3];
    body.extend_from_slice(&random);
    if quic {
        body.push(0);
    } else {
        body.push(32);
        body.extend(random_bytes(r, 32));
    }
    put16(&mut body, ciphers.len() * 2);
    for c in &ciphers {
        body.extend_from_slice(&c.to_be_bytes());
    }
    body.extend_from_slice(&[1, 0]);
    put16(&mut body, exts.len());
    body.extend(exts);

    let mut hs = vec![1, (body.len() >> 16) as u8, (body.len() >> 8) as u8, body.len() as u8];
    hs.extend(body);
    hs
}

// ------------------------------------------------------------------------------- the fakes

/// A masked fake ClientHello (a whole TLS record) for the connection whose real hello is `real`.
/// Like zapret's `dupsid` it reuses the real session id when both have the same length, so the
/// fake and the real hello of one connection agree on it.
pub fn tls_fake(m: &Mask, real: &[u8], r: &mut u32) -> Vec<u8> {
    let b = m.browser(r);
    let host = m.host(r).to_owned();
    let hs = client_hello(b, &host, None, r);
    let mut rec = vec![0x16, 0x03, 0x01];
    put16(&mut rec, hs.len());
    rec.extend(hs);
    if real.len() >= 76 && real[43] == 32 && rec[43] == 32 {
        rec[44..76].copy_from_slice(&real[44..76]);
    }
    rec
}

/// A masked fake QUIC Initial datagram: valid, encrypted with the keys derived from its own random
/// connection id, padded to the size the imitated browser pads to.
pub fn quic_fake(m: &Mask, r: &mut u32) -> Vec<u8> {
    let b = m.browser(r);
    let host = m.host(r).to_owned();
    let mut dcid = [0u8; 8];
    fill(r, &mut dcid);
    let scid = match b {
        Browser::Chrome => Vec::new(),
        Browser::Firefox => random_bytes(r, 8),
    };
    let hs = client_hello(b, &host, Some(&scid), r);
    let target: usize = match b {
        Browser::Chrome => 1250,
        Browser::Firefox => 1357,
    };

    let mut frames = vec![0x06, 0x00];
    varint(&mut frames, hs.len() as u64);
    frames.extend(hs);

    const PN_LEN: usize = 4;
    let mut h = vec![0xC0 | (PN_LEN as u8 - 1), 0, 0, 0, 1, dcid.len() as u8];
    h.extend_from_slice(&dcid);
    h.push(scid.len() as u8);
    h.extend_from_slice(&scid);
    h.push(0); // token length
    let fixed = h.len() + 2 + PN_LEN + 16;
    frames.resize(target.saturating_sub(fixed).max(frames.len()), 0);
    let len = PN_LEN + frames.len() + 16;
    h.extend_from_slice(&(0x4000 | len as u16).to_be_bytes());
    let pn_off = h.len();
    h.extend_from_slice(&[0; PN_LEN]); // packet number 0

    let (key, iv, hp) = initial_keys(1, &dcid);
    let ct = aes128_gcm_encrypt(&key, &iv, &h, &frames);
    let mut d = h;
    d.extend(ct);
    let sample: [u8; 16] = d[pn_off + 4..pn_off + 20].try_into().expect("16 bytes");
    let mask = Aes128::new(&hp).encrypt_block(&sample);
    d[0] ^= mask[0] & 0x0f;
    for i in 0..PN_LEN {
        d[pn_off + i] ^= mask[1 + i];
    }
    d
}

/// A masked fake HTTP request.
pub fn http_fake(m: &Mask, r: &mut u32) -> Vec<u8> {
    let b = m.browser(r);
    let host = m.host(r).to_owned();
    let (ua, lang) = match b {
        Browser::Chrome => (format!("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{}.0.0.0 Safari/537.36", 140 + below(r, 9)), "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7"),
        Browser::Firefox => {
            let v = 136 + below(r, 10);
            (format!("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{v}.0) Gecko/20100101 Firefox/{v}.0"), "ru-RU,ru;q=0.8,en-US;q=0.5,en;q=0.3")
        }
    };
    format!("GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {ua}\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\nAccept-Language: {lang}\r\nAccept-Encoding: gzip, deflate\r\nConnection: keep-alive\r\nUpgrade-Insecure-Requests: 1\r\n\r\n").into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls;
    use std::collections::HashSet;

    struct Parsed {
        sid: Vec<u8>,
        ciphers: Vec<u16>,
        exts: Vec<(u16, Vec<u8>)>,
    }

    /// Walks a handshake message and fails on any length that does not add up.
    fn parse_hs(hs: &[u8]) -> Parsed {
        assert_eq!(hs[0], 1, "ClientHello");
        assert_eq!(((hs[1] as usize) << 16) | ((hs[2] as usize) << 8) | hs[3] as usize, hs.len() - 4, "handshake length");
        assert_eq!(&hs[4..6], &[3, 3]);
        let sl = hs[38] as usize;
        let sid = hs[39..39 + sl].to_vec();
        let mut o = 39 + sl;
        let cl = u16::from_be_bytes([hs[o], hs[o + 1]]) as usize;
        let ciphers = (0..cl / 2).map(|i| u16::from_be_bytes([hs[o + 2 + 2 * i], hs[o + 3 + 2 * i]])).collect();
        o += 2 + cl;
        assert_eq!(&hs[o..o + 2], &[1, 0], "null compression only");
        o += 2;
        let el = u16::from_be_bytes([hs[o], hs[o + 1]]) as usize;
        o += 2;
        assert_eq!(o + el, hs.len(), "extensions run to the end");
        let mut exts = Vec::new();
        while o < hs.len() {
            let t = u16::from_be_bytes([hs[o], hs[o + 1]]);
            let l = u16::from_be_bytes([hs[o + 2], hs[o + 3]]) as usize;
            exts.push((t, hs[o + 4..o + 4 + l].to_vec()));
            o += 4 + l;
        }
        assert_eq!(o, hs.len());
        Parsed { sid, ciphers, exts }
    }

    fn is_grease(v: u16) -> bool {
        v & 0x0f0f == 0x0a0a && v >> 8 == v & 0xff
    }

    fn mask(spec: &str) -> Mask {
        Mask::parse(spec).unwrap()
    }

    #[test]
    fn the_mask_argument_is_parsed_and_validated() {
        let m = Mask::parse("Chrome, ya.ru,vk.com").unwrap();
        assert_eq!(m.browser, Some(Browser::Chrome));
        assert_eq!(m.hosts, ["ya.ru", "vk.com"]);
        assert_eq!(Mask::parse("firefox,mail.ru,mixed").unwrap().browser, None);
        for bad in ["", "chrome", "nodot", "a..ru", "-a.ru", "a-.ru", "a b.ru", "ya.ru/x", "ya.ru:443", "é.ru"] {
            assert!(Mask::parse(bad).is_err(), "{bad:?}");
        }
        assert!(Mask::parse(&(0..65).map(|i| format!("h{i}.ru")).collect::<Vec<_>>().join(",")).is_err());
    }

    #[test]
    fn grease_values_are_valid() {
        let mut r = 1;
        for _ in 0..500 {
            assert!(is_grease(grease(&mut r)));
        }
    }

    #[test]
    fn a_chrome_hello_is_well_formed_and_shaped_like_chromes() {
        let m = mask("chrome,ya.ru,vk.com,mail.ru");
        let mut r = 7;
        for _ in 0..200 {
            let rec = tls_fake(&m, &[], &mut r);
            assert_eq!(&rec[..3], &[0x16, 3, 1]);
            assert_eq!(u16::from_be_bytes([rec[3], rec[4]]) as usize, rec.len() - 5, "record length");
            assert!(rec.len() < 1400, "fits one segment");
            let p = parse_hs(&rec[5..]);
            assert_eq!(p.sid.len(), 32);
            assert!(is_grease(p.ciphers[0]) && p.ciphers[1..4] == [0x1301, 0x1302, 0x1303] && p.ciphers.len() == 16);
            let types: Vec<u16> = p.exts.iter().map(|e| e.0).collect();
            assert_eq!(types.iter().collect::<HashSet<_>>().len(), types.len(), "no extension twice");
            assert!(is_grease(types[0]) && is_grease(*types.last().unwrap()) && types[0] != *types.last().unwrap(), "GREASE first and last");
            for t in [0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010, 0x0005, 0x0012, 0x000d, 0x0033, 0x002d, 0x002b, 0x001b, 0x4469, 0xfe0d] {
                assert!(types.contains(&t), "missing extension {t:#x}");
            }
            // the engine's own parser finds the name, and it is one of ours
            let h = tls::parse(&rec).expect("parsed by the engine");
            assert!(m.hosts.iter().any(|x| Some(x.as_str()) == tls::sni(&rec, &h)));
            // GREASE in groups / versions / key share is the same kind of value
            let get = |t: u16| &p.exts.iter().find(|e| e.0 == t).unwrap().1;
            assert!(is_grease(u16::from_be_bytes([get(0x000a)[2], get(0x000a)[3]])));
            assert!(is_grease(u16::from_be_bytes([get(0x002b)[1], get(0x002b)[2]])));
            let ech = get(0xfe0d).len();
            assert!([42 + 144, 42 + 176, 42 + 208, 42 + 240].contains(&ech), "ECH GREASE length {ech}");
        }
    }

    #[test]
    fn chrome_orders_its_extensions_differently_every_time_but_never_the_ends() {
        let m = mask("chrome,ya.ru");
        let mut orders = HashSet::new();
        let mut r = 99;
        for _ in 0..60 {
            let rec = tls_fake(&m, &[], &mut r);
            let p = parse_hs(&rec[5..]);
            orders.insert(p.exts.iter().map(|e| if is_grease(e.0) { 0 } else { e.0 }).collect::<Vec<_>>());
        }
        assert!(orders.len() > 50, "only {} distinct orders in 60 hellos", orders.len());
    }

    #[test]
    fn nothing_that_should_be_random_repeats() {
        let m = mask("chrome,ya.ru");
        let mut r = 5;
        let a = parse_hs(&tls_fake(&m, &[], &mut r)[5..]);
        let b = parse_hs(&tls_fake(&m, &[], &mut r)[5..]);
        assert_ne!(a.sid, b.sid);
        let ks = |p: &Parsed| p.exts.iter().find(|e| e.0 == 0x0033).unwrap().1.clone();
        let ech = |p: &Parsed| p.exts.iter().find(|e| e.0 == 0xfe0d).unwrap().1.clone();
        assert_ne!(ks(&a), ks(&b), "key share");
        assert_ne!(ech(&a)[6..38], ech(&b)[6..38], "ECH enc");
    }

    #[test]
    fn a_firefox_hello_keeps_firefoxs_fixed_order_and_lists() {
        let m = mask("firefox,ya.ru,vk.com");
        let mut r = 3;
        let mut order = None;
        for _ in 0..50 {
            let rec = tls_fake(&m, &[], &mut r);
            let p = parse_hs(&rec[5..]);
            assert_eq!(p.ciphers.len(), 17);
            assert!(!p.ciphers.iter().any(|c| is_grease(*c)) && !p.exts.iter().any(|e| is_grease(e.0)), "Firefox sends no GREASE");
            let types: Vec<u16> = p.exts.iter().map(|e| e.0).collect();
            assert_eq!(types[0], 0);
            assert_eq!(*order.get_or_insert(types.clone()), types, "fixed order");
            assert_eq!(p.exts.iter().find(|e| e.0 == 0x0033).unwrap().1.len(), 2 + 36 + 69, "x25519 + secp256r1 shares");
            assert_eq!(p.exts.iter().find(|e| e.0 == 0xfe0d).unwrap().1.len(), 42 + 239);
        }
    }

    #[test]
    fn the_server_name_is_drawn_from_the_whole_pool() {
        let m = mask("ya.ru,vk.com,mail.ru,ozon.ru");
        let mut r = 11;
        let mut seen = HashSet::new();
        for _ in 0..80 {
            let rec = tls_fake(&m, &[], &mut r);
            let h = tls::parse(&rec).unwrap();
            seen.insert(tls::sni(&rec, &h).unwrap().to_owned());
        }
        assert_eq!(seen.len(), 4, "{seen:?}");
    }

    #[test]
    fn the_session_id_follows_the_real_hello_when_it_has_the_same_length() {
        let m = mask("chrome,ya.ru");
        let real = tls::tests::hello_sid(Some("blocked.test"), &[0x77; 32]);
        let rec = tls_fake(&m, &real, &mut 1);
        assert_eq!(&rec[44..76], &[0x77; 32]);
        let short = tls::tests::hello_sid(Some("blocked.test"), &[0x77; 8]);
        let rec = tls_fake(&m, &short, &mut 1);
        assert_ne!(&rec[44..76], &[0x77; 32][..]);
    }

    #[test]
    fn a_masked_quic_initial_decrypts_with_the_engines_own_reader_and_names_a_pool_host() {
        use crate::quic_sni::{Crypto, decrypt_initial, host};
        let m = mask("ya.ru,vk.com,gosuslugi.ru");
        let mut r = 21;
        let mut sizes = HashSet::new();
        let mut dcids = HashSet::new();
        for _ in 0..120 {
            let d = quic_fake(&m, &mut r);
            sizes.insert(d.len());
            assert!(crate::quic::is_quic_initial(&d), "recognised as a QUIC Initial");
            let h = host(&d).expect("the engine reads a name out of it");
            assert!(m.hosts.contains(&h), "{h}");
            let frames = decrypt_initial(&d).expect("decrypts");
            let mut c = Crypto::default();
            assert!(c.feed(&frames) && c.complete());
            assert_eq!(c.host().as_deref(), Some(h.as_str()));
            // the CRYPTO payload is a well-formed ClientHello for QUIC: no session id, h3, parameters
            assert_eq!(frames[0], 6);
            assert_eq!(frames[1], 0, "CRYPTO offset 0");
            let n = (((frames[2] & 0x3f) as usize) << 8) | frames[3] as usize;
            let p = parse_hs(&frames[4..4 + n]);
            assert!(p.sid.is_empty());
            assert!(p.exts.iter().any(|e| e.0 == 0x0039) && p.exts.iter().any(|e| e.0 == 0x0010 && e.1 == [0, 3, 2, b'h', b'3']));
            assert!(p.ciphers.iter().filter(|c| !is_grease(**c)).count() == 3);
            dcids.insert(d[6..14].to_vec());
        }
        assert!(sizes.iter().all(|s| *s == 1250 || *s == 1357), "{sizes:?}");
        assert!(dcids.len() > 100, "a new connection id every time");
    }

    #[test]
    fn two_quic_fakes_never_share_bytes_that_a_filter_could_key_on() {
        let m = mask("chrome,ya.ru");
        let mut r = 4;
        let (a, b) = (quic_fake(&m, &mut r), quic_fake(&m, &mut r));
        assert_eq!(a.len(), b.len());
        let same = a.iter().zip(&b).filter(|(x, y)| x == y).count();
        // header bytes (version, lengths) agree; the encrypted body must not
        assert!(same < 40, "{same} identical bytes out of {}", a.len());
    }

    #[test]
    fn the_http_fake_is_a_plausible_request_for_a_pool_host() {
        let m = mask("ya.ru,vk.com");
        let mut r = 8;
        let mut agents = HashSet::new();
        for _ in 0..60 {
            let s = String::from_utf8(http_fake(&m, &mut r)).unwrap();
            assert!(s.starts_with("GET / HTTP/1.1\r\nHost: ") && s.ends_with("\r\n\r\n") && s.len() < 600);
            let host = s.lines().nth(1).unwrap().strip_prefix("Host: ").unwrap();
            assert!(m.hosts.iter().any(|h| h == host));
            agents.insert(s.lines().find(|l| l.starts_with("User-Agent:")).unwrap().to_owned());
        }
        assert!(agents.len() > 5);
        assert!(crate::http::is_request(&http_fake(&m, &mut 1)));
    }

    #[test]
    fn generators_never_panic_and_stay_within_a_packet() {
        let m = mask("a.bc,ya.ru,a-very-long-host-name-for-the-test.example.org");
        for seed in 1..3000u32 {
            let mut r = seed.wrapping_mul(2_654_435_761);
            assert!(tls_fake(&m, &[], &mut r).len() < 1400);
            let q = quic_fake(&m, &mut r);
            assert!(q.len() >= 1200 && q.len() <= 1400);
            assert!(http_fake(&m, &mut r).len() < 700);
        }
    }

    #[test]
    fn building_a_quic_fake_is_cheap() {
        let m = mask("ya.ru,vk.com");
        let t = std::time::Instant::now();
        let mut r = 2;
        for _ in 0..200 {
            std::hint::black_box(quic_fake(&m, &mut r));
        }
        // the engine builds a few per new QUIC flow; even a debug build must stay far from a visible delay
        assert!(t.elapsed().as_millis() < 4000, "{:?} for 200", t.elapsed());
    }
}
