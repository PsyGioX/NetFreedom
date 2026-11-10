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

//! `--dpi-desync-fake-tls-mod` for the native engine, following zapret v72.9 (`nfq/nfqws.c`
//! `onetime_tls_mod_blob`, `nfq/desync.c` `runtime_tls_mod`).
//!
//! Two stages, like in zapret:
//!   * once, when the plan is built ([`prepare`]): `sni=<host>` and `rndsni` rewrite the blob and
//!     fix every length field (record, handshake, extensions, server_name extension, list, name);
//!   * per packet ([`apply`]): `rnd` randomises the Random and the session id (same length),
//!     `dupsid` copies the real session id, but only when both have the same length.
//!
//! `padencap` is not implemented; the plan parser refuses it so the launcher falls back to winws.

use crate::tls;

/// zapret's built-in fake ClientHello (SNI www.microsoft.com, 680 bytes, MIT licence, see
/// THIRD-PARTY-NOTICES.md).
pub const DEFAULT_FAKE_TLS: &[u8] = include_bytes!("data/fake_tls_default.bin");

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TlsMod {
    pub rnd: bool,
    pub dupsid: bool,
    pub rndsni: bool,
    pub sni: Option<String>,
}

impl TlsMod {
    pub fn parse(s: &str) -> Result<TlsMod, String> {
        let mut m = TlsMod::default();
        for item in s.split(',') {
            match item {
                "none" | "" => {}
                "rnd" => m.rnd = true,
                "dupsid" => m.dupsid = true,
                "rndsni" => m.rndsni = true,
                _ => match item.strip_prefix("sni=") {
                    Some(h) if !h.is_empty() && h.len() < 200 && h.is_ascii() => m.sni = Some(h.to_owned()),
                    _ => return Err(format!("unsupported --dpi-desync-fake-tls-mod item \"{item}\"")),
                },
            }
        }
        Ok(m)
    }

    /// What zapret applies to its built-in blob when the rule says nothing: `rnd,rndsni,dupsid`.
    pub fn builtin_default() -> TlsMod {
        TlsMod { rnd: true, dupsid: true, rndsni: true, sni: None }
    }

    /// The part that has to run for every packet.
    pub fn runtime(&self) -> TlsMod {
        TlsMod { rnd: self.rnd, dupsid: self.dupsid, rndsni: false, sni: None }
    }
}

fn adj(f: &mut [u8], off: usize, len: usize, delta: i64) {
    let mut v: i64 = 0;
    for b in &f[off..off + len] {
        v = (v << 8) | *b as i64;
    }
    v += delta;
    for i in 0..len {
        f[off + i] = (v >> (8 * (len - 1 - i))) as u8;
    }
}

pub fn next(rng: &mut u32) -> u8 {
    let mut x = *rng | 1;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *rng = x;
    (x >> 11) as u8
}

/// One-time edits: `sni=` then `rndsni`. Fails when the blob is not a ClientHello with an SNI.
pub fn prepare(blob: &[u8], m: &TlsMod, rng: &mut u32) -> Result<Vec<u8>, String> {
    let mut f = blob.to_vec();
    if m.sni.is_none() && !m.rndsni {
        return Ok(f);
    }
    if f.len() < 44 || f.len() < 44 + f[43] as usize {
        return Err("fake TLS blob is not a ClientHello".into());
    }
    let h = tls::parse(&f).ok_or("fake TLS blob is not a ClientHello")?;
    let (Some((o, n)), Some(_)) = (h.host, h.sni_ext) else {
        return Err("fake TLS blob has no SNI to modify".into());
    };
    let mut n = n;
    if let Some(name) = &m.sni {
        let delta = name.len() as i64 - n as i64;
        f.splice(o..o + n, name.bytes());
        adj(&mut f, 3, 2, delta);
        adj(&mut f, 6, 3, delta);
        adj(&mut f, h.ext_len_off, 2, delta); // all extensions
        adj(&mut f, o - 7, 2, delta); // server_name extension
        adj(&mut f, o - 5, 2, delta); // server_name list
        adj(&mut f, o - 2, 2, delta); // host name
        n = name.len();
    }
    if m.rndsni {
        if n == 0 {
            return Err("rndsni on an empty SNI".into());
        }
        let az = |r: &mut u32| b'a' + next(r) % 26;
        let az09 = |r: &mut u32| {
            let k = next(r) % 36;
            if k < 26 { b'a' + k } else { b'0' + k - 26 }
        };
        f[o] = az(rng);
        if n >= 7 {
            for i in 1..n - 4 {
                f[o + i] = az09(rng);
            }
            f[o + n - 4] = b'.';
            let tld = [b"com", b"org", b"net", b"edu", b"gov", b"biz"][next(rng) as usize % 6];
            f[o + n - 3..o + n].copy_from_slice(tld);
        } else {
            for i in 1..n {
                f[o + i] = az09(rng);
            }
        }
    }
    Ok(f)
}

/// Per-packet part. `fake` is the prepared blob, `real` the ClientHello being replaced. A blob
/// that is not a ClientHello is returned unchanged (some profiles send junk as the "fake TLS").
pub fn apply(fake: &[u8], m: &TlsMod, real: &[u8], rng: &mut u32) -> Vec<u8> {
    let mut f = fake.to_vec();
    if (!m.rnd && !m.dupsid) || f.len() < 44 || f[0] != 0x16 || f.len() < 44 + f[43] as usize {
        return f;
    }
    let sl = f[43] as usize;
    if m.rnd {
        for b in &mut f[11..43] {
            *b = next(rng);
        }
        for b in &mut f[44..44 + sl] {
            *b = next(rng);
        }
    }
    if m.dupsid && real.len() >= 44 && real[43] as usize == sl && real.len() >= 44 + sl {
        f[44..44 + sl].copy_from_slice(&real[44..44 + sl]);
    }
    f
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::tests::{hello, hello_sid};
    use crate::tls::{parse, sni};

    fn consistent(f: &[u8]) {
        assert_eq!(u16::from_be_bytes([f[3], f[4]]) as usize, f.len() - 5, "record length");
        assert_eq!(((f[6] as usize) << 16) | ((f[7] as usize) << 8) | f[8] as usize, f.len() - 9, "handshake length");
        let h = parse(f).expect("still a ClientHello");
        let ext_total = u16::from_be_bytes([f[h.ext_len_off], f[h.ext_len_off + 1]]) as usize;
        assert_eq!(h.ext_len_off + 2 + ext_total, f.len(), "extensions length");
    }

    #[test]
    fn parses_the_profile_spellings() {
        let m = TlsMod::parse("rnd,dupsid,sni=www.google.com").unwrap();
        assert!(m.rnd && m.dupsid && !m.rndsni && m.sni.as_deref() == Some("www.google.com"));
        assert!(TlsMod::parse("rndsni").unwrap().rndsni);
        assert_eq!(TlsMod::parse("none").unwrap(), TlsMod::default());
        assert!(TlsMod::parse("padencap").is_err());
    }

    #[test]
    fn the_builtin_blob_is_zaprets_and_valid() {
        assert_eq!(DEFAULT_FAKE_TLS.len(), 680);
        consistent(DEFAULT_FAKE_TLS);
        let h = parse(DEFAULT_FAKE_TLS).unwrap();
        assert_eq!(sni(DEFAULT_FAKE_TLS, &h), Some("www.microsoft.com"));
        assert_eq!(DEFAULT_FAKE_TLS[43], 32);
    }

    #[test]
    fn sni_replacement_keeps_every_length_consistent() {
        let fake = hello(Some("www.example.com"));
        for name in ["ya.ru", "www.google.com", "a.very.long.host.name.example.org"] {
            let m = TlsMod { sni: Some(name.into()), ..Default::default() };
            let out = prepare(&fake, &m, &mut 7).unwrap();
            consistent(&out);
            assert_eq!(sni(&out, &parse(&out).unwrap()), Some(name));
        }
        assert!(prepare(&hello(None), &TlsMod::parse("rndsni").unwrap(), &mut 1).is_err());
    }

    #[test]
    fn rndsni_keeps_the_length_and_looks_like_a_domain() {
        let m = TlsMod::parse("rndsni").unwrap();
        let out = prepare(DEFAULT_FAKE_TLS, &m, &mut 4242).unwrap();
        assert_eq!(out.len(), 680);
        consistent(&out);
        let s = sni(&out, &parse(&out).unwrap()).unwrap().to_owned();
        assert_eq!(s.len(), 17);
        assert!(s[..13].chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()) && s[..1].chars().all(|c| c.is_ascii_lowercase()));
        assert!(["com", "org", "net", "edu", "gov", "biz"].contains(&&s[14..]) && &s[13..14] == ".");
        assert_ne!(s, "www.microsoft.com");
    }

    #[test]
    fn dupsid_only_copies_a_session_id_of_the_same_length() {
        let m = TlsMod::parse("rnd,dupsid").unwrap();
        let fake = hello_sid(Some("www.example.com"), &[1u8; 32]);
        let real = hello_sid(Some("blocked.test"), &[9u8; 32]);
        let out = apply(&fake, &m, &real, &mut 12345);
        consistent(&out);
        assert_eq!(&out[44..76], &[9u8; 32]);
        assert_ne!(&out[11..43], &fake[11..43]);
        assert_eq!(out.len(), fake.len());
        // different length: zapret keeps the (random) session id of the fake
        let short = hello_sid(Some("a.example.com"), &[3u8; 8]);
        let out = apply(&short, &m, &real, &mut 99);
        assert_eq!(out[43], 8);
        assert_ne!(&out[44..52], &[9u8; 8]);
        assert_ne!(&out[44..52], &[3u8; 8]);
    }

    #[test]
    fn non_hello_blob_and_noop_pass_through() {
        assert_eq!(apply(&[0, 1, 2, 3], &TlsMod::parse("rnd").unwrap(), &[], &mut 1), vec![0, 1, 2, 3]);
        let f = hello(Some("a.b"));
        assert_eq!(apply(&f, &TlsMod::default(), &f, &mut 1), f);
    }

    #[test]
    fn the_shipped_google_blob_survives_the_profile_mod() {
        let blob = include_bytes!("../dist/windows/bin/tls_clienthello_www_google_com.bin");
        let m = TlsMod::parse("rnd,dupsid,sni=ya.ru").unwrap();
        let prepared = prepare(blob, &m, &mut 99).unwrap();
        let real = hello_sid(Some("blocked.test"), &[5u8; 32]);
        let out = apply(&prepared, &m.runtime(), &real, &mut 99);
        consistent(&out);
        assert_eq!(sni(&out, &parse(&out).unwrap()), Some("ya.ru"));
        assert_eq!(out[43], 32);
        assert_eq!(&out[44..76], &[5u8; 32], "the Google blob has a 32-byte session id like Chrome's");
    }
}
