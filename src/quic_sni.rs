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

//! Reads the TLS server name out of a QUIC Initial packet, the way zapret does
//! (`QUICDecryptInitial`, `QUICDefragCrypto`, `IsQUICCryptoHello` in `nfq/protocol.c`): derive the
//! Initial keys from the destination connection id, remove header protection, decrypt, collect
//! the CRYPTO frames and parse the ClientHello they carry. Nothing secret is involved: Initial
//! keys are derivable by anyone who sees the packet.

use crate::crypto::{aes128_gcm_decrypt, hkdf_expand, hkdf_extract, Aes128};
use crate::quic::{draft_version, is_v2, varint};
use crate::tls;

const MAX_CID: usize = 20;
/// zapret reassembles into a 1500-byte buffer with a 10-byte prefix; a Chrome hello with the
/// post-quantum key share and ECH is already about that large, so the limit here is wider.
const MAX_CRYPTO: usize = 4096;

fn salt(version: u32) -> [u8; 20] {
    let draft = draft_version(version);
    let max = |m: u8| draft != 0 && draft <= m;
    match version {
        0x5130_3530 => [0x50, 0x45, 0x74, 0xEF, 0xD0, 0x66, 0xFE, 0x2F, 0x9D, 0x94, 0x5C, 0xFC, 0xDB, 0xD3, 0xA7, 0xF0, 0xD3, 0xB5, 0x6B, 0x45],
        0x5430_3530 => [0x7f, 0xf5, 0x79, 0xe5, 0xac, 0xd0, 0x72, 0x91, 0x55, 0x80, 0x30, 0x4c, 0x43, 0xa2, 0x36, 0x7c, 0x60, 0x48, 0x83, 0x10],
        0x5430_3531 => [0x7a, 0x4e, 0xde, 0xf4, 0xe7, 0xcc, 0xee, 0x5f, 0xa4, 0x50, 0x6c, 0x19, 0x12, 0x4f, 0xc8, 0xcc, 0xda, 0x6e, 0x03, 0x3d],
        _ if max(22) => [0x7f, 0xbc, 0xdb, 0x0e, 0x7c, 0x66, 0xbb, 0xe9, 0x19, 0x3a, 0x96, 0xcd, 0x21, 0x51, 0x9e, 0xbd, 0x7a, 0x02, 0x64, 0x4a],
        _ if max(28) => [0xc3, 0xee, 0xf7, 0x12, 0xc7, 0x2e, 0xbb, 0x5a, 0x11, 0xa7, 0xd2, 0x43, 0x2b, 0xb4, 0x63, 0x65, 0xbe, 0xf9, 0xf5, 0x02],
        _ if max(32) => [0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99],
        _ if max(34) => [0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a],
        _ => [0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9],
    }
}

fn expand_label(secret: &[u8], label: &str, n: usize) -> Vec<u8> {
    let full = format!("tls13 {label}");
    let mut info = Vec::new();
    info.extend_from_slice(&(n as u16).to_be_bytes());
    info.push(full.len() as u8);
    info.extend_from_slice(full.as_bytes());
    info.push(0);
    hkdf_expand(secret, &info, n)
}

/// (key, iv, header-protection key) of the client's Initial packets.
pub fn initial_keys(version: u32, dcid: &[u8]) -> ([u8; 16], [u8; 12], [u8; 16]) {
    let secret = hkdf_extract(&salt(version), dcid);
    let client = expand_label(&secret, "client in", 32);
    let pre = if is_v2(version) { "quicv2" } else { "quic" };
    let k = |l: &str, n: usize| expand_label(&client, &format!("{pre} {l}"), n);
    (k("key", 16).try_into().unwrap(), k("iv", 12).try_into().unwrap(), k("hp", 16).try_into().unwrap())
}

/// Decrypts the payload of a client Initial: the frames, or `None` if it is not one we can read.
pub fn decrypt_initial(d: &[u8]) -> Option<Vec<u8>> {
    if d.len() < 7 || d[0] & 0x80 == 0 {
        return None;
    }
    let version = u32::from_be_bytes([d[1], d[2], d[3], d[4]]);
    let dcid_len = d[5] as usize;
    if version == 0 || dcid_len == 0 || dcid_len > MAX_CID || 6 + dcid_len > d.len() {
        return None;
    }
    let (key, mut iv, hp) = initial_keys(version, &d[6..6 + dcid_len]);

    let mut pn = 1 + 4 + 1 + dcid_len;
    pn += 1 + *d.get(pn)? as usize; // source connection id
    let (token_len, n) = varint(d, pn)?;
    pn = pn.checked_add(n)?.checked_add(usize::try_from(token_len).ok()?)?;
    let (payload_len, n) = varint(d, pn)?;
    pn = pn.checked_add(n)?;
    let payload_len = usize::try_from(payload_len).ok()?;
    if payload_len < 20 || pn.checked_add(payload_len)? > d.len() {
        return None;
    }

    // header protection (AES-ECB over a 16-byte sample taken 4 bytes after the packet number start)
    let sample: [u8; 16] = d[pn + 4..pn + 20].try_into().ok()?;
    let mask = Aes128::new(&hp).encrypt_block(&sample);
    let first = d[0] ^ (mask[0] & 0x0f);
    let pn_len = (first & 3) as usize + 1;
    if payload_len < pn_len + 16 {
        return None;
    }
    let mut pkn = 0u64;
    let mut header = d[..pn + pn_len].to_vec();
    header[0] = first;
    for i in 0..pn_len {
        let b = d[pn + i] ^ mask[1 + i];
        header[pn + i] = b;
        pkn = (pkn << 8) | b as u64;
    }
    let tail = u64::from_be_bytes(iv[4..].try_into().ok()?) ^ pkn;
    iv[4..].copy_from_slice(&tail.to_be_bytes());
    aes128_gcm_decrypt(&key, &iv, &header, &d[pn + pn_len..pn + payload_len])
}

/// The CRYPTO data of a client's Initial packets, collected over one or more datagrams. A modern
/// browser's ClientHello (post-quantum key share) does not fit into one 1200-byte Initial, so it
/// travels in two datagrams and the server name may be in either of them (zapret keeps the first
/// datagram back and reads the name once the hello is whole; so does the native engine).
#[derive(Default, Debug)]
pub struct Crypto {
    buf: Vec<u8>,
    ranges: Vec<(usize, usize)>,
}

impl Crypto {
    /// Adds the CRYPTO frames of one decrypted Initial (zapret's `QUICDefragCrypto`). `false` on
    /// any other frame type or a malformed frame; nothing is kept then.
    pub fn feed(&mut self, frames: &[u8]) -> bool {
        let (mut buf, mut ranges) = (self.buf.clone(), self.ranges.clone());
        let mut pos = 0;
        while pos < frames.len() {
            let ft = frames[pos];
            pos += 1;
            if ft > 1 {
                if ft != 6 {
                    return false;
                }
                let Some((off, n)) = varint(frames, pos) else { return false };
                pos += n;
                let Some((len, n)) = varint(frames, pos) else { return false };
                pos += n;
                let (Ok(off), Ok(len)) = (usize::try_from(off), usize::try_from(len)) else { return false };
                if pos.checked_add(len).is_none_or(|e| e > frames.len()) || off.checked_add(len).is_none_or(|e| e > MAX_CRYPTO) || ranges.len() >= 128 {
                    return false;
                }
                if buf.len() < off + len {
                    buf.resize(off + len, 0);
                }
                buf[off..off + len].copy_from_slice(&frames[pos..pos + len]);
                ranges.push((off, len));
                pos += len;
            }
        }
        if ranges.is_empty() {
            return false;
        }
        self.buf = buf;
        self.ranges = ranges;
        true
    }

    /// The hello bytes known from offset 0 on without a gap.
    pub fn prefix(&self) -> &[u8] {
        let mut r = self.ranges.clone();
        r.sort_unstable();
        let mut covered = 0;
        for (o, l) in r {
            if o > covered {
                break;
            }
            covered = covered.max(o + l);
        }
        &self.buf[..covered.min(self.buf.len())]
    }

    /// Does the collected data begin with a ClientHello header (the head is here)?
    pub fn started(&self) -> bool {
        let p = self.prefix();
        p.len() >= 4 && p[0] == 1
    }

    /// Is the whole ClientHello message here (as far as its own length field says)?
    pub fn complete(&self) -> bool {
        let p = self.prefix();
        p.len() >= 4 && p[0] == 1 && p.len() >= 4 + ((p[1] as usize) << 16 | (p[2] as usize) << 8 | p[3] as usize)
    }

    /// The server name, if the part collected so far contains it.
    pub fn host(&self) -> Option<String> {
        let hs = self.prefix();
        if hs.len() < 4 || hs[0] != 1 {
            return None;
        }
        // reuse the TLS parser: it wants a record header in front of the handshake message
        let mut rec = vec![0x16, 3, 1, 0, 0];
        rec.extend_from_slice(hs);
        let h = tls::parse(&rec)?;
        let name = tls::sni(&rec, &h)?;
        (name.is_ascii() && !name.is_empty()).then(|| name.to_owned())
    }
}

/// The server name in a client Initial datagram, if this one carries it. A ClientHello that
/// continues in the next datagram yields a name only when the SNI lies in the part seen here.
pub fn host(datagram: &[u8]) -> Option<String> {
    let mut c = Crypto::default();
    c.feed(&decrypt_initial(datagram)?).then(|| c.host()).flatten()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::crypto::hex;

    /// A client Initial (QUIC v1, 2-byte packet number) carrying `crypto` = (offset, data) CRYPTO
    /// frames, padded to 1200 bytes. Built with the same primitives the engine decrypts with.
    pub fn build_initial(dcid: &[u8], pn: u16, crypto: &[(usize, &[u8])]) -> Vec<u8> {
        use crate::crypto::aes128_gcm_encrypt;
        let mut frames = Vec::new();
        for (off, data) in crypto {
            frames.push(6);
            frames.extend_from_slice(&(0x4000u16 | *off as u16).to_be_bytes());
            frames.extend_from_slice(&(0x4000u16 | data.len() as u16).to_be_bytes());
            frames.extend_from_slice(data);
        }
        let head = 1 + 4 + 1 + dcid.len() + 1 + 1 + 2 + 2; // flags, version, dcid, scid len, token len, length, pn
        frames.resize(1200usize.saturating_sub(head + 16).max(frames.len()), 0);
        let len = 2 + frames.len() + 16;
        let mut h = vec![0xC1, 0, 0, 0, 1, dcid.len() as u8];
        h.extend_from_slice(dcid);
        h.extend_from_slice(&[0, 0]);
        h.extend_from_slice(&(0x4000u16 | len as u16).to_be_bytes());
        let pn_off = h.len();
        h.extend_from_slice(&pn.to_be_bytes());
        let (key, mut iv, hp) = initial_keys(1, dcid);
        let tail = u64::from_be_bytes(iv[4..].try_into().unwrap()) ^ pn as u64;
        iv[4..].copy_from_slice(&tail.to_be_bytes());
        let ct = aes128_gcm_encrypt(&key, &iv, &h, &frames);
        let mut d = h;
        d.extend_from_slice(&ct);
        let sample: [u8; 16] = d[pn_off + 4..pn_off + 20].try_into().unwrap();
        let mask = Aes128::new(&hp).encrypt_block(&sample);
        d[0] ^= mask[0] & 0x0f;
        d[pn_off] ^= mask[1];
        d[pn_off + 1] ^= mask[2];
        d
    }

    #[test]
    fn crypto_collects_a_hello_over_two_datagrams() {
        let rec = crate::tls::tests::hello_late_sni("late.example.org", 1500);
        let hs = &rec[5..];
        let (a, b) = hs.split_at(1000);
        let d1 = build_initial(&[9; 8], 0, &[(0, a)]);
        let d2 = build_initial(&[9; 8], 1, &[(1000, b)]);
        assert_eq!(d1.len(), 1200);
        assert_eq!(host(&d1), None, "the name is in the second datagram");
        let mut c = Crypto::default();
        assert!(c.feed(&decrypt_initial(&d1).unwrap()));
        assert!(c.started() && !c.complete() && c.host().is_none());
        assert!(c.feed(&decrypt_initial(&d2).unwrap()));
        assert!(c.complete());
        assert_eq!(c.host().as_deref(), Some("late.example.org"));
        // the tail alone (no head) is not a started hello
        let mut t = Crypto::default();
        assert!(t.feed(&decrypt_initial(&d2).unwrap()) && !t.started());
    }

    const V1: &[u8] = include_bytes!("data/quic_initial_v1.bin");
    const SPLIT: &[u8] = include_bytes!("data/quic_initial_v1_split.bin");
    const TAIL: &[u8] = include_bytes!("data/quic_initial_v1_tail.bin");
    const V2: &[u8] = include_bytes!("data/quic_initial_v2.bin");

    #[test]
    fn initial_keys_match_rfc_9001_appendix_a1() {
        let (k, iv, hp) = initial_keys(1, &hex("8394c8f03e515708"));
        assert_eq!(k.to_vec(), hex("1f369613dd76d5467730efcbe3b1a22d"));
        assert_eq!(iv.to_vec(), hex("fa044b2f42a3fd3b46fb255c"));
        assert_eq!(hp.to_vec(), hex("9f50449e04a0e810283a1e9933adedd2"));
    }

    #[test]
    fn reads_the_sni_of_a_plain_v1_initial() {
        assert_eq!(host(V1).as_deref(), Some("example.com"));
        assert!(crate::quic::is_quic_initial(V1), "the same packet is an Initial for the detector too");
    }

    #[test]
    fn reassembles_out_of_order_crypto_frames_with_ping_and_padding() {
        assert_eq!(host(SPLIT).as_deref(), Some("www.blocked.test"));
    }

    #[test]
    fn a_hello_whose_head_is_in_another_datagram_has_no_name_here() {
        assert!(decrypt_initial(TAIL).is_some(), "it decrypts fine");
        assert_eq!(host(TAIL), None, "but the CRYPTO data does not start at offset 0");
    }

    #[test]
    fn reads_quic_v2() {
        assert_eq!(host(V2).as_deref(), Some("v2.example.org"));
    }

    #[test]
    fn corrupted_and_foreign_packets_are_rejected_without_panicking() {
        let mut bad = V1.to_vec();
        bad[600] ^= 1; // breaks the GCM tag
        assert_eq!(host(&bad), None);
        for cut in [0usize, 1, 6, 7, 20, 40, 100, 1199] {
            let _ = host(&V1[..cut]);
        }
        assert_eq!(host(&[0x16, 3, 1, 0, 5, 1, 2, 3]), None);
        let mut short_hdr = V1.to_vec();
        short_hdr[0] &= 0x7f; // not a long header
        assert_eq!(host(&short_hdr), None);
        // random bytes behind a plausible long header never panic
        let mut junk = vec![0xC3, 0, 0, 0, 1, 8];
        junk.extend((0..200u32).map(|i| (i * 37 + 11) as u8));
        let _ = host(&junk);
    }
}
