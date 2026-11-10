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

//! QUIC Initial detection, ported 1:1 from zapret v72.9 (`IsQUICInitial`, `QUICDraftVersion`)
//! so the native engine picks exactly the packets winws would treat as QUIC Initials.

const MAX_CID: usize = 20;

pub(crate) fn draft_version(v: u32) -> u8 {
    if v >> 8 == 0x00ff_0000 {
        return v as u8;
    }
    match v {
        0xfaceb001 => 22,
        0xfaceb002 | 0xfaceb00e => 27,
        0x5130_3530 | 0x5430_3530 | 0x5430_3531 => 27,
        _ if v & 0x0F0F_0F0F == 0x0a0a_0a0a => 29,
        0x0000_0001 => 34,
        0x709A_50C4 | 0x6b33_43cf => 100,
        _ => 0,
    }
}

pub(crate) fn is_v2(v: u32) -> bool {
    v == 0x709A_50C4 || v == 0x6b33_43cf
}

/// QUIC variable-length integer at `d[off..]`: (value, encoded size).
pub(crate) fn varint(d: &[u8], off: usize) -> Option<(u64, usize)> {
    let first = *d.get(off)?;
    let size = 1usize << (first >> 6);
    let b = d.get(off..off + size)?;
    let mut v = (b[0] & 0x3F) as u64;
    for x in &b[1..] {
        v = (v << 8) | *x as u64;
    }
    Some((v, size))
}

pub fn is_quic_initial(d: &[u8]) -> bool {
    if d.len() < 256 || d[0] & 0xC0 != 0xC0 {
        return false;
    }
    let ver = u32::from_be_bytes([d[1], d[2], d[3], d[4]]);
    if draft_version(ver) < 11 {
        return false;
    }
    // v1: Initial = 00b, v2: Initial = 01b
    if d[0] & 0x30 != if is_v2(ver) { 0x10 } else { 0x00 } {
        return false;
    }
    let mut off = 5usize;
    let dcid = d[off] as usize;
    if dcid == 0 || dcid > MAX_CID {
        return false;
    }
    off += 1 + dcid;
    let Some(&scid) = d.get(off) else { return false };
    if scid as usize > MAX_CID {
        return false;
    }
    off += 1 + scid as usize;
    let Some((token_len, n)) = varint(d, off) else { return false };
    off += n + token_len as usize;
    if off >= d.len() {
        return false;
    }
    let Some((payload_len, _)) = varint(d, off) else { return false };
    // zapret adds the payload length value itself to the offset (not the varint size)
    off = off.saturating_add(payload_len as usize);
    off <= d.len() && payload_len >= 96
}

#[cfg(test)]
pub fn sample_initial(len: usize) -> Vec<u8> {
    // long header, v1, Initial; DCID 8 bytes; SCID 0; token len 0; payload length 0x4400|..
    let mut p = vec![0xC3, 0, 0, 0, 1, 8];
    p.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    p.push(0); // SCID len
    p.push(0); // token length
    let plen = (len - p.len() - 2) as u16 | 0x4000;
    p.extend_from_slice(&plen.to_be_bytes());
    p.resize(len, 0xAA);
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_v1_initial_and_rejects_the_rest() {
        let ok = sample_initial(1200);
        assert!(is_quic_initial(&ok));
        let mut handshake = ok.clone();
        handshake[0] = 0xE3; // Handshake type
        assert!(!is_quic_initial(&handshake));
        let mut short = ok.clone();
        short[0] = 0x43; // short header
        assert!(!is_quic_initial(&short));
        assert!(!is_quic_initial(&ok[..200])); // too small
        let mut old = ok.clone();
        old[1..5].copy_from_slice(&[0, 0, 0, 7]); // unknown version
        assert!(!is_quic_initial(&old));
        let mut nodcid = ok.clone();
        nodcid[5] = 0;
        assert!(!is_quic_initial(&nodcid));
    }

    #[test]
    fn quic_v2_uses_type_01() {
        let mut p = sample_initial(1200);
        p[1..5].copy_from_slice(&0x6b33_43cfu32.to_be_bytes());
        assert!(!is_quic_initial(&p)); // type 00 is not Initial in v2
        p[0] = 0xD3;
        assert!(is_quic_initial(&p));
    }
}
