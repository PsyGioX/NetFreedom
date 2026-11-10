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

//! TLS ClientHello parsing for the native engine: where the SNI is and where the split markers
//! (`host`, `midsld`, `sniext`, ...) fall. Pure functions over a byte slice, no allocation.

/// Offsets inside the TCP payload (a TLS record).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hello {
    /// (offset, length) of the host name inside the server_name extension.
    pub host: Option<(usize, usize)>,
    /// Offset of the *data* of the server_name extension (just after its 4-byte header).
    pub sni_ext: Option<usize>,
    /// Offset of the 2-byte "extensions length" field (TLS only; 0 for HTTP).
    pub ext_len_off: usize,
    /// Offset of the HTTP method (always 0); `None` for TLS, so `method+N` markers are skipped.
    pub method: Option<usize>,
}

pub fn is_client_hello(p: &[u8]) -> bool {
    p.len() >= 6 && p[0] == 0x16 && p[1] == 0x03 && p[2] <= 0x04 && p[5] == 0x01
}

/// Size of the whole TLS record (header included) that starts with this ClientHello, as the
/// record header announces it. Larger than `p.len()` when the hello continues in the next TCP
/// segment(s): the operating system cuts a hello of more than one MSS (post-quantum key shares
/// make every modern browser's hello about 1.5 KB) and the SNI may sit in the part not seen yet.
pub fn record_total(p: &[u8]) -> Option<usize> {
    if !is_client_hello(p) {
        return None;
    }
    Some(5 + u16::from_be_bytes([p[3], p[4]]) as usize)
}

fn u16_at(p: &[u8], o: usize) -> Option<usize> {
    Some(u16::from_be_bytes([*p.get(o)?, *p.get(o + 1)?]) as usize)
}

/// Parses a ClientHello. A hello without SNI is still a hello (`host == None`); a truncated or
/// malformed one is `None`. Only the first segment is looked at: if the extension block does not
/// fit, the SNI is reported as absent rather than guessed.
pub fn parse(p: &[u8]) -> Option<Hello> {
    if !is_client_hello(p) {
        return None;
    }
    let mut o = 5 + 4 + 2 + 32; // record header, handshake header, version, random
    o += 1 + *p.get(o)? as usize; // session id
    o += 2 + u16_at(p, o)?; // cipher suites
    o += 1 + *p.get(o)? as usize; // compression methods
    let ext_total = u16_at(p, o)?;
    let ext_len_off = o;
    o += 2;
    let end = (o + ext_total).min(p.len());
    let mut out = Hello { host: None, sni_ext: None, ext_len_off, method: None };
    while o + 4 <= end {
        let ty = u16_at(p, o)?;
        let len = u16_at(p, o + 2)?;
        let data = o + 4;
        if ty == 0 {
            out.sni_ext = Some(data);
            // list length(2), name type(1), name length(2), name
            if len >= 5 && p.get(data + 2) == Some(&0) {
                let n = u16_at(p, data + 3)?;
                if data + 5 + n <= p.len() && n > 0 {
                    out.host = Some((data + 5, n));
                }
            }
            return Some(out);
        }
        o = data + len;
    }
    Some(out)
}

pub fn sni<'a>(p: &'a [u8], h: &Hello) -> Option<&'a str> {
    let (o, n) = h.host?;
    std::str::from_utf8(p.get(o..o + n)?).ok()
}

/// Split marker as written in `--dpi-desync-split-pos`: `1`, `-3`, `host`, `midsld+1`, `sniext+1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pos {
    pub marker: Marker,
    pub off: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Marker {
    /// Plain number; negative counts from the end of the payload.
    Abs,
    Method,
    Host,
    EndHost,
    Sld,
    EndSld,
    MidSld,
    SniExt,
}

impl Pos {
    pub fn parse(s: &str) -> Result<Pos, String> {
        let s = s.trim();
        if let Ok(n) = s.parse::<i64>() {
            return Ok(Pos { marker: Marker::Abs, off: n });
        }
        let split = s.find(['+', '-']).unwrap_or(s.len());
        let (name, rest) = s.split_at(split);
        let marker = match name {
            "method" => Marker::Method,
            "host" => Marker::Host,
            "endhost" => Marker::EndHost,
            "sld" => Marker::Sld,
            "endsld" => Marker::EndSld,
            "midsld" => Marker::MidSld,
            "sniext" => Marker::SniExt,
            _ => return Err(format!("unknown split marker \"{s}\"")),
        };
        let off = if rest.is_empty() { 0 } else { rest.parse::<i64>().map_err(|_| format!("bad split marker \"{s}\""))? };
        Ok(Pos { marker, off })
    }

    /// Absolute offset in `p`, or `None` when the marker does not exist in this payload
    /// (`method` on TLS, `host` without SNI, ...); such positions are skipped, as zapret does.
    pub fn resolve(&self, p: &[u8], h: Option<&Hello>) -> Option<usize> {
        let base: i64 = match self.marker {
            Marker::Abs => {
                if self.off < 0 {
                    p.len() as i64 + self.off
                } else {
                    self.off
                }
            }
            Marker::Method => h?.method? as i64,
            Marker::SniExt => h?.sni_ext? as i64,
            m => {
                let (o, n) = h?.host?;
                let name = p.get(o..o + n)?;
                // second-level label = the label before the last dot (no public-suffix list)
                let last_dot = name.iter().rposition(|&c| c == b'.');
                let (sld_s, sld_e) = match last_dot {
                    Some(d) => {
                        let s = name[..d].iter().rposition(|&c| c == b'.').map_or(0, |x| x + 1);
                        (s, d)
                    }
                    None => (0, n),
                };
                (o + match m {
                    Marker::Host => 0,
                    Marker::EndHost => n,
                    Marker::Sld => sld_s,
                    Marker::EndSld => sld_e,
                    _ => (sld_s + sld_e) / 2, // MidSld
                }) as i64
            }
        };
        let v = if self.marker == Marker::Abs { base } else { base + self.off };
        (v > 0 && (v as usize) < p.len()).then_some(v as usize)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A minimal but well-formed ClientHello with the given SNI (None: no server_name extension).
    pub fn hello(sni: Option<&str>) -> Vec<u8> {
        hello_sid(sni, &[])
    }

    pub fn hello_sid(sni: Option<&str>, sid: &[u8]) -> Vec<u8> {
        let mut ext = Vec::new();
        if let Some(h) = sni {
            let n = h.len();
            ext.extend_from_slice(&[0, 0]);
            ext.extend_from_slice(&((n + 5) as u16).to_be_bytes());
            ext.extend_from_slice(&((n + 3) as u16).to_be_bytes());
            ext.push(0);
            ext.extend_from_slice(&(n as u16).to_be_bytes());
            ext.extend_from_slice(h.as_bytes());
        }
        ext.extend_from_slice(&[0, 0x0b, 0, 2, 1, 0]); // ec_point_formats
        let mut body = vec![3, 3];
        body.extend_from_slice(&[7u8; 32]);
        body.push(sid.len() as u8);
        body.extend_from_slice(sid);
        body.extend_from_slice(&[0, 4, 0x13, 1, 0x13, 2]);
        body.extend_from_slice(&[1, 0]);
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);
        let mut hs = vec![1, 0, (body.len() >> 8) as u8, body.len() as u8];
        hs.extend_from_slice(&body);
        let mut rec = vec![0x16, 3, 1];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    /// A ClientHello whose server_name extension comes after `pad` bytes of padding extension, so
    /// that a long `pad` pushes the SNI out of the first TCP segment / QUIC Initial.
    pub fn hello_late_sni(sni: &str, pad: usize) -> Vec<u8> {
        let n = sni.len();
        let mut ext = vec![0, 21];
        ext.extend_from_slice(&(pad as u16).to_be_bytes());
        ext.resize(4 + pad, 0);
        ext.extend_from_slice(&[0, 0]);
        ext.extend_from_slice(&((n + 5) as u16).to_be_bytes());
        ext.extend_from_slice(&((n + 3) as u16).to_be_bytes());
        ext.push(0);
        ext.extend_from_slice(&(n as u16).to_be_bytes());
        ext.extend_from_slice(sni.as_bytes());
        let mut body = vec![3, 3];
        body.extend_from_slice(&[7u8; 32]);
        body.push(0);
        body.extend_from_slice(&[0, 4, 0x13, 1, 0x13, 2]);
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

    #[test]
    fn record_total_and_late_sni() {
        let p = hello_late_sni("late.example.org", 1800);
        assert_eq!(record_total(&p), Some(p.len()));
        assert_eq!(parse(&p[..1400]).and_then(|h| h.host), None, "the name is beyond the first 1400 bytes");
        let h = parse(&p).unwrap();
        assert_eq!(sni(&p, &h), Some("late.example.org"));
        assert_eq!(record_total(b"GET / HTTP/1.1"), None);
    }

    #[test]
    fn finds_the_sni() {
        let p = hello(Some("www.example.com"));
        let h = parse(&p).unwrap();
        assert_eq!(sni(&p, &h), Some("www.example.com"));
        let (o, _) = h.host.unwrap();
        assert_eq!(h.sni_ext, Some(o - 5));
    }

    #[test]
    fn hello_without_sni_and_non_hello() {
        let p = hello(None);
        let h = parse(&p).unwrap();
        assert!(h.host.is_none() && h.sni_ext.is_none());
        assert!(parse(b"GET / HTTP/1.1\r\n\r\n").is_none());
        assert!(parse(&p[..40]).is_none(), "truncated hello must not panic or guess");
    }

    #[test]
    fn markers_resolve_like_zapret() {
        let p = hello(Some("www.example.com"));
        let h = parse(&p).unwrap();
        let (o, _) = h.host.unwrap();
        let r = |s: &str| Pos::parse(s).unwrap().resolve(&p, Some(&h));
        assert_eq!(r("1"), Some(1));
        assert_eq!(r("host"), Some(o));
        assert_eq!(r("endhost"), Some(o + 15));
        assert_eq!(r("sld"), Some(o + 4));
        assert_eq!(r("endsld"), Some(o + 11));
        assert_eq!(r("midsld"), Some(o + 7));
        assert_eq!(r("sniext+1"), Some(o - 5 + 1));
        assert_eq!(r("-1"), Some(p.len() - 1));
        assert_eq!(r("method+2"), None);
        assert_eq!(r("0"), None);
        assert_eq!(r("100000"), None);
        assert!(Pos::parse("bogus").is_err());
    }
}
