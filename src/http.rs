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

//! Plain HTTP/1.x requests for the native engine: detection and the `Host:` header position, so
//! that `--hostlist` and the `host` / `method+N` split markers work on port 80 like they do on TLS.

use crate::tls::Hello;

/// zapret's `http_methods` (protocol.c): the method plus the space or slash that follows it.
const METHODS: [&[u8]; 8] = [b"GET /", b"POST /", b"HEAD /", b"OPTIONS ", b"PUT /", b"DELETE /", b"CONNECT ", b"TRACE /"];

pub fn is_request(p: &[u8]) -> bool {
    METHODS.iter().any(|m| p.starts_with(m))
}

fn find_ci(h: &[u8], needle: &[u8]) -> Option<usize> {
    h.windows(needle.len()).position(|w| w.eq_ignore_ascii_case(needle))
}

/// `host` is the value of the Host header without a `:port`. A request whose header is not in
/// this segment still parses (`host == None`).
pub fn parse(p: &[u8]) -> Option<Hello> {
    if !is_request(p) {
        return None;
    }
    let mut out = Hello { host: None, sni_ext: None, ext_len_off: 0, method: Some(0) };
    if let Some(i) = find_ci(p, b"\nhost:") {
        let mut s = i + 6;
        while p.get(s).is_some_and(|c| *c == b' ' || *c == b'\t') {
            s += 1;
        }
        let mut e = s;
        while p.get(e).is_some_and(|c| !matches!(c, b'\r' | b'\n' | b':' | b' ')) {
            e += 1;
        }
        if e > s && p.get(e).is_some() {
            out.host = Some((s, e - s));
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::{sni, Pos};

    #[test]
    fn finds_host_and_resolves_method_markers() {
        let p = b"GET /a HTTP/1.1\r\nUser-Agent: x\r\nhost:  Example.com:8080\r\n\r\n";
        let h = parse(p).unwrap();
        assert_eq!(sni(p, &h), Some("Example.com"));
        assert_eq!(Pos::parse("method+2").unwrap().resolve(p, Some(&h)), Some(2));
        assert_eq!(Pos::parse("method").unwrap().resolve(p, Some(&h)), None, "position 0 is no split");
        let (o, _) = h.host.unwrap();
        assert_eq!(Pos::parse("host").unwrap().resolve(p, Some(&h)), Some(o));
    }

    #[test]
    fn rejects_non_http_and_tolerates_cut_requests() {
        assert!(!is_request(&[0x16, 3, 1]));
        assert!(!is_request(b"PATCH /x HTTP/1.1\r\n"), "zapret does not treat PATCH as HTTP");
        assert!(!is_request(b"GET index"), "needs the slash");
        assert!(parse(b"GET / HTTP/1.1\r\nHos").unwrap().host.is_none());
        assert!(parse(b"GET / HTTP/1.1\r\nHost: abc").unwrap().host.is_none(), "unterminated value is not trusted");
    }
}
