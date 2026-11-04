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

//! nftables rules that feed nfqws (Linux). Pure string logic, tested on every OS.
//!
//! The Windows profiles describe capture with winws-only options (`--wf-tcp`, `--wf-udp`,
//! `--wf-raw`). On Linux these are translated into an equivalent nft ruleset, and removed from the
//! nfqws command line (nfqws would reject them).

pub const TABLE: &str = "netfreedom";
/// nfqws marks its own raw packets with this fwmark (`--dpi-desync-fwmark`); the rules skip them.
pub const FWMARK: &str = "0x40000000";
pub const QNUM: u16 = 200;

/// Capture described by a LEAN `--wf-raw` filter: Cloudflare ranges, UDP ports, payload byte test.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Raw {
    pub v4: Vec<(String, String)>,
    pub v6: Vec<(String, String)>,
    pub ports: Vec<u16>,
    /// `udp.Payload[0]>=0xNN`
    pub payload_min: Option<u8>,
}

/// Capture requested by a profile.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Capture {
    pub tcp: Option<String>,
    pub udp: Option<String>,
    pub raw: Option<Raw>,
}

/// Parses the subset of the WinDivert filter language used by the LEAN profiles.
pub fn parse_wfraw(s: &str) -> Result<Raw, String> {
    if s.contains("tcp.") || s.contains("ip.SrcAddr") || s.contains("inbound") {
        return Err("unsupported --wf-raw expression (only outbound UDP destination filters are translated)".into());
    }
    let cleaned = s.replace(['(', ')'], " ");
    let toks: Vec<&str> = cleaned.split_whitespace().collect();
    let mut raw = Raw::default();
    let mut i = 0;
    while i < toks.len() {
        let t = toks[i];
        for (lo_key, hi_key, dst) in [("ip.DstAddr>=", "ip.DstAddr<=", 4), ("ipv6.DstAddr>=", "ipv6.DstAddr<=", 6)] {
            if let Some(lo) = t.strip_prefix(lo_key) {
                let hi = toks
                    .get(i + 1..i + 3)
                    .and_then(|w| (w[0] == "and").then(|| w[1].strip_prefix(hi_key)).flatten())
                    .ok_or_else(|| format!("cannot pair the range starting at {lo}"))?;
                let pair = (lo.to_owned(), hi.to_owned());
                if dst == 4 { raw.v4.push(pair) } else { raw.v6.push(pair) }
                i += 2;
            }
        }
        if let Some(p) = t.strip_prefix("udp.DstPort==") {
            raw.ports.push(p.parse().map_err(|_| format!("bad port {p}"))?);
        } else if let Some(h) = t.strip_prefix("udp.Payload[0]>=0x") {
            raw.payload_min = Some(u8::from_str_radix(h, 16).map_err(|_| format!("bad payload byte {h}"))?);
        }
        i += 1;
    }
    if raw.ports.is_empty() {
        return Err("the --wf-raw filter has no udp.DstPort conditions".into());
    }
    Ok(raw)
}

/// Splits an expanded winws command line into the capture request and the pure nfqws arguments.
pub fn split_args(args: &[String]) -> Result<(Capture, Vec<String>), String> {
    let mut cap = Capture::default();
    let mut rest = Vec::with_capacity(args.len());
    for a in args {
        if let Some(v) = a.strip_prefix("--wf-tcp=") {
            cap.tcp = Some(check_ports(v)?);
        } else if let Some(v) = a.strip_prefix("--wf-udp=") {
            cap.udp = Some(check_ports(v)?);
        } else if let Some(v) = a.strip_prefix("--wf-raw=") {
            cap.raw = Some(parse_wfraw(v)?);
        } else if a.starts_with("--wf-") {
            return Err(format!("unsupported capture option {a}"));
        } else {
            rest.push(a.clone());
        }
    }
    if cap.tcp.is_none() && cap.udp.is_none() && cap.raw.is_none() {
        return Err("the profile defines no capture (--wf-tcp / --wf-udp / --wf-raw)".into());
    }
    Ok((cap, rest))
}

fn check_ports(v: &str) -> Result<String, String> {
    if !v.is_empty() && v.split(',').all(|i| !i.is_empty() && i.chars().all(|c| c.is_ascii_digit() || c == '-')) {
        Ok(v.to_owned())
    } else {
        Err(format!("bad port list \"{v}\""))
    }
}

fn set(items: impl IntoIterator<Item = String>) -> String {
    format!("{{ {} }}", items.into_iter().collect::<Vec<_>>().join(", "))
}

fn ports_set(list: &str) -> String {
    set(list.split(',').map(str::to_owned))
}

/// Builds the nft script. `ct_limit`: only queue the first packets of each connection (needs
/// conntrack accounting). `skip_lo`: never touch loopback (always true outside of tests).
pub fn ruleset(c: &Capture, qnum: u16, ct_limit: bool, skip_lo: bool) -> String {
    let queue = format!("queue flags bypass to {qnum}");
    let ct = if ct_limit { "ct original packets 1-12 " } else { "" };
    let mut r = String::new();
    r.push_str(&format!("table inet {TABLE} {{\n  chain postrouting {{\n"));
    r.push_str("    type filter hook postrouting priority 99; policy accept;\n");
    r.push_str(&format!("    meta mark & {FWMARK} != 0 return\n"));
    if skip_lo {
        r.push_str("    oifname \"lo\" return\n");
    }
    if let Some(t) = &c.tcp {
        r.push_str(&format!("    tcp dport {} {ct}{queue}\n", ports_set(t)));
    }
    if let Some(u) = &c.udp {
        r.push_str(&format!("    udp dport {} {ct}{queue}\n", ports_set(u)));
    }
    if let Some(raw) = &c.raw {
        let ports = set(raw.ports.iter().map(u16::to_string));
        let payload = raw.payload_min.map(|b| format!("@th,64,8 >= 0x{b:02x} ")).unwrap_or_default();
        if !raw.v4.is_empty() {
            let addrs = set(raw.v4.iter().map(|(a, b)| format!("{a}-{b}")));
            r.push_str(&format!("    ip daddr {addrs} udp dport {ports} {payload}{queue}\n"));
        }
        if !raw.v6.is_empty() {
            let addrs = set(raw.v6.iter().map(|(a, b)| format!("{a}-{b}")));
            r.push_str(&format!("    ip6 daddr {addrs} udp dport {ports} {payload}{queue}\n"));
        }
        if raw.v4.is_empty() && raw.v6.is_empty() {
            r.push_str(&format!("    udp dport {ports} {payload}{queue}\n"));
        }
    }
    r.push_str("  }\n}\n");
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::{expand, Vars};
    use crate::profiles::{find, PROFILES, WFRAW};

    fn args_of(name: &str, lean: bool) -> Vec<String> {
        let p = find(name).unwrap();
        let tpl = if lean { p.lean } else { p.classic }.unwrap();
        expand(tpl, &Vars { bin: "/b/", lists: "/l/", wfraw: WFRAW, gf_tcp: "12", gf_udp: "500,1701" })
    }

    #[test]
    fn wfraw_of_warp_lean_is_translated_completely() {
        let raw = parse_wfraw(WFRAW).unwrap();
        assert_eq!(raw.v4, vec![("162.159.0.0".into(), "162.159.255.255".into()), ("188.114.96.0".into(), "188.114.99.255".into())]);
        assert_eq!(raw.v6, vec![("2606:4700::".into(), "2606:4700:ffff:ffff:ffff:ffff:ffff:ffff".into())]);
        assert_eq!(raw.ports, vec![443, 500, 1701, 4443, 4500, 8095, 8443]);
        assert_eq!(raw.payload_min, Some(0xC0));
    }

    #[test]
    fn split_removes_every_winws_only_option() {
        for p in PROFILES {
            for lean in [true, false] {
                let Some(tpl) = (if lean { p.lean } else { p.classic }) else { continue };
                let v = Vars { bin: "/b/", lists: "/l/", wfraw: WFRAW, gf_tcp: "12", gf_udp: "500" };
                let (cap, rest) = split_args(&expand(tpl, &v)).unwrap_or_else(|e| panic!("{} lean={lean}: {e}", p.name));
                assert!(rest.iter().all(|a| !a.starts_with("--wf-")), "{}", p.name);
                assert_eq!(cap.raw.is_some(), lean, "{}", p.name);
            }
        }
    }

    #[test]
    fn classic_ruleset() {
        let (cap, rest) = split_args(&args_of("general", false)).unwrap();
        let r = ruleset(&cap, 200, true, true);
        assert!(r.contains("table inet netfreedom"));
        assert!(r.contains("meta mark & 0x40000000 != 0 return"));
        assert!(r.contains("tcp dport { 80, 443, 2053, 2083, 2087, 2096, 8443, 12 } ct original packets 1-12 queue flags bypass to 200"), "{r}");
        assert!(r.contains("udp dport { 443, 19294-19344, 50000-50100, 500, 1701 } ct original packets 1-12 queue flags bypass to 200"), "{r}");
        assert!(rest.iter().any(|a| a.starts_with("--filter-tcp=")));
    }

    #[test]
    fn lean_ruleset_matches_the_windivert_filter() {
        let (cap, _) = split_args(&args_of("warp", true)).unwrap();
        let r = ruleset(&cap, 200, false, true);
        assert!(r.contains("ip daddr { 162.159.0.0-162.159.255.255, 188.114.96.0-188.114.99.255 } udp dport { 443, 500, 1701, 4443, 4500, 8095, 8443 } @th,64,8 >= 0xc0 queue flags bypass to 200"), "{r}");
        assert!(r.contains("ip6 daddr { 2606:4700::-2606:4700:ffff:ffff:ffff:ffff:ffff:ffff }"), "{r}");
        assert!(!r.contains("ct original"));
        assert!(!ruleset(&cap, 200, false, false).contains("oifname"));
    }

    #[test]
    fn rejects_what_it_cannot_translate() {
        assert!(parse_wfraw("tcp and tcp.DstPort==80").is_err());
        assert!(parse_wfraw("udp and udp.PayloadLength>=1").is_err());
        assert!(split_args(&["--dpi-desync=fake".to_string()]).is_err());
        assert!(split_args(&["--wf-tcp=80;rm".to_string()]).is_err());
    }
}
