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

//! Capture settings (which ports WinDivert hands to winws) and argument templating.

/// Cloudflare WARP (MASQUE) fallback UDP ports. UDP 443 is always captured by every profile.
pub const WARP_UDP_PORTS: &str = "500,1701,4443,4500,8095,8443";
pub const ALL_PORTS: &str = "1024-65535";
/// A harmless port used to "disable" a protocol in templates that always mention it.
const DUMMY_PORT: &str = "12";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GfMode {
    Disabled,
    Tcp,
    Udp,
    All,
}

impl GfMode {
    pub fn as_str(self) -> &'static str {
        match self {
            GfMode::Disabled => "disabled",
            GfMode::Tcp => "tcp",
            GfMode::Udp => "udp",
            GfMode::All => "all",
        }
    }
}

/// The "game filter": extra TCP/UDP ports captured on top of what the profile always captures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GameFilter {
    pub mode: GfMode,
    pub tcp_range: String,
    pub udp_range: String,
}

impl GameFilter {
    /// Mode 1 / LEAN: only the WARP tunnel ports.
    pub fn low_latency() -> Self {
        Self { mode: GfMode::Udp, tcp_range: ALL_PORTS.into(), udp_range: WARP_UDP_PORTS.into() }
    }

    /// No game traffic at all: bypass for sites, YouTube and Discord only.
    pub fn disabled() -> Self {
        Self { mode: GfMode::Disabled, tcp_range: ALL_PORTS.into(), udp_range: ALL_PORTS.into() }
    }

    /// Mode 2: everything above 1023, TCP and UDP.
    pub fn compatibility() -> Self {
        Self { mode: GfMode::All, tcp_range: ALL_PORTS.into(), udp_range: ALL_PORTS.into() }
    }

    /// Mode 3: user supplied ports; an empty field skips that protocol.
    pub fn custom(tcp: &str, udp: &str) -> Self {
        let mode = match (tcp.is_empty(), udp.is_empty()) {
            (false, false) => GfMode::All,
            (true, false) => GfMode::Udp,
            (false, true) => GfMode::Tcp,
            (true, true) => GfMode::Disabled,
        };
        Self {
            mode,
            tcp_range: if tcp.is_empty() { ALL_PORTS.into() } else { tcp.into() },
            udp_range: if udp.is_empty() { ALL_PORTS.into() } else { udp.into() },
        }
    }

    /// Values substituted for `{GF_TCP}` / `{GF_UDP}`.
    pub fn effective(&self) -> (&str, &str) {
        match self.mode {
            GfMode::All => (&self.tcp_range, &self.udp_range),
            GfMode::Tcp => (&self.tcp_range, DUMMY_PORT),
            GfMode::Udp => (DUMMY_PORT, &self.udp_range),
            GfMode::Disabled => (DUMMY_PORT, DUMMY_PORT),
        }
    }
}

/// Validates a port list such as `3074,27000-27100`. Returns the list without spaces.
/// Rules are identical to the old `validate_game_filter_range`: 1..=65535, at most five digits,
/// no leading zero, start <= end.
pub fn normalize_ports(input: &str) -> Option<String> {
    let s: String = input.chars().filter(|c| *c != ' ').collect();
    if s.is_empty() {
        return None;
    }
    for item in s.split(',') {
        let (a, b) = match item.split_once('-') {
            Some((a, b)) => (a, b),
            None => (item, item),
        };
        let a = port(a)?;
        let b = port(b)?;
        if a > b {
            return None;
        }
    }
    Some(s)
}

fn port(s: &str) -> Option<u32> {
    let bytes = s.as_bytes();
    if bytes.is_empty() || bytes.len() > 5 || bytes[0] == b'0' || !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let n: u32 = s.parse().ok()?;
    (n <= 65535).then_some(n)
}

/// Values for the placeholders used in the generated profile templates.
pub struct Vars<'a> {
    pub bin: &'a str,
    pub lists: &'a str,
    pub wfraw: &'a str,
    pub gf_tcp: &'a str,
    pub gf_udp: &'a str,
}

/// Expands `{BIN}`, `{LISTS}`, `{WFRAW}`, `{GF_TCP}`, `{GF_UDP}` in one pass per token.
pub fn expand(template: &[&str], v: &Vars) -> Vec<String> {
    let vars = [
        ("{BIN}", v.bin),
        ("{LISTS}", v.lists),
        ("{WFRAW}", v.wfraw),
        ("{GF_TCP}", v.gf_tcp),
        ("{GF_UDP}", v.gf_udp),
    ];
    let mut out = Vec::with_capacity(template.len());
    for t in template {
        if !t.contains('{') {
            out.push((*t).to_owned());
            continue;
        }
        let mut s = String::with_capacity(t.len() + 48);
        let mut rest = *t;
        while let Some(i) = rest.find('{') {
            s.push_str(&rest[..i]);
            let tail = &rest[i..];
            match vars.iter().find(|(k, _)| tail.starts_with(k)) {
                Some((k, val)) => {
                    s.push_str(val);
                    rest = &tail[k.len()..];
                }
                None => {
                    s.push('{');
                    rest = &tail[1..];
                }
            }
        }
        s.push_str(rest);
        out.push(s);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profiles::{PROFILES, WFRAW};

    #[test]
    fn ports_validation_matches_the_old_rules() {
        assert_eq!(normalize_ports("3074, 27000-27100").as_deref(), Some("3074,27000-27100"));
        assert_eq!(normalize_ports("1024-65535").as_deref(), Some("1024-65535"));
        for bad in ["", "0", "70000", "100-50", "80,", "a", "012", "123456", "1-", "-5", "1--2"] {
            assert!(normalize_ports(bad).is_none(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn effective_ports_per_mode() {
        assert_eq!(GameFilter::low_latency().effective(), ("12", WARP_UDP_PORTS));
        assert_eq!(GameFilter::compatibility().effective(), (ALL_PORTS, ALL_PORTS));
        let c = GameFilter::custom("3074", "");
        assert_eq!(c.mode, GfMode::Tcp);
        assert_eq!(c.effective(), ("3074", "12"));
        assert_eq!(GameFilter::custom("", "").effective(), ("12", "12"));
    }

    #[test]
    fn no_placeholder_survives_expansion() {
        let gf = GameFilter::low_latency();
        let (t, u) = gf.effective();
        let v = Vars { bin: "C:\\z\\bin\\", lists: "C:\\z\\lists\\", wfraw: WFRAW, gf_tcp: t, gf_udp: u };
        for p in PROFILES {
            for tpl in [p.classic, p.lean].into_iter().flatten() {
                for a in expand(tpl, &v) {
                    assert!(
                        !["{BIN}", "{LISTS}", "{WFRAW}", "{GF_TCP}", "{GF_UDP}"].iter().any(|k| a.contains(k)),
                        "{}: {a}",
                        p.name
                    );
                }
            }
        }
    }

    #[test]
    fn warp_lean_command_line() {
        let p = crate::profiles::find("warp").unwrap();
        let gf = GameFilter::low_latency();
        let (t, u) = gf.effective();
        let v = Vars { bin: "B\\", lists: "L\\", wfraw: "RAW", gf_tcp: t, gf_udp: u };
        let a = expand(p.lean.unwrap(), &v);
        assert_eq!(a[0], "--wf-raw=RAW");
        assert!(a.contains(&"--dpi-desync-fake-quic=B\\quic_initial_www_google_com.bin".to_string()));
        assert!(a.contains(&"--filter-udp=500,1701,4443,4500,8095,8443".to_string()));
    }

    #[test]
    fn no_placeholder_or_batch_escape_survives_expansion() {
        let v = Vars { bin: "B/", lists: "L/", wfraw: "RAW", gf_tcp: "12", gf_udp: "12" };
        for p in crate::profiles::PROFILES {
            for tpl in p.lean.into_iter().chain(p.classic) {
                for a in expand(tpl, &v) {
                    assert!(!a.contains('{') && !a.contains('^'), "{}: {a}", p.name);
                }
            }
        }
        let a = expand(crate::profiles::find("max").unwrap().classic.unwrap(), &v);
        assert!(a.contains(&"--dpi-desync-fake-tls=B/tls_clienthello_www_google_com.bin".to_string()));
    }
}
