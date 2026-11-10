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

//! Static strategy table. The data is produced by `tools/gen_strategies.py` from a handful of
//! small blocks and lives in read-only memory: nothing is parsed or allocated at start-up.

pub use crate::profiles_data::{PROFILES, WFRAW};

/// One selectable strategy.
pub struct Profile {
    pub name: &'static str,
    /// One line for `netfreedom list` and the menus.
    pub desc: &'static str,
    /// Port-based capture arguments (bypass strategies). `None` for the WARP-only strategies.
    pub classic: Option<&'static [&'static str]>,
    /// WARP strategies: only the QUIC/UDP handshake to Cloudflare is diverted.
    pub lean: Option<&'static [&'static str]>,
}

impl Profile {
    /// WARP-only strategy: no port capture variant exists.
    pub fn is_dedicated_lean(&self) -> bool {
        self.classic.is_none()
    }

    /// Strategy that works without WARP (web, YouTube, Discord, games).
    pub fn is_bypass(&self) -> bool {
        self.classic.is_some()
    }
}

/// Name of the recommended default strategy for games through WARP.
pub const DEFAULT_PROFILE: &str = "warp";
/// Name of the recommended first try for bypassing blocks without WARP.
pub const DEFAULT_BYPASS: &str = "balanced";

/// Old names (from the BAT/Rust 2.x launchers and their config files) -> current strategies.
/// "general (ALT2)" is now simply `alt2`; the few that were merged map to their equivalent.
fn legacy(name: &str) -> Option<&'static str> {
    let l = name.to_ascii_lowercase();
    let inner = l.strip_prefix("general (").and_then(|r| r.strip_suffix(')')).map(|r| r.replace(' ', "-"));
    Some(match inner.as_deref() {
        None if l == "general" => "general",
        Some("warp-lean") => "warp",
        Some("alt6") => "split",
        Some("alt7") => "sni-split",
        Some("alt5") | Some("fake-tls-auto-alt2") => "seqfake",
        Some("fake-tls-auto-alt3") | Some("fake-tls-auto-alt3-") => "balanced",
        Some("fake-tls-auto") => "disorder",
        Some("simple-fake") => "simple-fake",
        Some("fake-tls-auto-alt") => "fta-alt",
        Some(r) => return PROFILES.iter().find(|p| p.name == r).map(|p| p.name),
        None => return None,
    })
}

/// Case-insensitive lookup; a trailing `.bat` and the old 2.x names are understood.
pub fn find(name: &str) -> Option<&'static Profile> {
    let n = name.trim();
    let n = if n.len() >= 4 && n.is_char_boundary(n.len() - 4) && n[n.len() - 4..].eq_ignore_ascii_case(".bat") {
        &n[..n.len() - 4]
    } else {
        n
    };
    PROFILES
        .iter()
        .find(|p| p.name.eq_ignore_ascii_case(n))
        .or_else(|| legacy(n).and_then(|l| PROFILES.iter().find(|p| p.name == l)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn table_is_complete() {
        assert_eq!(PROFILES.len(), 7 + 29);
        assert!(find(DEFAULT_PROFILE).unwrap().is_dedicated_lean());
        assert!(find(DEFAULT_BYPASS).unwrap().is_bypass());
        assert!(find("BALANCED").is_some());
        assert!(find("nope").is_none());
    }

    /// The game scenarios exist to shrink the burst sent while a connection is set up; the numbers
    /// in the README follow from these arguments, so the test pins them.
    #[test]
    fn game_scenarios_send_a_smaller_burst_than_the_default() {
        fn burst(name: &str) -> (u32, u32) {
            let a = find(name).unwrap().lean.unwrap();
            let rep = |i: usize| a[i..].iter().find_map(|x| x.strip_prefix("--dpi-desync-repeats=")).unwrap().parse::<u32>().unwrap();
            let port = a.iter().position(|x| x.starts_with("--filter-udp=500")).unwrap();
            (rep(0), rep(port))
        }
        let (q0, p0) = burst("warp");
        for n in ["warp-esports", "warp-esports-ttl", "warp-lowburst"] {
            let p = find(n).unwrap();
            assert!(p.is_dedicated_lean(), "{n} is a WARP strategy");
            let (q, port) = burst(n);
            assert!(q < q0 && port < p0, "{n}: {q}/{port} must be below {q0}/{p0}");
            assert!(p.lean.unwrap().contains(&"--dpi-desync-cutoff=n2"), "{n}: fakes on the first packet only");
        }
        assert!(find("warp-esports-ttl").unwrap().lean.unwrap().contains(&"--dpi-desync-ttl=5"));
        assert!(find("warp-lowburst").unwrap().lean.unwrap().contains(&"--dpi-desync-fake-unknown-udp={BIN}stun.bin"));
    }

    #[test]
    fn old_names_still_resolve() {
        assert_eq!(find("general (WARP LEAN)").unwrap().name, "warp");
        assert_eq!(find("general (ALT5).bat").unwrap().name, "seqfake");
        assert!(find("general (ALT13)").is_some());
    }

    #[test]
    fn every_strategy_is_unique_and_described() {
        let mut seen = HashSet::new();
        for p in PROFILES {
            assert!(seen.insert(p.name), "duplicate name {}", p.name);
            assert!(!p.desc.is_empty());
            assert!(p.lean.is_some() ^ p.classic.is_some(), "{}: exactly one variant expected", p.name);
        }
        // no two strategies may expand to the same arguments: that was the old table's main waste
        let mut args = HashSet::new();
        for p in PROFILES {
            let a = p.lean.or(p.classic).unwrap();
            assert!(args.insert(a.to_vec()), "{} duplicates another strategy", p.name);
        }
    }

    fn segments<'a>(a: &'a [&'static str]) -> Vec<&'a [&'static str]> {
        let mut segs = Vec::new();
        let mut start = 0;
        for (i, x) in a.iter().enumerate() {
            if *x == "--new" {
                segs.push(&a[start..i]);
                start = i + 1;
            }
        }
        segs.push(&a[start..]);
        segs
    }

    #[test]
    fn no_past_sequence_fooling() {
        // youtubeUnblock#356: TSPU drops connections that carry fakes with a sequence in the past,
        // and `badseq` WITHOUT an explicit increment means exactly that (default -10000)
        for p in PROFILES {
            let a: Vec<&str> = p.lean.into_iter().chain(p.classic).flatten().copied().collect();
            let badseq = a.iter().any(|x| x.starts_with("--dpi-desync-fooling=") && x.contains("badseq"));
            if badseq {
                let inc = a.iter().find_map(|x| x.strip_prefix("--dpi-desync-badseq-increment=")).unwrap_or_else(|| panic!("{}: badseq without an increment", p.name));
                assert!(inc.parse::<i64>().unwrap() > 0, "{}: badseq must point to the future", p.name);
            }
        }
    }

    #[test]
    fn tls_tricks_never_touch_port_80() {
        // plain HTTP to CDN ranges carries the OCSP/CRL revocation checks; splitting them with a
        // TLS-shaped trick made "working" HTTPS fail in a real tune report
        for p in PROFILES.iter().filter(|p| p.is_bypass()) {
            for s in segments(p.classic.unwrap()) {
                let desync = s.iter().find(|x| x.starts_with("--dpi-desync=")).copied().unwrap_or("");
                let tls_trick = ["multisplit", "multidisorder", "fakedsplit", "fakeddisorder", "hostfakesplit", "syndata"].iter().any(|m| desync.contains(m));
                let tcp = s.iter().find_map(|x| x.strip_prefix("--filter-tcp="));
                if let (true, Some(ports)) = (tls_trick, tcp) {
                    if s.contains(&"--filter-l7=http") {
                        continue; // the dedicated HTTP rule
                    }
                    assert!(!ports.split(',').any(|p| p == "80"), "{}: {desync} on port 80", p.name);
                }
            }
        }
    }

    #[test]
    fn instagram_and_x_are_covered_by_every_bypass_strategy() {
        for p in PROFILES.iter().filter(|p| p.is_bypass()) {
            let a = p.classic.unwrap();
            let with_social = segments(a).iter().filter(|s| s.contains(&"--hostlist={LISTS}list-social.txt")).count();
            assert!(with_social >= 3, "{}: list-social.txt must be in the QUIC, TLS and HTTP list segments, found {with_social}", p.name);
        }
    }

    #[test]
    fn developer_hosting_is_covered_by_every_bypass_strategy() {
        for p in PROFILES.iter().filter(|p| p.is_bypass()) {
            let n = segments(p.classic.unwrap()).iter().filter(|s| s.contains(&"--hostlist={LISTS}list-dev.txt")).count();
            assert!(n >= 3, "{}: list-dev.txt must be in the QUIC, TLS and HTTP list segments, found {n}", p.name);
        }
    }

    #[test]
    fn youtube_quic_and_googlevideo_are_covered() {
        for p in PROFILES.iter().filter(|p| p.is_bypass()) {
            let segs = segments(p.classic.unwrap());
            assert!(
                segs.iter().any(|s| s.contains(&"--filter-udp=443") && s.contains(&"--hostlist={LISTS}list-google.txt")),
                "{}: no QUIC rule for YouTube",
                p.name
            );
            // the first matching rule wins, so the specific googlevideo rule must precede the generic Google one
            let generic = segs.iter().position(|s| s.contains(&"--filter-tcp=443") && s.contains(&"--hostlist={LISTS}list-google.txt")).unwrap();
            if let Some(gv) = segs.iter().position(|s| s.contains(&"--hostlist-domains=googlevideo.com")) {
                assert!(gv < generic, "{}: the googlevideo rule must come before the generic Google rule", p.name);
            }
        }
        // the proven originals stay verbatim and the fake-free techniques stay free of fakes
        for name in ["general", "alt2", "alt11", "alt13", "split", "sni-split", "hostfake-g"] {
            let segs = segments(find(name).unwrap().classic.unwrap());
            assert!(!segs.iter().any(|s| s.contains(&"--hostlist-domains=googlevideo.com")), "{name}");
        }
        let balanced = segments(find("balanced").unwrap().classic.unwrap());
        assert!(balanced.iter().any(|s| s.contains(&"--hostlist-domains=googlevideo.com")));
    }

    #[test]
    fn game_segments_never_rewrite_real_data() {
        for p in PROFILES.iter().filter(|p| p.is_bypass()) {
            for s in segments(p.classic.unwrap()).iter().filter(|s| s.iter().any(|x| x.contains("{GF_") && !x.starts_with("--wf-"))) {
                let desync = s.iter().find(|x| x.starts_with("--dpi-desync=")).unwrap();
                assert_eq!(*desync, "--dpi-desync=fake", "{}: game segment must only add fakes", p.name);
                assert!(s.iter().any(|x| x.starts_with("--dpi-desync-cutoff=n")), "{}: game segment needs a cutoff", p.name);
            }
        }
    }

    #[test]
    fn telegram_ranges_are_covered_on_the_tls_port_only() {
        for p in PROFILES.iter().filter(|p| p.is_bypass()) {
            let segs = segments(p.classic.unwrap());
            let seg = segs.iter().find(|s| s.contains(&"--ipset={LISTS}ipset-social.txt")).unwrap_or_else(|| panic!("{}: no Telegram segment", p.name));
            assert!(seg.contains(&"--filter-tcp=443"), "{}: Telegram segment must be TLS port only", p.name);
        }
    }

    #[test]
    fn warp_strategies_do_not_depend_on_list_files() {
        for p in PROFILES.iter().filter(|p| p.is_dedicated_lean()) {
            for a in p.lean.unwrap() {
                assert!(!a.contains("{LISTS}"), "{}: {a}", p.name);
            }
            assert!(p.lean.unwrap().contains(&"--wf-raw={WFRAW}"));
        }
    }
}
