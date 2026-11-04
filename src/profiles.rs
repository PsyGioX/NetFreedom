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
fn legacy(name: &str) -> Option<&'static str> {
    let l = name.to_ascii_lowercase();
    Some(match l.as_str() {
        "general (warp lean)" => "warp",
        "general" | "general (alt)" | "general (alt2)" | "general (alt3)" | "general (alt9)" => "split",
        "general (alt4)" | "general (alt6)" => "hostfake",
        "general (alt5)" | "general (alt7)" | "general (alt11)" | "general (alt13)" => "seqfake",
        "general (alt8)" | "general (alt10)" => "syndata",
        "general (alt12)" => "sni-split",
        "general (exp)" | "general (fake tls auto)" | "general (fake tls auto alt)" | "general (fake tls auto alt2)"
        | "general (fake tls auto alt3)" => "balanced",
        "general (simple fake)" | "general (simple fake alt)" | "general (simple fake alt2)" => "ttl",
        _ => return None,
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
        assert_eq!(PROFILES.len(), 4 + 9);
        assert!(find(DEFAULT_PROFILE).unwrap().is_dedicated_lean());
        assert!(find(DEFAULT_BYPASS).unwrap().is_bypass());
        assert!(find("BALANCED").is_some());
        assert!(find("nope").is_none());
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

    #[test]
    fn no_past_sequence_fooling() {
        // youtubeUnblock#356: TSPU drops connections that carry fakes with a sequence in the past
        for p in PROFILES {
            for a in p.lean.into_iter().chain(p.classic).flatten() {
                if let Some(v) = a.strip_prefix("--dpi-desync-badseq-increment=") {
                    assert!(v.parse::<i64>().unwrap() > 0, "{}: badseq must point to the future", p.name);
                }
                assert!(*a != "--dpi-desync-fooling=badseq" || p.name == "seqfake");
            }
        }
    }

    #[test]
    fn game_segments_never_rewrite_real_data() {
        for p in PROFILES.iter().filter(|p| p.is_bypass()) {
            let a = p.classic.unwrap();
            let mut segs: Vec<&[&str]> = Vec::new();
            let mut start = 0;
            for (i, x) in a.iter().enumerate() {
                if *x == "--new" {
                    segs.push(&a[start..i]);
                    start = i + 1;
                }
            }
            segs.push(&a[start..]);
            for s in segs.iter().filter(|s| s.iter().any(|x| x.contains("{GF_") && !x.starts_with("--wf-"))) {
                let desync = s.iter().find(|x| x.starts_with("--dpi-desync=")).unwrap();
                assert_eq!(*desync, "--dpi-desync=fake", "{}: game segment must only add fakes", p.name);
                assert!(s.iter().any(|x| x.starts_with("--dpi-desync-cutoff=n")), "{}: game segment needs a cutoff", p.name);
            }
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
