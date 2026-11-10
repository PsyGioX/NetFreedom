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

//! Host lists for the native engine (`--hostlist`, `--hostlist-exclude`).
//!
//! zapret semantics: an entry matches the host itself and every subdomain of it; a leading `$`
//! means "exactly this host". Lines starting with `#` and empty lines are ignored. Entries are
//! kept in one `HashSet<Box<str>>` and a lookup walks the label suffixes, so memory is one small
//! allocation per domain and a lookup costs a handful of hash probes.

use std::collections::HashSet;

#[derive(Debug, Default, Clone)]
pub struct HostList {
    suffix: HashSet<Box<str>>,
    exact: HashSet<Box<str>>,
}

impl HostList {
    pub fn parse(text: &str) -> HostList {
        let mut l = HostList::default();
        for line in text.lines() {
            let t = line.trim().trim_start_matches('\u{feff}');
            if t.is_empty() || t.starts_with('#') {
                continue;
            }
            match t.strip_prefix('$') {
                Some(h) => l.exact.insert(h.to_ascii_lowercase().into()),
                None => l.suffix.insert(t.trim_start_matches("*.").to_ascii_lowercase().into()),
            };
        }
        l
    }

    pub fn merge(&mut self, o: HostList) {
        self.suffix.extend(o.suffix);
        self.exact.extend(o.exact);
    }

    pub fn len(&self) -> usize {
        self.suffix.len() + self.exact.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn contains(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.');
        let mut buf = [0u8; 255];
        let b = host.as_bytes();
        if b.len() > buf.len() {
            return false;
        }
        for (d, s) in buf.iter_mut().zip(b) {
            *d = s.to_ascii_lowercase();
        }
        let Ok(h) = std::str::from_utf8(&buf[..b.len()]) else { return false };
        if self.exact.contains(h) {
            return true;
        }
        let mut rest = h;
        loop {
            if self.suffix.contains(rest) {
                return true;
            }
            match rest.find('.') {
                Some(i) => rest = &rest[i + 1..],
                None => return false,
            }
        }
    }
}

/// zapret rule: apply when the host is in the include list (if there is one) and not in the
/// exclude list. No SNI means the include list cannot match, so the packet is left alone.
pub fn applies(include: Option<&HostList>, exclude: Option<&HostList>, host: Option<&str>) -> bool {
    if let (Some(x), Some(h)) = (exclude, host) {
        if x.contains(h) {
            return false;
        }
    }
    match include {
        None => true,
        Some(i) => host.is_some_and(|h| i.contains(h)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subdomains_match_but_lookalikes_do_not() {
        let l = HostList::parse("# c\n\nyoutube.com\n$exact.org\n*.Discord.com\n");
        assert_eq!(l.len(), 3);
        assert!(l.contains("youtube.com") && l.contains("m.YouTube.com") && l.contains("a.b.youtube.com."));
        assert!(!l.contains("notyoutube.com") && !l.contains("com"));
        assert!(l.contains("exact.org") && !l.contains("www.exact.org"));
        assert!(l.contains("discord.com") && l.contains("cdn.discord.com"));
    }

    #[test]
    fn include_exclude_and_missing_sni() {
        let inc = HostList::parse("example.com");
        let exc = HostList::parse("private.example.com");
        assert!(applies(Some(&inc), Some(&exc), Some("www.example.com")));
        assert!(!applies(Some(&inc), Some(&exc), Some("private.example.com")));
        assert!(!applies(Some(&inc), None, None));
        assert!(applies(None, Some(&exc), None));
    }
}
