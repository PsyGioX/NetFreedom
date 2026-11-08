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

//! Remembered choices (`utils/netfreedom.cfg`; the 2.x `warp_launcher.cfg` is still read once).

use std::fs;
use std::io;
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub profile: String,
    /// Last strategy used for bypass without WARP.
    pub bypass: String,
    pub mode: u8,
    pub cap: u8,
    pub tcp: String,
    pub udp: String,
    /// Game server (IP) whose latency / loss is watched; empty = Cloudflare 1.1.1.1.
    pub target: String,
    /// `ru` / `en`; empty = auto.
    pub lang: String,
    /// Encrypted DNS: `cloudflare` / `google` / `quad9` / `auto`; empty = leave the system's DNS alone.
    pub dns: String,
    /// DNS: no fallback to plain DNS when the encrypted resolver is unreachable.
    pub dns_strict: bool,
    /// DNS: on a system without an encrypted-DNS client (Windows 10) accept the provider's plain DNS.
    pub dns_plain: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self { profile: String::new(), bypass: String::new(), mode: 1, cap: 1, tcp: String::new(), udp: String::new(), target: String::new(), lang: String::new(), dns: String::new(), dns_strict: false, dns_plain: false }
    }
}

impl Config {
    pub fn parse(text: &str) -> Self {
        let mut c = Self::default();
        for line in text.lines() {
            let Some((k, v)) = line.trim().split_once('=') else { continue };
            let v = v.trim();
            match k.trim().to_ascii_lowercase().as_str() {
                "profile" => c.profile = v.to_owned(),
                "bypass" => c.bypass = v.to_owned(),
                "mode" => c.mode = v.parse().ok().filter(|m| (1..=3).contains(m)).unwrap_or(1),
                "cap" => c.cap = v.parse().ok().filter(|m| (1..=2).contains(m)).unwrap_or(1),
                "tcp" => c.tcp = v.to_owned(),
                "udp" => c.udp = v.to_owned(),
                "target" => c.target = v.to_owned(),
                "lang" => c.lang = v.to_ascii_lowercase(),
                "dns" => c.dns = v.to_ascii_lowercase(),
                "dns_strict" => c.dns_strict = v == "1",
                "dns_plain" => c.dns_plain = v == "1",
                _ => {}
            }
        }
        c
    }

    pub fn render(&self) -> String {
        format!(
            "profile={}\nbypass={}\nmode={}\ncap={}\ntcp={}\nudp={}\ntarget={}\nlang={}\ndns={}\ndns_strict={}\ndns_plain={}\n",
            self.profile, self.bypass, self.mode, self.cap, self.tcp, self.udp, self.target, self.lang, self.dns, u8::from(self.dns_strict), u8::from(self.dns_plain)
        )
    }

    pub fn load(path: &Path) -> Self {
        fs::read_to_string(path).map(|t| Self::parse(&t)).unwrap_or_default()
    }

    /// `path` if it exists, otherwise the legacy file, otherwise defaults.
    pub fn load_with_legacy(path: &Path, legacy: &Path) -> Self {
        if path.exists() { Self::load(path) } else { Self::load(legacy) }
    }

    pub fn save(&self, path: &Path) -> io::Result<()> {
        crate::util::write_atomic(path, self.render().as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_legacy_files() {
        let c = Config { profile: "warp".into(), bypass: "split".into(), mode: 3, cap: 2, tcp: "80".into(), udp: "3074".into(), target: "203.0.113.7".into(), lang: "ru".into(), dns: "quad9".into(), dns_strict: true, dns_plain: false };
        assert_eq!(Config::parse(&c.render()), c);
        // file written by the BAT launcher (CRLF, .bat suffix kept as is)
        let old = Config::parse("profile=general (ALT).bat\r\nmode=2\r\ncap=1\r\ntcp=\r\nudp=\r\n");
        assert_eq!(old.profile, "general (ALT).bat");
        assert_eq!(old.mode, 2);
        // garbage falls back to defaults
        assert_eq!(Config::parse("mode=9\ncap=x\nnonsense").mode, 1);
        // settings written before DNS existed load with the DNS left alone
        let before_dns = Config::parse("profile=warp\nmode=1\n");
        assert_eq!((before_dns.dns.as_str(), before_dns.dns_strict, before_dns.dns_plain), ("", false, false));
    }
}
