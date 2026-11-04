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
}

impl Default for Config {
    fn default() -> Self {
        Self { profile: String::new(), bypass: String::new(), mode: 1, cap: 1, tcp: String::new(), udp: String::new() }
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
                _ => {}
            }
        }
        c
    }

    pub fn render(&self) -> String {
        format!(
            "profile={}\nbypass={}\nmode={}\ncap={}\ntcp={}\nudp={}\n",
            self.profile, self.bypass, self.mode, self.cap, self.tcp, self.udp
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
        fs::write(path, self.render())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_legacy_files() {
        let c = Config { profile: "warp".into(), bypass: "split".into(), mode: 3, cap: 2, tcp: "80".into(), udp: "3074".into() };
        assert_eq!(Config::parse(&c.render()), c);
        // file written by the BAT launcher (CRLF, .bat suffix kept as is)
        let old = Config::parse("profile=general (ALT).bat\r\nmode=2\r\ncap=1\r\ntcp=\r\nudp=\r\n");
        assert_eq!(old.profile, "general (ALT).bat");
        assert_eq!(old.mode, 2);
        // garbage falls back to defaults
        assert_eq!(Config::parse("mode=9\ncap=x\nnonsense").mode, 1);
    }
}
