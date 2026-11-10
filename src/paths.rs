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

//! Folder layout: the executable sits next to `bin\`, `lists\` and `utils\`.

use std::fs;
use std::io;
use std::path::PathBuf;

#[derive(Clone)]
pub struct Layout {
    pub root: PathBuf,
    /// `...\bin\` with a trailing separator (templates append file names directly).
    pub bin: String,
    /// `...\lists\` with a trailing separator.
    pub lists: String,
    pub cfg: PathBuf,
    /// Settings file of the 2.x launcher; read once if `cfg` does not exist yet.
    pub cfg_legacy: PathBuf,
    pub utils: PathBuf,
}

impl Layout {
    pub fn discover() -> io::Result<Self> {
        let exe = std::env::current_exe()?;
        let root = exe.parent().map(PathBuf::from).unwrap_or_default();
        Ok(Self::at(root))
    }

    pub fn at(root: PathBuf) -> Self {
        let sep = std::path::MAIN_SEPARATOR;
        let with_sep = |name: &str| format!("{}{sep}", root.join(name).display());
        Self {
            bin: with_sep("bin"),
            lists: with_sep("lists"),
            cfg: root.join("utils").join("netfreedom.cfg"),
            cfg_legacy: root.join("utils").join("warp_launcher.cfg"),
            utils: root.join("utils"),
            root,
        }
    }

    /// Linux: `nfqws` from `bin/`, `bin/<zapret platform dir>/` or PATH.
    #[cfg(unix)]
    pub fn nfqws_exe(&self) -> Option<PathBuf> {
        let dir = match std::env::consts::ARCH {
            "x86_64" => "linux-x86_64",
            "aarch64" => "linux-arm64",
            "arm" => "linux-arm",
            "x86" => "linux-x86",
            "mips" => "linux-mips",
            "mips64" => "linux-mips64",
            "powerpc" => "linux-ppc",
            "riscv64" => "linux-riscv64",
            other => other,
        };
        let bin = PathBuf::from(&self.bin);
        [bin.join("nfqws"), bin.join(dir).join("nfqws")]
            .into_iter()
            .find(|p| p.is_file())
            .or_else(|| crate::sys::which("nfqws"))
    }

    /// Creates the user list files that profiles reference, if they are missing.
    pub fn ensure_user_lists(&self) -> io::Result<()> {
        let lists = PathBuf::from(&self.lists);
        fs::create_dir_all(&lists)?;
        fs::create_dir_all(self.root.join("utils"))?;
        for (name, body) in [
            ("ipset-exclude-user.txt", "203.0.113.113/32\n"),
            ("list-general-user.txt", "# Never leave this file empty\ndomain.example.abc\n"),
            ("list-exclude-user.txt", "domain.example.abc\n"),
            // Instagram/Meta and X/Twitter: ours, never overwritten by `lists update`. Created here
            // so that an older install that lacks the file still starts (a missing list file makes
            // the engine refuse to run).
            ("list-social.txt", include_str!("../assets/list-social.txt")),
            ("ipset-social.txt", include_str!("../assets/ipset-social.txt")),
            // developer hosting blocked in 2026 (Vercel, Netlify): ours as well
            ("list-dev.txt", include_str!("../assets/list-dev.txt")),
        ] {
            let p = lists.join(name);
            if !p.exists() {
                fs::write(p, body)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_old_install_gets_the_social_list_and_keeps_user_edits() {
        let root = std::env::temp_dir().join(format!("nf-lists-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let l = Layout::at(root.clone());
        fs::create_dir_all(root.join("lists")).unwrap();
        fs::write(root.join("lists").join("list-general-user.txt"), "my.example\n").unwrap();
        l.ensure_user_lists().unwrap();
        let social = fs::read_to_string(root.join("lists").join("list-social.txt")).unwrap();
        for d in ["instagram.com", "cdninstagram.com", "x.com", "twimg.com", "t.co", "telegram.org", "t.me", "whatsapp.com", "whatsapp.net"] {
            assert!(social.lines().any(|x| x.trim() == d), "{d} missing");
        }
        let ipset = fs::read_to_string(root.join("lists").join("ipset-social.txt")).unwrap();
        for r in ["149.154.160.0/20", "91.105.192.0/23", "2001:b28:f23c::/48"] {
            assert!(ipset.lines().any(|x| x.trim() == r), "{r} missing");
        }
        let dev = fs::read_to_string(root.join("lists").join("list-dev.txt")).unwrap();
        for d in ["vercel.app", "netlify.app"] {
            assert!(dev.lines().any(|x| x.trim() == d), "{d} missing");
        }
        assert_eq!(fs::read_to_string(root.join("lists").join("list-general-user.txt")).unwrap(), "my.example\n", "user files are never overwritten");
        // a second run must not touch an edited social list either
        fs::write(root.join("lists").join("list-social.txt"), "mine.example\n").unwrap();
        l.ensure_user_lists().unwrap();
        assert_eq!(fs::read_to_string(root.join("lists").join("list-social.txt")).unwrap(), "mine.example\n");
        let _ = fs::remove_dir_all(&root);
    }
}
