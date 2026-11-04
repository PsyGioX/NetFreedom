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

    pub fn winws_exe(&self) -> PathBuf {
        PathBuf::from(&self.bin).join("winws.exe")
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
        ] {
            let p = lists.join(name);
            if !p.exists() {
                fs::write(p, body)?;
            }
        }
        Ok(())
    }
}
