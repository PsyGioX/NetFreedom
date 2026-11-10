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

//! Safety checks before the folder is deleted by the uninstaller (pure string logic).

/// Lower-cases, uses `\` separators and drops the trailing one, so comparisons are
/// case-insensitive like NTFS paths.
pub fn norm(p: &str) -> String {
    let mut s = p.replace('/', "\\").to_lowercase();
    while s.len() > 1 && s.ends_with('\\') {
        s.pop();
    }
    s
}

/// Files that must exist for a folder to be recognised as this package.
#[cfg(windows)]
pub fn markers() -> &'static [&'static str] {
    &["netfreedom.exe", "bin\\winws.exe", "bin\\windivert64.sys"]
}

/// Files that must exist for a folder to be recognised as this package.
#[cfg(unix)]
pub fn markers() -> &'static [&'static str] {
    &["netfreedom", "lists/list-general.txt"]
}

/// Returns `None` when `root` is safe to delete, otherwise a human readable reason.
/// `protected` are well-known folders (Windows, Program Files, the profile, Desktop, ...).
pub fn unsafe_reason(root: &str, protected: &[String], has_file: &dyn Fn(&str) -> bool) -> Option<String> {
    if root.trim().is_empty() {
        return Some("empty path".into());
    }
    let full = norm(root);
    // drive root: "c:" (or a UNC share root)
    if full == "\\" || (full.len() == 2 && full.ends_with(':')) || full.trim_start_matches('\\').split('\\').count() < 2 && full.starts_with("\\\\") {
        return Some("it is a drive root".into());
    }
    for p in protected {
        let pt = norm(p);
        if pt.is_empty() {
            continue;
        }
        if full == pt {
            return Some(format!("it is a protected system folder ({p})"));
        }
        if pt.starts_with(&format!("{full}\\")) {
            return Some(format!("it contains a protected folder ({p})"));
        }
    }
    for m in markers().iter().copied() {
        if !has_file(m) {
            return Some(format!("it does not look like a netfreedom folder (missing {m})"));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prot() -> Vec<String> {
        vec!["C:\\Windows".into(), "C:\\Users\\me".into(), "C:\\Users\\me\\Desktop".into()]
    }

    #[test]
    fn rejects_dangerous_targets() {
        let all = |_: &str| true;
        for bad in ["", "/", "C:\\", "c:", "C:\\Windows", "c:\\windows\\", "C:\\Users\\me", "C:\\Users", "C:\\Users\\me\\Desktop"] {
            assert!(unsafe_reason(bad, &prot(), &all).is_some(), "{bad:?}");
        }
    }

    #[test]
    fn linux_paths() {
        let p = vec!["/home/me".to_string(), "/home/me/Downloads".to_string(), "/usr".to_string(), "/home".to_string()];
        assert!(unsafe_reason("/", &p, &|_| true).is_some());
        assert!(unsafe_reason("/home/me/", &p, &|_| true).is_some());
        assert!(unsafe_reason("/home", &p, &|_| true).is_some());
        assert!(unsafe_reason("/home/me/netfreedom", &p, &|_| true).is_none());
        assert!(unsafe_reason("/opt/zw", &p, &|m| m != markers()[0]).is_some());
    }

    #[test]
    fn accepts_a_real_folder_and_checks_markers() {
        assert!(unsafe_reason("C:\\netfreedom", &prot(), &|_| true).is_none());
        let second = markers()[1];
        let missing = unsafe_reason("C:\\netfreedom", &prot(), &|m| m != second).unwrap();
        assert!(missing.contains(second));
        // a subfolder of a protected one is fine as long as it looks like the package
        assert!(unsafe_reason("C:\\Users\\me\\Games\\zw", &prot(), &|_| true).is_none());
    }
}
