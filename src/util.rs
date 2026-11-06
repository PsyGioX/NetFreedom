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

//! Small pure helpers.

/// Finds the first `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}` (MSI product code) in `s`.
pub fn extract_guid(s: &str) -> Option<&str> {
    let b = s.as_bytes();
    let mut i = 0;
    while i + 38 <= b.len() {
        if b[i] == b'{' && b[i + 37] == b'}' {
            let g = &b[i + 1..i + 37];
            let ok = g.iter().enumerate().all(|(k, &c)| match k {
                8 | 13 | 18 | 23 => c == b'-',
                _ => c.is_ascii_hexdigit(),
            });
            if ok {
                return Some(&s[i..i + 38]);
            }
        }
        i += 1;
    }
    None
}

/// Milliseconds for humans: two decimals below 10 ms (LAN / loopback), one decimal above.
pub fn fmt_ms(x: f64) -> String {
    if x < 10.0 { format!("{x:.2}") } else { format!("{x:.1}") }
}

/// `YYYY-MM-DD HH:MM UTC` from a Unix timestamp (civil-from-days, no time crate needed).
pub fn fmt_utc(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02} UTC", rem / 3600, rem % 3600 / 60)
}

/// Directories searched for system tools by a program that runs with administrator rights.
/// `PATH` and the current directory are deliberately NOT used: a planted `curl.exe` / `nft` in a
/// user-writable folder would otherwise run elevated.
#[cfg(unix)]
pub const SYSTEM_DIRS: [&str; 6] = ["/usr/sbin", "/usr/bin", "/sbin", "/bin", "/usr/local/sbin", "/usr/local/bin"];

/// First existing `dir/name` among `dirs`.
pub fn find_in<S: AsRef<str>>(dirs: &[S], name: &str) -> Option<std::path::PathBuf> {
    dirs.iter().map(|d| std::path::Path::new(d.as_ref()).join(name)).find(|p| p.is_file())
}

/// Absolute path of a system tool (`curl`, `netsh`, `nft`, `systemctl`, ...). If it is not found
/// the bare name is returned, so the caller gets the usual "not found" error, never a surprise.
#[cfg(windows)]
pub fn system_tool(name: &str) -> std::path::PathBuf {
    let root = std::env::var_os("SystemRoot").map(std::path::PathBuf::from).unwrap_or_else(|| "C:\\Windows".into());
    let sys32 = root.join("System32");
    let exe = if name.contains('.') { name.to_owned() } else { format!("{name}.exe") };
    let p = if name.eq_ignore_ascii_case("powershell") { sys32.join("WindowsPowerShell").join("v1.0").join(&exe) } else { sys32.join(&exe) };
    if p.is_file() { p } else { std::path::PathBuf::from(name) }
}

#[cfg(unix)]
pub fn system_tool(name: &str) -> std::path::PathBuf {
    find_in(&SYSTEM_DIRS, name).unwrap_or_else(|| std::path::PathBuf::from(name))
}

/// Writes `data` next to `path` and renames it over: a crash or a power cut never leaves a
/// half-written settings file behind.
pub fn write_atomic(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        e
    })
}

/// `1 h 02 min` / `4 min 07 s` / `35 s` for session timers.
pub fn fmt_dur(secs: u64) -> String {
    let (h, m, s) = (secs / 3600, secs % 3600 / 60, secs % 60);
    if h > 0 {
        format!("{h}:{m:02}:{s:02}")
    } else {
        format!("{m:02}:{s:02}")
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn ms_formatting() {
        assert_eq!(super::fmt_ms(0.12996000000000002), "0.13");
        assert_eq!(super::fmt_ms(14.04), "14.0");
        assert_eq!(super::fmt_ms(120.0), "120.0");
    }

    #[test]
    fn duration_and_lookup() {
        assert_eq!(super::fmt_dur(35), "00:35");
        assert_eq!(super::fmt_dur(3725), "1:02:05");
        let d = std::env::temp_dir().join(format!("nf-find-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("tool"), "x").unwrap();
        let dirs = [d.to_string_lossy().into_owned()];
        assert!(super::find_in(&dirs, "tool").is_some());
        assert!(super::find_in(&dirs, "nope").is_none());
        let f = d.join("cfg");
        super::write_atomic(&f, b"a").unwrap();
        super::write_atomic(&f, b"b").unwrap();
        assert_eq!(std::fs::read(&f).unwrap(), b"b");
        assert!(!f.with_extension("tmp").exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn utc_formatting() {
        assert_eq!(super::fmt_utc(0), "1970-01-01 00:00 UTC");
        assert_eq!(super::fmt_utc(1_709_210_096), "2024-02-29 12:34 UTC");
    }

    use super::*;

    #[test]
    fn guid_extraction() {
        let s = "MsiExec.exe /X{1A2B3C4D-0000-4abc-9DEF-0123456789AB} /qn";
        assert_eq!(extract_guid(s), Some("{1A2B3C4D-0000-4abc-9DEF-0123456789AB}"));
        assert_eq!(extract_guid("C:\\app\\uninstall.exe"), None);
        assert_eq!(extract_guid("{1A2B3C4D-0000-4abc-9DEF-0123456789A}"), None);
    }
}
