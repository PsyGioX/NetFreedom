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

#[cfg(test)]
mod tests {
    #[test]
    fn ms_formatting() {
        assert_eq!(super::fmt_ms(0.12996000000000002), "0.13");
        assert_eq!(super::fmt_ms(14.04), "14.0");
        assert_eq!(super::fmt_ms(120.0), "120.0");
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
