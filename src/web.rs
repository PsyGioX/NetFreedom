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

//! Does the bypass work *right now*? Downloads a few real resources through the system `curl`
//! (it ships with Windows 10 1803+ and every Linux distribution, so nothing is bundled) and reports
//! what arrived. The first target is the one TSPU throttles: a Cloudflare-hosted file that is
//! larger than the ~16 KB the provider lets through, so a cut-off connection is plain to see.

use std::process::{Command, Stdio};
use std::time::Duration;

#[derive(Clone, Copy)]
pub struct Target {
    pub name: &'static str,
    pub url: &'static str,
    /// Body size that must arrive for a pass (0 = only the status code matters).
    pub min_bytes: u64,
}

pub const TARGETS: &[Target] = &[
    Target { name: "Cloudflare 300 KB", url: "https://speed.cloudflare.com/__down?bytes=300000", min_bytes: 300_000 },
    Target { name: "Discord API", url: "https://discord.com/api/v9/gateway", min_bytes: 1 },
    Target { name: "YouTube", url: "https://www.youtube.com/generate_204", min_bytes: 0 },
];

#[derive(Clone, Debug, PartialEq)]
pub struct WebResult {
    pub name: String,
    pub ok: bool,
    pub code: u32,
    pub bytes: u64,
    pub secs: f64,
    pub note: String,
}

impl WebResult {
    pub fn line(&self) -> String {
        if self.ok {
            format!("{:<20} OK    {:>7} bytes in {:.1} s", self.name, self.bytes, self.secs)
        } else {
            format!("{:<20} FAIL  {}", self.name, self.note)
        }
    }
}

/// Parses curl's `-w "%{http_code} %{size_download} %{time_total}"` output.
pub fn parse_write_out(out: &str) -> Option<(u32, u64, f64)> {
    let mut it = out.split_whitespace();
    let code = it.next()?.parse().ok()?;
    let bytes = it.next()?.parse().ok()?;
    let secs = it.next()?.replace(',', ".").parse().ok()?;
    Some((code, bytes, secs))
}

/// Verdict for one download. `curl_ok`: curl itself exited with 0.
pub fn judge(t: &Target, curl_ok: bool, code: u32, bytes: u64, secs: f64) -> WebResult {
    let status_ok = (200..400).contains(&code);
    let ok = curl_ok && status_ok && bytes >= t.min_bytes;
    let note = if ok {
        String::new()
    } else if !curl_ok && (12_000..=24_000).contains(&bytes) && t.min_bytes > 24_000 {
        format!("connection cut after {bytes} bytes: the typical ~16 KB TSPU throttle of Cloudflare-hosted sites")
    } else if !curl_ok && bytes == 0 {
        "no data (blocked, reset or timed out)".to_owned()
    } else if !curl_ok {
        format!("transfer broke after {bytes} bytes")
    } else if !status_ok {
        format!("HTTP status {code}")
    } else {
        format!("only {bytes} of {} bytes", t.min_bytes)
    };
    WebResult { name: t.name.to_owned(), ok, code, bytes, secs, note }
}

/// Lower is better. A failed target costs far more than any realistic download time, so the
/// strategy that opens the most targets always wins, and speed only decides between equals.
pub fn score(results: &[WebResult]) -> f64 {
    results.iter().map(|r| if r.ok { r.secs } else { 100.0 }).sum()
}

fn null_device() -> &'static str {
    if cfg!(windows) { "NUL" } else { "/dev/null" }
}

fn fetch(t: &Target, timeout: Duration) -> WebResult {
    let mut cmd = Command::new("curl");
    cmd.args(["-s", "-o", null_device(), "--connect-timeout", "6", "-m"])
        .arg(timeout.as_secs().to_string())
        .args(["-w", "%{http_code} %{size_download} %{time_total}", t.url])
        .stdin(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    match cmd.output() {
        Ok(o) => {
            let text = String::from_utf8_lossy(&o.stdout);
            match parse_write_out(&text) {
                Some((code, bytes, secs)) => judge(t, o.status.success(), code, bytes, secs),
                None => WebResult { name: t.name.to_owned(), ok: false, code: 0, bytes: 0, secs: 0.0, note: "curl gave no result".into() },
            }
        }
        Err(e) => WebResult { name: t.name.to_owned(), ok: false, code: 0, bytes: 0, secs: 0.0, note: format!("cannot run curl: {e}") },
    }
}

/// Is `curl` available at all?
pub fn curl_available() -> bool {
    Command::new("curl").arg("--version").stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok_and(|s| s.success())
}

/// Runs every target at the same time (the slowest one decides how long this takes).
pub fn probe(timeout: Duration) -> Vec<WebResult> {
    std::thread::scope(|s| {
        let handles: Vec<_> = TARGETS.iter().map(|t| s.spawn(move || fetch(t, timeout))).collect();
        handles
            .into_iter()
            .zip(TARGETS)
            .map(|(h, t)| h.join().unwrap_or_else(|_| WebResult { name: t.name.to_owned(), ok: false, code: 0, bytes: 0, secs: 0.0, note: "probe crashed".into() }))
            .collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn curl_output_is_parsed() {
        assert_eq!(parse_write_out("200 300000 0.842"), Some((200, 300_000, 0.842)));
        assert_eq!(parse_write_out("000 0 0,000"), Some((0, 0, 0.0)));
        assert_eq!(parse_write_out(""), None);
        assert_eq!(parse_write_out("abc"), None);
    }

    #[test]
    fn the_sixteen_kb_cutoff_is_recognised() {
        let cf = &TARGETS[0];
        let r = judge(cf, false, 200, 16_384, 10.0);
        assert!(!r.ok);
        assert!(r.note.contains("16 KB"), "{}", r.note);
        assert!(judge(cf, true, 200, 300_000, 0.9).ok);
        assert!(!judge(cf, true, 200, 5_000, 0.9).ok, "a short body is not a pass");
        assert!(judge(&TARGETS[2], true, 204, 0, 0.2).ok, "204 without a body passes");
        assert!(!judge(&TARGETS[2], true, 503, 0, 0.2).ok);
    }

    #[test]
    fn open_targets_beat_speed() {
        let ok = |s| WebResult { name: "a".into(), ok: true, code: 200, bytes: 1, secs: s, note: String::new() };
        let bad = WebResult { name: "b".into(), ok: false, code: 0, bytes: 0, secs: 0.0, note: String::new() };
        let slow_but_open = [ok(9.0), ok(9.0), ok(9.0)];
        let fast_but_blocked = [ok(0.1), ok(0.1), bad];
        assert!(score(&slow_but_open) < score(&fast_but_blocked));
    }
}
