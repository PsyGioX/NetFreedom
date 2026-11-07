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
    /// Body size that must arrive for a pass (0 = no minimum).
    pub min_bytes: u64,
    /// Reachability targets (social networks, anti-bot front pages): ANY HTTP answer proves that
    /// TLS and HTTP got through, even a 403 for a program that is not a browser.
    pub any_status: bool,
}

pub const TARGETS: &[Target] = &[
    Target { name: "Cloudflare 300 KB", url: "https://speed.cloudflare.com/__down?bytes=300000", min_bytes: 300_000, any_status: false },
    Target { name: "Discord", url: "https://discord.com/api/v9/gateway", min_bytes: 1, any_status: false },
    Target { name: "YouTube", url: "https://www.youtube.com/generate_204", min_bytes: 0, any_status: false },
    // the video servers are a different host (and often a different rule) than the page
    Target { name: "YouTube video", url: "https://redirector.googlevideo.com/generate_204", min_bytes: 0, any_status: true },
    Target { name: "Instagram", url: "https://www.instagram.com/", min_bytes: 0, any_status: true },
    Target { name: "X (Twitter)", url: "https://x.com/", min_bytes: 0, any_status: true },
    Target { name: "Telegram", url: "https://web.telegram.org/", min_bytes: 0, any_status: true },
    Target { name: "WhatsApp", url: "https://web.whatsapp.com/", min_bytes: 0, any_status: true },
    // developer hosting: Roskomnadzor started to block *.vercel.app / *.netlify.app in 2026
    Target { name: "Vercel", url: "https://vercel.com/", min_bytes: 0, any_status: true },
    Target { name: "Netlify", url: "https://www.netlify.com/", min_bytes: 0, any_status: true },
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

    fn failed(name: &str, note: String) -> Self {
        Self { name: name.to_owned(), ok: false, code: 0, bytes: 0, secs: 0.0, note }
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

/// What a curl exit code means for a bypass test, in plain words. The old "no data (blocked,
/// reset or timed out)" lumped together causes that need opposite fixes.
pub fn explain_exit(code: i32, stderr: &str) -> String {
    let first = stderr.lines().map(str::trim).find(|l| !l.is_empty()).unwrap_or("");
    let short: String = first.chars().take(110).collect();
    let revocation = stderr.to_ascii_lowercase().contains("revocation");
    let what = match code {
        35 | 60 if revocation => "certificate revocation check failed (not a block: the test itself was disturbed)",
        6 => "DNS did not resolve the name (DNS blocked or poisoned)",
        7 => "connection refused or dropped while connecting",
        28 if stderr.contains("Connection timed out after") => "connect timed out: the server's IP does not answer at all (IP-level block or poisoned DNS; an SNI/TLS strategy cannot fix that)",
        28 => "timed out: packets are being dropped (typical for blocking or throttling)",
        35 => "TLS handshake failed (the connection was cut during the handshake)",
        52 => "server closed the connection without an answer",
        55 | 56 => "connection reset while transferring",
        60 => "certificate was not accepted",
        _ => "curl failed",
    };
    if short.is_empty() { format!("{what} [curl {code}]") } else { format!("{what} [curl {code}: {short}]") }
}

/// Verdict for one download. `curl_ok`: curl itself exited with 0.
pub fn judge(t: &Target, curl_ok: bool, code: u32, bytes: u64, secs: f64, why: &str) -> WebResult {
    let status_ok = if t.any_status { (100..600).contains(&code) } else { (200..400).contains(&code) };
    let ok = curl_ok && status_ok && bytes >= t.min_bytes;
    let note = if ok {
        String::new()
    } else if !curl_ok && (12_000..=24_000).contains(&bytes) && t.min_bytes > 24_000 {
        format!("connection cut after {bytes} bytes: the typical ~16 KB TSPU throttle of Cloudflare-hosted sites")
    } else if !curl_ok && bytes > 0 {
        format!("transfer broke after {bytes} bytes; {why}")
    } else if !curl_ok {
        why.to_owned()
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

pub fn null_device() -> &'static str {
    if cfg!(windows) { "NUL" } else { "/dev/null" }
}

/// Browser-like identity: some front pages answer a bare curl with an error page or nothing.
const USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36";

/// `curl` with an absolute path (this program runs elevated, so PATH is not trusted), no console
/// window, no stdin, HTTPS only (also for redirects) and TLS 1.2+.
pub fn curl_command() -> Command {
    let mut cmd = Command::new(crate::util::system_tool("curl"));
    cmd.args(["--proto", "=https", "--proto-redir", "=https", "--tlsv1.2"]).stdin(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    cmd
}

fn fetch_once(t: &Target, timeout: Duration) -> WebResult {
    let mut cmd = curl_command();
    // --ssl-no-revoke: curl on Windows (Schannel) asks the CA's OCSP/CRL server whether the
    // certificate was revoked. Those are separate plain-HTTP requests that blocking and the
    // strategies themselves break, so a working bypass looked like a failure ("YouTube FAIL" while
    // the browser, which does not do this, opened it). We test reachability, not PKI.
    cmd.args(["-sS", "--ssl-no-revoke", "-L", "--max-redirs", "3", "-A", USER_AGENT, "-o", null_device(), "--connect-timeout", "5", "-m"])
        .arg(timeout.as_secs().to_string())
        .args(["-w", "%{http_code} %{size_download} %{time_total}", t.url]);
    match cmd.output() {
        Ok(o) => {
            let text = String::from_utf8_lossy(&o.stdout);
            let err = String::from_utf8_lossy(&o.stderr);
            let why = explain_exit(o.status.code().unwrap_or(-1), &err);
            match parse_write_out(&text) {
                Some((code, bytes, secs)) => judge(t, o.status.success(), code, bytes, secs, &why),
                None => WebResult::failed(t.name, why),
            }
        }
        Err(e) => WebResult::failed(t.name, format!("cannot run curl: {e}")),
    }
}

/// One retry for a QUICK failure (a reset): the very first connection after the engine starts is
/// the flakiest. A timeout is not retried, it already used the whole budget.
pub fn fetch(t: &Target, timeout: Duration) -> WebResult {
    let t0 = std::time::Instant::now();
    let first = fetch_once(t, timeout);
    if first.ok || t0.elapsed() > timeout / 2 {
        return first;
    }
    let second = fetch_once(t, timeout);
    if second.ok { second } else { first }
}

/// Is `curl` available at all?
pub fn curl_available() -> bool {
    curl_command().arg("--version").stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok_and(|s| s.success())
}

/// The failure happened BEFORE any TLS: the server's address does not answer the very first packet
/// (or DNS gave nothing). No desync strategy can change that, it is an IP-level block or a
/// poisoned DNS answer. `tune --bypass` uses this to stop waiting for such sites.
pub fn connect_blocked(r: &WebResult) -> bool {
    !r.ok && r.bytes == 0 && (r.note.contains("connect timed out") || r.note.contains("DNS did not resolve") || r.note.starts_with("skipped"))
}

/// Result for a site that is not tested again because it cannot be fixed by a strategy.
fn skipped(t: &Target) -> WebResult {
    WebResult::failed(t.name, "skipped: IP-level block or poisoned DNS (no strategy can fix it)".into())
}

/// Runs every target at the same time (the slowest one decides how long this takes). Targets named
/// in `skip` are not requested; they are reported as failed without costing any time.
pub fn probe_skip(timeout: Duration, skip: &[String]) -> Vec<WebResult> {
    std::thread::scope(|s| {
        let handles: Vec<_> = TARGETS
            .iter()
            .map(|t| {
                let skip_it = skip.iter().any(|n| n == t.name);
                s.spawn(move || if skip_it { skipped(t) } else { fetch(t, timeout) })
            })
            .collect();
        handles.into_iter().zip(TARGETS).map(|(h, t)| h.join().unwrap_or_else(|_| WebResult::failed(t.name, "probe crashed".into()))).collect()
    })
}

/// Runs every target at the same time (the slowest one decides how long this takes).
pub fn probe(timeout: Duration) -> Vec<WebResult> {
    probe_skip(timeout, &[])
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
        let r = judge(cf, false, 200, 16_384, 10.0, "timed out");
        assert!(!r.ok);
        assert!(r.note.contains("16 KB"), "{}", r.note);
        assert!(judge(cf, true, 200, 300_000, 0.9, "").ok);
        assert!(!judge(cf, true, 200, 5_000, 0.9, "").ok, "a short body is not a pass");
        let yt = TARGETS.iter().find(|t| t.name == "YouTube").unwrap();
        assert!(judge(yt, true, 204, 0, 0.2, "").ok, "204 without a body passes");
        assert!(!judge(yt, true, 503, 0, 0.2, "").ok);
    }

    #[test]
    fn any_answer_proves_reachability_for_social_networks() {
        for name in ["Instagram", "X (Twitter)", "Telegram", "WhatsApp"] {
            let t = TARGETS.iter().find(|t| t.name == name).unwrap();
            assert!(judge(t, true, 403, 1500, 0.4, "").ok, "{name}: a 403 from an anti-bot wall still means TLS got through");
            assert!(!judge(t, false, 0, 0, 0.0, "timed out").ok);
        }
    }

    #[test]
    fn unanswered_syn_is_told_apart_from_a_later_drop() {
        let t = &TARGETS[1];
        let syn = explain_exit(28, "curl: (28) Connection timed out after 5004 milliseconds");
        let later = explain_exit(28, "curl: (28) Operation timed out after 10000 milliseconds with 0 bytes received");
        let r = judge(t, false, 0, 0, 0.0, &syn);
        assert!(connect_blocked(&r), "{}", r.note);
        assert!(!connect_blocked(&judge(t, false, 0, 0, 0.0, &later)), "a drop after the handshake CAN be an SNI block");
        assert!(connect_blocked(&judge(t, false, 0, 0, 0.0, &explain_exit(6, ""))));
        assert!(!connect_blocked(&judge(t, true, 200, 10, 0.1, "")));
    }

    #[test]
    fn skipped_sites_cost_no_time_and_count_as_failed() {
        let names: Vec<String> = TARGETS.iter().map(|t| t.name.to_owned()).collect();
        let t0 = std::time::Instant::now();
        let r = probe_skip(Duration::from_secs(1), &names);
        assert!(t0.elapsed() < Duration::from_millis(500));
        assert_eq!(r.len(), TARGETS.len());
        assert!(r.iter().all(|x| !x.ok && x.note.starts_with("skipped")));
    }

    #[test]
    fn failures_say_why() {
        let t = &TARGETS[1];
        assert!(judge(t, false, 0, 0, 0.0, &explain_exit(28, "")).note.contains("timed out"));
        assert!(explain_exit(6, "curl: (6) Could not resolve host").contains("DNS"));
        assert!(explain_exit(35, "schannel: ... CRYPT_E_NO_REVOCATION_CHECK").contains("[curl 35"));
        assert!(explain_exit(60, "revocation").contains("revocation"));
    }

    #[test]
    fn open_targets_beat_speed() {
        let ok = |s| WebResult { name: "a".into(), ok: true, code: 200, bytes: 1, secs: s, note: String::new() };
        let bad = WebResult::failed("b", String::new());
        let slow_but_open = [ok(9.0), ok(9.0), ok(9.0)];
        let fast_but_blocked = [ok(0.1), ok(0.1), bad];
        assert!(score(&slow_but_open) < score(&fast_but_blocked));
    }
}
