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

//! Honest tunnel verification.
//!
//! `warp-cli status` saying "Connected" only means the daemon finished its handshake. It says
//! nothing about whether packets actually flow through the tunnel, and pinging 1.1.1.1 proves even
//! less: that address answers with or without WARP. Cloudflare's own trace endpoint reports
//! `warp=on|plus|off` for the very connection that asked, so it is the one check that cannot be
//! fooled by a half-up tunnel, a local router that owns 1.1.1.1, or a stale "Connected".

use std::time::{Duration, Instant};

use crate::probe::{self, Options};
use crate::ui::tr;
use crate::stats::{self, Summary};
use crate::warp::Warp;
use crate::web;

pub const TRACE_URL: &str = "https://www.cloudflare.com/cdn-cgi/trace";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WarpFlag {
    On,
    Plus,
    Off,
    Unknown,
}

impl WarpFlag {
    pub fn through_tunnel(self) -> bool {
        matches!(self, WarpFlag::On | WarpFlag::Plus)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trace {
    pub warp: WarpFlag,
    /// Cloudflare data centre that answered (`FRA`, `AMS`, ...).
    pub colo: String,
    pub ip: String,
    pub loc: String,
}

/// Parses the `key=value` lines of `/cdn-cgi/trace`. Anything else (the timing line we append) is ignored.
pub fn parse_trace(text: &str) -> Trace {
    let mut t = Trace { warp: WarpFlag::Unknown, colo: String::new(), ip: String::new(), loc: String::new() };
    for line in text.lines() {
        let Some((k, v)) = line.trim().split_once('=') else { continue };
        let v = v.trim();
        match k.trim() {
            "warp" => {
                t.warp = match v {
                    "on" => WarpFlag::On,
                    "plus" => WarpFlag::Plus,
                    "off" => WarpFlag::Off,
                    _ => WarpFlag::Unknown,
                }
            }
            "colo" => t.colo = v.to_owned(),
            "ip" => t.ip = v.to_owned(),
            "loc" => t.loc = v.to_owned(),
            _ => {}
        }
    }
    t
}

/// A trace is only believed if it looks like Cloudflare's answer (it has a `colo`), not like a
/// captive-portal page that happens to contain an equals sign.
pub fn trace_is_genuine(t: &Trace) -> bool {
    t.warp != WarpFlag::Unknown && !t.colo.is_empty()
}

pub fn fetch_trace(timeout_s: u64) -> Result<Trace, String> {
    let out = web::curl_command()
        .args(["-sS", "--ssl-no-revoke", "--connect-timeout", "5", "-m", &timeout_s.to_string(), TRACE_URL])
        .output()
        .map_err(|e| format!("cannot run curl: {e}"))?;
    if !out.status.success() {
        let e = String::from_utf8_lossy(&out.stderr);
        return Err(e.trim().lines().last().unwrap_or("request failed").to_owned());
    }
    let t = parse_trace(&String::from_utf8_lossy(&out.stdout));
    if trace_is_genuine(&t) { Ok(t) } else { Err("the answer is not Cloudflare's trace (a captive portal or a filter in the way?)".into()) }
}

/// Waits until the daemon says Connected AND the trace confirms `warp=on|plus` twice in a row
/// (one sighting can be a stale connection that is just being torn down). `Ok` carries the trace;
/// `Err` says why the tunnel is not usable.
pub fn wait_tunnel_on(warp: &Warp, timeout: Duration) -> Result<Trace, String> {
    let t0 = Instant::now();
    let mut streak = 0;
    let mut last = String::from("daemon is not connected");
    loop {
        if warp.is_connected() {
            match fetch_trace(6) {
                Ok(t) if t.warp.through_tunnel() => {
                    streak += 1;
                    if streak >= 2 {
                        return Ok(t);
                    }
                }
                Ok(_) => {
                    streak = 0;
                    last = "WARP reports Connected, but your traffic does NOT go through it (warp=off)".into();
                }
                Err(e) => {
                    streak = 0;
                    last = format!("no answer from Cloudflare through the tunnel: {e}");
                }
            }
        } else {
            streak = 0;
            last = format!("daemon is not connected {}", crate::warp::status_reason(&warp.status_text()));
        }
        if t0.elapsed() >= timeout {
            return Err(last);
        }
        std::thread::sleep(Duration::from_millis(if streak > 0 { 400 } else { 700 }));
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Grade {
    Good,
    Fair,
    Bad,
    /// Numbers exist but cannot be trusted (not through the tunnel, too few replies, ICMP/TCP disagree).
    Unverified,
}

pub struct Report {
    pub target: String,
    /// `None` when the report is for a plain bypass (no tunnel expected).
    pub trace: Option<Result<Trace, String>>,
    pub icmp: Option<Summary>,
    pub tcp: Option<Summary>,
    pub download: Option<web::WebResult>,
    pub notes: Vec<String>,
    pub grade: Grade,
}

/// Pure decision, separated from the measuring so that it can be tested.
pub fn grade(expect_tunnel: bool, trace: Option<&Result<Trace, String>>, main: Option<&Summary>, disagree: bool, download_ok: Option<bool>) -> Grade {
    if expect_tunnel && !matches!(trace, Some(Ok(t)) if t.warp.through_tunnel()) {
        return Grade::Unverified;
    }
    let Some(s) = main else { return Grade::Bad };
    if !stats::reliable(s) || disagree {
        return Grade::Unverified;
    }
    if download_ok == Some(false) {
        return Grade::Bad;
    }
    // the same scale as the `check` verdict and the live panel (see `stats::level`)
    match stats::level(s) {
        stats::Level::Bad => Grade::Bad,
        stats::Level::Fair => Grade::Fair,
        stats::Level::Good => Grade::Good,
    }
}

/// The post-connection test. Order matters: first prove the tunnel carries traffic, then measure.
pub fn full_check(target: &str, count: u32, expect_tunnel: bool) -> Report {
    let mut notes = Vec::new();
    let trace = expect_tunnel.then(|| fetch_trace(8));
    if let Some(Ok(t)) = &trace {
        if !t.warp.through_tunnel() {
            notes.push("traffic bypasses the tunnel: the numbers below describe your normal connection, not WARP".to_owned());
        }
    }
    let o = Options { count, interval_ms: 200, warmup: true, tunnel_stats: false, ..Options::default() };
    let ip = probe::resolve_v4(target);
    let (mut icmp, mut tcp) = (None, None);
    if let Some(ip) = ip {
        icmp = probe::measure_icmp(ip, &o).ok().and_then(|t| stats::summarize(&t, o.count));
        let o2 = Options { count: (count / 2).max(6), ..Options { warmup: false, ..Options::default() } };
        tcp = stats::summarize(&probe::measure_tcp(ip, 443, &o2), o2.count);
    } else {
        notes.push(format!("cannot resolve {target}"));
    }
    let disagree = matches!((&icmp, &tcp), (Some(a), Some(b)) if probe::methods_disagree(a.median, b.median));
    if disagree {
        notes.push("ICMP and TCP latencies differ a lot: something in between answers for the host, do not trust the ping".to_owned());
    }
    let main = icmp.as_ref().or(tcp.as_ref());
    if icmp.is_none() && tcp.is_some() {
        notes.push("ICMP is filtered, using TCP-connect timing".to_owned());
    }
    if let Some(Err(e)) = &trace {
        notes.push(format!("{}: {e}", tr("туннель не подтверждён", "tunnel not confirmed")));
    }
    if let Some(s) = icmp.as_ref().or(tcp.as_ref()) {
        if !stats::reliable(s) {
            notes.push(format!("{} ({}/{})", tr("слишком мало ответов для вывода", "too few replies to conclude"), s.received, s.sent));
        }
    }
    let download = web::curl_available().then(|| web::fetch(&web::TARGETS[0], Duration::from_secs(12)));
    let grade = grade(expect_tunnel, trace.as_ref(), main, disagree, download.as_ref().map(|d| d.ok));
    Report { target: target.to_owned(), trace, icmp, tcp, download, notes, grade }
}

fn lat_line(label: &str, s: &Summary) -> String {
    use crate::util::fmt_ms;
    format!(
        "{} {} · {} {} · p95 {} · {} {} · {} {}% ({}/{})",
        crate::ui::paint(crate::ui::DIM, &crate::ui::pad(label, 4)),
        crate::ui::paint(crate::ui::BOLD, &format!("{} ms", fmt_ms(s.median))),
        tr("мин", "min"),
        fmt_ms(s.min),
        fmt_ms(s.p95),
        tr("джиттер", "jitter"),
        fmt_ms(s.jitter),
        tr("потери", "loss"),
        s.loss_pct,
        s.received,
        s.sent
    )
}

/// Prints the report as a panel with an honest verdict.
pub fn print_report(r: &Report) {
    use crate::ui::{self, kv, GREEN, RED, YELLOW};
    let mut lines = Vec::new();
    match &r.trace {
        None => lines.push(kv(tr("Туннель", "Tunnel"), tr("не используется (обход без WARP)", "not used (bypass without WARP)"))),
        Some(Ok(t)) if t.warp.through_tunnel() => lines.push(kv(
            tr("Туннель", "Tunnel"),
            &format!("{} warp={} · {} {} · {}", ui::dot(GREEN), if t.warp == WarpFlag::Plus { "plus" } else { "on" }, tr("дата-центр", "data centre"), t.colo, t.loc),
        )),
        Some(Ok(_)) => lines.push(kv(tr("Туннель", "Tunnel"), &format!("{} {}", ui::dot(RED), tr("трафик идёт МИМО WARP (warp=off)", "traffic bypasses WARP (warp=off)")))),
        Some(Err(e)) => lines.push(kv(tr("Туннель", "Tunnel"), &format!("{} {}", ui::dot(RED), ui::clip(e, 50)))),
    }
    lines.push(kv(tr("Хост", "Host"), &r.target));
    if let Some(s) = &r.icmp {
        lines.push(lat_line("ICMP", s));
    }
    if let Some(s) = &r.tcp {
        lines.push(lat_line("TCP", s));
    }
    if r.icmp.is_none() && r.tcp.is_none() {
        lines.push(kv(tr("Ответы", "Replies"), &format!("{} {}", ui::dot(RED), tr("нет ни ICMP, ни TCP 443", "none, neither ICMP nor TCP 443"))));
    }
    if let Some(d) = &r.download {
        let (c, txt) = if d.ok { (GREEN, format!("{} {:.1} s", tr("300 КБ скачано за", "300 KB downloaded in"), d.secs)) } else { (RED, format!("{}: {}", tr("загрузка не удалась", "download failed"), ui::clip(&d.note, 38))) };
        lines.push(kv(tr("Загрузка", "Download"), &format!("{} {}", ui::dot(c), ui::clip(&txt, 52))));
    }
    let (code, verdict) = match r.grade {
        Grade::Good => (GREEN, tr("Хорошо: потерь нет, джиттер низкий", "Good: no loss, low jitter")),
        Grade::Fair => (YELLOW, tr("Терпимо: есть джиттер или потери. Попробуйте `netfreedom tune`", "Fair: some jitter or loss. Try `netfreedom tune`")),
        Grade::Bad => (RED, tr("Плохо: потери, сильный джиттер или не работает загрузка. `netfreedom tune` подберёт стратегию", "Bad: loss, heavy jitter or a failing download. `netfreedom tune` finds a better strategy")),
        Grade::Unverified => (YELLOW, tr("НЕ ПОДТВЕРЖДЕНО: цифрам нельзя доверять (см. ниже)", "UNVERIFIED: do not trust these numbers (see below)")),
    };
    lines.push(String::new());
    for (i, l) in ui::wrap(verdict, 62).iter().enumerate() {
        lines.push(format!("{} {}", if i == 0 { ui::dot(code) } else { " ".to_owned() }, ui::paint(code, l)));
    }
    for n in &r.notes {
        for (i, l) in ui::wrap(n, 60).iter().enumerate() {
            lines.push(format!("{} {l}", if i == 0 { " -" } else { "  " }));
        }
    }
    ui::panel(tr("Проверка качества", "Quality check"), &lines);
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "fl=29f\nh=www.cloudflare.com\nip=203.0.113.9\nts=1.2\nvisit_scheme=https\nuag=curl\ncolo=FRA\nsliver=none\nhttp=http/2\nloc=DE\ntls=TLSv1.3\nsni=plaintext\nwarp=on\ngateway=off\nrbi=off\nkex=X25519";

    fn s(med: f64, jit: f64, loss: f64, sent: u32) -> Summary {
        let received = (sent as f64 * (1.0 - loss / 100.0)).round() as u32;
        Summary { sent, received, loss_pct: loss, min: med, median: med, avg: med, p95: med, max: med, stdev: 0.0, jitter: jit }
    }

    #[test]
    fn trace_parsing() {
        let t = parse_trace(SAMPLE);
        assert_eq!((t.warp, t.colo.as_str(), t.ip.as_str(), t.loc.as_str()), (WarpFlag::On, "FRA", "203.0.113.9", "DE"));
        assert!(trace_is_genuine(&t));
        assert_eq!(parse_trace("warp=plus\ncolo=AMS\n").warp, WarpFlag::Plus);
        assert_eq!(parse_trace(&SAMPLE.replace("warp=on", "warp=off")).warp, WarpFlag::Off);
        assert!(!trace_is_genuine(&parse_trace("<html>Login to the Wi-Fi a=b</html>")));
        assert!(!trace_is_genuine(&parse_trace("warp=on")), "no colo, not Cloudflare's answer");
    }

    #[test]
    fn grading_refuses_to_flatter() {
        let on: Result<Trace, String> = Ok(parse_trace(SAMPLE));
        let off: Result<Trace, String> = Ok(parse_trace(&SAMPLE.replace("warp=on", "warp=off")));
        let good = s(24.0, 1.0, 0.0, 25);
        assert_eq!(grade(true, Some(&on), Some(&good), false, Some(true)), Grade::Good);
        // the old behaviour: a perfect-looking ping while the tunnel is not carrying the traffic
        assert_eq!(grade(true, Some(&off), Some(&good), false, Some(true)), Grade::Unverified);
        assert_eq!(grade(true, Some(&Err("timeout".into())), Some(&good), false, Some(true)), Grade::Unverified);
        assert_eq!(grade(false, None, Some(&good), false, Some(true)), Grade::Good, "plain bypass expects no tunnel");
        assert_eq!(grade(true, Some(&on), Some(&s(24.0, 1.0, 0.0, 3)), false, None), Grade::Unverified, "3 probes are not a test");
        assert_eq!(grade(true, Some(&on), Some(&good), true, None), Grade::Unverified, "ICMP and TCP disagree");
        assert_eq!(grade(true, Some(&on), Some(&s(24.0, 9.0, 0.0, 25)), false, None), Grade::Good, "jitter up to 10 ms is 'good' in the check verdict too");
        assert_eq!(grade(true, Some(&on), Some(&s(24.0, 12.0, 0.0, 25)), false, None), Grade::Fair);
        assert_eq!(grade(true, Some(&on), Some(&s(24.0, 16.0, 0.0, 25)), false, None), Grade::Bad);
        assert_eq!(grade(true, Some(&on), Some(&s(24.0, 2.0, 8.0, 25)), false, None), Grade::Bad);
        assert_eq!(grade(true, Some(&on), Some(&good), false, Some(false)), Grade::Bad, "a stalled download is bad whatever the ping says");
        assert_eq!(grade(true, Some(&on), None, false, None), Grade::Bad);
    }
}
