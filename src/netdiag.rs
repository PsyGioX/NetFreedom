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

//! Network diagnostics that the tunnel tests cannot give: what is wrong INSIDE the home network.
//!
//!   * link type (Wi-Fi or a cable) and the traffic that is already flowing in the background;
//!   * latency UNDER LOAD (bufferbloat). A speed test and an idle ping both look fine on a line
//!     whose queues fill up the moment somebody downloads or uploads: the game's packets then wait
//!     behind that traffic. The only test is to saturate the line and ping while it is saturated.
//!
//! `netfreedom check <host> --load` runs the load test, `netfreedom doctor --net` runs all of it.
//! The load is generated with the system `curl` (HTTPS only), nothing is bundled or installed.

use std::io::Write;
use std::net::Ipv4Addr;
use std::process::Stdio;
use std::time::{Duration, Instant};

use crate::probe::{self, Via};
use crate::stats::{self, Summary};
use crate::ui::{self, dot, kv, tr, DIM, GREEN, RED, YELLOW};
use crate::util::fmt_ms;
use crate::web;

// ----------------------------------------------------------------------------------- link type

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkKind {
    Wired,
    Wifi { signal_pct: Option<u32> },
    /// The default route goes through a virtual interface (VPN, WARP, bridge): the physical link is unknown.
    Virtual,
    Other,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    pub kind: LinkKind,
    pub iface: String,
}

/// Interface of the default route in `/proc/net/route` (lowest metric wins).
pub fn default_iface(route: &str) -> Option<String> {
    route
        .lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            // Iface Destination Gateway Flags RefCnt Use Metric Mask ...
            (f.len() >= 8 && f[1] == "00000000" && f[7] == "00000000").then(|| (f[6].parse::<u32>().unwrap_or(u32::MAX), f[0].to_owned()))
        })
        .min_by_key(|(metric, _)| *metric)
        .map(|(_, iface)| iface)
}

/// Pure classification from what sysfs says about an interface.
pub fn link_kind_for(has_wireless: bool, has_device: bool, if_type: Option<u32>) -> LinkKind {
    if has_wireless {
        LinkKind::Wifi { signal_pct: None }
    } else if !has_device {
        LinkKind::Virtual
    } else if if_type == Some(1) {
        LinkKind::Wired
    } else {
        LinkKind::Other
    }
}

/// Received and sent bytes of `iface` from `/proc/net/dev`.
pub fn parse_proc_net_dev(text: &str, iface: &str) -> Option<(u64, u64)> {
    for l in text.lines() {
        let Some((name, rest)) = l.split_once(':') else { continue };
        if name.trim() != iface {
            continue;
        }
        let f: Vec<&str> = rest.split_whitespace().collect();
        return Some((f.first()?.parse().ok()?, f.get(8)?.parse().ok()?));
    }
    None
}

/// Signal strength from `netsh wlan show interfaces`. The labels are localised (and the console
/// code page garbles non-ASCII), so this looks for the one value that ends with a percent sign.
pub fn parse_netsh_signal(text: &str) -> Option<u32> {
    text.lines().filter_map(|l| l.split_once(':')).find_map(|(_, v)| v.trim().strip_suffix('%')?.trim().parse::<u32>().ok().filter(|p| *p <= 100))
}

#[cfg(unix)]
pub fn link() -> Link {
    use std::path::Path;
    let unknown = Link { kind: LinkKind::Unknown, iface: String::new() };
    let route = std::fs::read_to_string("/proc/net/route").unwrap_or_default();
    let Some(iface) = default_iface(&route) else { return unknown };
    if iface.contains('/') || iface.contains("..") {
        return unknown;
    }
    let base = format!("/sys/class/net/{iface}");
    let has_wireless = Path::new(&format!("{base}/wireless")).is_dir() || Path::new(&format!("{base}/phy80211")).exists();
    let has_device = Path::new(&format!("{base}/device")).exists();
    let if_type = std::fs::read_to_string(format!("{base}/type")).ok().and_then(|t| t.trim().parse().ok());
    Link { kind: link_kind_for(has_wireless, has_device, if_type), iface }
}

#[cfg(windows)]
pub fn link() -> Link {
    use std::os::windows::process::CommandExt;
    use std::process::Command;
    let mut cmd = Command::new(crate::util::system_tool("netsh"));
    cmd.args(["wlan", "show", "interfaces"]).stdin(Stdio::null());
    cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    // A connected Wi-Fi adapter reports a signal strength. That says Wi-Fi is up, not that the
    // default route uses it, so the wording in `print_link` stays careful.
    let signal = cmd.output().ok().and_then(|o| parse_netsh_signal(&String::from_utf8_lossy(&o.stdout)));
    match signal {
        Some(p) => Link { kind: LinkKind::Wifi { signal_pct: Some(p) }, iface: String::new() },
        None => Link { kind: LinkKind::Unknown, iface: String::new() },
    }
}

/// Bytes per second flowing through the default interface right now (both directions), measured
/// over one second. Linux only; `None` where it cannot be read.
#[cfg(unix)]
pub fn background_rate() -> Option<f64> {
    let route = std::fs::read_to_string("/proc/net/route").ok()?;
    let iface = default_iface(&route)?;
    let read = || std::fs::read_to_string("/proc/net/dev").ok().and_then(|t| parse_proc_net_dev(&t, &iface));
    let (r0, t0) = read()?;
    std::thread::sleep(Duration::from_secs(1));
    let (r1, t1) = read()?;
    Some((r1.saturating_sub(r0) + t1.saturating_sub(t0)) as f64)
}

#[cfg(windows)]
pub fn background_rate() -> Option<f64> {
    None
}

/// Background traffic above this (about 4 Mbit/s) is worth a hint: it competes with the game.
pub const BUSY_BYTES_S: f64 = 500_000.0;

// ----------------------------------------------------------------------------- load generation

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    Down,
    Up,
}

/// Where the load comes from. `extra_curl_args` is empty in production; it exists so that the
/// whole pipeline can be exercised against a local test server.
#[derive(Debug, Clone)]
pub struct LoadUrls {
    pub down: String,
    pub up: String,
    pub extra_curl_args: Vec<String>,
}

impl LoadUrls {
    /// The same Cloudflare speed endpoint the unblock check already uses.
    pub fn cloudflare() -> Self {
        Self { down: "https://speed.cloudflare.com/__down?bytes=100000000".into(), up: "https://speed.cloudflare.com/__up".into(), extra_curl_args: Vec::new() }
    }
}

/// Parallel curl processes per direction: one TCP stream often cannot fill a fast line.
const LOAD_STREAMS: usize = 4;
/// Load that never got going (below about 2 Mbit/s) proves nothing about queues.
pub const MIN_LOAD_BYTES_S: f64 = 250_000.0;

/// The curl command line of one load stream. `secs` is curl's own `-m`, so that every stream ends
/// by itself and still prints its statistics.
pub fn load_args(dir: Dir, url: &str, secs: u64, extra: &[String]) -> Vec<String> {
    let mut v: Vec<String> = ["-sS", "--ssl-no-revoke", "--connect-timeout", "6", "-m"].iter().map(|s| (*s).to_owned()).collect();
    v.push(secs.to_string());
    v.extend(extra.iter().cloned());
    if dir == Dir::Up {
        // the body is streamed from stdin (zeros); the server only has to swallow it
        v.extend(["-X", "POST", "-T", "-", "-H", "Content-Type: application/octet-stream"].iter().map(|s| (*s).to_owned()));
    }
    v.extend(["-o".to_owned(), web::null_device().to_owned(), "-w".to_owned(), "%{http_code} %{size_download} %{size_upload}".to_owned(), url.to_owned()]);
    v
}

/// `(http code, bytes downloaded, bytes uploaded)` from curl's `-w` output.
pub fn parse_load_out(out: &str) -> Option<(u32, u64, u64)> {
    let mut it = out.split_whitespace();
    Some((it.next()?.parse().ok()?, it.next()?.parse().ok()?, it.next()?.parse().ok()?))
}

/// One load stream: restarts curl when a transfer ends early (a fast line finishes 100 MB in
/// seconds) until `deadline`. Returns the bytes moved in the loaded direction.
fn worker(dir: Dir, urls: &LoadUrls, deadline: Instant) -> u64 {
    let mut bytes = 0u64;
    let mut bad = 0u32;
    while Instant::now() + Duration::from_millis(1500) < deadline && bad < 3 {
        let left = deadline.saturating_duration_since(Instant::now()).as_secs().max(2);
        let url = if dir == Dir::Down { &urls.down } else { &urls.up };
        let mut cmd = web::curl_command();
        cmd.args(load_args(dir, url, left, &urls.extra_curl_args)).stdout(Stdio::piped()).stderr(Stdio::null());
        if dir == Dir::Up {
            cmd.stdin(Stdio::piped());
        }
        let Ok(mut child) = cmd.spawn() else { return bytes };
        let feeder = if dir == Dir::Up {
            child.stdin.take().map(|mut stdin| {
                std::thread::spawn(move || {
                    let chunk = vec![0u8; 64 * 1024];
                    while stdin.write_all(&chunk).is_ok() {} // ends when curl exits (broken pipe)
                })
            })
        } else {
            None
        };
        let out = child.wait_with_output();
        if let Some(f) = feeder {
            let _ = f.join();
        }
        match out.ok().and_then(|o| parse_load_out(&String::from_utf8_lossy(&o.stdout))) {
            Some((code, down, up)) => {
                let moved = if dir == Dir::Down { down } else { up };
                if moved > 0 && !(400..600).contains(&code) {
                    bytes += moved;
                } else {
                    bad += 1;
                }
            }
            None => bad += 1,
        }
    }
    bytes
}

/// Pings `ip` every 200 ms for `dur`. A probe that never comes back costs its whole 2 s timeout
/// (a loaded line can hold a packet for more than a second), so the time, not the count, is fixed.
fn sample_for(ip: Ipv4Addr, via: Via, dur: Duration) -> (Vec<f64>, u32) {
    let end = Instant::now() + dur;
    let mut pinger = if via == Via::Icmp { probe::Pinger::new(ip, 2000) } else { None };
    let (mut times, mut sent) = (Vec::new(), 0u32);
    while Instant::now() < end {
        let t0 = Instant::now();
        let r = match (&mut pinger, via) {
            (_, Via::Tcp443) => probe::tcp_sample(ip, 2000),
            (Some(p), Via::Icmp) => p.ping(),
            (None, Via::Icmp) => None,
        };
        sent += 1;
        if let Some(t) = r {
            times.push(t);
        }
        if let Some(rest) = Duration::from_millis(200).checked_sub(t0.elapsed()) {
            std::thread::sleep(rest);
        }
    }
    (times, sent)
}

#[derive(Debug, Clone)]
pub struct LoadResult {
    pub dir: Dir,
    pub loaded: Option<Summary>,
    pub sent: u32,
    pub rate_bytes_s: f64,
}

pub fn measure_under_load(ip: Ipv4Addr, via: Via, dir: Dir, urls: &LoadUrls, measure: Duration) -> LoadResult {
    let ramp = Duration::from_secs(2); // let the queues fill before the first probe counts
    let total = ramp + measure + Duration::from_secs(1);
    let deadline = Instant::now() + total;
    let ((times, sent), bytes) = std::thread::scope(|s| {
        let handles: Vec<_> = (0..LOAD_STREAMS).map(|_| s.spawn(|| worker(dir, urls, deadline))).collect();
        std::thread::sleep(ramp);
        let sampled = sample_for(ip, via, measure);
        let bytes: u64 = handles.into_iter().map(|h| h.join().unwrap_or(0)).sum();
        (sampled, bytes)
    });
    LoadResult { dir, loaded: stats::summarize(&times, sent), sent, rate_bytes_s: bytes as f64 / total.as_secs_f64() }
}

// ------------------------------------------------------------------------------------ judgement

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bloat {
    Fine,
    Noticeable,
    Severe,
    /// The load did not run properly or there was too little data: no conclusion.
    Inconclusive,
}

/// Project heuristics (not an industry standard): added median latency under load of up to 20 ms
/// is fine, up to 60 ms is noticeable in a game, beyond that (or with real loss) it is severe.
/// Returns the verdict and the added latency when it could be measured.
pub fn bloat_grade(idle: &Summary, r: &LoadResult) -> (Bloat, Option<f64>) {
    if !stats::reliable(idle) || r.rate_bytes_s < MIN_LOAD_BYTES_S || r.sent < 5 {
        return (Bloat::Inconclusive, None);
    }
    let Some(l) = &r.loaded else { return (Bloat::Severe, None) }; // the load ran and nothing answered
    if l.received * 2 < l.sent {
        return (Bloat::Severe, None); // the line collapses under load
    }
    let added = (l.median - idle.median).max(0.0);
    let b = if added > 60.0 || l.loss_pct > 5.0 {
        Bloat::Severe
    } else if added > 20.0 || l.loss_pct > 1.0 {
        Bloat::Noticeable
    } else {
        Bloat::Fine
    };
    (b, Some(added))
}

#[derive(Debug, Clone)]
pub struct LoadReport {
    pub target: String,
    pub via: Via,
    pub idle: Summary,
    pub down: LoadResult,
    pub up: LoadResult,
}

pub fn run_load_test(target: &str, urls: &LoadUrls, measure: Duration) -> Result<LoadReport, String> {
    if !web::curl_available() {
        return Err("curl was not found: the load test needs it (it ships with Windows 10+ and Linux)".into());
    }
    let ip = probe::resolve_v4(target).ok_or_else(|| format!("cannot resolve an IPv4 address for \"{target}\""))?;
    let via = probe::detect_method(target).ok_or_else(|| format!("{target} does not answer, neither ICMP nor TCP 443: pass the IP of your game server"))?;
    println!("{}", tr("Покой: 5 с без нагрузки…", "Idle: 5 s without load..."));
    let (times, sent) = sample_for(ip, via, Duration::from_secs(5));
    let idle = stats::summarize(&times, sent).ok_or("no replies while idle")?;
    println!("{}", tr("Нагрузка на скачивание…", "Download load..."));
    let down = measure_under_load(ip, via, Dir::Down, urls, measure);
    println!("{}", tr("Нагрузка на отдачу…", "Upload load..."));
    let up = measure_under_load(ip, via, Dir::Up, urls, measure);
    Ok(LoadReport { target: target.to_owned(), via, idle, down, up })
}

fn mbit(bytes_s: f64) -> String {
    format!("{:.0} {}", bytes_s * 8.0 / 1_000_000.0, tr("Мбит/с", "Mbit/s"))
}

fn dir_line(label: &str, idle: &Summary, r: &LoadResult) -> String {
    let (b, added) = bloat_grade(idle, r);
    let (c, txt) = match (b, added, &r.loaded) {
        (Bloat::Inconclusive, _, _) => (YELLOW, tr("нет вывода: нагрузка не пошла", "inconclusive: load did not run").to_owned()),
        (Bloat::Severe, None, _) => (RED, tr("почти нет ответов под нагрузкой", "almost no replies under load").to_owned()),
        (b, Some(a), Some(l)) => (if b == Bloat::Fine { GREEN } else if b == Bloat::Noticeable { YELLOW } else { RED }, format!("{} ms (+{}) · p95 {} · {} {}%", fmt_ms(l.median), fmt_ms(a), fmt_ms(l.p95), tr("потери", "loss"), l.loss_pct)),
        _ => (YELLOW, String::new()),
    };
    format!("{} {} {} {}", ui::paint(DIM, &ui::pad(label, 10)), dot(c), ui::clip(&txt, 40), ui::paint(DIM, &format!("[{}]", mbit(r.rate_bytes_s))))
}

pub fn print_load_report(r: &LoadReport) {
    let mut lines = vec![kv(tr("Хост", "Host"), &format!("{} · {}", ui::clip(&r.target, 40), r.via.label()))];
    lines.push(kv(tr("Покой", "Idle"), &format!("{} ms · {} {} · {} {}%", fmt_ms(r.idle.median), tr("джиттер", "jitter"), fmt_ms(r.idle.jitter), tr("потери", "loss"), r.idle.loss_pct)));
    lines.push(dir_line(tr("Скачивание", "Download"), &r.idle, &r.down));
    lines.push(dir_line(tr("Отдача", "Upload"), &r.idle, &r.up));
    lines.push(String::new());
    let (bd, ad) = bloat_grade(&r.idle, &r.down);
    let (bu, au) = bloat_grade(&r.idle, &r.up);
    let worst = [bd, bu].into_iter().max_by_key(|b| match b {
        Bloat::Inconclusive => 0,
        Bloat::Fine => 1,
        Bloat::Noticeable => 2,
        Bloat::Severe => 3,
    });
    let (c, verdict) = match worst {
        Some(Bloat::Fine) => (GREEN, tr("Очереди в порядке: под нагрузкой задержка почти не растёт.", "Queues are fine: latency barely grows under load.")),
        Some(Bloat::Noticeable) => (YELLOW, tr("Заметный bufferbloat: пока кто-то качает или раздаёт, пакеты игры ждут в очереди.", "Noticeable bufferbloat: while someone downloads or uploads, game packets wait in a queue.")),
        Some(Bloat::Severe) => (RED, tr("Сильный bufferbloat: под нагрузкой игра будет лагать, хотя без неё пинг хороший.", "Severe bufferbloat: the game will lag under load even though the idle ping is good.")),
        _ => (YELLOW, tr("Вывода нет: нагрузка не набрала скорость (проверьте доступ к speed.cloudflare.com).", "No conclusion: the load did not get going (check access to speed.cloudflare.com).")),
    };
    for (i, l) in ui::wrap(verdict, 62).iter().enumerate() {
        lines.push(format!("{} {}", if i == 0 { dot(c) } else { " ".to_owned() }, ui::paint(c, l)));
    }
    if matches!(worst, Some(Bloat::Noticeable | Bloat::Severe)) {
        let advice = tr(
            "Лечится на роутере: включите умное управление очередью (SQM: fq_codel или CAKE) и ограничьте скорость на 90-95% от реальной. Одного QoS часто мало. Нет такой опции: ограничьте скорость раздачи и загрузки в программах на время игры.",
            "Fix it on the router: enable smart queue management (SQM: fq_codel or CAKE) and limit the rate to 90-95% of the real line speed. Plain QoS is often not enough. No such option: cap upload and download rates in your apps while gaming.",
        );
        for (i, l) in ui::wrap(advice, 60).iter().enumerate() {
            lines.push(format!("{} {l}", if i == 0 { " -" } else { "  " }));
        }
        if au.unwrap_or(0.0) > ad.unwrap_or(0.0) + 10.0 {
            lines.push(format!(" - {}", tr("Исходящий канал забивается сильнее: облачные копии и раздача в первую очередь.", "Upload is hit harder: cloud backups and seeding first.")));
        }
    }
    ui::panel(tr("Задержка под нагрузкой", "Latency under load"), &lines);
}

// ---------------------------------------------------------------------------------------- report

/// Prints the link type and the background traffic.
pub fn print_local() {
    let l = link();
    let (c, txt) = match &l.kind {
        LinkKind::Wired => (GREEN, format!("{} ({})", tr("кабель (Ethernet)", "wired (Ethernet)"), l.iface)),
        LinkKind::Wifi { signal_pct } => {
            let sig = signal_pct.map(|p| format!(", {} {p}%", tr("сигнал", "signal"))).unwrap_or_default();
            (YELLOW, format!("Wi-Fi{sig}: {}", tr("кабель стабильнее: меньше джиттера и потерь", "a cable is steadier: less jitter and loss")))
        }
        LinkKind::Virtual => (DIM, format!("{} ({})", tr("маршрут идёт через виртуальный интерфейс (VPN, WARP, мост): тип канала не определён", "the route goes through a virtual interface (VPN, WARP, bridge): link type unknown"), l.iface)),
        LinkKind::Other => (DIM, format!("{} ({})", tr("другой тип соединения", "another kind of link"), l.iface)),
        LinkKind::Unknown => (DIM, tr("не определён (кабель надёжнее Wi-Fi)", "not detected (a cable is steadier than Wi-Fi)").to_owned()),
    };
    let mut lines = vec![kv(tr("Канал", "Link"), &format!("{} {}", dot(c), ui::clip(&txt, 56)))];
    match background_rate() {
        Some(b) if b > BUSY_BYTES_S => lines.push(kv(tr("Фон", "Background"), &format!("{} {:.1} MB/s: {}", dot(YELLOW), b / 1_000_000.0, tr("идёт загрузка или раздача, она мешает игре", "a download or upload is running and competes with the game")))),
        Some(b) => lines.push(kv(tr("Фон", "Background"), &format!("{} {:.2} MB/s: {}", dot(GREEN), b / 1_000_000.0, tr("тихо", "quiet")))),
        None => {}
    }
    ui::panel(tr("Домашняя сеть", "Home network"), &lines);
}

/// `netfreedom doctor --net`.
pub fn run_report(target: &str) {
    println!();
    print_local();
    println!("{}", tr("Дальше нагрузка на канал около 30 секунд: не играйте и не качайте в это время.", "Next the line is loaded for about 30 seconds: do not play or download meanwhile."));
    match run_load_test(target, &LoadUrls::cloudflare(), Duration::from_secs(8)) {
        Ok(r) => print_load_report(&r),
        Err(e) => ui::warn(&e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROUTE: &str = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
        wlan0\t00000000\t0100A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n\
        eth0\t00000000\t0100A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
        eth0\t0000A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n";

    fn sm(med: f64, jit: f64, loss: f64, sent: u32) -> Summary {
        let received = (sent as f64 * (1.0 - loss / 100.0)).round() as u32;
        Summary { sent, received, loss_pct: loss, min: med, median: med, avg: med, p95: med, max: med, stdev: 0.0, jitter: jit }
    }

    fn lr(loaded: Option<Summary>, sent: u32, rate: f64) -> LoadResult {
        LoadResult { dir: Dir::Down, loaded, sent, rate_bytes_s: rate }
    }

    #[test]
    fn default_route_prefers_the_lowest_metric() {
        assert_eq!(default_iface(ROUTE).as_deref(), Some("eth0"), "wired (metric 100) beats Wi-Fi (600)");
        assert_eq!(default_iface("Iface\tDestination\n"), None);
        assert_eq!(default_iface(""), None);
    }

    #[test]
    fn link_kinds() {
        assert_eq!(link_kind_for(true, true, Some(1)), LinkKind::Wifi { signal_pct: None }, "wireless wins even though it is ARPHRD_ETHER");
        assert_eq!(link_kind_for(false, true, Some(1)), LinkKind::Wired);
        assert_eq!(link_kind_for(false, false, Some(1)), LinkKind::Virtual, "no device behind it: bridge, veth, tun");
        assert_eq!(link_kind_for(false, true, Some(512)), LinkKind::Other);
    }

    #[test]
    fn proc_net_dev_parsing() {
        let dev = "Inter-|   Receive                                                |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n    lo:  100 1 0 0 0 0 0 0  100 1 0 0 0 0 0 0\n  eth0: 5000 10 0 0 0 0 0 0  7000 12 0 0 0 0 0 0\n";
        assert_eq!(parse_proc_net_dev(dev, "eth0"), Some((5000, 7000)));
        assert_eq!(parse_proc_net_dev(dev, "wlan0"), None);
    }

    #[test]
    fn netsh_signal_is_found_whatever_the_language() {
        let en = "    Name                   : Wi-Fi\n    State                  : connected\n    Signal                 : 91%\n    Receive rate (Mbps)    : 866\n";
        let ru = "    Имя                    : Wi-Fi\n    Состояние              : подключено\n    Сигнал                 : 64%\n";
        assert_eq!(parse_netsh_signal(en), Some(91));
        assert_eq!(parse_netsh_signal(ru), Some(64));
        assert_eq!(parse_netsh_signal("There is no wireless interface on the system."), None);
        assert_eq!(parse_netsh_signal("    X : 250%\n"), None, "not a signal strength");
    }

    #[test]
    fn load_command_lines() {
        let d = load_args(Dir::Down, "https://h/x", 12, &[]);
        assert_eq!(&d[..5], ["-sS", "--ssl-no-revoke", "--connect-timeout", "6", "-m"]);
        assert!(d.contains(&"12".to_string()) && d.last().unwrap() == "https://h/x");
        assert!(!d.contains(&"-T".to_string()), "a download sends no body");
        let u = load_args(Dir::Up, "https://h/up", 12, &["-k".to_string()]);
        assert!(u.windows(2).any(|w| w == ["-T", "-"]), "the upload streams stdin");
        assert!(u.windows(2).any(|w| w == ["-X", "POST"]));
        assert!(u.contains(&"-k".to_string()));
        assert_eq!(parse_load_out("200 104857600 0"), Some((200, 104_857_600, 0)));
        assert_eq!(parse_load_out("000 0 733184"), Some((0, 0, 733_184)), "an upload cut by -m has no response code");
        assert_eq!(parse_load_out(""), None);
    }

    #[test]
    fn bufferbloat_grades() {
        let idle = sm(20.0, 1.0, 0.0, 25);
        let fast = 5_000_000.0;
        assert_eq!(bloat_grade(&idle, &lr(Some(sm(28.0, 2.0, 0.0, 40)), 40, fast)), (Bloat::Fine, Some(8.0)));
        assert_eq!(bloat_grade(&idle, &lr(Some(sm(55.0, 5.0, 0.0, 40)), 40, fast)), (Bloat::Noticeable, Some(35.0)));
        assert_eq!(bloat_grade(&idle, &lr(Some(sm(380.0, 40.0, 0.0, 40)), 40, fast)), (Bloat::Severe, Some(360.0)));
        assert_eq!(bloat_grade(&idle, &lr(Some(sm(22.0, 2.0, 8.0, 40)), 40, fast)).0, Bloat::Severe, "real loss under load");
        assert_eq!(bloat_grade(&idle, &lr(Some(sm(22.0, 2.0, 2.5, 40)), 40, fast)).0, Bloat::Noticeable);
        assert_eq!(bloat_grade(&idle, &lr(None, 40, fast)), (Bloat::Severe, None), "the load ran and nothing answered");
        assert_eq!(bloat_grade(&idle, &lr(Some(sm(900.0, 10.0, 60.0, 40)), 40, fast)), (Bloat::Severe, None), "most probes lost");
    }

    #[test]
    fn a_load_that_never_got_going_proves_nothing() {
        let idle = sm(20.0, 1.0, 0.0, 25);
        // a perfect-looking result while nothing was transferred must NOT read as "queues are fine"
        assert_eq!(bloat_grade(&idle, &lr(Some(sm(20.0, 1.0, 0.0, 40)), 40, 1_000.0)).0, Bloat::Inconclusive);
        assert_eq!(bloat_grade(&idle, &lr(Some(sm(20.0, 1.0, 0.0, 3)), 3, 5_000_000.0)).0, Bloat::Inconclusive, "3 probes are too few");
        assert_eq!(bloat_grade(&sm(20.0, 1.0, 0.0, 3), &lr(Some(sm(20.0, 1.0, 0.0, 40)), 40, 5_000_000.0)).0, Bloat::Inconclusive, "unreliable idle baseline");
    }
}
