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

//! `netfreedom tune`: runs every scenario against the real network, measures the result and picks
//! the best one for THIS provider, then remembers it as the default.
//!
//! Two goals:
//!   * games (default): WARP is connected per scenario and the tunnel is measured (latency, jitter,
//!     loss), ranked with a games-oriented score;
//!   * `--bypass`: no WARP; every bypass strategy is started and real downloads (a Cloudflare file
//!     over 16 KB, Discord, YouTube) decide.
//!
//! Robustness (the 2.x version closed its window before printing the table): results are printed
//! and saved after EVERY scenario, a panic inside one scenario only fails that scenario, Ctrl+C
//! stops cleanly and still shows what was measured, and the window waits for Enter at the end.

use std::fs;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::backend;
use crate::capture::GameFilter;
use crate::config::Config;
use crate::crash;
use crate::health;
use crate::session;
use crate::paths::Layout;
use crate::probe::{self, Options, Via};
use crate::profiles::{self, Profile};
use crate::run::{self, Plan, StartArgs};
use crate::stats::{self, Summary};
use crate::sys;
use crate::ui;
use crate::util::{fmt_ms, fmt_utc};
use crate::warp::Warp;
use crate::web::{self, WebResult};

pub struct TuneArgs {
    /// Bypass without WARP: judge by real downloads instead of tunnel latency.
    pub bypass: bool,
    /// Skip the port-capture variants (WARP goal only).
    pub quick: bool,
    /// Also test the heavy "compatibility" capture mode of every bypass strategy (WARP goal only).
    pub full: bool,
    pub only: Vec<String>,
    pub target: String,
    pub count: u32,
    pub timeout_s: u64,
    pub no_save: bool,
    pub no_confirm: bool,
    pub no_baseline: bool,
    pub top: usize,
    /// Rank with the plain formula instead of the games one.
    pub plain_score: bool,
    /// Skip the final "direct path vs the best tunnel" comparison (WARP goal only).
    pub no_direct: bool,
    /// Measuring method fixed for the whole run (set by `run` after a warm-up connection).
    pub via: Option<probe::Via>,
    /// Bypass goal: sites whose address never answers (IP block / poisoned DNS) in every scenario
    /// measured so far. No strategy can open them, so they are not waited for any more.
    pub skip_sites: Vec<String>,
}

/// What `tune` measures when no `--target` is given. It answers with or without WARP, so it says
/// nothing about the path to a game server.
const DEFAULT_TARGET: &str = "1.1.1.1";

impl Default for TuneArgs {
    fn default() -> Self {
        Self {
            bypass: false,
            quick: false,
            full: false,
            only: Vec::new(),
            target: DEFAULT_TARGET.into(),
            count: 15,
            timeout_s: 12,
            no_save: false,
            no_confirm: false,
            no_baseline: false,
            top: 3,
            plain_score: false,
            no_direct: false,
            via: None,
            skip_sites: Vec::new(),
        }
    }
}

impl TuneArgs {
    pub fn parse(args: &[String]) -> Result<Self, String> {
        let mut a = Self::default();
        let mut it = args.iter();
        while let Some(arg) = it.next() {
            let mut value = |name: &str| it.next().cloned().ok_or(format!("{name} needs a value"));
            match arg.as_str() {
                "--bypass" => a.bypass = true,
                "--quick" => a.quick = true,
                "--full" => a.full = true,
                "--plain-score" => a.plain_score = true,
                "--no-direct" => a.no_direct = true,
                "--only" => a.only = value("--only")?.split(';').map(|s| s.trim().to_lowercase()).filter(|s| !s.is_empty()).collect(),
                "--target" => a.target = value("--target")?,
                "--count" => a.count = value("--count")?.parse().ok().filter(|n| (5..=200).contains(n)).ok_or("--count must be 5..200")?,
                "--timeout" => a.timeout_s = value("--timeout")?.parse().ok().filter(|n| (3..=120).contains(n)).ok_or("--timeout must be 3..120 seconds")?,
                "--top" => a.top = value("--top")?.parse().ok().filter(|n| (1..=10).contains(n)).ok_or("--top must be 1..10")?,
                "--no-save" => a.no_save = true,
                "--no-confirm" => a.no_confirm = true,
                "--no-baseline" => a.no_baseline = true,
                other => return Err(format!("unknown option: {other}")),
            }
        }
        if a.quick && a.full {
            return Err("--quick and --full exclude each other".into());
        }
        Ok(a)
    }
}

#[derive(Clone)]
pub struct Scenario {
    pub label: String,
    /// `None` = no packet engine (baseline).
    pub profile: Option<&'static Profile>,
    pub mode: u8,
    pub penalty: f64,
    /// Bypass goal: port filter for game traffic is off.
    pub bypass_goal: bool,
}

impl Scenario {
    fn plan(&self) -> Option<Plan> {
        let profile = self.profile?;
        let lean = profile.is_dedicated_lean();
        let gf = if lean {
            GameFilter::low_latency()
        } else if self.bypass_goal {
            GameFilter::disabled()
        } else if self.mode == 1 {
            GameFilter::low_latency()
        } else {
            GameFilter::compatibility()
        };
        Some(Plan { profile, lean, gf, mode: self.mode })
    }

    /// The `start` command line that reproduces this scenario.
    pub fn command(&self) -> String {
        match self.profile {
            None => "(no packet engine needed)".into(),
            Some(p) if self.bypass_goal => format!("netfreedom start --bypass --strategy {}", p.name),
            Some(p) if p.is_dedicated_lean() => format!("netfreedom start --strategy {}", p.name),
            Some(p) => format!("netfreedom start --strategy {} --mode {}", p.name, self.mode),
        }
    }
}

/// `--quick` for the bypass goal: the strategies that are most often the answer (about a third of
/// the full run).
const QUICK_BYPASS: [&str; 11] = ["balanced", "balanced-lite", "disorder", "max", "hostfake-g", "hostfake", "alt9", "alt11", "alt12", "alt13", "split"];

/// Builds the list of scenarios for the given options (pure, unit-tested). Every strategy is unique
/// (the table is deduplicated), so nothing is measured twice.
pub fn scenarios(a: &TuneArgs) -> Vec<Scenario> {
    let wanted = |p: &Profile| a.only.is_empty() || a.only.iter().any(|o| p.name.to_lowercase().contains(o));
    let mut v = Vec::new();
    if !a.no_baseline && a.only.is_empty() {
        let label = if a.bypass { "no bypass (baseline)" } else { "plain WARP (no bypass)" };
        v.push(Scenario { label: label.into(), profile: None, mode: 0, penalty: 0.0, bypass_goal: a.bypass });
    }
    for p in profiles::PROFILES.iter().filter(|p| wanted(p)) {
        if a.bypass {
            if p.is_bypass() && (!a.quick || QUICK_BYPASS.contains(&p.name)) {
                v.push(Scenario { label: p.name.into(), profile: Some(p), mode: 1, penalty: 0.0, bypass_goal: true });
            }
        } else if p.is_dedicated_lean() {
            v.push(Scenario { label: p.name.into(), profile: Some(p), mode: 1, penalty: 0.0, bypass_goal: false });
        } else if !a.quick {
            v.push(Scenario { label: format!("{} [low latency]", p.name), profile: Some(p), mode: 1, penalty: 2.0, bypass_goal: false });
            if a.full {
                v.push(Scenario { label: format!("{} [compatibility]", p.name), profile: Some(p), mode: 2, penalty: 5.0, bypass_goal: false });
            }
        }
    }
    v
}

#[derive(Clone)]
pub struct Result1 {
    pub scenario: Scenario,
    pub connected: bool,
    pub connect_s: f64,
    pub summary: Option<Summary>,
    pub via: Option<Via>,
    pub web: Vec<WebResult>,
    pub note: String,
    pub score: f64,
}

fn blank(sc: &Scenario) -> Result1 {
    Result1 { scenario: sc.clone(), connected: false, connect_s: 0.0, summary: None, via: None, web: Vec::new(), note: String::new(), score: f64::INFINITY }
}

fn settle(ms: u64) {
    std::thread::sleep(Duration::from_millis(ms));
}

/// Sites that failed BEFORE any TLS (the address does not answer, or DNS gave nothing) in every
/// measured scenario, the baseline included. A packet strategy changes how a ClientHello is sent;
/// it cannot make an unanswered SYN answered, so waiting for these sites again only costs time.
/// Needs at least three measured scenarios, so one unlucky run decides nothing.
fn unfixable_sites(results: &[Result1]) -> Vec<String> {
    let measured: Vec<&Result1> = results.iter().filter(|r| !r.web.is_empty()).collect();
    if measured.len() < 3 {
        return Vec::new();
    }
    measured[0]
        .web
        .iter()
        .filter(|w| web::connect_blocked(w))
        .map(|w| w.name.clone())
        .filter(|name| measured.iter().all(|r| r.web.iter().any(|w| w.name == *name && web::connect_blocked(w))))
        .collect()
}

fn teardown(warp: Option<&Warp>) {
    if let Some(w) = warp {
        w.disconnect();
        // Wait until the daemon is really down. Reconnecting while the previous session was still
        // winding down made every later scenario slower or flaky ("worse with each restart").
        w.wait_disconnected(Duration::from_secs(6));
    }
    backend::native_stop();
    backend::stop_all();
    settle(800);
}

/// Runs one scenario from a clean state and leaves a clean state behind.
fn evaluate(layout: &Layout, warp: Option<&Warp>, sc: &Scenario, a: &TuneArgs, count: u32) -> Result1 {
    let mut r = blank(sc);
    teardown(warp);

    if let Some(plan) = sc.plan() {
        if let Err(e) = run::launch(layout, &plan, &StartArgs::default(), true) {
            r.note = format!("engine failed: {}", e.lines().next().unwrap_or(""));
            teardown(warp);
            return r;
        }
    }

    if a.bypass {
        settle(1200);
        // an engine that already died cannot explain "nothing opens": say so, with its own words
        if sc.profile.is_some() && !backend::engine_running() {
            let log = backend::engine_log_tail(layout, 3);
            r.note = format!("the packet engine stopped right after start{}", if log.is_empty() { String::new() } else { format!(": {log}") });
            teardown(None);
            return r;
        }
        r.web = web::probe_skip(Duration::from_secs(a.timeout_s.min(10)), &a.skip_sites);
        r.connected = r.web.iter().any(|w| w.ok);
        r.score = web::score(&r.web);
        if sc.profile.is_some() && !backend::engine_running() {
            r.note = "the packet engine stopped during the test, the result is unreliable".into();
            r.score += 100.0; // never let an engine that crashed win
        }
        teardown(None);
        return r;
    }

    let Some(warp) = warp else {
        r.note = "WARP is not available".into();
        return r;
    };
    let (ok, secs, status) = run::connect_warp(warp, Duration::from_secs(a.timeout_s));
    r.connect_s = secs as f64;
    if !ok {
        r.note = format!("not connected in {} s ({})", a.timeout_s, status.lines().next().unwrap_or("no status").trim());
        teardown(Some(warp));
        return r;
    }
    // "Connected" from warp-cli is not proof. A scenario only counts if Cloudflare confirms that
    // our traffic really arrives through WARP; otherwise its numbers describe the plain connection.
    match health::wait_tunnel_on(warp, Duration::from_secs(a.timeout_s.max(8))) {
        Ok(t) => r.note = format!("{} {}", t.colo, t.loc).trim().to_owned(),
        Err(e) => {
            r.note = format!("not through the tunnel: {e}");
            teardown(Some(warp));
            return r;
        }
    }
    r.connected = true;
    settle(1500);
    let opts = Options { count, interval_ms: 120, timeout_ms: 1000, warmup: true, tunnel_stats: false };
    match probe::measure_with(&a.target, &opts, a.via) {
        Ok((s, via)) if !stats::reliable(&s) => {
            r.note = format!("{}: only {}/{} replies, not enough to rank", r.note, s.received, s.sent);
            r.summary = Some(s);
            r.via = Some(via);
        }
        Ok((s, via)) => {
            r.score = if a.plain_score { stats::score(&s, r.connect_s, sc.penalty) } else { stats::score_games(&s, r.connect_s, sc.penalty) };
            r.summary = Some(s);
            r.via = Some(via);
        }
        Err(e) => r.note = e,
    }
    teardown(Some(warp));
    r
}

/// `evaluate`, but a panic only fails this scenario.
fn evaluate_safe(layout: &Layout, warp: Option<&Warp>, sc: &Scenario, a: &TuneArgs, count: u32) -> Result1 {
    match crash::guard(|| evaluate(layout, warp, sc, a, count)) {
        Ok(r) => r,
        Err(msg) => {
            teardown(warp);
            let mut r = blank(sc);
            r.note = format!("internal error (see utils/crash.log): {}", msg.lines().next().unwrap_or(""));
            r
        }
    }
}

fn describe(r: &Result1) -> String {
    if !r.web.is_empty() {
        let ok = r.web.iter().filter(|w| w.ok).count();
        let detail = r.web.iter().map(|w| format!("{} {}", w.name.split(' ').next().unwrap_or(""), if w.ok { "ok" } else { "FAIL" })).collect::<Vec<_>>().join(", ");
        return format!("{ok}/{} open ({detail}) | score {:.1}", r.web.len(), r.score);
    }
    match (&r.summary, r.connected) {
        (Some(s), _) => format!(
            "connected {:.1}s | median {} ms, jitter {}, p95 {}, loss {}% via {} | score {:.1}",
            r.connect_s, fmt_ms(s.median), fmt_ms(s.jitter), fmt_ms(s.p95), s.loss_pct, r.via.map(Via::label).unwrap_or("?"), r.score
        ),
        (None, true) => format!("connected {:.1}s but no measurement: {}", r.connect_s, r.note),
        (None, false) => format!("FAILED: {}", r.note),
    }
}

/// Sorted best-first; failures last (stable, pure).
pub fn rank(results: &mut [Result1]) {
    results.sort_by(|a, b| a.score.total_cmp(&b.score));
}

/// Direct path vs the best tunnel, judged with the same games score.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathVerdict {
    TunnelBetter,
    Similar,
    DirectBetter,
}

/// Differences under 10% (and under 5 points of score) are noise, not an answer.
pub fn compare_paths(direct: &Summary, tunnel: &Summary) -> PathVerdict {
    let d = stats::score_games(direct, 0.0, 0.0);
    let t = stats::score_games(tunnel, 0.0, 0.0);
    let margin = (d.max(t) * 0.10).max(5.0);
    if (d - t).abs() <= margin {
        PathVerdict::Similar
    } else if t < d {
        PathVerdict::TunnelBetter
    } else {
        PathVerdict::DirectBetter
    }
}

fn path_line(label: &str, s: &Summary, via: Via) -> String {
    format!("{label}: median {} ms, jitter {}, p95 {}, loss {}% via {}", fmt_ms(s.median), fmt_ms(s.jitter), fmt_ms(s.p95), s.loss_pct, via.label())
}

/// The question `tune` could not answer before: does WARP help on the route to YOUR game server at
/// all, or is the plain connection just as good (or better)? Runs once, after the ranking, with
/// WARP switched off, and does not take part in the ranking.
fn direct_vs_tunnel(warp: Option<&Warp>, a: &TuneArgs, tunnel: Option<&Summary>) -> Vec<String> {
    use crate::ui::tr;
    if a.target == DEFAULT_TARGET {
        return vec![tr(
            "Сравнение с прямым путём пропущено: 1.1.1.1 отвечает и с WARP, и без него. Укажите --target <IP игрового сервера>.",
            "Direct-path comparison skipped: 1.1.1.1 answers with and without WARP. Pass --target <your game server's IP>.",
        )
        .to_owned()];
    }
    let Some(t) = tunnel.filter(|t| stats::reliable(t)) else {
        return vec![tr("Сравнение с прямым путём пропущено: нет надёжного замера через туннель.", "Direct-path comparison skipped: no reliable tunnel measurement.").to_owned()];
    };
    if let Some(w) = warp {
        w.disconnect();
        w.wait_disconnected(Duration::from_secs(6));
    }
    settle(1500);
    let opts = Options { count: a.count, interval_ms: 120, timeout_ms: 1000, warmup: true, tunnel_stats: false };
    let (direct, via) = match probe::measure_with(&a.target, &opts, a.via) {
        Ok(x) => x,
        Err(e) => return vec![format!("{}: {e}", tr("Прямой путь не измерен", "Direct path not measured"))],
    };
    if !stats::reliable(&direct) {
        return vec![format!("{} ({}/{})", tr("Прямой путь: слишком мало ответов для вывода", "Direct path: too few replies to conclude"), direct.received, direct.sent)];
    }
    let mut v = vec![path_line(tr("Напрямую (без WARP)   ", "Direct (no WARP)      "), &direct, via), path_line(tr("Через WARP (лучший)  ", "Through WARP (best)   "), t, via)];
    v.push(
        match compare_paths(&direct, t) {
            PathVerdict::TunnelBetter => tr("Вывод: на этом маршруте WARP заметно лучше прямого пути.", "Verdict: on this route WARP is clearly better than the direct path."),
            PathVerdict::Similar => tr("Вывод: разница небольшая, WARP не даёт заметного выигрыша по задержке.", "Verdict: the difference is small, WARP brings no clear latency gain."),
            PathVerdict::DirectBetter => tr("Вывод: напрямую лучше, WARP добавляет задержку или джиттер.", "Verdict: the direct path is better, WARP adds latency or jitter."),
        }
        .to_owned(),
    );
    v.push(
        tr(
            "Это замер задержки, а не доступности: если без WARP игра блокируется, выбирать надо по доступности.",
            "This measures latency, not reachability: if the game is blocked without WARP, choose by reachability.",
        )
        .to_owned(),
    );
    v
}

/// Adds lines to the saved report (the report is rewritten after every scenario, so this runs last).
fn append_report(layout: &Layout, lines: &[String]) {
    if lines.is_empty() {
        return;
    }
    use std::io::Write;
    if let Ok(mut f) = fs::OpenOptions::new().append(true).open(layout.utils.join("tune_report.txt")) {
        let _ = writeln!(f, "\nDirect path vs the best tunnel:");
        for l in lines {
            let _ = writeln!(f, "  {l}");
        }
    }
}

fn report_text(results: &[Result1], a: &TuneArgs, started: u64, finished: bool) -> String {
    let goal = if a.bypass { "bypass (real downloads)".to_string() } else { format!("games through WARP, target {}, {} probes", a.target, a.count) };
    let mut t = format!("netfreedom tune report, {}\ngoal: {goal} | timeout {} s{}\n\n", fmt_utc(started), a.timeout_s, if finished { "" } else { "\nINCOMPLETE: stopped before all scenarios were measured" });
    for (i, r) in results.iter().enumerate() {
        t.push_str(&format!("{:>2}. {}\n      {}\n", i + 1, r.scenario.label, describe(r)));
        for w in r.web.iter().filter(|w| !w.ok) {
            t.push_str(&format!("      - {}\n", w.line()));
        }
    }
    if let Some(best) = results.first().filter(|r| r.score.is_finite()) {
        t.push_str(&format!("\nBest: {}\n  {}\n", best.scenario.label, best.scenario.command()));
    }
    t
}

fn save_report(layout: &Layout, results: &[Result1], a: &TuneArgs, started: u64, finished: bool) {
    let mut sorted = results.to_vec();
    rank(&mut sorted);
    let _ = fs::create_dir_all(&layout.utils);
    let _ = fs::write(layout.utils.join("tune_report.txt"), report_text(&sorted, a, started, finished));
}

pub fn run(layout: &Layout, mut a: TuneArgs) -> Result<(), String> {
    let warp = if a.bypass {
        if !web::curl_available() {
            return Err("curl was not found: `tune --bypass` downloads real files with it (it ships with Windows 10+ and Linux).".into());
        }
        None
    } else {
        let w = Warp::locate().ok_or("Cloudflare WARP is not installed. Run `netfreedom install-warp` first (or use `netfreedom tune --bypass` to test unblocking without WARP).")?;
        Some(w)
    };
    if backend::engine_running() {
        return Err("The packet engine is already running: stop it first (`netfreedom stop`).".into());
    }
    backend::check_engine(layout)?;
    layout.ensure_user_lists().map_err(|e| format!("cannot prepare lists: {e}"))?;

    let list = scenarios(&a);
    if list.is_empty() {
        return Err("no scenario matches --only".into());
    }

    let per = if a.bypass { 10 } else { a.count as u64 * 120 / 1000 + 6 };
    let est = list.len() as u64 * per;
    println!("Tuning: {} scenarios, about {} min (a failed one costs up to {} s).", list.len(), est.div_ceil(60), a.timeout_s);
    if a.bypass {
        println!("Goal: bypass without WARP. Each strategy is started and real files are downloaded (Cloudflare, Discord, YouTube).");
    } else {
        println!("Goal: games through WARP, target {}. WARP will connect and disconnect repeatedly; do not play or download meanwhile.", a.target);
    }
    println!("Ctrl+C stops safely and still shows what was measured. Results are saved after every scenario.");
    if !ui::yes_no("Start?") {
        println!("Cancelled.");
        return Ok(());
    }

    session::set_warp_owned(!a.bypass);
    sys::arm_cleanup(true);
    sys::set_graceful(true);
    let started = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    if let Some(w) = &warp {
        let (_, out) = w.set_masque();
        if !out.is_empty() {
            println!("{out}");
        }
        w.launch_app();
        // Warm-up: the first connection after a start pays for registration, endpoint choice and a
        // cold route. Without this the first scenario was always unfairly slow, and a re-run after
        // a restart looked "worse" than the previous one. It also fixes ONE measuring method
        // (ICMP or TCP) for every scenario so that the numbers are comparable.
        println!("{}", ui::tr("Прогрев туннеля (результат не учитывается)…", "Warming up the tunnel (not counted)..."));
        // Warm up UNDER a bypass strategy: where the provider's DPI blocks the WARP handshake
        // (QUIC/UDP), plain WARP stays "Connecting" forever and tuning would abort before it even
        // started. The first of the first few strategies that connects wins; plain WARP is only
        // the last resort (networks where nothing is blocked).
        let mut ok = false;
        let mut status = String::new();
        let mut prepared = false;
        let candidates: Vec<Option<&Scenario>> = list.iter().filter(|s| s.profile.is_some()).take(5).map(Some).chain(std::iter::once(None)).collect();
        for cand in candidates {
            if sys::interrupted() {
                break;
            }
            teardown(Some(w));
            match cand {
                Some(sc) => {
                    let Some(plan) = sc.plan() else { continue };
                    if let Err(e) = run::launch(layout, &plan, &StartArgs::default(), true) {
                        println!("  {}: engine failed: {}", sc.label, e.lines().next().unwrap_or(""));
                        continue;
                    }
                    println!("  {} {}", ui::tr("со стратегией", "with strategy"), sc.label);
                }
                None => println!("  {}", ui::tr("без обхода (последняя попытка)", "plain WARP (last attempt)")),
            }
            // daemon check + first-run registration need Cloudflare: do them with the engine up
            if !prepared {
                match w.prepare() {
                    Ok(note) => {
                        prepared = true;
                        if let Some(note) = note {
                            println!("{note}");
                        }
                    }
                    Err(e) => {
                        status = e;
                        continue;
                    }
                }
            }
            let (o, _, st) = run::connect_warp(w, Duration::from_secs(a.timeout_s.max(20)));
            status = st;
            if o {
                ok = true;
                break;
            }
        }
        if !ok {
            teardown(Some(w));
            return Err(format!("WARP does not connect at all ({}). Fix that first, otherwise every scenario would fail.", status.lines().next().unwrap_or("no status").trim()));
        }
        match health::wait_tunnel_on(w, Duration::from_secs(20)) {
            Ok(t) => println!("  warp=on, {} {} {}", ui::tr("дата-центр", "data centre"), t.colo, t.loc),
            Err(e) => {
                teardown(Some(w));
                return Err(format!("WARP says Connected but the traffic does not go through it: {e}"));
            }
        }
        settle(1500);
        a.via = probe::detect_method(&a.target);
        match a.via {
            Some(v) => println!("  {} {}", ui::tr("метод измерения для всех сценариев:", "measuring method for every scenario:"), v.label()),
            None => {
                teardown(Some(w));
                return Err(format!("{} does not answer through the tunnel, neither ICMP nor TCP 443: pass another --target (your game server's IP).", a.target));
            }
        }
        teardown(Some(w));
    }
    println!();

    let total = list.len();
    let mut results: Vec<Result1> = Vec::with_capacity(total);
    let mut stopped = false;
    for (i, sc) in list.iter().enumerate() {
        if sys::interrupted() {
            stopped = true;
            break;
        }
        if a.bypass {
            let skip = unfixable_sites(&results);
            if !skip.is_empty() && skip != a.skip_sites {
                ui::say(&format!(
                    "        {} {}",
                    ui::tr("не жду сайты, которые не отвечают на сам SYN (блокировка по IP/DNS, стратегией не лечится):", "no longer waiting for sites that never answer the SYN (IP/DNS block, no strategy fixes that):"),
                    skip.join(", ")
                ));
            }
            a.skip_sites = skip;
        }
        let r = evaluate_safe(layout, warp.as_ref(), sc, &a, a.count);
        ui::say(&format!("[{:>2}/{}] {:<26} {}", i + 1, total, sc.label, describe(&r)));
        results.push(r);
        save_report(layout, &results, &a, started, false);
        // running leader, so even a closed window leaves the answer on screen
        let mut sorted = results.clone();
        rank(&mut sorted);
        if let Some(best) = sorted.first().filter(|b| b.score.is_finite()) {
            ui::say(&format!("        leader so far: {}", best.scenario.label));
        }
    }
    rank(&mut results);

    // second, longer pass over the leaders so that one lucky run does not decide
    let finalists: Vec<usize> = results.iter().enumerate().filter(|(_, r)| r.score.is_finite()).map(|(i, _)| i).take(a.top).collect();
    if !stopped && !a.no_confirm && finalists.len() >= 2 {
        println!("\nConfirming the top {} {}...", finalists.len(), if a.bypass { "again".to_string() } else { format!("with {} probes each", a.count * 2) });
        for &i in &finalists {
            if sys::interrupted() {
                stopped = true;
                break;
            }
            let sc = results[i].scenario.clone();
            let again = evaluate_safe(layout, warp.as_ref(), &sc, &a, a.count * 2);
            ui::say(&format!("  {:<26} {}", sc.label, describe(&again)));
            if again.score.is_finite() {
                // pessimistic on purpose: a strategy that is great once and mediocre the next time
                // is not what a game needs, so the worse of the two runs decides
                results[i].score = results[i].score.max(again.score);
            } else {
                results[i].score = f64::INFINITY; // unstable: worked once, failed the second time
                results[i].note = "failed the confirmation run".into();
            }
        }
        rank(&mut results);
    }

    // clean up first, then print: the table is the last thing on screen
    sys::arm_cleanup(false);
    sys::set_graceful(false);
    if a.bypass {
        run::cleanup_engine_only();
    } else {
        run::cleanup_all();
    }
    let direct_lines = if !a.bypass && !a.no_direct && !stopped && !sys::interrupted() {
        println!("{}", ui::tr("\nСравниваю с прямым путём (без WARP)…", "\nComparing with the direct path (no WARP)..."));
        direct_vs_tunnel(warp.as_ref(), &a, results.first().filter(|r| r.score.is_finite()).and_then(|r| r.summary.as_ref()))
    } else {
        Vec::new()
    };
    save_report(layout, &results, &a, started, !stopped);
    append_report(layout, &direct_lines);

    println!("\n==================== Results (best first) ====================");
    if a.bypass {
        let base = results.iter().find(|r| r.scenario.profile.is_none());
        let broke_all = results.iter().filter(|r| r.scenario.profile.is_some() && r.connected).count() == 0;
        if broke_all && base.is_some_and(|b| b.connected) {
            println!("Every strategy opened LESS than no bypass at all. That points at the engine, not at the sites:");
            println!("check antivirus/firewall (WinDivert is a kernel driver), and try `netfreedom start --bypass -v`.");
        }
    }
    if a.bypass && !a.skip_sites.is_empty() {
        println!("Not fixable by any strategy on this connection (the server's IP does not answer, or DNS is poisoned): {}.", a.skip_sites.join(", "));
        println!("These need another resolver (`netfreedom dns set cloudflare` turns on DNS-over-HTTPS), WARP, or a proxy: not a different strategy.");
    }
    if stopped {
        println!("(stopped early: only {} of {} scenarios were measured)", results.len(), total);
    }
    for (i, r) in results.iter().enumerate().take(12) {
        println!("{:>2}. {:<26} {}", i + 1, r.scenario.label, describe(r));
    }
    let failed = results.iter().filter(|r| !r.score.is_finite()).count();
    if failed > 0 {
        println!("    ... {failed} scenario(s) did not work on this connection (see utils/tune_report.txt)");
    }

    if !direct_lines.is_empty() {
        println!();
        for l in &direct_lines {
            println!("  {l}");
        }
    }

    let report_path = layout.utils.join("tune_report.txt");
    let Some(best) = results.first().filter(|r| r.score.is_finite()) else {
        println!("\nNo scenario worked. Check the Internet connection, antivirus/firewall{}.", if a.bypass { "" } else { ", and that WARP can register" });
        println!("Full report: {}", report_path.display());
        return Ok(());
    };
    for w in best.web.iter().filter(|w| !w.ok) {
        println!("    still failing with the best result: {}", w.line());
    }
    println!();
    match best.scenario.profile {
        None if a.bypass => {
            println!("Nothing is blocked right now: no bypass is needed. If sites stop opening later, run this again.");
        }
        None => {
            println!("Plain WARP is the best result: your provider does not seem to block the WARP handshake, so a bypass is not needed.");
            if let Some(alt) = results.iter().find(|r| r.scenario.profile.is_some() && r.score.is_finite()) {
                println!("Best with a bypass (use only if WARP stops connecting later): {}  ->  {}", alt.scenario.label, alt.scenario.command());
            }
        }
        Some(p) => {
            println!("Best for this connection: {}", best.scenario.label);
            println!("Start it with: {}", best.scenario.command());
            if !a.no_save {
                let mut cfg = Config::load_with_legacy(&layout.cfg, &layout.cfg_legacy);
                if a.bypass {
                    cfg.bypass = p.name.to_owned();
                } else {
                    cfg.profile = p.name.to_owned();
                    cfg.mode = best.scenario.mode.max(1);
                }
                if cfg.save(&layout.cfg).is_ok() {
                    println!("Saved as the default: the next `netfreedom start` offers it first.");
                }
            }
        }
    }
    println!("Full report: {}", report_path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn res(label: &str, score: f64) -> Result1 {
        let mut r = blank(&Scenario { label: label.into(), profile: None, mode: 0, penalty: 0.0, bypass_goal: false });
        r.connected = score.is_finite();
        r.score = score;
        r
    }

    #[test]
    fn scenario_lists_have_no_duplicates() {
        let all = scenarios(&TuneArgs::default());
        // baseline + 8 WARP strategies + 32 bypass strategies (low latency)
        assert_eq!(all.len(), 1 + 8 + 32);
        assert!(all[0].profile.is_none());
        let labels: std::collections::HashSet<_> = all.iter().map(|s| s.label.clone()).collect();
        assert_eq!(labels.len(), all.len());
        assert_eq!(scenarios(&TuneArgs { quick: true, ..Default::default() }).len(), 1 + 8);
        assert_eq!(scenarios(&TuneArgs { full: true, ..Default::default() }).len(), 1 + 8 + 64);
        let b = scenarios(&TuneArgs { bypass: true, ..Default::default() });
        assert_eq!(b.len(), 1 + 32, "bypass goal: baseline + the 32 bypass strategies, no WARP strategies");
        assert!(b.iter().skip(1).all(|s| s.bypass_goal && s.profile.unwrap().is_bypass()));
        let q = scenarios(&TuneArgs { bypass: true, quick: true, ..Default::default() });
        assert_eq!(q.len(), 1 + QUICK_BYPASS.len(), "every quick name must exist in the table");
        let only = scenarios(&TuneArgs { only: vec!["split".into()], ..Default::default() });
        assert!(only.iter().all(|s| s.label.contains("split")), "no baseline when filtering");
    }

    #[test]
    fn every_scenario_can_build_a_plan_and_a_command() {
        for bypass in [false, true] {
            for s in scenarios(&TuneArgs { full: !bypass, bypass, ..Default::default() }) {
                if let Some(p) = s.plan() {
                    assert!(if p.lean { p.profile.lean } else { p.profile.classic }.is_some(), "{}", s.label);
                }
                assert!(!s.command().is_empty());
            }
        }
        let s = scenarios(&TuneArgs::default());
        assert_eq!(s[1].command(), "netfreedom start --strategy warp");
        let b = scenarios(&TuneArgs { bypass: true, ..Default::default() });
        assert_eq!(b[1].command(), "netfreedom start --bypass --strategy balanced");
    }

    #[test]
    fn bypass_scenarios_do_not_capture_game_ports() {
        let b = scenarios(&TuneArgs { bypass: true, ..Default::default() });
        let plan = b[1].plan().unwrap();
        assert_eq!(plan.gf.effective(), ("12", "12"));
    }

    #[test]
    fn ranking_puts_failures_last() {
        let mut v = vec![res("fail", f64::INFINITY), res("b", 30.0), res("a", 12.5)];
        rank(&mut v);
        assert_eq!(v.iter().map(|r| r.scenario.label.as_str()).collect::<Vec<_>>(), ["a", "b", "fail"]);
    }

    #[test]
    fn a_partial_report_says_so() {
        let a = TuneArgs::default();
        let r = vec![res("x", 10.0)];
        assert!(report_text(&r, &a, 0, false).contains("INCOMPLETE"));
        assert!(!report_text(&r, &a, 0, true).contains("INCOMPLETE"));
        assert!(report_text(&r, &a, 0, true).contains("Best: x"));
    }

    fn sm(med: f64, jit: f64, loss: f64) -> Summary {
        let sent = 20;
        let received = (sent as f64 * (1.0 - loss / 100.0)).round() as u32;
        Summary { sent, received, loss_pct: loss, min: med, median: med, avg: med, p95: med, max: med, stdev: 0.0, jitter: jit }
    }

    #[test]
    fn direct_vs_tunnel_verdicts() {
        assert_eq!(compare_paths(&sm(80.0, 2.0, 0.0), &sm(40.0, 2.0, 0.0)), PathVerdict::TunnelBetter);
        assert_eq!(compare_paths(&sm(40.0, 2.0, 0.0), &sm(80.0, 2.0, 0.0)), PathVerdict::DirectBetter);
        assert_eq!(compare_paths(&sm(40.0, 2.0, 0.0), &sm(42.0, 2.0, 0.0)), PathVerdict::Similar, "2 ms is noise");
        assert_eq!(compare_paths(&sm(10.0, 1.0, 0.0), &sm(13.0, 1.0, 0.0)), PathVerdict::Similar, "small absolute gaps are noise");
        // a steady direct path beats a faster but lossy tunnel: the games score decides, not the median
        assert_eq!(compare_paths(&sm(45.0, 2.0, 0.0), &sm(30.0, 2.0, 5.0)), PathVerdict::DirectBetter);
    }

    #[test]
    fn the_default_target_skips_the_direct_comparison() {
        let a = TuneArgs::default();
        let lines = direct_vs_tunnel(None, &a, Some(&sm(20.0, 1.0, 0.0)));
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("--target"), "{lines:?}");
    }

    #[test]
    fn argument_parsing() {
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        let a = TuneArgs::parse(&s(&["--quick", "--target", "8.8.8.8", "--count", "10", "--only", "ALT; fake", "--no-save"])).unwrap();
        assert!(a.quick && a.no_save && !a.no_direct);
        assert!(TuneArgs::parse(&s(&["--no-direct"])).unwrap().no_direct);
        assert_eq!((a.target.as_str(), a.count), ("8.8.8.8", 10));
        assert_eq!(a.only, ["alt", "fake"]);
        assert!(TuneArgs::parse(&s(&["--bypass"])).unwrap().bypass);
        assert!(TuneArgs::parse(&s(&["--quick", "--full"])).is_err());
        assert!(TuneArgs::parse(&s(&["--count", "1"])).is_err());
        assert!(TuneArgs::parse(&s(&["--bogus"])).is_err());
    }
}
