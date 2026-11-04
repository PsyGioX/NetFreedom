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
}

impl Default for TuneArgs {
    fn default() -> Self {
        Self {
            bypass: false,
            quick: false,
            full: false,
            only: Vec::new(),
            target: "1.1.1.1".into(),
            count: 15,
            timeout_s: 12,
            no_save: false,
            no_confirm: false,
            no_baseline: false,
            top: 3,
            plain_score: false,
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

/// Builds the list of scenarios for the given options (pure, unit-tested). Every strategy is unique
/// (the table is deduplicated), so nothing is measured twice.
pub fn scenarios(a: &TuneArgs) -> Vec<Scenario> {
    let wanted = |p: &Profile| a.only.is_empty() || a.only.iter().any(|o| p.name.to_lowercase().contains(o));
    let mut v = Vec::new();
    if !a.no_baseline && a.only.is_empty() {
        let label = if a.bypass { "no bypass (baseline)" } else { "plain WARP (no zapret)" };
        v.push(Scenario { label: label.into(), profile: None, mode: 0, penalty: 0.0, bypass_goal: a.bypass });
    }
    for p in profiles::PROFILES.iter().filter(|p| wanted(p)) {
        if a.bypass {
            if p.is_bypass() {
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

fn teardown(warp: Option<&Warp>) {
    if let Some(w) = warp {
        w.disconnect();
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
        if let Err(e) = run::launch(layout, &plan, &StartArgs::default(), false, true) {
            r.note = format!("engine failed: {}", e.lines().next().unwrap_or(""));
            teardown(warp);
            return r;
        }
    }

    if a.bypass {
        settle(600);
        r.web = web::probe(Duration::from_secs(a.timeout_s));
        r.connected = r.web.iter().any(|w| w.ok);
        r.score = web::score(&r.web);
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
    r.connected = true;
    settle(700);
    let opts = Options { count, interval_ms: 120, timeout_ms: 1000, warmup: true, tunnel_stats: false };
    match probe::measure(&a.target, &opts) {
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

pub fn run(layout: &Layout, a: TuneArgs) -> Result<(), String> {
    let warp = if a.bypass {
        if !web::curl_available() {
            return Err("curl was not found: `tune --bypass` downloads real files with it (it ships with Windows 10+ and Linux).".into());
        }
        None
    } else {
        let w = Warp::locate().ok_or("Cloudflare WARP is not installed. Run `netfreedom install-warp` first (or use `netfreedom tune --bypass` to test unblocking without WARP).")?;
        if let Some(note) = w.prepare()? {
            println!("{note}");
        }
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

    let per = if a.bypass { 14 } else { a.count as u64 * 120 / 1000 + 6 };
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

    sys::install_cleanup_handler(if a.bypass { run::cleanup_engine_only } else { run::cleanup_all });
    sys::arm_cleanup(true);
    sys::set_graceful(true);
    let started = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    if let Some(w) = &warp {
        let (_, out) = w.set_masque();
        if !out.is_empty() {
            println!("{out}");
        }
        w.launch_app();
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
                results[i].score = (results[i].score + again.score) / 2.0;
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
    save_report(layout, &results, &a, started, !stopped);

    println!("\n==================== Results (best first) ====================");
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

    let report_path = layout.utils.join("tune_report.txt");
    let Some(best) = results.first().filter(|r| r.score.is_finite()) else {
        println!("\nNo scenario worked. Check the Internet connection, antivirus/firewall{}.", if a.bypass { "" } else { ", and that WARP can register" });
        println!("Full report: {}", report_path.display());
        return Ok(());
    };
    println!();
    match best.scenario.profile {
        None if a.bypass => {
            println!("Nothing is blocked right now: no bypass is needed. If sites stop opening later, run this again.");
        }
        None => {
            println!("Plain WARP is the best result: your provider does not seem to block the WARP handshake, so zapret is not needed.");
            if let Some(alt) = results.iter().find(|r| r.scenario.profile.is_some() && r.score.is_finite()) {
                println!("Best with zapret (use only if WARP stops connecting later): {}  ->  {}", alt.scenario.label, alt.scenario.command());
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
        // baseline + 4 WARP strategies + 9 bypass strategies (low latency)
        assert_eq!(all.len(), 1 + 4 + 9);
        assert!(all[0].profile.is_none());
        let labels: std::collections::HashSet<_> = all.iter().map(|s| s.label.clone()).collect();
        assert_eq!(labels.len(), all.len());
        assert_eq!(scenarios(&TuneArgs { quick: true, ..Default::default() }).len(), 1 + 4);
        assert_eq!(scenarios(&TuneArgs { full: true, ..Default::default() }).len(), 1 + 4 + 18);
        let b = scenarios(&TuneArgs { bypass: true, ..Default::default() });
        assert_eq!(b.len(), 1 + 9, "bypass goal: baseline + the 9 bypass strategies, no WARP strategies");
        assert!(b.iter().skip(1).all(|s| s.bypass_goal && s.profile.unwrap().is_bypass()));
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

    #[test]
    fn argument_parsing() {
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        let a = TuneArgs::parse(&s(&["--quick", "--target", "8.8.8.8", "--count", "10", "--only", "ALT; fake", "--no-save"])).unwrap();
        assert!(a.quick && a.no_save);
        assert_eq!((a.target.as_str(), a.count), ("8.8.8.8", 10));
        assert_eq!(a.only, ["alt", "fake"]);
        assert!(TuneArgs::parse(&s(&["--bypass"])).unwrap().bypass);
        assert!(TuneArgs::parse(&s(&["--quick", "--full"])).is_err());
        assert!(TuneArgs::parse(&s(&["--count", "1"])).is_err());
        assert!(TuneArgs::parse(&s(&["--bogus"])).is_err());
    }
}
