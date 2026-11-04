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

//! The `start` and `stop` flows. Two modes share one engine:
//!
//!   * games through WARP (default): the packet engine protects the WARP handshake, WARP carries
//!     the traffic;
//!   * bypass (`--bypass`): no WARP at all, the strategy itself unblocks sites, YouTube, Discord.

use std::time::{Duration, Instant};

use crate::backend::{self, Outcome};
use crate::capture::{self, expand, GameFilter, Vars};
use crate::config::Config;
use crate::paths::Layout;
use crate::probe;
use crate::profiles::{self, Profile, DEFAULT_BYPASS, DEFAULT_PROFILE, WFRAW};
use crate::sys;
use crate::ui;
use crate::warp::Warp;
use crate::web;

#[derive(Default)]
pub struct StartArgs {
    pub profile: Option<String>,
    pub mode: Option<u8>,
    pub tcp: Option<String>,
    pub udp: Option<String>,
    pub show_winws: bool,
    pub no_probe: bool,
    pub verbose: bool,
    /// Experimental: run the packet engine inside this process instead of winws.exe.
    pub native: bool,
    /// No WARP: the strategy unblocks sites directly.
    pub bypass: bool,
    /// No prompts: run until stopped (autostart, services).
    pub headless: bool,
}

impl StartArgs {
    pub fn parse(args: &[String]) -> Result<Self, String> {
        let mut a = Self::default();
        let mut it = args.iter();
        while let Some(arg) = it.next() {
            let mut value = |name: &str| it.next().cloned().ok_or(format!("{name} needs a value"));
            match arg.as_str() {
                "--profile" | "--strategy" | "-p" | "-s" => a.profile = Some(value("--strategy")?),
                "--mode" | "-m" => {
                    let m: u8 = value("--mode")?.parse().map_err(|_| "--mode must be 1, 2 or 3")?;
                    if !(1..=3).contains(&m) {
                        return Err("--mode must be 1, 2 or 3".into());
                    }
                    a.mode = Some(m);
                }
                "--tcp" => a.tcp = Some(value("--tcp")?),
                "--udp" => a.udp = Some(value("--udp")?),
                "--show-winws" => a.show_winws = true,
                "--no-probe" => a.no_probe = true,
                "--native" => a.native = true,
                "--bypass" => a.bypass = true,
                "--headless" => a.headless = true,
                "--verbose" | "-v" => a.verbose = true,
                // 2.x switches: the choice is now implied by the strategy itself
                "--lean" | "--classic" => {}
                other => return Err(format!("unknown option: {other}")),
            }
        }
        Ok(a)
    }
}

pub struct Plan {
    pub profile: &'static Profile,
    pub lean: bool,
    pub gf: GameFilter,
    /// Capture mode answer (1-3), used to decide whether compatibility was already tried.
    pub mode: u8,
}

fn choose_profile(cfg: &Config, arg: &Option<String>, bypass: bool, headless: bool) -> Result<&'static Profile, String> {
    if let Some(name) = arg {
        let p = profiles::find(name).ok_or_else(|| format!("unknown strategy \"{name}\" (see `netfreedom list`)"))?;
        if bypass && !p.is_bypass() {
            return Err(format!("\"{}\" only protects the WARP handshake; for bypass without WARP use one of: {}", p.name, bypass_names()));
        }
        return Ok(p);
    }
    let remembered = if bypass { &cfg.bypass } else { &cfg.profile };
    let default_name = if bypass { DEFAULT_BYPASS } else { DEFAULT_PROFILE };
    let last = profiles::find(remembered).filter(|p| !bypass || p.is_bypass()).or_else(|| profiles::find(default_name));
    if headless {
        return last.ok_or_else(|| "no strategy to run".to_string());
    }
    println!();
    println!("{}", if bypass { "Select a bypass strategy (no WARP):" } else { "Select a strategy (WARP strategies = least overhead, recommended):" });
    let shown: Vec<&'static Profile> = profiles::PROFILES.iter().filter(|p| !bypass || p.is_bypass()).collect();
    let mut last_idx = None;
    for (i, p) in shown.iter().enumerate() {
        let is_last = last.is_some_and(|l| std::ptr::eq(l, *p));
        if is_last {
            last_idx = Some(i + 1);
        }
        println!("  {:>2}. {:<11} {}{}", i + 1, p.name, p.desc, if is_last { "   <-- last used" } else { "" });
    }
    println!();
    let def = last_idx.map(|i| i.to_string()).unwrap_or_default();
    let answer = ui::ask("Enter number", &def);
    let n: usize = answer.parse().map_err(|_| "Invalid number.".to_string())?;
    shown.get(n.wrapping_sub(1)).copied().ok_or_else(|| "Invalid number.".to_string())
}

fn bypass_names() -> String {
    profiles::PROFILES.iter().filter(|p| p.is_bypass()).map(|p| p.name).collect::<Vec<_>>().join(", ")
}

fn read_ports(prompt: &str, default: &str) -> Result<String, String> {
    let v = ui::ask(prompt, default);
    if v.is_empty() {
        return Ok(v);
    }
    capture::normalize_ports(&v).ok_or_else(|| "Invalid port list: use digits, commas and dashes, 1-65535.".to_string())
}

fn select(cfg: &mut Config, a: &StartArgs) -> Result<Plan, String> {
    let profile = choose_profile(cfg, &a.profile, a.bypass, a.headless)?;
    if a.bypass {
        cfg.bypass = profile.name.to_owned();
    } else {
        cfg.profile = profile.name.to_owned();
    }

    if profile.is_dedicated_lean() {
        println!("\n{}: only the QUIC handshake packets to Cloudflare are diverted, capture mode is not used.", profile.name);
        return Ok(Plan { profile, lean: true, gf: GameFilter::low_latency(), mode: cfg.mode });
    }

    // port-based capture: which extra (game) ports go through the engine
    let mode = match a.mode {
        Some(m) => m,
        None if a.headless => cfg.mode,
        None if a.bypass => {
            println!("\nGame traffic through the engine:");
            println!("  1. Off           - sites, YouTube and Discord only (recommended)");
            println!("  2. All ports     - 1024-65535 TCP+UDP (heavier; for games that are blocked themselves)");
            println!("  3. Custom ports");
            ui::ask("Mode", "1").parse().ok().filter(|m| (1..=3).contains(m)).unwrap_or(1)
        }
        None => {
            println!("\nSelect capture mode (which ports the packet engine intercepts):");
            println!("  1. Low latency   - only WARP tunnel ports (recommended, least overhead)");
            println!("  2. Compatibility - all ports 1024-65535 TCP+UDP (heavier, use if mode 1 fails)");
            println!("  3. Custom ports\n");
            ui::ask("Mode", &cfg.mode.to_string()).parse().ok().filter(|m| (1..=3).contains(m)).unwrap_or(1)
        }
    };
    cfg.mode = mode;
    let gf = match mode {
        2 => GameFilter::compatibility(),
        3 => {
            println!("\nEnter ports or ranges separated by commas, for example: 3074,27000-27100");
            println!("Leave a field empty to skip that protocol.");
            let udp = match &a.udp {
                Some(v) => capture::normalize_ports(v).ok_or("Invalid --udp port list")?,
                None if a.headless => cfg.udp.clone(),
                None => read_ports("UDP ports", &cfg.udp)?,
            };
            let tcp = match &a.tcp {
                Some(v) => capture::normalize_ports(v).ok_or("Invalid --tcp port list")?,
                None if a.headless => cfg.tcp.clone(),
                None => read_ports("TCP ports", &cfg.tcp)?,
            };
            cfg.udp = udp.clone();
            cfg.tcp = tcp.clone();
            GameFilter::custom(&tcp, &udp)
        }
        _ if a.bypass => GameFilter::disabled(),
        _ => GameFilter::low_latency(),
    };
    Ok(Plan { profile, lean: false, gf, mode })
}

/// Starts the packet engine for `plan`. `quiet` suppresses progress lines (used by `tune`).
pub fn launch(layout: &Layout, plan: &Plan, a: &StartArgs, use_native: bool, quiet: bool) -> Result<(), String> {
    let tpl = if plan.lean { plan.profile.lean } else { plan.profile.classic }
        .ok_or_else(|| format!("strategy \"{}\" has no such variant", plan.profile.name))?;
    let (tcp, udp) = plan.gf.effective();
    let args = expand(tpl, &Vars { bin: &layout.bin, lists: &layout.lists, wfraw: WFRAW, gf_tcp: tcp, gf_udp: udp });

    if !quiet {
        println!();
        if plan.lean {
            println!("Starting \"{}\": WARP handshake only (QUIC to Cloudflare)", plan.profile.name);
        } else {
            println!("Starting \"{}\": capture mode {} (extra TCP {tcp} / UDP {udp})", plan.profile.name, plan.gf.mode.as_str());
        }
    }
    if !plan.lean {
        backend::prepare_classic();
    }
    if a.verbose && !quiet {
        println!("engine arguments: {}", args.iter().map(|s| format!("\"{s}\"")).collect::<Vec<_>>().join(" "));
    }

    if use_native && plan.lean {
        match backend::native_try(layout, &args) {
            Ok(true) => {
                if !quiet {
                    println!("Native engine is running inside this process (EXPERIMENTAL: no winws.exe, no Cygwin).");
                }
                return Ok(());
            }
            Ok(false) => {}
            Err(e) => ui::warn(&format!("native engine unavailable: {e}\n         falling back to the normal engine")),
        }
    }

    backend::start(layout, &args, a.show_winws)?;
    if !quiet {
        println!("The packet engine is running.");
    }
    Ok(())
}

/// Disconnect WARP and stop the engine. Idempotent, silent on success.
pub fn cleanup_all() {
    if let Some(w) = Warp::locate() {
        w.disconnect();
        w.close_app();
    }
    backend::native_stop();
    backend::stop_all();
}

/// Cleanup for bypass mode: WARP is not touched (the user may be using it for something else).
pub fn cleanup_engine_only() {
    backend::native_stop();
    backend::stop_all();
}

fn cleanup_verbose(had_warp: bool) {
    sys::arm_cleanup(false);
    println!();
    if let Some(s) = backend::native_stop() {
        println!("Native engine: {} packets seen, {} desynchronised, {} fake packets sent, {} passed.", s.packets, s.desynced, s.fakes_sent, s.passed);
    }
    if had_warp {
        if let Some(w) = Warp::locate() {
            println!("Disconnecting Cloudflare WARP...");
            w.disconnect();
        }
    }
    println!("Stopping the packet engine...");
    backend::stop_all();
    if had_warp {
        if let Some(w) = Warp::locate() {
            w.close_app();
        }
    }
    println!("Everything has been stopped.");
}

/// Connects WARP and waits for `Connected`. Returns (connected, seconds, last status text).
pub fn connect_warp(warp: &Warp, timeout: Duration) -> (bool, f32, String) {
    let t0 = Instant::now();
    warp.connect();
    let (ok, status) = warp.wait_connected(timeout);
    (ok, t0.elapsed().as_secs_f32(), status)
}

/// Blocks until the user presses Enter (interactive) or the process is asked to stop (headless).
fn wait_until_stopped(headless: bool) {
    if headless {
        sys::set_graceful(true);
        while !sys::interrupted() {
            std::thread::sleep(Duration::from_millis(500));
        }
    } else {
        print!("Press Enter to stop everything...");
        ui::read_line();
    }
}

fn print_web(results: &[web::WebResult]) {
    for r in results {
        if r.ok {
            ui::ok(&r.line());
        } else {
            ui::warn(&r.line());
        }
    }
}

pub fn start(layout: &Layout, a: StartArgs) -> Result<(), String> {
    if a.bypass {
        return start_bypass(layout, a);
    }
    let warp = Warp::locate().ok_or("Cloudflare WARP is not installed. Run `netfreedom install-warp` first (or use `netfreedom start --bypass` to unblock sites without WARP).")?;
    if backend::engine_running() {
        return Err("The packet engine is already running.\nReturn to the existing window and press Enter to stop it, or run `netfreedom stop`.".into());
    }
    backend::check_engine(layout)?;
    if let Some(note) = warp.prepare()? {
        println!("{note}");
    }
    layout.ensure_user_lists().map_err(|e| format!("cannot prepare lists: {e}"))?;

    let mut cfg = Config::load_with_legacy(&layout.cfg, &layout.cfg_legacy);
    let mut plan = select(&mut cfg, &a)?;
    let _ = cfg.save(&layout.cfg);

    let mut compat_tried = !plan.lean && plan.mode == 2;
    sys::install_cleanup_handler(cleanup_all);

    let mut use_native = a.native;
    let connected = loop {
        launch(layout, &plan, &a, use_native, false)?;
        sys::arm_cleanup(true);

        println!("Selecting the MASQUE tunnel protocol...");
        let (_, out) = warp.set_masque();
        if !out.is_empty() {
            println!("{out}");
        }
        warp.launch_app();
        println!("Connecting Cloudflare WARP...");
        let (_, out) = warp.connect();
        if !out.is_empty() {
            println!("{out}");
        }

        println!("Waiting for the tunnel (up to 30 s)...");
        let t0 = Instant::now();
        let (connected, status) = warp.wait_connected(Duration::from_secs(30));
        println!("{status}");
        if connected {
            println!("Connected in {:.1} s.", t0.elapsed().as_secs_f32());
            break true;
        }

        println!("\nWARP did not report Connected.");
        if a.headless {
            // nobody to ask: keep what is running, the tunnel may still come up
            break false;
        }
        if backend::native_active() {
            match ui::choice("[W] retry with winws.exe, [C] continue anyway, [Q] stop everything: ", "WCQ") {
                'Q' => {
                    cleanup_verbose(true);
                    return Ok(());
                }
                'C' => break false,
                _ => {
                    use_native = false;
                    warp.disconnect();
                    backend::native_stop();
                    backend::stop_all();
                }
            }
        } else if !compat_tried {
            println!("Compatibility mode captures all ports and may help on strict networks.");
            match ui::choice("[R] retry in Compatibility mode, [C] continue anyway, [Q] stop everything: ", "RCQ") {
                'Q' => {
                    cleanup_verbose(true);
                    return Ok(());
                }
                'C' => break false,
                _ => {
                    compat_tried = true;
                    if plan.profile.is_dedicated_lean() {
                        plan.profile = profiles::find(DEFAULT_BYPASS).expect("default bypass strategy exists");
                    }
                    plan.lean = false;
                    plan.gf = GameFilter::compatibility();
                    warp.disconnect();
                    backend::stop_all();
                }
            }
        } else if ui::choice("[C] continue anyway, [Q] stop everything: ", "CQ") == 'Q' {
            cleanup_verbose(true);
            return Ok(());
        } else {
            break false;
        }
    };

    println!();
    if connected && !a.no_probe && !a.headless {
        println!("Quick link quality check through the tunnel...");
        probe::run("1.1.1.1", &probe::Options { count: 20, ..Default::default() });
        println!("\nFor your game server use `netfreedom check <server-ip>`.");
    }
    println!("\nNow start your game or launcher (Steam, Epic, Battle.net, EA, Ubisoft, Riot, ...).");
    println!("Keep this window open while you play. Closing it also stops everything.");
    println!("\nWhen you finish, return to this window and press Enter.");
    wait_until_stopped(a.headless);
    cleanup_verbose(true);
    Ok(())
}

/// Bypass without WARP: engine only.
fn start_bypass(layout: &Layout, a: StartArgs) -> Result<(), String> {
    if backend::engine_running() {
        return Err("The packet engine is already running.\nReturn to the existing window and press Enter to stop it, or run `netfreedom stop`.".into());
    }
    backend::check_engine(layout)?;
    layout.ensure_user_lists().map_err(|e| format!("cannot prepare lists: {e}"))?;

    let mut cfg = Config::load_with_legacy(&layout.cfg, &layout.cfg_legacy);
    let plan = select(&mut cfg, &a)?;
    let _ = cfg.save(&layout.cfg);

    sys::install_cleanup_handler(cleanup_engine_only);
    launch(layout, &plan, &a, false, false)?;
    sys::arm_cleanup(true);

    if !a.no_probe && !a.headless {
        if web::curl_available() {
            println!("\nChecking that it works (a Cloudflare-hosted file, Discord, YouTube)...");
            let results = web::probe(Duration::from_secs(12));
            print_web(&results);
            if results.iter().any(|r| !r.ok) {
                println!("\nSomething is still blocked. `netfreedom tune --bypass` tries every strategy on your connection and picks the best.");
            }
        } else {
            ui::warn("curl was not found, so the result was not checked.");
        }
    }
    println!("\nThe bypass is active. Keep this window open; closing it also stops everything.");
    wait_until_stopped(a.headless);
    cleanup_verbose(false);
    Ok(())
}

/// `netfreedom stop` - emergency stop.
pub fn stop() {
    if let Some(w) = Warp::locate() {
        let (ok, out) = w.disconnect();
        if ok {
            ui::ok("Cloudflare WARP disconnected");
        } else if !out.is_empty() {
            ui::warn(&out);
        }
        w.close_app();
    }
    for (name, r) in backend::stop_all() {
        match r {
            Outcome::Done => ui::ok(&format!("{name} stopped / removed")),
            Outcome::Absent => ui::skip(&format!("{name}: nothing to remove")),
            Outcome::Failed(e) => ui::warn(&format!("{name}: {e}")),
        }
    }
    println!("Done: WARP disconnected, the packet engine stopped.");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn start_arguments() {
        let a = StartArgs::parse(&s(&["--bypass", "-s", "split", "--headless", "--mode", "2"])).unwrap();
        assert!(a.bypass && a.headless);
        assert_eq!((a.profile.as_deref(), a.mode), (Some("split"), Some(2)));
        // 2.x switches are accepted and ignored
        assert!(StartArgs::parse(&s(&["--lean", "--classic", "-p", "warp"])).is_ok());
        assert!(StartArgs::parse(&s(&["--mode", "9"])).is_err());
        assert!(StartArgs::parse(&s(&["--bogus"])).is_err());
    }

    #[test]
    fn bypass_refuses_warp_only_strategies() {
        let cfg = Config::default();
        let e = choose_profile(&cfg, &Some("warp".into()), true, false).err().unwrap();
        assert!(e.contains("only protects the WARP handshake"), "{e}");
        assert_eq!(choose_profile(&cfg, &Some("split".into()), true, false).unwrap().name, "split");
        assert_eq!(choose_profile(&cfg, &Some("general (ALT5)".into()), false, false).unwrap().name, "seqfake", "old names keep working");
    }
}
