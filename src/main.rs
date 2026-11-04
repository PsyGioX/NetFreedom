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

use std::io::{self, Write};

use nf::crash;
use nf::maint;
use nf::paths::Layout;
use nf::probe;
use nf::profiles;
use nf::run::{self, StartArgs};
use nf::sys;
use nf::tune::{self, TuneArgs};
use nf::ui;
use nf::uninstall;

const HELP: &str = "\
NetFreedom - an open, local, reversible way to reach the open Internet
Games through Cloudflare WARP, or direct bypass of blocks (YouTube, Discord, Cloudflare sites).
Windows: winws + WinDivert.  Linux: nfqws + nftables.

USAGE
  netfreedom                          interactive menu
  netfreedom start [options]          games: zapret protects the WARP handshake, WARP carries the traffic
  netfreedom start --bypass [options] no WARP: unblock sites, YouTube and Discord directly
  netfreedom tune [--bypass]          measure EVERY strategy on your connection and pick the best
  netfreedom stop                     emergency stop (WARP and the packet engine)
  netfreedom check [host] [count]     ping / jitter / packet loss (default 1.1.1.1, 50 probes)
  netfreedom list                     list strategies
  netfreedom doctor                   diagnose the system (drivers, services, lists, conflicts)
  netfreedom ipset [none|any|loaded]  switch the address filter (no argument: show it)
  netfreedom lists update             download fresh host and address lists
  netfreedom fakes [list|set ..]      show / change the fake packets (discord, game)
  netfreedom discord-clean            clear the Discord cache (fixes stuck voice / updates)
  netfreedom autostart <on|off|status> run at logon (Windows task) / boot (systemd)
  netfreedom install-warp             how to install Cloudflare WARP on this system
  netfreedom verify                   check the package against SHA256SUMS.txt, show this program's SHA-256
  netfreedom about                    the philosophy of the project
  netfreedom uninstall                full cleanup

START OPTIONS
  -s, --strategy <name>  e.g. warp, balanced, split   (default: last used / recommended)
  -m, --mode <1|2|3>     bypass strategies: 1 low latency / game traffic off, 2 all ports, 3 custom ports
      --tcp <ports>      custom TCP ports (mode 3), e.g. 3074,27000-27100
      --udp <ports>      custom UDP ports (mode 3)
      --bypass           no WARP
      --headless         no prompts, run until stopped (used by autostart)
      --show-winws       show the winws console window (Windows)
      --no-probe         skip the quick check after start
      --native           EXPERIMENTAL (Windows): packet engine inside this process, WARP strategies only
  -v, --verbose          print the engine command line

TUNE OPTIONS
      --bypass           judge by real downloads (Cloudflare file, Discord, YouTube) instead of tunnel latency
      --quick            WARP strategies only (about a third of the time)
      --full             also test the heavy compatibility capture of every bypass strategy
      --only \"a;b\"       only strategies whose name contains one of these words
      --target <host>    what to measure through the tunnel (default 1.1.1.1; a game server IP is best)
      --count <5-200>    probes per scenario (default 15)       --timeout <3-120>  connect timeout, s (default 12)
      --top <1-10>       how many leaders get a longer confirmation run (default 3; --no-confirm skips it)
      --plain-score      rank by median latency only (default ranking punishes jitter and spikes, as games feel them)
      --no-baseline      skip the no-bypass test       --no-save   do not remember the winner
";

const ABOUT: &str = "\
NetFreedom - philosophy

  1. Access is not a privilege. The tool exists so that an ordinary person can reach the open
     Internet and play with friends without becoming a network engineer.
  2. Local and transparent. Everything runs on your machine. No server of ours, no account, no
     telemetry, no hidden updates. The only network traffic is what you asked for.
  3. Reversible. Every start can be undone: closing the window, Ctrl+C, a crash or `stop` all
     return the system to how it was (WARP disconnected, driver and firewall rules removed).
  4. Measure, do not guess. What works depends on the provider and changes with time, so the tool
     tests strategies on YOUR connection and shows the numbers, including its own failures.
  5. Games first. Least overhead wins: only the packets that must be touched are touched, only
     the first ones of a flow, and real game data is never rewritten.
  6. Small and honest. One executable, strategies as plain data, no promises it cannot keep:
     if nothing works on your connection it says so instead of pretending.
";

fn main() {
    sys::console_init();
    let log = Layout::discover().map(|l| l.utils.join("crash.log")).unwrap_or_else(|_| std::env::temp_dir().join("netfreedom-crash.log"));
    crash::install(log.clone());
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (code, pause) = match crash::guard(|| dispatch(&args)) {
        Ok(r) => r,
        Err(msg) if msg.contains("failed printing to std") => (0, false), // closed pipe (`| head`)
        Err(msg) => {
            // a panic must never just close the window: undo what is running, say what happened
            let _ = crash::guard(run::cleanup_all);
            ui::error(&format!("Internal error: {}", msg.lines().next().unwrap_or("unknown")));
            ui::say(&format!("Details were saved to {}. Everything that was running has been stopped.", log.display()));
            (101, true)
        }
    };
    if pause || code != 0 {
        ui::pause_if_own_console();
    }
    std::process::exit(code);
}

fn needs_admin_msg() -> &'static str {
    if cfg!(windows) {
        "Administrator rights are required (WinDivert driver, services)."
    } else {
        "Root rights are required (nftables, NFQUEUE). Run with sudo."
    }
}

/// Returns (exit code, keep the window open when it is our own console).
fn dispatch(args: &[String]) -> (i32, bool) {
    let cmd = args.first().map(String::as_str).unwrap_or("");
    let rest = args.get(1..).unwrap_or(&[]);
    match cmd {
        "-h" | "--help" | "help" => {
            let _ = io::stdout().write_all(HELP.as_bytes());
            (0, false)
        }
        "-V" | "--version" => {
            println!("netfreedom {}", env!("CARGO_PKG_VERSION"));
            (0, false)
        }
        "verify" => {
            let r = match Layout::discover() {
                Ok(l) => nf::verify::run(&l),
                Err(e) => Err(format!("cannot locate the program folder: {e}")),
            };
            finish(r, true)
        }
        "about" => {
            let _ = io::stdout().write_all(ABOUT.as_bytes());
            (0, true)
        }
        "list" => {
            let mut out = io::stdout().lock();
            for p in profiles::PROFILES {
                let kind = if p.is_dedicated_lean() { "warp  " } else { "bypass" };
                if writeln!(out, "{kind} {:<11} {}", p.name, p.desc).is_err() {
                    break; // closed pipe (e.g. `| head`): stop quietly instead of panicking
                }
            }
            (0, false)
        }
        "check" => {
            check(rest);
            (0, true)
        }
        "install-warp" => {
            install_warp();
            (0, true)
        }
        "start" | "stop" | "tune" | "uninstall" | "doctor" | "ipset" | "lists" | "fakes" | "discord-clean" | "autostart" | "" => {
            if !sys::is_elevated() {
                if sys::relaunch_elevated(args) {
                    return (0, false);
                }
                ui::error(needs_admin_msg());
                return (1, true);
            }
            let layout = match Layout::discover() {
                Ok(l) => l,
                Err(e) => {
                    ui::error(&format!("cannot locate the program folder: {e}"));
                    return (1, true);
                }
            };
            match cmd {
                "start" => start(&layout, rest),
                "tune" => tune_cmd(&layout, rest),
                "stop" => {
                    run::stop();
                    (0, true)
                }
                "uninstall" => finish(uninstall::run(&layout), true),
                "doctor" => finish(maint::doctor(&layout), true),
                "ipset" => finish(maint::ipset(&layout, rest.first().map(String::as_str)), true),
                "lists" => match rest.first().map(String::as_str) {
                    Some("update") => finish(maint::lists_update(&layout), true),
                    _ => {
                        ui::error("use: netfreedom lists update");
                        (2, true)
                    }
                },
                "fakes" => finish(maint::fakes(&layout, rest), true),
                "discord-clean" => finish(maint::discord_clean(), true),
                "autostart" => finish(maint::autostart(rest), true),
                _ => menu(&layout),
            }
        }
        other => {
            ui::error(&format!("unknown command: {other}\n"));
            let _ = io::stdout().write_all(HELP.as_bytes());
            (2, true)
        }
    }
}

fn finish(r: Result<(), String>, pause: bool) -> (i32, bool) {
    match r {
        Ok(()) => (0, pause),
        Err(e) => {
            ui::error(&e);
            (1, true)
        }
    }
}

fn start(layout: &Layout, rest: &[String]) -> (i32, bool) {
    match StartArgs::parse(rest) {
        Ok(a) => {
            sys::set_title(if a.bypass { "NetFreedom: bypass" } else { "NetFreedom: games via WARP" });
            finish(run::start(layout, a), false)
        }
        Err(e) => {
            ui::error(&e);
            (2, true)
        }
    }
}

fn tune_cmd(layout: &Layout, rest: &[String]) -> (i32, bool) {
    sys::set_title("NetFreedom: provider tuning");
    match TuneArgs::parse(rest) {
        Ok(a) => finish(tune::run(layout, a), true),
        Err(e) => {
            ui::error(&e);
            (2, true)
        }
    }
}

fn check(rest: &[String]) {
    sys::set_title("Ping and packet loss check");
    let (target, count) = match rest.first() {
        Some(t) => (t.clone(), rest.get(1).and_then(|c| c.parse().ok()).unwrap_or(50)),
        None => {
            println!("Measures latency, jitter and packet loss to any host.");
            println!("Run it while WARP is connected to measure the path through the tunnel.");
            println!("Tip: use the IP of your game server for the most meaningful result.\n");
            let t = ui::ask("Target IP or host", "1.1.1.1");
            let c = ui::ask("Number of probes", "50").parse().unwrap_or(50);
            (t, c)
        }
    };
    probe::run(&target, &probe::Options { count: count.clamp(1, 1000), ..Default::default() });
}

#[cfg(windows)]
fn install_warp() {
    const WARP_DOWNLOAD: &str = "https://downloads.cloudflareclient.com/v1/download/windows/ga";
    println!("This is the ONLY step of the project that needs the Internet:");
    println!("downloading the official Cloudflare WARP installer.\n");
    println!("After installation:");
    println!("  1. Select Private browsing.");
    println!("  2. Accept the terms.");
    println!("  3. Do not connect WARP yet.");
    println!("  4. Run `netfreedom start` as administrator.\n");
    if !sys::open_url(WARP_DOWNLOAD) {
        println!("Could not open the browser. Download manually:\n{WARP_DOWNLOAD}");
    }
}

#[cfg(unix)]
fn install_warp() {
    println!("{}", uninstall::install_instructions(uninstall::family()));
}

fn menu(layout: &Layout) -> (i32, bool) {
    sys::set_title("NetFreedom");
    loop {
        println!("\n  NetFreedom {}\n", env!("CARGO_PKG_VERSION"));
        println!("  1. Games via Cloudflare WARP");
        println!("  2. Unblock sites, YouTube, Discord (no WARP)");
        println!("  3. Find the best strategy for my provider (tune)");
        println!("  4. Stop everything");
        println!("  5. Check ping and packet loss");
        println!("  6. Diagnostics (doctor)");
        println!("  7. Tools: lists, ipset, Discord cache, autostart");
        println!("  8. How to install Cloudflare WARP");
        println!("  9. About / philosophy");
        println!("  U. Full uninstall");
        println!("  0. Exit\n");
        match ui::choice("Select: ", "1234567890uU89") {
            '1' => return start(layout, &[]),
            '2' => return start(layout, &["--bypass".to_string()]),
            '3' => {
                let bypass = ui::choice("Tune for [G]ames via WARP or [B]ypass without WARP? ", "GB") == 'B';
                let a: Vec<String> = if bypass { vec!["--bypass".to_string()] } else { Vec::new() };
                return tune_cmd(layout, &a);
            }
            '4' => run::stop(),
            '5' => check(&[]),
            '6' => {
                let _ = maint::doctor(layout);
            }
            '7' => tools_menu(layout),
            '8' => install_warp(),
            '9' => {
                let _ = io::stdout().write_all(ABOUT.as_bytes());
            }
            'u' | 'U' => {
                if let Err(e) = uninstall::run(layout) {
                    ui::error(&e);
                }
            }
            _ => return (0, false),
        }
    }
}

fn tools_menu(layout: &Layout) {
    println!("\n  1. Update host and address lists");
    println!("  2. Address filter (ipset): show / change");
    println!("  3. Clear the Discord cache");
    println!("  4. Fake packets: show");
    println!("  5. Autostart: show / enable / disable");
    println!("  0. Back\n");
    let r = match ui::choice("Select: ", "123450") {
        '1' => maint::lists_update(layout),
        '2' => {
            let _ = maint::ipset(layout, None);
            let a = ui::ask("Change to none / any / loaded (Enter = keep)", "");
            if a.is_empty() { Ok(()) } else { maint::ipset(layout, Some(&a)) }
        }
        '3' => maint::discord_clean(),
        '4' => maint::fakes(layout, &[]),
        '5' => {
            let _ = maint::autostart(&[]);
            match ui::choice("[E]nable (bypass or WARP, last used strategy), [D]isable, [B]ack: ", "EDB") {
                'E' => {
                    let bypass = ui::choice("Autostart [G]ames via WARP or [B]ypass without WARP? ", "GB") == 'B';
                    maint::autostart(&if bypass { vec!["on".to_string(), "--bypass".into()] } else { vec!["on".to_string()] })
                }
                'D' => maint::autostart(&["off".to_string()]),
                _ => Ok(()),
            }
        }
        _ => Ok(()),
    };
    if let Err(e) = r {
        ui::error(&e);
    }
}
