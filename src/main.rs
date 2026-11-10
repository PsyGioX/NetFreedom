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

use nf::config::Config;
use nf::dns;
use nf::crash;
use nf::dash;
use nf::health;
use nf::maint;
use nf::netdiag;
use nf::paths::Layout;
use nf::probe;
use nf::profiles;
use nf::run::{self, StartArgs};
use nf::session;
use nf::sys;
use nf::tune::{self, TuneArgs};
use nf::ui;
use nf::uninstall;

const HELP: &str = "\
NetFreedom - an open, local, reversible way to reach the open Internet
Games through Cloudflare WARP, or direct bypass of blocks (YouTube, Discord, Cloudflare sites).
Windows: built-in engine + WinDivert driver.  Linux: nfqws + nftables.

USAGE
  netfreedom                          interactive menu
  netfreedom start [options]          games: the engine protects the WARP handshake, WARP carries the traffic
  netfreedom start --bypass [options] no WARP: unblock sites, YouTube and Discord directly
  netfreedom tune [--bypass]          measure EVERY strategy on your connection and pick the best
  netfreedom stop                     emergency stop (WARP and the packet engine)
  netfreedom check [host] [count]     ping / jitter / packet loss (default 1.1.1.1, 50 probes)
      --load                          also test latency UNDER LOAD (bufferbloat): the line is saturated for ~30 s
  netfreedom list                     list strategies
  netfreedom doctor [--net [host]]    diagnose the system (drivers, services, lists, conflicts);
                                      --net adds Wi-Fi/cable, background traffic and latency under load
  netfreedom dns [status|list|bench|set|restore]  encrypted DNS: Cloudflare, Google or Quad9 (DoH on Windows 11, DoT on Linux)
  netfreedom ipset [none|any|loaded]  switch the address filter (no argument: show it)
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
      --dns <name>       encrypted DNS for this session: cloudflare, google, quad9, auto (fastest) or off; remembered
      --headless         no prompts, run until stopped (used by autostart)
      --no-probe         skip the quick check after start
  -v, --verbose          print the engine command line

TUNE OPTIONS
      --bypass           judge by real downloads (Cloudflare file, Discord, YouTube) instead of tunnel latency
      --quick            WARP goal: WARP strategies only; bypass goal: the 10 most likely strategies (about a third of the time)
      --full             also test the heavy compatibility capture of every bypass strategy
      --only \"a;b\"       only strategies whose name contains one of these words
      --target <host>    what to measure through the tunnel (default 1.1.1.1; a game server IP is best)
      --count <5-200>    probes per scenario (default 15)       --timeout <3-120>  connect timeout, s (default 12)
      --top <1-10>       how many leaders get a longer confirmation run (default 3; --no-confirm skips it)
      --plain-score      rank by median latency only (default ranking punishes jitter and spikes, as games feel them)
      --no-baseline      skip the no-bypass test       --no-save   do not remember the winner
      --no-direct        WARP goal: skip the final comparison with the direct path (it needs a real --target)
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
    let saved_lang = Layout::discover().map(|l| Config::load_with_legacy(&l.cfg, &l.cfg_legacy).lang).unwrap_or_default();
    ui::init_lang(&saved_lang);
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (code, pause) = match crash::guard(|| dispatch(&args)) {
        Ok(r) => r,
        Err(msg) if msg.contains("failed printing to std") => (0, false), // closed pipe (`| head`)
        Err(msg) => {
            // a panic must never just close the window: undo what is running, say what happened
            let _ = crash::guard(session::cleanup);
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
        "dns" => {
            // only `restore` changes system settings and needs administrator rights
            if rest.first().map(String::as_str) == Some("restore") && !sys::is_elevated() {
                if sys::relaunch_elevated(args) {
                    return (0, false);
                }
                ui::error(needs_admin_msg());
                return (1, true);
            }
            match Layout::discover() {
                Ok(l) => finish(dns::command(&l, rest), true),
                Err(e) => {
                    ui::error(&format!("cannot locate the program folder: {e}"));
                    (1, true)
                }
            }
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
            // One handler for the whole run, installed before any thread exists: Ctrl+C, closing the
            // window, logoff and shutdown all undo what the session did (it only acts while armed).
            sys::install_cleanup_handler(session::cleanup);
            if matches!(cmd, "start" | "" | "tune") {
                dns::recover_stale(&layout); // a crashed run may have left its DNS behind
            }
            match cmd {
                "start" => start(&layout, rest),
                "tune" => tune_cmd(&layout, rest),
                "stop" => {
                    run::stop();
                    (0, true)
                }
                "uninstall" => finish(uninstall::run(&layout), true),
                "doctor" => {
                    let r = maint::doctor(&layout);
                    if rest.iter().any(|a| a == "--net") {
                        // the host to ping under load: an argument, else the saved game server, else 1.1.1.1
                        let host = rest.iter().find(|a| !a.starts_with("--")).cloned().unwrap_or_else(|| {
                            let t = Config::load_with_legacy(&layout.cfg, &layout.cfg_legacy).target;
                            if t.is_empty() { "1.1.1.1".to_owned() } else { t }
                        });
                        netdiag::run_report(&host);
                    }
                    finish(r, true)
                }
                "ipset" => finish(maint::ipset(&layout, rest.first().map(String::as_str)), true),
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

/// `netfreedom start ...`: starts the session, then hands over to the main menu (which shows the
/// live status and stops everything). `--headless` keeps the old behaviour: run until stopped.
fn start(layout: &Layout, rest: &[String]) -> (i32, bool) {
    match StartArgs::parse(rest) {
        Ok(a) => {
            let headless = a.headless;
            sys::set_title(if a.bypass { "NetFreedom: bypass" } else { "NetFreedom: games via WARP" });
            let r = run::start(layout, a);
            if headless || r.is_err() || !session::is_active() {
                return finish(r, false);
            }
            menu(layout)
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
    // `--load` adds the latency-under-load (bufferbloat) test after the usual report
    let load = rest.iter().any(|a| a == "--load");
    let rest: Vec<String> = rest.iter().filter(|a| *a != "--load").cloned().collect();
    let (target, count) = match rest.first() {
        Some(t) => (t.clone(), rest.get(1).and_then(|c| c.parse().ok()).unwrap_or(50)),
        None => {
            println!("{}", ui::tr("Измеряет задержку, джиттер и потери до любого узла.", "Measures latency, jitter and packet loss to any host."));
            println!("{}", ui::tr("Запускайте при включённом WARP, чтобы измерить путь через туннель.", "Run it while WARP is connected to measure the path through the tunnel."));
            println!("{}\n", ui::tr("Совет: для осмысленного результата укажите IP вашего игрового сервера.", "Tip: use the IP of your game server for the most meaningful result."));
            let default = Config::load_with_legacy(&Layout::discover().map(|l| l.cfg).unwrap_or_default(), std::path::Path::new("")).target;
            let default = if default.is_empty() { "1.1.1.1".to_owned() } else { default };
            let t = ui::ask(ui::tr("IP или имя узла", "Target IP or host"), &default);
            let c = ui::ask(ui::tr("Число проб", "Number of probes"), "50").parse().unwrap_or(50);
            (t, c)
        }
    };
    // Is WARP up right now? Then the tunnel must be PROVEN (trace), not assumed.
    let expect_tunnel = nf::warp::Warp::locate().is_some_and(|w| w.is_connected());
    println!("{}", ui::tr("Измеряю…", "Measuring..."));
    health::print_report(&health::full_check(&target, count.clamp(8, 1000), expect_tunnel));
    if load {
        println!("{}", ui::tr("\nДальше канал нагружается около 30 секунд: не играйте и не качайте в это время.", "\nNext the line is loaded for about 30 seconds: do not play or download meanwhile."));
        match netdiag::run_load_test(&target, &netdiag::LoadUrls::cloudflare(), std::time::Duration::from_secs(8)) {
            Ok(r) => netdiag::print_load_report(&r),
            Err(e) => ui::warn(&e),
        }
    }
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

fn pause_back() {
    print!("\n{}", ui::tr("Нажмите Enter, чтобы вернуться в главное меню…", "Press Enter to return to the main menu..."));
    ui::read_line();
}

fn save_cfg(layout: &Layout, f: impl FnOnce(&mut Config)) {
    let mut c = Config::load_with_legacy(&layout.cfg, &layout.cfg_legacy);
    f(&mut c);
    let _ = c.save(&layout.cfg);
}

fn current_target(layout: &Layout) -> String {
    let c = Config::load_with_legacy(&layout.cfg, &layout.cfg_legacy);
    if c.target.is_empty() { "1.1.1.1".to_owned() } else { c.target }
}

/// Starts a session from the menu; shows the outcome and waits so that it can be read.
fn start_from_menu(layout: &Layout, args: &[&str]) {
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    match StartArgs::parse(&args) {
        Ok(a) => {
            sys::set_title(if a.bypass { "NetFreedom: bypass" } else { "NetFreedom: games via WARP" });
            if let Err(e) = run::start(layout, a) {
                ui::error(&e);
            }
        }
        Err(e) => ui::error(&e),
    }
    pause_back();
}

/// Full-screen live status, refreshed every second; Enter returns to the menu.
fn live_monitor() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    let done = Arc::new(AtomicBool::new(false));
    let flag = done.clone();
    let _ = std::thread::Builder::new().name("live-input".into()).spawn(move || {
        ui::read_line();
        flag.store(true, Ordering::SeqCst);
    });
    ui::clear();
    while !done.load(Ordering::SeqCst) && session::is_active() {
        ui::home();
        dash::print();
        ui::say(&format!("\n  {}", ui::paint(ui::DIM, ui::tr("Обновляется каждую секунду · Enter — назад в меню", "Refreshes every second · Enter: back to the menu"))));
        ui::clear_below();
        for _ in 0..10 {
            if done.load(Ordering::SeqCst) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }
    if !done.load(Ordering::SeqCst) {
        println!("{}", ui::tr("Сессия остановлена. Нажмите Enter…", "The session was stopped. Press Enter..."));
        while !done.load(Ordering::SeqCst) {
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }
}

fn quality_now() {
    let Some(a) = session::active() else { return };
    println!("{}", ui::tr("Измеряю (обычно 10–15 с, максимум около 30 с)…", "Measuring (usually 10-15 s, at most about 30 s)..."));
    match a.mode {
        session::Mode::Warp => health::print_report(&health::full_check(&a.target, 25, true)),
        session::Mode::Bypass => {
            let t0 = std::time::Instant::now();
            let r = nf::web::probe(std::time::Duration::from_secs(8));
            run::print_web(&r);
            println!("{} {:.0} {}", ui::tr("Заняло", "Took"), t0.elapsed().as_secs_f64(), ui::tr("с", "s"));
            session::with_health(|h| {
                h.web = r;
                h.web_at = Some(std::time::Instant::now());
            });
        }
    }
}

fn set_game_server(layout: &Layout) {
    println!("{}", ui::tr("IP (или имя) игрового сервера: по нему монитор считает задержку, джиттер и потери.", "IP (or name) of your game server: the monitor measures latency, jitter and loss to it."));
    println!("{}", ui::tr("Узнать его можно в консоли игры, в Resource Monitor → Network → TCP/UDP-соединения игры.", "Find it in the game console or in Resource Monitor -> Network."));
    let t = ui::ask(ui::tr("Сервер", "Server"), &current_target(layout));
    if probe::resolve_v4(&t).is_none() {
        ui::error(&format!("{} \"{t}\"", ui::tr("не удалось получить IPv4-адрес для", "cannot resolve an IPv4 address for")));
        return;
    }
    save_cfg(layout, |c| c.target = t.clone());
    session::set_target(&t);
    ui::ok(&format!("{}: {t}", ui::tr("Сервер сохранён", "Server saved")));
}

fn menu_item(key: &str, text: &str, hint: &str) {
    let hint = if hint.is_empty() { String::new() } else { format!("  {}", ui::paint(ui::DIM, hint)) };
    ui::say(&format!("  {}  {text}{hint}", ui::paint(ui::CYAN, &ui::paint(ui::BOLD, key))));
}

fn menu(layout: &Layout) -> (i32, bool) {
    sys::set_title("NetFreedom");
    loop {
        let active = session::is_active();
        ui::clear();
        dash::print();
        println!();
        if active {
            menu_item("1", ui::tr("Остановить всё", "Stop everything"), ui::tr("отключить WARP и движок", "disconnect WARP and the engine"));
            menu_item("2", ui::tr("Живой мониторинг", "Live monitor"), ui::tr("задержка, потери, туннель в реальном времени", "latency, loss and tunnel in real time"));
            menu_item("3", ui::tr("Проверить качество сейчас", "Check quality now"), ui::tr("честный тест: сначала проверяет туннель", "an honest test: proves the tunnel first"));
        } else {
            menu_item("1", ui::tr("Игры через Cloudflare WARP", "Games via Cloudflare WARP"), ui::tr("снижает пинг и потери в играх", "lower ping and loss in games"));
            menu_item("2", ui::tr("Разблокировка сайтов, YouTube, Discord", "Unblock sites, YouTube, Discord"), ui::tr("без WARP", "no WARP"));
            menu_item("3", ui::tr("Подобрать лучшую стратегию (tune)", "Find the best strategy (tune)"), ui::tr("тестирует всё на вашем соединении", "tests everything on your connection"));
        }
        menu_item("4", ui::tr("Проверка пинга и потерь", "Check ping and packet loss"), "");
        menu_item("5", ui::tr("IP игрового сервера", "Game server IP"), &current_target(layout));
        menu_item("6", ui::tr("Диагностика (doctor)", "Diagnostics (doctor)"), "");
        menu_item("7", ui::tr("Инструменты: списки, ipset, кэш Discord, автозапуск", "Tools: lists, ipset, Discord cache, autostart"), "");
        menu_item("8", ui::tr("Как установить Cloudflare WARP", "How to install Cloudflare WARP"), "");
        menu_item("9", ui::tr("О проекте", "About"), "");
        menu_item("D", ui::tr("DNS (шифрованный)", "DNS (encrypted)"), &dns_hint(layout));
        menu_item("S", ui::tr("Аварийная остановка", "Emergency stop"), ui::tr("если что-то осталось после сбоя", "if something is left after a crash"));
        menu_item("L", "Язык / Language", if ui::is_ru() { "RU → EN" } else { "EN → RU" });
        if !active {
            menu_item("U", ui::tr("Полное удаление", "Full uninstall"), "");
        }
        menu_item("0", ui::tr("Выход", "Exit"), if active { ui::tr("остановит всё", "stops everything") } else { "" });
        println!();
        let keys = if active { "123456789DSL0" } else { "123456789DSLU0" };
        match (ui::choice(ui::tr("Выбор: ", "Select: "), keys), active) {
            ('1', true) => {
                run::stop_session();
                pause_back();
            }
            ('2', true) => live_monitor(),
            ('3', true) => {
                quality_now();
                pause_back();
            }
            ('1', false) => start_from_menu(layout, &[]),
            ('2', false) => start_from_menu(layout, &["--bypass"]),
            ('3', false) => {
                let bypass = ui::choice(ui::tr("Подбор для [G] игр через WARP или [B] обхода без WARP? ", "Tune for [G]ames via WARP or [B]ypass without WARP? "), "GB") == 'B';
                let a: Vec<String> = if bypass { vec!["--bypass".to_string()] } else { Vec::new() };
                let _ = tune_cmd(layout, &a);
                sys::set_title("NetFreedom");
                pause_back();
            }
            ('4', _) => {
                check(&[]);
                pause_back();
            }
            ('5', _) => {
                set_game_server(layout);
                pause_back();
            }
            ('6', _) => {
                let _ = maint::doctor(layout);
                pause_back();
            }
            ('7', _) => {
                tools_menu(layout);
                pause_back();
            }
            ('8', _) => {
                install_warp();
                pause_back();
            }
            ('9', _) => {
                let _ = io::stdout().write_all(ABOUT.as_bytes());
                pause_back();
            }
            ('D', _) => {
                dns_menu(layout);
                pause_back();
            }
            ('S', _) => {
                run::stop();
                pause_back();
            }
            ('L', _) => {
                ui::set_ru(!ui::is_ru());
                let code = if ui::is_ru() { "ru" } else { "en" };
                save_cfg(layout, |c| c.lang = code.to_owned());
            }
            ('U', false) => {
                if let Err(e) = uninstall::run(layout) {
                    ui::error(&e);
                }
                pause_back();
            }
            _ => {
                if active {
                    // closed stdin counts as "yes": never loop forever on a dead console
                    print!("{} [Y/N]: ", ui::tr("Остановить всё и выйти?", "Stop everything and exit?"));
                    let yes = ui::read_line_opt().map_or(true, |a| a.chars().next().is_some_and(|c| matches!(ui::fold_key(c).to_ascii_uppercase(), 'Y')));
                    if !yes {
                        continue;
                    }
                    run::stop_session();
                }
                return (0, false);
            }
        }
    }
}

fn dns_hint(layout: &Layout) -> String {
    let c = Config::load_with_legacy(&layout.cfg, &layout.cfg_legacy);
    let mut s = dns::Choice::parse(&c.dns).unwrap_or(dns::Choice::Off).title();
    if dns::is_applied() {
        s.push_str(ui::tr(" · применён", " · applied"));
    }
    s
}

/// Pick the DNS provider; applied right away when a session is running, otherwise at the next start.
fn dns_menu(layout: &Layout) {
    let cfg = Config::load_with_legacy(&layout.cfg, &layout.cfg_legacy);
    println!("\n  {}: {}\n", ui::tr("Сейчас", "Now"), dns_hint(layout));
    for (i, p) in dns::PROVIDERS.iter().enumerate() {
        println!("  {}. {}  ({})", i + 1, p.title, p.v4[0]);
    }
    println!("  4. {}", ui::tr("Авто: самый быстрый на вашем соединении", "Auto: the fastest on your connection"));
    println!("  5. {}", ui::tr("Не менять DNS системы", "Leave the system's DNS alone"));
    println!("  6. {}", ui::tr("Замерить провайдеров", "Measure the providers"));
    println!("  7. {}: {}", ui::tr("Строгий режим (без обычного DNS при сбое)", "Strict mode (no plain-DNS fallback)"), if cfg.dns_strict { "ON" } else { "off" });
    println!("  0. {}\n", ui::tr("Назад", "Back"));
    let pick = match ui::choice(ui::tr("Выбор: ", "Select: "), "12345670") {
        '1' => dns::Choice::Fixed(&dns::PROVIDERS[0]),
        '2' => dns::Choice::Fixed(&dns::PROVIDERS[1]),
        '3' => dns::Choice::Fixed(&dns::PROVIDERS[2]),
        '4' => dns::Choice::Auto,
        '5' => dns::Choice::Off,
        '6' => {
            println!("{}", ui::tr("Измеряю (около 5 с)…", "Measuring (about 5 s)..."));
            dns::print_bench(&dns::bench(10));
            return;
        }
        '7' => {
            save_cfg(layout, |c| c.dns_strict = !cfg.dns_strict);
            ui::ok(ui::tr("Режим изменён; применится при следующем запуске или смене провайдера.", "Mode changed; it applies at the next start or provider change."));
            return;
        }
        _ => return,
    };
    save_cfg(layout, |c| c.dns = pick.key().to_owned());
    ui::ok(&format!("DNS: {}", pick.title()));
    if !session::is_active() {
        println!("{}", ui::tr("Применится при следующем запуске.", "It will be applied at the next start."));
        return;
    }
    let cfg = Config::load_with_legacy(&layout.cfg, &layout.cfg_legacy);
    let (choice, strict, plain) = dns::saved(&cfg);
    let result = match (choice, dns::is_applied()) {
        (dns::Choice::Off, true) => dns::restore(layout).map(|_| None),
        (dns::Choice::Off, false) => Ok(None),
        (dns::Choice::Fixed(p), true) => dns::switch(p).map(Some),
        (c, true) => match c {
            dns::Choice::Auto => dns::best(&dns::bench(6)).ok_or_else(|| "no provider is reachable".to_owned()).and_then(|p| dns::switch(p).map(Some)),
            _ => Ok(None),
        },
        (c, false) => dns::apply(layout, c, strict, plain).map(Some),
    };
    match result {
        Ok(Some(a)) => dns::print_applied(&a),
        Ok(None) => ui::ok(ui::tr("DNS системы возвращён как был.", "The system's DNS is back as it was.")),
        Err(e) => ui::warn(&format!("DNS: {e}")),
    }
}

fn tools_menu(layout: &Layout) {
    println!("\n  1. Address filter (ipset): show / change");
    println!("  2. Clear the Discord cache");
    println!("  3. Fake packets: show");
    println!("  4. Autostart: show / enable / disable");
    println!("  0. Back\n");
    let r = match ui::choice("Select: ", "12340") {
        '1' => {
            let _ = maint::ipset(layout, None);
            let a = ui::ask("Change to none / any / loaded (Enter = keep)", "");
            if a.is_empty() { Ok(()) } else { maint::ipset(layout, Some(&a)) }
        }
        '2' => maint::discord_clean(),
        '3' => maint::fakes(layout, &[]),
        '4' => {
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
