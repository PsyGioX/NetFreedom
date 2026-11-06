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

//! Everything the old `service.bat` menu did, natively: diagnostics, ipset mode, list updates,
//! Discord cache cleanup, fake payload selection and autostart. No batch file, no PowerShell.
//! The pure parts (classification, validation, text generation) are unit-tested.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::backend;
use crate::paths::Layout;
use crate::sys;
use crate::ui;
use crate::warp::Warp;
use crate::web;

// ------------------------------------------------------------------------------------- ipset

/// Placeholder address (TEST-NET-3): matches nothing, so "no ipset" really means no ipset.
const IPSET_NONE: &str = "203.0.113.113/32";

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum IpsetMode {
    /// Empty file: the filter does not restrict by address (everything matches).
    Any,
    /// Only the placeholder: nothing matches.
    None,
    /// The real list of blocked ranges.
    Loaded,
}

impl IpsetMode {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "any" => Some(Self::Any),
            "none" => Some(Self::None),
            "loaded" => Some(Self::Loaded),
            _ => None,
        }
    }
}

pub fn classify_ipset(content: &str) -> IpsetMode {
    let lines: Vec<&str> = content.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    match lines.as_slice() {
        [] => IpsetMode::Any,
        [one] if *one == IPSET_NONE => IpsetMode::None,
        _ => IpsetMode::Loaded,
    }
}

fn ipset_file(l: &Layout) -> PathBuf {
    Path::new(&l.lists).join("ipset-all.txt")
}
fn ipset_full(l: &Layout) -> PathBuf {
    Path::new(&l.lists).join("ipset-service.txt")
}

pub fn ipset(layout: &Layout, arg: Option<&str>) -> Result<(), String> {
    let file = ipset_file(layout);
    let current = classify_ipset(&fs::read_to_string(&file).unwrap_or_default());
    let Some(arg) = arg.filter(|a| *a != "status") else {
        println!("ipset filter: {current:?}  (none = off, any = everything, loaded = the real list)");
        println!("Change it with: netfreedom ipset <none|any|loaded>");
        return Ok(());
    };
    let want = IpsetMode::parse(arg).ok_or("use: netfreedom ipset <none|any|loaded|status>")?;
    if want == current {
        println!("ipset filter is already {want:?}.");
        return Ok(());
    }
    // never lose the real list when switching away from it
    if current == IpsetMode::Loaded && !ipset_full(layout).exists() {
        fs::copy(&file, ipset_full(layout)).map_err(|e| format!("cannot keep a copy of the list: {e}"))?;
    }
    let text = match want {
        IpsetMode::None => format!("{IPSET_NONE}\n"),
        IpsetMode::Any => String::new(),
        IpsetMode::Loaded => fs::read_to_string(ipset_full(layout)).map_err(|_| "no saved list: run `netfreedom lists update` first".to_string())?,
    };
    fs::write(&file, text).map_err(|e| format!("cannot write {}: {e}", file.display()))?;
    ui::ok(&format!("ipset filter is now {want:?}. Restart the strategy for it to take effect."));
    Ok(())
}

// -------------------------------------------------------------------------------- list update

const UPSTREAM: &str = "https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/refs/heads/main/";
/// (upstream path, local file, minimum plausible number of lines)
const LIST_FILES: [(&str, &str, usize); 5] = [
    (".service/ipset-service.txt", "ipset-service.txt", 1000),
    ("lists/list-general.txt", "list-general.txt", 5),
    ("lists/list-google.txt", "list-google.txt", 2),
    ("lists/list-exclude.txt", "list-exclude.txt", 1),
    ("lists/ipset-exclude.txt", "ipset-exclude.txt", 1),
];

/// A downloaded list is accepted only if it looks like a list: not an HTML error page, not empty,
/// not suspiciously short, only printable text.
pub fn valid_list(text: &str, min_lines: usize) -> bool {
    let lines = text.lines().filter(|l| !l.trim().is_empty()).count();
    lines >= min_lines
        && text.len() <= 8_000_000
        && !text.contains("<html")
        && !text.contains("<!DOCTYPE")
        && text.chars().all(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t'))
        && text.lines().all(plausible_entry)
}

/// One line of a list: empty, a `#` comment, or only what a domain / IP / CIDR can consist of.
/// (Defence in depth: the lists come from a third-party repository and feed a root-run engine.)
fn plausible_entry(line: &str) -> bool {
    let l = line.trim();
    l.is_empty() || l.starts_with('#') || (l.len() <= 253 && l.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':' | '/' | '*')))
}

/// A refresh that would shrink a list to less than half is more likely truncated or tampered
/// with than genuine.
pub fn plausible_update(old_lines: usize, new_lines: usize) -> bool {
    old_lines < 20 || new_lines * 2 >= old_lines
}

fn count_lines(p: &Path) -> usize {
    fs::read_to_string(p).map(|t| t.lines().filter(|l| !l.trim().is_empty()).count()).unwrap_or(0)
}

fn download(url: &str) -> Result<String, String> {
    let mut cmd = crate::web::curl_command();
    // --max-filesize: a list is a few hundred KB; refuse anything absurd instead of filling the disk
    cmd.args(["-sS", "-f", "--max-filesize", "8000000", "--connect-timeout", "10", "-m", "60", url]);
    let o = cmd.output().map_err(|e| format!("cannot run curl: {e}"))?;
    if !o.status.success() {
        return Err(String::from_utf8_lossy(&o.stderr).trim().to_owned());
    }
    String::from_utf8(o.stdout).map_err(|_| "not text".to_owned())
}

pub fn lists_update(layout: &Layout) -> Result<(), String> {
    if !web::curl_available() {
        return Err("curl was not found (it ships with Windows 10+ and Linux).".into());
    }
    let was = classify_ipset(&fs::read_to_string(ipset_file(layout)).unwrap_or_default());
    let mut failed = 0;
    for (remote, local, min) in LIST_FILES {
        let dest = Path::new(&layout.lists).join(local);
        match download(&format!("{UPSTREAM}{remote}")) {
            Ok(text) if valid_list(&text, min) && plausible_update(count_lines(&dest), text.lines().filter(|l| !l.trim().is_empty()).count()) => {
                let _ = fs::copy(&dest, dest.with_extension("txt.bak"));
                let tmp = dest.with_extension("txt.new");
                fs::write(&tmp, text).and_then(|_| fs::rename(&tmp, &dest)).map_err(|e| format!("{local}: {e}"))?;
                ui::ok(&format!("{local} updated"));
            }
            Ok(_) => {
                failed += 1;
                ui::warn(&format!("{local}: the download does not look like a list, kept the old one"));
            }
            Err(e) => {
                failed += 1;
                ui::warn(&format!("{local}: {e}"));
            }
        }
    }
    if was == IpsetMode::Loaded && ipset_full(layout).exists() {
        let _ = fs::copy(ipset_full(layout), ipset_file(layout));
    }
    if failed == 0 { Ok(()) } else { Err(format!("{failed} file(s) could not be updated; the old ones are untouched")) }
}

// ------------------------------------------------------------------------------ Discord cache

const DISCORD_CACHES: [&str; 3] = ["Cache", "Code Cache", "GPUCache"];

/// The only folders that are ever deleted: three known cache folders directly inside a folder
/// named like a Discord profile directory.
pub fn discord_cache_dirs(base: &Path) -> Vec<PathBuf> {
    let name = base.file_name().and_then(|n| n.to_str()).unwrap_or("").to_ascii_lowercase();
    if !name.starts_with("discord") {
        return Vec::new();
    }
    DISCORD_CACHES.iter().map(|c| base.join(c)).collect()
}

fn discord_bases() -> Vec<PathBuf> {
    let mut v = Vec::new();
    #[cfg(windows)]
    if let Some(a) = std::env::var_os("APPDATA") {
        for n in ["discord", "discordptb", "discordcanary"] {
            v.push(PathBuf::from(&a).join(n));
        }
    }
    #[cfg(unix)]
    {
        // running through sudo: the user's home, not root's
        let home = std::env::var("SUDO_USER").ok().map(|u| format!("/home/{u}")).or_else(|| std::env::var("HOME").ok());
        if let Some(h) = home {
            for n in ["discord", "discordptb", "discordcanary"] {
                v.push(PathBuf::from(&h).join(".config").join(n));
            }
        }
    }
    v
}

pub fn discord_clean() -> Result<(), String> {
    let killed = ["Discord.exe", "Discord", "DiscordPTB.exe", "DiscordCanary.exe"].iter().map(|n| sys::kill_by_name(n)).sum::<usize>();
    if killed > 0 {
        ui::ok("Discord was closed");
    }
    let mut removed = 0;
    for base in discord_bases() {
        for dir in discord_cache_dirs(&base) {
            if dir.is_dir() && fs::remove_dir_all(&dir).is_ok() {
                ui::ok(&format!("cleared {}", dir.display()));
                removed += 1;
            }
        }
    }
    if removed == 0 {
        println!("No Discord cache folders found.");
    } else {
        println!("Start Discord again: it rebuilds the cache.");
    }
    Ok(())
}

// ----------------------------------------------------------------------------------- fakes

/// A plain file name inside `bin`: no separators, no parent references, a `.bin` extension.
pub fn valid_fake_name(n: &str) -> bool {
    !n.is_empty() && n.len() < 80 && n.ends_with(".bin") && !n.contains(['/', '\\', ':']) && !n.contains("..")
}

pub fn fakes(layout: &Layout, args: &[String]) -> Result<(), String> {
    let bin = Path::new(&layout.bin);
    match args.first().map(String::as_str) {
        None | Some("list") => {
            let active = |slot: &str| fs::read(bin.join(slot)).unwrap_or_default();
            let (ad, ag) = (active("ACTIVE_DISCORD_UDP.bin"), active("ACTIVE_GAME_UDP.bin"));
            let mut names: Vec<_> = fs::read_dir(bin).map_err(|e| e.to_string())?.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).filter(|n| n.ends_with(".bin") && !n.starts_with("ACTIVE_")).collect();
            names.sort();
            for n in names {
                let data = fs::read(bin.join(&n)).unwrap_or_default();
                let tag = match (data == ad, data == ag) {
                    (true, true) => "  <- discord + game",
                    (true, false) => "  <- discord",
                    (false, true) => "  <- game",
                    _ => "",
                };
                println!("  {:<48} {:>5} bytes{tag}", n, data.len());
            }
            println!("\nChange with: netfreedom fakes set <discord|game> <file.bin>");
            Ok(())
        }
        Some("set") => {
            let slot = match args.get(1).map(String::as_str) {
                Some("discord") => "ACTIVE_DISCORD_UDP.bin",
                Some("game") => "ACTIVE_GAME_UDP.bin",
                _ => return Err("use: netfreedom fakes set <discord|game> <file.bin>".into()),
            };
            let name = args.get(2).ok_or("which file? see `netfreedom fakes list`")?;
            if !valid_fake_name(name) {
                return Err("the file must be a plain *.bin name from the bin folder".into());
            }
            let src = bin.join(name);
            let size = fs::metadata(&src).map_err(|_| format!("{name} not found in the bin folder"))?.len();
            if size == 0 || size > 1500 {
                return Err(format!("{name} is {size} bytes: a UDP fake must be 1..1500 bytes"));
            }
            fs::copy(&src, bin.join(slot)).map_err(|e| e.to_string())?;
            ui::ok(&format!("{slot} is now {name}"));
            Ok(())
        }
        _ => Err("use: netfreedom fakes [list | set <discord|game> <file.bin>]".into()),
    }
}

// -------------------------------------------------------------------------------- autostart

fn quote(a: &str) -> String {
    if a.contains([' ', '\t', '"']) { format!("\"{}\"", a.replace('"', "\\\"")) } else { a.to_owned() }
}

/// Command line that the autostart entry runs.
pub fn autostart_command(exe: &str, start_args: &[String]) -> String {
    let mut parts = vec![quote(exe), "start".to_owned(), "--headless".to_owned()];
    parts.extend(start_args.iter().map(|a| quote(a)));
    parts.join(" ")
}

/// systemd unit text (Linux).
pub fn systemd_unit(exe: &str, start_args: &[String]) -> String {
    format!(
        "[Unit]\nDescription=NetFreedom\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nExecStart={}\nExecStopPost={} stop\nRestart=on-failure\nRestartSec=5\n\n[Install]\nWantedBy=multi-user.target\n",
        autostart_command(exe, start_args),
        quote(exe)
    )
}

#[cfg(unix)]
const UNIT_PATH: &str = "/etc/systemd/system/netfreedom.service";
#[cfg(windows)]
const TASK: &str = "NetFreedom";

fn run_quiet(prog: &str, args: &[&str]) -> bool {
    let mut c = Command::new(crate::util::system_tool(prog));
    c.args(args).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        c.creation_flags(0x0800_0000);
    }
    c.status().is_ok_and(|s| s.success())
}

/// Removes the autostart entry if there is one (also used by the uninstaller). Silent.
pub fn disable_autostart() {
    #[cfg(windows)]
    run_quiet("schtasks", &["/Delete", "/TN", TASK, "/F"]);
    #[cfg(unix)]
    if Path::new(UNIT_PATH).exists() {
        run_quiet("systemctl", &["disable", "--now", "netfreedom.service"]);
        let _ = fs::remove_file(UNIT_PATH);
        run_quiet("systemctl", &["daemon-reload"]);
    }
}

pub fn autostart(args: &[String]) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?.to_string_lossy().into_owned();
    let exe = exe.strip_prefix(r"\\?\").unwrap_or(&exe).to_owned();
    match args.first().map(String::as_str) {
        Some("on") => {
            let start_args = &args[1..];
            #[cfg(windows)]
            {
                let cmd = autostart_command(&exe, start_args);
                if !run_quiet("schtasks", &["/Create", "/TN", TASK, "/TR", &cmd, "/SC", "ONLOGON", "/RL", "HIGHEST", "/F"]) {
                    return Err("schtasks refused to create the task (run as administrator)".into());
                }
            }
            #[cfg(unix)]
            {
                fs::write(UNIT_PATH, systemd_unit(&exe, start_args)).map_err(|e| format!("cannot write {UNIT_PATH}: {e}"))?;
                run_quiet("systemctl", &["daemon-reload"]);
                if !run_quiet("systemctl", &["enable", "--now", "netfreedom.service"]) {
                    return Err("systemctl could not enable the service".into());
                }
            }
            ui::ok("Autostart enabled. Without --strategy it uses the last strategy you ran or tuned.");
            Ok(())
        }
        Some("off") => {
            disable_autostart();
            ui::ok("Autostart disabled.");
            Ok(())
        }
        None | Some("status") => {
            #[cfg(windows)]
            let on = run_quiet("schtasks", &["/Query", "/TN", TASK]);
            #[cfg(unix)]
            let on = Path::new(UNIT_PATH).exists();
            println!("Autostart: {}", if on { "enabled" } else { "disabled" });
            println!("Enable with: netfreedom autostart on [--bypass] [--strategy <name>]");
            Ok(())
        }
        _ => Err("use: netfreedom autostart <on [start options] | off | status>".into()),
    }
}

// ------------------------------------------------------------------------------------ doctor

/// Software known to interfere with packet interception.
#[cfg(windows)]
const CONFLICTS: [(&str, &str); 6] = [
    ("AdguardSvc.exe", "AdGuard: disable its filtering or exclude the bin folder"),
    ("Killer Network Service.exe", "Killer Network Service: known to break WinDivert, disable it"),
    ("SmartByte.exe", "SmartByte: network throttling that conflicts with the engine"),
    ("CheckPointService.exe", "Check Point VPN: conflicts with WinDivert"),
    ("Intel.Connectivity.Network.Service.exe", "Intel Connectivity Network Service: disable it"),
    ("OpenVPNServiceInteractive.exe", "OpenVPN is running: another tunnel competes with WARP"),
];
#[cfg(unix)]
const CONFLICTS: [(&str, &str); 3] = [
    ("openvpn", "OpenVPN is running: another tunnel competes with WARP"),
    ("wireguard-go", "a WireGuard tunnel is running: it competes with WARP"),
    ("nfqws", "an nfqws process is already running (run `netfreedom stop`)"),
];

pub fn doctor(layout: &Layout) -> Result<(), String> {
    let mut problems = 0;
    let mut check = |ok: bool, good: &str, bad: &str| {
        if ok {
            ui::ok(good);
        } else {
            problems += 1;
            ui::warn(bad);
        }
    };
    check(sys::is_elevated(), "administrator / root rights", "no administrator / root rights: start, tune and stop need them");
    match backend::check_engine(layout) {
        Ok(()) => check(true, "packet engine files are in place", ""),
        Err(e) => check(false, "", &format!("packet engine: {}", e.lines().next().unwrap_or(""))),
    }
    #[cfg(windows)]
    check(Command::new(crate::util::system_tool("sc")).args(["query", "BFE"]).output().is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains("RUNNING")), "Base Filtering Engine service is running", "Base Filtering Engine (BFE) is not running: WinDivert cannot work without it");
    for f in ["list-general.txt", "ipset-all.txt", "list-google.txt", "list-social.txt", "ipset-social.txt"] {
        check(Path::new(&layout.lists).join(f).exists(), &format!("lists/{f}"), &format!("lists/{f} is missing: run `netfreedom lists update`"));
    }
    let mode = classify_ipset(&fs::read_to_string(ipset_file(layout)).unwrap_or_default());
    println!("      ipset filter: {mode:?}");
    check(web::curl_available(), "curl is available (tune --bypass, lists update)", "curl was not found: `tune --bypass` and `lists update` need it");
    match Warp::locate() {
        Some(_) => check(true, "Cloudflare WARP is installed", ""),
        None => println!("      Cloudflare WARP is not installed (only needed for games via WARP: `netfreedom install-warp`)"),
    }
    for (proc_name, advice) in CONFLICTS {
        if sys::is_running(proc_name) && !(proc_name == "nfqws" && backend::engine_running()) {
            check(false, "", advice);
        }
    }
    if backend::engine_running() {
        println!("      the packet engine is running right now");
    }
    println!();
    if problems == 0 { println!("Everything looks fine.") } else { println!("{problems} problem(s) found.") }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipset_modes_are_recognised() {
        assert_eq!(classify_ipset(""), IpsetMode::Any);
        assert_eq!(classify_ipset("\r\n \n"), IpsetMode::Any);
        assert_eq!(classify_ipset("203.0.113.113/32\r\n"), IpsetMode::None);
        assert_eq!(classify_ipset("1.0.0.0/24\n1.1.1.0/24\n"), IpsetMode::Loaded);
        assert_eq!(IpsetMode::parse("LOADED"), Some(IpsetMode::Loaded));
        assert_eq!(IpsetMode::parse("x"), None);
    }

    #[test]
    fn downloaded_lists_are_validated() {
        let good = "1.0.0.0/24\n".repeat(1200);
        assert!(valid_list(&good, 1000));
        assert!(!valid_list("<!DOCTYPE html><title>404</title>", 1));
        assert!(!valid_list("a\nb\n", 5), "too short is suspicious");
        assert!(!valid_list("a\u{0}b\n", 1), "control characters are refused");
        assert!(!valid_list("example.com\n--flag=$(x)\n", 1), "shell-ish junk is refused");
        assert!(valid_list("# c\nexample.com\n2001:db8::/32\n*.x-y.org\n", 3));
        assert!(plausible_update(1000, 900) && !plausible_update(1000, 100) && plausible_update(5, 1));
    }

    #[test]
    fn only_known_discord_cache_folders_are_ever_deleted() {
        let d = discord_cache_dirs(Path::new("/home/u/.config/discord"));
        assert_eq!(d.len(), 3);
        assert!(d.iter().all(|p| p.starts_with("/home/u/.config/discord")));
        assert!(discord_cache_dirs(Path::new("/home/u/Documents")).is_empty(), "other folders are never touched");
    }

    #[test]
    fn fake_names_cannot_escape_the_bin_folder() {
        assert!(valid_fake_name("quic_initial_www_google_com.bin"));
        for bad in ["", "../x.bin", "a/b.bin", "a\\b.bin", "C:x.bin", "x.exe", "x.bin.exe", ".."] {
            assert!(!valid_fake_name(bad), "{bad}");
        }
    }

    #[test]
    fn autostart_text() {
        let args = vec!["--bypass".to_string(), "--strategy".into(), "split".into()];
        assert_eq!(autostart_command("/opt/nf dir/netfreedom", &args), "\"/opt/nf dir/netfreedom\" start --headless --bypass --strategy split");
        let u = systemd_unit("/usr/local/bin/netfreedom", &[]);
        assert!(u.contains("ExecStart=/usr/local/bin/netfreedom start --headless\n"));
        assert!(u.contains("ExecStopPost=/usr/local/bin/netfreedom stop"));
    }
}
