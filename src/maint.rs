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

//! Everything the old `service.bat` menu did, natively: diagnostics, ipset mode,
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
        IpsetMode::Loaded => fs::read_to_string(ipset_full(layout)).map_err(|_| "no saved list: put your list into lists/ipset-service.txt first".to_string())?,
    };
    fs::write(&file, text).map_err(|e| format!("cannot write {}: {e}", file.display()))?;
    ui::ok(&format!("ipset filter is now {want:?}. Restart the strategy for it to take effect."));
    Ok(())
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

/// The folders Discord is installed in (Windows): the per-user Squirrel install and Program Files.
/// A process named like Discord that runs from anywhere else is not Discord.
pub fn discord_roots(local_app_data: Option<&str>, program_files: &[String]) -> Vec<String> {
    let mut v = Vec::new();
    for name in ["Discord", "DiscordPTB", "DiscordCanary", "DiscordDevelopment"] {
        if let Some(l) = local_app_data.filter(|l| !l.is_empty()) {
            v.push(format!("{}\\{name}", l.trim_end_matches(['\\', '/'])));
        }
        v.extend(program_files.iter().map(|pf| format!("{}\\{name}", pf.trim_end_matches(['\\', '/']))));
    }
    v
}

/// Closes Discord. Windows: only processes that run from a Discord install folder (the name alone
/// proves nothing and this runs with administrator rights). Linux: by process name, as before
/// (the same user could only end its own processes anyway).
fn close_discord() -> usize {
    #[cfg(windows)]
    {
        let roots = discord_roots(std::env::var("LOCALAPPDATA").ok().as_deref(), &crate::util::program_files_dirs());
        let (mut ended, mut skipped) = (0, 0);
        for n in ["Discord.exe", "DiscordPTB.exe", "DiscordCanary.exe"] {
            let (e, s) = sys::kill_by_name_in(n, &roots);
            ended += e;
            skipped += s;
        }
        if skipped > 0 {
            ui::warn(&format!("{skipped} process(es) named like Discord were left alone: they do not run from a Discord install folder"));
        }
        ended
    }
    #[cfg(unix)]
    {
        ["Discord.exe", "Discord", "DiscordPTB.exe", "DiscordCanary.exe"].iter().map(|n| sys::kill_by_name(n)).sum::<usize>()
    }
}

pub fn discord_clean() -> Result<(), String> {
    let killed = close_discord();
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

/// The autostart entry runs this program with administrator rights at every logon, so whoever can
/// replace `netfreedom.exe` or `bin\\WinDivert.dll` gets administrator rights too. Where the folder
/// is decides what is needed.
#[derive(Debug, PartialEq)]
pub enum AutostartPlace {
    /// Inside Program Files: only administrators can change it.
    Safe,
    /// An ordinary folder (`C:\\NetFreedom`): acceptable once its permissions are limited to administrators.
    NeedsLock,
    /// Inside a user profile (Downloads, Desktop, ...): the user can always rename or replace the
    /// folder itself, so locking the files inside would not help. Autostart is refused.
    Refused(String),
}

/// `admin_roots`: folders only administrators can write to (Program Files). `user_roots`: the user
/// profile folders and the folder holding all profiles.
pub fn autostart_place(exe: &str, admin_roots: &[String], user_roots: &[String]) -> AutostartPlace {
    if admin_roots.iter().any(|r| crate::safety::is_inside(exe, r)) {
        return AutostartPlace::Safe;
    }
    if let Some(r) = user_roots.iter().find(|r| crate::safety::is_inside(exe, r)) {
        return AutostartPlace::Refused(format!(
            "NetFreedom runs from {r}, where any program of your user account can replace it, and the autostart entry would start it with administrator rights. Move the whole NetFreedom folder to C:\\Program Files (or to a folder such as C:\\NetFreedom) and run `netfreedom autostart on` from there."
        ));
    }
    AutostartPlace::NeedsLock
}

/// The `icacls` calls (arguments only, no shell) that make `dir` writable by administrators only:
/// 1. the owner becomes Administrators (an owner can always rewrite the permissions),
/// 2. inheritance is cut and only SYSTEM and Administrators (full) and Users (read/execute) remain,
/// 3. everything inside is reset to inherit exactly that.
pub fn icacls_lock_steps(dir: &str) -> [Vec<String>; 3] {
    let d = dir.trim_end_matches(['\\', '/']).to_owned();
    let v = |a: &[&str]| a.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
    let mut s1 = vec![d.clone()];
    s1.extend(v(&["/setowner", "*S-1-5-32-544", "/T", "/Q"]));
    let mut s2 = vec![d.clone()];
    s2.extend(v(&["/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-32-545:(OI)(CI)RX", "/Q"]));
    let mut s3 = vec![format!("{d}\\*")];
    s3.extend(v(&["/reset", "/T", "/Q"]));
    [s1, s2, s3]
}

/// Windows: limits the folder of `exe` to administrators (see [`icacls_lock_steps`]). Refuses
/// folders that are or contain Desktop, Documents, Downloads, the profile, Windows, ... and folders
/// that do not look like a NetFreedom package.
#[cfg(windows)]
fn lock_install_folder(exe: &str) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    let dir = Path::new(exe).parent().ok_or("cannot find the folder of netfreedom.exe")?;
    if let Some(why) = crate::uninstall::folder_problem(dir) {
        return Err(format!("not changing the permissions of {}: {why}", dir.display()));
    }
    for step in icacls_lock_steps(&dir.to_string_lossy()) {
        let out = Command::new(crate::util::system_tool("icacls"))
            .args(&step)
            .stdin(Stdio::null())
            .creation_flags(0x0800_0000)
            .output()
            .map_err(|e| format!("cannot run icacls: {e}"))?;
        if !out.status.success() {
            let msg = format!("{} {}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
            return Err(format!("icacls {} failed: {}", step.get(1).map_or("", String::as_str), msg.trim()));
        }
    }
    Ok(())
}

/// Windows: the folders in which a program of an ordinary user can always replace things.
#[cfg(windows)]
fn user_profile_roots() -> Vec<String> {
    let mut v: Vec<String> = ["USERPROFILE", "OneDrive", "OneDriveConsumer", "OneDriveCommercial", "PUBLIC"].iter().filter_map(|k| std::env::var(k).ok()).filter(|s| !s.is_empty()).collect();
    if let Some(all) = std::env::var("USERPROFILE").ok().and_then(|p| Path::new(&p).parent().map(|d| d.to_string_lossy().into_owned())) {
        v.push(all); // C:\Users: every profile, Public included
    }
    v
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
                match autostart_place(&exe, &crate::util::program_files_dirs(), &user_profile_roots()) {
                    AutostartPlace::Safe => {}
                    AutostartPlace::Refused(why) => return Err(format!("autostart was NOT enabled: {why}")),
                    AutostartPlace::NeedsLock => {
                        lock_install_folder(&exe).map_err(|e| format!("autostart was NOT enabled: {e}"))?;
                        ui::ok("The NetFreedom folder can now be changed only by administrators (so that nobody can swap netfreedom.exe or WinDivert.dll).");
                        ui::warn("Editing the list files and netfreedom.cfg now needs an administrator (e.g. Notepad run as administrator). The folder must stay where no ordinary user can rename it (not under a user folder).");
                    }
                }
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
    let stale = crate::dns::stale_owner(layout);
    check(stale.is_none(), "DNS settings are clean", "DNS is still changed by a NetFreedom run that ended abnormally: run `netfreedom dns restore`");
    match backend::check_engine(layout) {
        Ok(()) => check(true, "packet engine files are in place", ""),
        Err(e) => check(false, "", &format!("packet engine: {}", e.lines().next().unwrap_or(""))),
    }
    #[cfg(windows)]
    check(Command::new(crate::util::system_tool("sc")).args(["query", "BFE"]).output().is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains("RUNNING")), "Base Filtering Engine service is running", "Base Filtering Engine (BFE) is not running: WinDivert cannot work without it");
    for f in ["list-general.txt", "ipset-all.txt", "list-google.txt", "list-social.txt", "ipset-social.txt", "list-dev.txt"] {
        check(Path::new(&layout.lists).join(f).exists(), &format!("lists/{f}"), &format!("lists/{f} is missing: restore it from the release archive (the program no longer downloads lists)"));
    }
    let mode = classify_ipset(&fs::read_to_string(ipset_file(layout)).unwrap_or_default());
    println!("      ipset filter: {mode:?}");
    check(web::curl_available(), "curl is available (tune --bypass)", "curl was not found: `tune --bypass` needs it");
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
    fn only_known_discord_cache_folders_are_ever_deleted() {
        let d = discord_cache_dirs(Path::new("/home/u/.config/discord"));
        assert_eq!(d.len(), 3);
        assert!(d.iter().all(|p| p.starts_with("/home/u/.config/discord")));
        assert!(discord_cache_dirs(Path::new("/home/u/Documents")).is_empty(), "other folders are never touched");
    }

    #[test]
    fn discord_is_only_closed_when_it_runs_from_its_install_folder() {
        let roots = discord_roots(Some(r"C:\Users\u\AppData\Local"), &[r"C:\Program Files".to_owned()]);
        let ok = |p: &str| roots.iter().any(|r| crate::safety::is_inside(p, r));
        assert!(ok(r"C:\Users\u\AppData\Local\Discord\app-1.0.9\Discord.exe"));
        assert!(ok(r"c:\users\u\appdata\local\discordptb\app-1\DiscordPTB.exe"), "case does not matter");
        assert!(!ok(r"C:\Users\u\Downloads\Discord.exe"), "same name, other folder");
        assert!(!ok(r"C:\Users\u\AppData\Local\DiscordEvil\Discord.exe"), "folder boundary");
        assert!(!ok(r"C:\Users\u\AppData\Local\Discord\..\Temp\Discord.exe"), "no .. tricks");
        assert!(discord_roots(None, &[]).is_empty());
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

    #[test]
    fn autostart_place_decides_between_ok_lock_and_refuse() {
        let admin = vec!["C:\\Program Files".to_string()];
        let user = vec!["C:\\Users\\me".to_string(), "C:\\Users".to_string()];
        let place = |p: &str| autostart_place(p, &admin, &user);
        assert_eq!(place("C:\\Program Files\\NetFreedom\\netfreedom.exe"), AutostartPlace::Safe);
        assert_eq!(place("c:\\program files\\NetFreedom\\netfreedom.exe"), AutostartPlace::Safe, "case does not matter");
        for bad in ["C:\\Users\\me\\Downloads\\NetFreedom\\netfreedom.exe", "C:\\Users\\me\\Desktop\\netfreedom.exe", "C:\\Users\\Public\\nf\\netfreedom.exe", "C:\\Users\\other\\nf\\netfreedom.exe"] {
            assert!(matches!(place(bad), AutostartPlace::Refused(_)), "{bad}");
        }
        assert_eq!(place("C:\\NetFreedom\\netfreedom.exe"), AutostartPlace::NeedsLock);
        assert_eq!(place("D:\\Tools\\nf\\netfreedom.exe"), AutostartPlace::NeedsLock);
        assert_eq!(place("C:\\Program Files Evil\\netfreedom.exe"), AutostartPlace::NeedsLock, "prefix of the name is not inside the folder");
        assert_eq!(place("C:\\Program Files\\..\\Temp\\netfreedom.exe"), AutostartPlace::NeedsLock, "no .. tricks");
    }

    #[test]
    fn icacls_steps_leave_ordinary_users_read_only() {
        let [owner, acl, reset] = icacls_lock_steps("C:\\NetFreedom\\");
        assert_eq!(owner, ["C:\\NetFreedom", "/setowner", "*S-1-5-32-544", "/T", "/Q"]);
        assert_eq!(acl[0], "C:\\NetFreedom");
        assert!(acl.contains(&"/inheritance:r".to_string()), "inherited permissions are cut");
        let grants: Vec<&String> = acl.iter().filter(|a| a.contains(":(OI)(CI)")).collect();
        assert_eq!(grants.len(), 3);
        assert!(grants.iter().any(|g| g.starts_with("*S-1-5-32-545:") && g.ends_with("RX")), "Users: read and execute only");
        assert!(grants.iter().all(|g| g.starts_with("*S-1-5-18:") || g.starts_with("*S-1-5-32-544:") || g.ends_with("RX")), "only SYSTEM and Administrators get more");
        assert_eq!(reset, ["C:\\NetFreedom\\*", "/reset", "/T", "/Q"], "the folder itself is not reset, only what is inside");
    }
}
