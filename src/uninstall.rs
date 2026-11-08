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

//! Full uninstall (no helper scripts: everything is done by the executable itself).
//! Services, processes, registry and the folder-safety logic are native; only the Defender
//! exclusion cleanup still needs PowerShell (there is no stable native API for it).

use std::fs;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::paths::Layout;
use crate::safety;
use crate::sys::{self, KeyDelete, Removal};
use crate::ui;
use crate::util::extract_guid;
use crate::warp::Warp;
use crate::winws;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

const DEFENDER_PS: &str = r#"
try {
    $full = [System.IO.Path]::GetFullPath($env:ZW_ROOT).TrimEnd('\')
    $pref = Get-MpPreference
    $removed = 0
    foreach ($e in @($pref.ExclusionPath)) {
        if ($e -and (($e.TrimEnd('\') -ieq $full) -or $e.StartsWith($full + '\', [System.StringComparison]::OrdinalIgnoreCase))) {
            Remove-MpPreference -ExclusionPath $e
            Write-Host "  [OK] Defender path exclusion removed: $e"
            $removed++
        }
    }
    foreach ($e in @($pref.ExclusionProcess)) {
        if ($e -and $e.StartsWith($full + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
            Remove-MpPreference -ExclusionProcess $e
            Write-Host "  [OK] Defender process exclusion removed: $e"
            $removed++
        }
    }
    if ($removed -eq 0) { Write-Host '  [--] no Defender exclusions point to this folder' }
} catch {
    Write-Host '  [--] Microsoft Defender settings are not available (third-party antivirus?) - check its exclusions manually'
}
"#;

fn env_path(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

fn protected_folders() -> Vec<String> {
    let mut v: Vec<String> = ["SystemRoot", "ProgramFiles", "ProgramFiles(x86)", "ProgramData", "USERPROFILE", "PUBLIC"]
        .iter()
        .filter_map(|n| env_path(n))
        .collect();
    let mut homes: Vec<String> = Vec::new();
    homes.extend(env_path("USERPROFILE"));
    homes.extend(env_path("OneDrive"));
    homes.extend(env_path("OneDriveConsumer"));
    for h in homes {
        for sub in ["Desktop", "Documents", "Downloads"] {
            v.push(format!("{h}\\{sub}"));
        }
    }
    v
}

fn folder_problem(root: &Path) -> Option<String> {
    let s = root.display().to_string();
    if s.contains(['"', '%', '^', '&', '!']) {
        return Some("its path contains special characters (\" % ^ & !)".into());
    }
    safety::unsafe_reason(&s, &protected_folders(), &|m| root.join(m).exists())
}

fn run_powershell_script(body: &str, root: &Path) {
    let file = std::env::temp_dir().join(format!("zw-cleanup-{}.ps1", std::process::id()));
    if fs::write(&file, body).is_err() {
        ui::skip("cannot write a temporary script, Defender exclusions not checked");
        return;
    }
    let _ = Command::new(crate::util::system_tool("powershell"))
        .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File"])
        .arg(&file)
        .env("ZW_ROOT", root)
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::null())
        .status();
    let _ = fs::remove_file(file);
}

fn uninstall_warp() -> i32 {
    sys::kill_by_name("Cloudflare WARP.exe");
    let Some(e) = sys::find_uninstall_entry(&["Cloudflare WARP", "Cloudflare One Client"]) else {
        ui::skip("Cloudflare WARP is not installed");
        return 3;
    };
    println!("  Uninstalling: {} {}", e.name, e.version);
    let Some(guid) = extract_guid(&e.uninstall) else {
        ui::warn("Non-MSI uninstaller - remove Cloudflare WARP from Windows Settings > Apps");
        return 4;
    };
    match Command::new(crate::util::system_tool("msiexec")).args(["/x", guid, "/qn", "/norestart"]).status().ok().and_then(|s| s.code()) {
        Some(0) => 0,
        Some(3010) | Some(1641) => 10,
        Some(c) => {
            ui::warn(&format!("msiexec returned code {c}"));
            1
        }
        None => 1,
    }
}

fn hosts_report() {
    let hosts: PathBuf = PathBuf::from(env_path("SystemRoot").unwrap_or_else(|| "C:\\Windows".into())).join("System32\\drivers\\etc\\hosts");
    let Ok(text) = fs::read_to_string(&hosts) else {
        ui::skip("hosts file not found");
        return;
    };
    let custom: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter(|l| {
            let mut it = l.split_whitespace();
            !(it.next().is_some() && it.next().is_some_and(|h| h.eq_ignore_ascii_case("localhost")) && it.next().is_none())
        })
        .collect();
    if custom.is_empty() {
        ui::ok("hosts has no custom entries");
        return;
    }
    println!("  [INFO] hosts has {} custom entries. This package never edits hosts; if you pasted entries from a zapret repository, remove them manually:", custom.len());
    for l in custom.iter().take(15) {
        println!("         {l}");
    }
    if custom.len() > 15 {
        println!("         ... and {} more", custom.len() - 15);
    }
    println!("         File: {}", hosts.display());
}

/// Deletes `root` from a detached process after this one has exited (the exe lives inside it).
fn schedule_folder_removal(root: &Path) -> bool {
    let p = root.display().to_string();
    let script = format!(
        "ping -n 5 127.0.0.1 >nul & for /l %i in (1,1,10) do @(if exist \"{p}\" (rd /s /q \"{p}\" 2>nul & ping -n 4 127.0.0.1 >nul))"
    );
    Command::new(crate::util::system_tool("cmd"))
        .raw_arg(format!("/d /s /c \"{script}\""))
        .current_dir(std::env::temp_dir())
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .is_ok()
}

pub fn run(layout: &Layout) -> Result<(), String> {
    let root = layout.root.clone();
    println!("================================================================");
    println!("  FULL UNINSTALL / CLEANUP of netfreedom");
    println!("================================================================\n");
    println!("This will:");
    println!("  - disconnect Cloudflare WARP and close its window");
    println!("  - stop winws.exe");
    println!("  - remove services zapret, WinDivert, WinDivert14 and their registry keys");
    println!("  - remove temporary leftovers and Defender exclusions for this folder");
    println!("  - list custom hosts-file entries for manual review (hosts is NOT edited)\n");
    println!("Folder: {}\n", root.display());
    println!("  1. Clean the system, keep this folder");
    println!("  2. Clean the system AND delete this folder");
    println!("  3. Cancel");
    let mut del_folder = match ui::choice("Select 1-3: ", "123") {
        '3' => {
            println!("\nCancelled. Nothing was changed.");
            return Ok(());
        }
        '2' => true,
        _ => false,
    };
    if del_folder {
        if let Some(reason) = folder_problem(&root) {
            ui::warn(&format!("The folder will NOT be deleted automatically: {reason}"));
            println!("Continuing with system cleanup only.");
            del_folder = false;
        }
    }

    println!();
    let rm_warp = ui::yes_no("Also UNINSTALL Cloudflare WARP itself?");
    println!("\nzapret turns TCP timestamps on. The Windows default is off.");
    let revert_ts = ui::yes_no("Set TCP timestamps back to the Windows default?");

    println!();
    if del_folder {
        println!("The folder above and everything inside it will be PERMANENTLY deleted.");
        print!("Type DELETE to confirm: ");
        if !ui::read_line().eq_ignore_ascii_case("DELETE") {
            println!("\nCancelled. Nothing was changed.");
            return Ok(());
        }
    } else if !ui::yes_no("Start cleanup?") {
        println!("\nCancelled. Nothing was changed.");
        return Ok(());
    }

    match crate::dns::restore(layout) {
        Ok(true) => ui::ok("DNS restored to the settings from before NetFreedom"),
        Ok(false) => {}
        Err(e) => ui::warn(&format!("DNS: {e}")),
    }
    println!("\n[1/8] Cloudflare WARP");
    match Warp::locate() {
        Some(w) => {
            w.disconnect();
            ui::ok("disconnect command sent");
        }
        None => ui::skip("warp-cli not found"),
    }
    sys::kill_by_name("Cloudflare WARP.exe");

    println!("[2/8] zapret process");
    if sys::kill_by_name("winws.exe") > 0 {
        ui::ok("winws.exe stopped");
    } else {
        ui::skip("winws.exe is not running");
    }

    println!("[3/8] Services");
    crate::maint::disable_autostart(); // the logon task, if autostart was enabled
    for (name, r) in winws::remove_services() {
        match r {
            Removal::Removed => ui::ok(&format!("{name} removed")),
            Removal::NotInstalled => ui::skip(&format!("{name} is not registered")),
            Removal::Failed(e) => ui::warn(&format!("{name}: error {e}")),
        }
    }

    println!("[4/8] Registry leftovers");
    for name in winws::SERVICES {
        match sys::delete_service_key(name) {
            KeyDelete::Absent => {}
            KeyDelete::Deleted => ui::ok(&format!("{name} key deleted")),
            KeyDelete::Failed(_) => ui::warn(&format!("{name} key is locked until restart")),
        }
    }

    println!("[5/8] Temporary files and Defender exclusions");
    let tmp = std::env::temp_dir();
    let _ = fs::remove_file(tmp.join("zapret_hosts.txt"));
    if let Ok(rd) = fs::read_dir(&tmp) {
        for e in rd.flatten() {
            let n = e.file_name().to_string_lossy().to_ascii_lowercase();
            if n.starts_with("windivert") && n.ends_with(".sys") {
                let _ = fs::remove_file(e.path());
            }
        }
    }
    ui::ok("temp leftovers removed");
    run_powershell_script(DEFENDER_PS, &root);

    println!("[6/8] TCP timestamps");
    if revert_ts {
        if winws::disable_tcp_timestamps() {
            ui::ok("TCP timestamps set to the Windows default");
        } else {
            ui::warn("could not change TCP timestamps");
        }
    } else {
        ui::skip("skipped by choice");
    }

    println!("[7/8] Cloudflare WARP uninstall");
    if rm_warp {
        match uninstall_warp() {
            0 => ui::ok("Cloudflare WARP uninstalled"),
            10 => ui::ok("Cloudflare WARP uninstalled, restart Windows to finish"),
            _ => {}
        }
    } else {
        ui::skip("skipped by choice, WARP stays installed");
    }

    println!("[8/8] hosts file");
    hosts_report();

    println!("\n---------------- Verification ----------------");
    let mut problems = 0;
    if sys::is_running("winws.exe") {
        ui::warn("winws.exe is still running");
        problems += 1;
    }
    for name in winws::SERVICES {
        if sys::service_state(name) != sys::SvcState::NotInstalled {
            ui::warn(&format!("service {name} is still registered"));
            problems += 1;
        }
    }
    if problems == 0 {
        ui::ok("no zapret processes or services left");
    } else {
        println!("  Restart Windows to finish removing the items above.");
    }

    if del_folder {
        println!();
        if schedule_folder_removal(&root) {
            println!("  The folder will be removed a few seconds after this window closes.");
        } else {
            println!("  Delete the folder manually: {}", root.display());
            return Err("could not schedule folder removal".into());
        }
    } else {
        println!("\nCleanup finished. You can delete this folder manually.");
    }
    Ok(())
}
