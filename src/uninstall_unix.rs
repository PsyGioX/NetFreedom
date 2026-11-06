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

//! Linux cleanup: stops the engine, removes nft rules, optionally removes WARP and this folder.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::backend::{self, Outcome};
use crate::paths::Layout;
use crate::safety;
use crate::ui;
use crate::warp::Warp;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    Debian,
    Rhel,
    Arch,
    Suse,
    Unknown,
}

/// Distribution family from the content of /etc/os-release (`ID` and `ID_LIKE`).
pub fn family_of(os_release: &str) -> Family {
    let mut ids = Vec::new();
    for l in os_release.lines() {
        if let Some(v) = l.strip_prefix("ID=").or_else(|| l.strip_prefix("ID_LIKE=")) {
            ids.extend(v.trim_matches('"').split_whitespace().map(str::to_lowercase));
        }
    }
    let has = |names: &[&str]| ids.iter().any(|i| names.contains(&i.as_str()));
    if has(&["debian", "ubuntu", "linuxmint", "pop", "raspbian", "kali", "zorin", "elementary"]) {
        Family::Debian
    } else if has(&["rhel", "fedora", "centos", "rocky", "almalinux", "ol", "amzn"]) {
        Family::Rhel
    } else if has(&["arch", "manjaro", "endeavouros", "cachyos", "garuda"]) {
        Family::Arch
    } else if has(&["suse", "opensuse", "opensuse-leap", "opensuse-tumbleweed", "sles"]) {
        Family::Suse
    } else {
        Family::Unknown
    }
}

pub fn family() -> Family {
    family_of(&fs::read_to_string("/etc/os-release").unwrap_or_default())
}

/// Command that removes the WARP package on this family (None: unknown, do it by hand).
pub fn remove_warp_command(f: Family) -> Option<Vec<&'static str>> {
    Some(match f {
        Family::Debian => vec!["apt-get", "remove", "-y", "cloudflare-warp"],
        Family::Rhel => vec!["dnf", "remove", "-y", "cloudflare-warp"],
        Family::Arch => vec!["pacman", "-Rns", "--noconfirm", "cloudflare-warp-bin"],
        Family::Suse => vec!["zypper", "--non-interactive", "remove", "cloudflare-warp"],
        Family::Unknown => return None,
    })
}

/// Text of the `install-warp` command (instructions only: nothing is downloaded or run).
pub fn install_instructions(f: Family) -> String {
    let head = "Install the official Cloudflare WARP client (package repository: https://pkg.cloudflareclient.com/):\n\n";
    let body = match f {
        Family::Debian => "  curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | sudo gpg --yes --dearmor --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg\n  echo \"deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ $(lsb_release -cs) main\" | sudo tee /etc/apt/sources.list.d/cloudflare-client.list\n  sudo apt-get update && sudo apt-get install cloudflare-warp\n\n  (On a release newer than the repository supports, use the nearest supported codename, e.g. noble.)",
        Family::Rhel => "  curl -fsSl https://pkg.cloudflareclient.com/cloudflare-warp-ascii.repo | sudo tee /etc/yum.repos.d/cloudflare-warp.repo\n  sudo dnf install cloudflare-warp      # or: sudo yum install cloudflare-warp",
        Family::Arch => "  yay -S cloudflare-warp-bin            # AUR (any AUR helper)",
        Family::Suse | Family::Unknown => "  Follow the instructions for your distribution at https://pkg.cloudflareclient.com/",
    };
    format!("{head}{body}\n\nThen:\n  sudo systemctl enable --now warp-svc\n  sudo netfreedom start        # registers a free WARP identity automatically on first run\n\nAlso needed: the nftables package (`nft`).")
}

fn protected() -> Vec<String> {
    let mut v: Vec<String> = ["/", "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib64", "/opt", "/proc", "/root", "/run", "/sbin", "/srv", "/sys", "/tmp", "/usr", "/var", "/mnt", "/media"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let mut homes: Vec<String> = Vec::new();
    homes.extend(std::env::var("HOME").ok());
    if let Ok(u) = std::env::var("SUDO_USER") {
        homes.push(format!("/home/{u}"));
    }
    for h in homes {
        for sub in ["", "/Desktop", "/Documents", "/Downloads"] {
            v.push(format!("{h}{sub}"));
        }
    }
    v
}

fn folder_problem(root: &Path) -> Option<String> {
    safety::unsafe_reason(&root.display().to_string(), &protected(), &|m| root.join(m).exists())
}

pub fn run(layout: &Layout) -> Result<(), String> {
    let root: PathBuf = layout.root.clone();
    println!("================================================================");
    println!("  FULL CLEANUP of netfreedom");
    println!("================================================================\n");
    println!("This will disconnect WARP, stop nfqws and remove the nftables table `inet netfreedom`.");
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
            del_folder = false;
        }
    }
    let fam = family();
    let rm_cmd = remove_warp_command(fam);
    let rm_warp = match &rm_cmd {
        Some(c) => ui::yes_no(&format!("Also REMOVE the Cloudflare WARP package (`{}`)?", c.join(" "))),
        None => {
            println!("(Unknown distribution: remove the cloudflare-warp package manually if you want to.)");
            false
        }
    };
    if del_folder {
        print!("Type DELETE to confirm deleting {}: ", root.display());
        if !ui::read_line().eq_ignore_ascii_case("DELETE") {
            println!("\nCancelled. Nothing was changed.");
            return Ok(());
        }
    } else if !ui::yes_no("Start cleanup?") {
        println!("\nCancelled. Nothing was changed.");
        return Ok(());
    }

    println!("\n[1/4] Cloudflare WARP");
    match Warp::locate() {
        Some(w) => {
            w.disconnect();
            ui::ok("disconnect command sent");
        }
        None => ui::skip("warp-cli not found"),
    }
    crate::maint::disable_autostart(); // the systemd unit, if autostart was enabled
    println!("[2/4] Packet engine");
    for (name, r) in backend::stop_all() {
        match r {
            Outcome::Done => ui::ok(&format!("{name} removed")),
            Outcome::Absent => ui::skip(&format!("{name}: nothing to remove")),
            Outcome::Failed(e) => ui::warn(&format!("{name}: {e}")),
        }
    }
    println!("[3/4] WARP package");
    match (rm_warp, rm_cmd) {
        (true, Some(c)) => match Command::new(crate::util::system_tool(c[0])).args(&c[1..]).status() {
            Ok(s) if s.success() => ui::ok("package removed"),
            Ok(s) => ui::warn(&format!("{} exited with {s}", c[0])),
            Err(e) => ui::warn(&format!("cannot run {}: {e}", c[0])),
        },
        _ => ui::skip("skipped"),
    }
    println!("[4/4] Verification");
    let mut problems = 0;
    if backend::engine_running() {
        ui::warn("nfqws is still running");
        problems += 1;
    }
    if problems == 0 {
        ui::ok("no zapret processes or rules left");
    }
    if del_folder {
        match fs::remove_dir_all(&root) {
            Ok(()) => println!("\nFolder deleted: {}", root.display()),
            Err(e) => return Err(format!("could not delete {}: {e}", root.display())),
        }
    } else {
        println!("\nCleanup finished. You can delete this folder manually.");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distro_families() {
        assert_eq!(family_of("NAME=\"Ubuntu\"\nID=ubuntu\nID_LIKE=debian\n"), Family::Debian);
        assert_eq!(family_of("ID=linuxmint\nID_LIKE=\"ubuntu debian\""), Family::Debian);
        assert_eq!(family_of("ID=\"fedora\""), Family::Rhel);
        assert_eq!(family_of("ID=rocky\nID_LIKE=\"rhel centos fedora\""), Family::Rhel);
        assert_eq!(family_of("ID=arch"), Family::Arch);
        assert_eq!(family_of("ID=endeavouros\nID_LIKE=arch"), Family::Arch);
        assert_eq!(family_of("ID=\"opensuse-tumbleweed\"\nID_LIKE=\"opensuse suse\""), Family::Suse);
        assert_eq!(family_of("ID=nixos"), Family::Unknown);
    }

    #[test]
    fn commands_and_instructions() {
        assert_eq!(remove_warp_command(Family::Debian).unwrap()[0], "apt-get");
        assert!(remove_warp_command(Family::Unknown).is_none());
        assert!(install_instructions(Family::Debian).contains("apt-get install cloudflare-warp"));
        assert!(install_instructions(Family::Arch).contains("cloudflare-warp-bin"));
        assert!(install_instructions(Family::Unknown).contains("pkg.cloudflareclient.com"));
    }
}
