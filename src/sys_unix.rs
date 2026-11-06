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

//! Linux / Unix counterpart of `sys.rs`: root check, sudo re-launch, process control, signals.

use std::io::IsTerminal;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

pub fn console_init() {}

pub fn set_title(title: &str) {
    if std::io::stdout().is_terminal() {
        print!("\x1b]0;{title}\x07");
    }
}

/// True when the terminal window may vanish the moment we exit: a terminal emulator started us
/// directly (desktop launcher with "Run in terminal", file manager) instead of the user typing the
/// command into a shell. `sudo` / `pkexec` / `su` wrappers are looked through.
pub fn owns_console() -> bool {
    if !std::io::stdin().is_terminal() {
        return false;
    }
    !launched_from_shell()
}

fn stat_parent(pid: u32) -> Option<u32> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // "pid (comm with spaces) S ppid ..." - comm may contain anything, so split after the LAST ')'
    s[s.rfind(')')? + 1..].split_whitespace().nth(1)?.parse().ok()
}

fn comm_of(pid: u32) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{pid}/comm")).ok().map(|c| c.trim().to_owned())
}

/// Is the first ancestor that is not a privilege wrapper an interactive shell?
pub fn launched_from_shell() -> bool {
    const WRAPPERS: [&str; 5] = ["sudo", "pkexec", "su", "doas", "env"];
    const SHELLS: [&str; 7] = ["bash", "zsh", "fish", "sh", "dash", "ksh", "tcsh"];
    let mut pid = std::process::id();
    for _ in 0..8 {
        let Some(pp) = stat_parent(pid) else { return false };
        let Some(name) = comm_of(pp) else { return false };
        if WRAPPERS.contains(&name.as_str()) {
            pid = pp;
            continue;
        }
        return SHELLS.contains(&name.as_str());
    }
    false
}

pub fn is_elevated() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// Finds an executable in PATH.
pub fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).map(|d| d.join(name)).find(|p| p.is_file())
}

/// Replaces this process with `sudo <exe> <args>` (or pkexec). Returns `false` if neither exists.
pub fn relaunch_elevated(args: &[String]) -> bool {
    let Ok(exe) = std::env::current_exe() else { return false };
    for tool in ["sudo", "pkexec"] {
        let path = crate::util::system_tool(tool);
        if path.is_absolute() {
            println!("Administrator rights are required, re-running with {tool}...");
            let err = Command::new(path).arg(&exe).args(args).exec();
            eprintln!("cannot run {tool}: {err}");
        }
    }
    false
}

pub fn open_url(url: &str) -> bool {
    which("xdg-open").is_some_and(|_| Command::new("xdg-open").arg(url).spawn().is_ok())
}

static CLEANUP: OnceLock<fn()> = OnceLock::new();
static ARMED: AtomicBool = AtomicBool::new(false);
static INTERRUPTED: AtomicBool = AtomicBool::new(false);
static GRACEFUL: AtomicBool = AtomicBool::new(false);

/// While graceful, SIGINT only sets a flag (see `interrupted`) so that a long job (`tune`) can stop
/// at a safe point, clean up and still print its results. SIGTERM / SIGHUP always clean up and exit.
pub fn set_graceful(on: bool) {
    INTERRUPTED.store(false, Ordering::SeqCst);
    GRACEFUL.store(on, Ordering::SeqCst);
}

pub fn interrupted() -> bool {
    INTERRUPTED.load(Ordering::SeqCst)
}

/// SIGINT / SIGTERM / SIGHUP are blocked in every thread and consumed by one watcher thread,
/// which runs `f` (undo everything) and exits. Must be called before other threads are created.
pub fn install_cleanup_handler(f: fn()) {
    if CLEANUP.set(f).is_err() {
        return;
    }
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        for s in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            libc::sigaddset(&mut set, s);
        }
        libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
        let _ = std::thread::Builder::new().name("signals".into()).spawn(move || loop {
            let mut sig = 0;
            libc::sigwait(&set, &mut sig);
            if sig == libc::SIGINT && GRACEFUL.load(Ordering::SeqCst) {
                INTERRUPTED.store(true, Ordering::SeqCst);
                continue;
            }
            if ARMED.swap(false, Ordering::SeqCst) {
                f();
            }
            std::process::exit(128 + sig);
        });
    }
}

pub fn arm_cleanup(on: bool) {
    ARMED.store(on, Ordering::SeqCst);
}

/// Process ids whose `comm` equals `name` (kernel truncates comm to 15 bytes).
pub fn pids_by_name(name: &str) -> Vec<u32> {
    let want: String = name.chars().take(15).collect();
    let Ok(rd) = std::fs::read_dir("/proc") else { return Vec::new() };
    rd.flatten()
        .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
        .filter(|pid| std::fs::read_to_string(format!("/proc/{pid}/comm")).is_ok_and(|c| c.trim_end() == want))
        .collect()
}

pub fn is_running(name: &str) -> bool {
    !pids_by_name(name).is_empty()
}

/// SIGTERM, then SIGKILL after one second. Returns how many processes were targeted.
pub fn kill_by_name(name: &str) -> usize {
    let pids = pids_by_name(name);
    for p in &pids {
        unsafe { libc::kill(*p as i32, libc::SIGTERM) };
    }
    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_secs(1) && pids.iter().any(|p| std::path::Path::new(&format!("/proc/{p}")).exists()) {
        std::thread::sleep(Duration::from_millis(30));
    }
    for p in &pids {
        if std::path::Path::new(&format!("/proc/{p}")).exists() {
            unsafe { libc::kill(*p as i32, libc::SIGKILL) };
        }
    }
    pids.len()
}
