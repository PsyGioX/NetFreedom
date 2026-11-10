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

//! Thin Win32 layer. Everything the BAT files did through `tasklist`, `taskkill`, `sc`, `net`,
//! `reg`, `fltmc` and PowerShell is done here with direct API calls: no helper process is spawned,
//! so each step costs microseconds instead of 50-300 ms.

use std::ffi::{c_void, OsStr};
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::OsStrExt;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use std::time::Duration;

use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Security::*;
use windows_sys::Win32::System::Console::*;
use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
use windows_sys::Win32::System::Registry::*;
use windows_sys::Win32::System::Services::*;
use windows_sys::Win32::System::Threading::*;
use windows_sys::Win32::UI::Shell::ShellExecuteW;
use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

/// UTF-16, NUL terminated.
pub fn wide(s: impl AsRef<OsStr>) -> Vec<u16> {
    s.as_ref().encode_wide().chain(Some(0)).collect()
}

fn from_wide(buf: &[u16]) -> String {
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..len])
}

// ------------------------------------------------------------------ elevation

pub fn is_elevated() -> bool {
    unsafe {
        let mut token: HANDLE = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elev = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut ret = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            &mut elev as *mut _ as *mut c_void,
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret,
        );
        CloseHandle(token);
        ok != 0 && elev.TokenIsElevated != 0
    }
}

fn quote_arg(a: &str) -> String {
    if !a.is_empty() && !a.contains([' ', '\t', '"']) {
        return a.to_owned();
    }
    format!("\"{}\"", a.replace('"', "\\\""))
}

/// Re-launches this executable with a UAC prompt. Returns `true` if the request was accepted.
pub fn relaunch_elevated(args: &[String]) -> bool {
    let Ok(exe) = std::env::current_exe() else { return false };
    let params = args.iter().map(|a| quote_arg(a)).collect::<Vec<_>>().join(" ");
    let verb = wide("runas");
    let file = wide(&exe);
    let par = wide(&params);
    let r = unsafe { ShellExecuteW(null_mut(), verb.as_ptr(), file.as_ptr(), par.as_ptr(), null(), SW_SHOWNORMAL) };
    r as isize > 32
}

/// Opens a URL or file with the default handler.
pub fn open_url(url: &str) -> bool {
    let verb = wide("open");
    let file = wide(url);
    let r = unsafe { ShellExecuteW(null_mut(), verb.as_ptr(), file.as_ptr(), null(), null(), SW_SHOWNORMAL) };
    r as isize > 32
}

// -------------------------------------------------------------------- console

/// UTF-8 code page, ANSI colours.
pub fn console_init() {
    unsafe {
        SetConsoleOutputCP(65001);
        SetConsoleCP(65001);
        let h = GetStdHandle(STD_OUTPUT_HANDLE);
        let mut mode = 0u32;
        if GetConsoleMode(h, &mut mode) != 0 {
            SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        }
    }
}

pub fn set_title(title: &str) {
    let t = wide(title);
    unsafe { SetConsoleTitleW(t.as_ptr()) };
}

/// True when the console window will disappear the moment this process exits: it was started
/// by double-click / UAC (so nobody reads the output afterwards), not typed into a shell.
/// Both signals are checked because either alone fails: other processes (the WARP tray, a
/// helper) may share the console and hide the "only process" case, and a UAC re-launch has no
/// shell parent at all.
pub fn owns_console() -> bool {
    let mut mode = 0u32;
    let interactive = unsafe { GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &mut mode) } != 0;
    if !interactive {
        return false; // redirected stdin: nobody to wait for
    }
    let mut pids = [0u32; 2];
    let attached = unsafe { GetConsoleProcessList(pids.as_mut_ptr(), 2) };
    attached <= 1 || !launched_from_shell()
}

/// Is the parent process a command interpreter / terminal (the user typed the command)?
pub fn launched_from_shell() -> bool {
    const SHELLS: [&str; 8] = ["cmd.exe", "powershell.exe", "pwsh.exe", "windowsterminal.exe", "wt.exe", "bash.exe", "conhost.exe", "openconsole.exe"];
    let mut table: Vec<(u32, u32, String)> = Vec::new();
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE {
            return false;
        }
        let mut e: PROCESSENTRY32W = zeroed();
        e.dwSize = size_of::<PROCESSENTRY32W>() as u32;
        if Process32FirstW(snap, &mut e) != 0 {
            loop {
                table.push((e.th32ProcessID, e.th32ParentProcessID, from_wide(&e.szExeFile).to_ascii_lowercase()));
                if Process32NextW(snap, &mut e) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snap);
    }
    let me = std::process::id();
    let parent = table.iter().find(|(pid, _, _)| *pid == me).map(|(_, pp, _)| *pp);
    parent.and_then(|pp| table.iter().find(|(pid, _, _)| *pid == pp)).is_some_and(|(_, _, name)| SHELLS.contains(&name.as_str()))
}

static CLEANUP: OnceLock<fn()> = OnceLock::new();
static CLEANUP_ARMED: AtomicBool = AtomicBool::new(false);

static INTERRUPTED: AtomicBool = AtomicBool::new(false);
static GRACEFUL: AtomicBool = AtomicBool::new(false);

/// While graceful, Ctrl+C / Ctrl+Break only set a flag (see `interrupted`) instead of ending the
/// process, so a long job (`tune`) can stop at a safe point, clean up and still print its results.
/// Closing the window, logoff and shutdown can never be graceful: Windows kills the process
/// after a few seconds, so those always run the cleanup and exit.
pub fn set_graceful(on: bool) {
    INTERRUPTED.store(false, Ordering::SeqCst);
    GRACEFUL.store(on, Ordering::SeqCst);
}

pub fn interrupted() -> bool {
    INTERRUPTED.load(Ordering::SeqCst)
}

unsafe extern "system" fn on_ctrl(event: u32) -> BOOL {
    if (event == CTRL_C_EVENT || event == CTRL_BREAK_EVENT) && GRACEFUL.load(Ordering::SeqCst) {
        INTERRUPTED.store(true, Ordering::SeqCst);
        return 1; // handled: the main thread notices the flag and winds down
    }
    // Ctrl+C outside a graceful job, closing the window, logoff, shutdown: undo everything, exit.
    // (The old BAT launcher left WARP and the WinDivert driver behind when the window was closed.)
    // The exit code is non-zero so that a cut-short run is never mistaken for a finished one.
    if CLEANUP_ARMED.swap(false, Ordering::SeqCst) {
        if let Some(f) = CLEANUP.get() {
            f();
        }
    }
    std::process::exit(if event == CTRL_C_EVENT || event == CTRL_BREAK_EVENT { 130 } else { 1 });
}

/// Installs the console handler that runs `f` on any termination request.
pub fn install_cleanup_handler(f: fn()) {
    let _ = CLEANUP.set(f);
    unsafe { SetConsoleCtrlHandler(Some(on_ctrl), 1) };
}

/// While armed, a termination request triggers the cleanup handler.
pub fn arm_cleanup(on: bool) {
    CLEANUP_ARMED.store(on, Ordering::SeqCst);
}

// ------------------------------------------------------------------ processes

/// Process ids whose image name equals `name` (case-insensitive).
pub fn pids_by_name(name: &str) -> Vec<u32> {
    let mut out = Vec::new();
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE {
            return out;
        }
        let mut e: PROCESSENTRY32W = zeroed();
        e.dwSize = size_of::<PROCESSENTRY32W>() as u32;
        if Process32FirstW(snap, &mut e) != 0 {
            loop {
                if from_wide(&e.szExeFile).eq_ignore_ascii_case(name) {
                    out.push(e.th32ProcessID);
                }
                if Process32NextW(snap, &mut e) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snap);
    }
    out
}

pub fn is_running(name: &str) -> bool {
    !pids_by_name(name).is_empty()
}

fn terminate(pid: u32) -> bool {
    unsafe {
        let h = OpenProcess(PROCESS_TERMINATE, 0, pid);
        if h.is_null() {
            return false;
        }
        let ok = TerminateProcess(h, 1) != 0;
        CloseHandle(h);
        ok
    }
}

/// Terminates every process with that image name. Returns how many were killed.
/// The name alone proves nothing (any program can be called `Discord.exe`): where the expected
/// install folder is known, use [`kill_by_name_in`] or [`kill_matching`] instead.
pub fn kill_by_name(name: &str) -> usize {
    pids_by_name(name).into_iter().filter(|&pid| terminate(pid)).count()
}

/// Full path of the program a process runs (`None` if it cannot be queried).
pub fn image_path(pid: u32) -> Option<String> {
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return None;
        }
        let mut buf = vec![0u16; 4096];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut len) != 0;
        CloseHandle(h);
        (ok && len > 0).then(|| from_wide(&buf[..len as usize]))
    }
}

/// Terminates the processes called `name` whose executable path satisfies `wanted`, never this
/// process. A process whose path cannot be read is NOT terminated. Returns (ended, left alone).
pub fn kill_matching(name: &str, wanted: impl Fn(&str) -> bool) -> (usize, usize) {
    let me = std::process::id();
    let (mut ended, mut skipped) = (0, 0);
    for pid in pids_by_name(name) {
        if pid == me {
            continue;
        }
        if image_path(pid).is_some_and(|p| wanted(&p)) && terminate(pid) {
            ended += 1;
        } else {
            skipped += 1;
        }
    }
    (ended, skipped)
}

/// Like [`kill_by_name`], but only for processes started from a file inside one of the `roots`
/// folders. Returns (ended, left alone).
pub fn kill_by_name_in(name: &str, roots: &[String]) -> (usize, usize) {
    kill_matching(name, |p| roots.iter().any(|r| crate::safety::is_inside(p, r)))
}

// ------------------------------------------------------------------- services

/// Standard access right `DELETE` (lives in the FileSystem feature of windows-sys; a literal is cheaper).
const DELETE: u32 = 0x0001_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SvcState {
    NotInstalled,
    Stopped,
    Running,
    Other,
}

pub fn service_state(name: &str) -> SvcState {
    unsafe {
        let scm = OpenSCManagerW(null(), null(), SC_MANAGER_CONNECT);
        if scm.is_null() {
            return SvcState::NotInstalled;
        }
        let n = wide(name);
        let h = OpenServiceW(scm, n.as_ptr(), SERVICE_QUERY_STATUS);
        let state = if h.is_null() {
            SvcState::NotInstalled
        } else {
            let mut st: SERVICE_STATUS = zeroed();
            let s = if QueryServiceStatus(h, &mut st) == 0 {
                SvcState::Other
            } else {
                match st.dwCurrentState {
                    SERVICE_RUNNING => SvcState::Running,
                    SERVICE_STOPPED => SvcState::Stopped,
                    _ => SvcState::Other,
                }
            };
            CloseServiceHandle(h);
            s
        };
        CloseServiceHandle(scm);
        state
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Removal {
    NotInstalled,
    Removed,
    Failed(u32),
}

/// `net stop` + `sc delete` in one call; waits (up to 5 s) for the service to stop.
pub fn service_remove(name: &str) -> Removal {
    unsafe {
        let scm = OpenSCManagerW(null(), null(), SC_MANAGER_CONNECT);
        if scm.is_null() {
            return Removal::Failed(GetLastError());
        }
        let n = wide(name);
        let h = OpenServiceW(scm, n.as_ptr(), SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
        if h.is_null() {
            let e = GetLastError();
            CloseServiceHandle(scm);
            return if e == ERROR_SERVICE_DOES_NOT_EXIST { Removal::NotInstalled } else { Removal::Failed(e) };
        }
        let mut st: SERVICE_STATUS = zeroed();
        ControlService(h, SERVICE_CONTROL_STOP, &mut st);
        for _ in 0..50 {
            if QueryServiceStatus(h, &mut st) == 0 || st.dwCurrentState == SERVICE_STOPPED {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let r = if DeleteService(h) != 0 {
            Removal::Removed
        } else {
            let e = GetLastError();
            // already marked for deletion counts as done
            if e == ERROR_SERVICE_MARKED_FOR_DELETE { Removal::Removed } else { Removal::Failed(e) }
        };
        CloseServiceHandle(h);
        CloseServiceHandle(scm);
        r
    }
}

// ------------------------------------------------------------------- registry

/// Result of deleting a `HKLM\System\CurrentControlSet\Services\<name>` key.
#[derive(Debug, PartialEq, Eq)]
pub enum KeyDelete {
    Absent,
    Deleted,
    Failed(u32),
}

pub fn delete_service_key(name: &str) -> KeyDelete {
    let path = wide(format!("System\\CurrentControlSet\\Services\\{name}"));
    unsafe {
        let mut k: HKEY = null_mut();
        let e = RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.as_ptr(), 0, KEY_READ, &mut k);
        if e == ERROR_FILE_NOT_FOUND {
            return KeyDelete::Absent;
        }
        if e == 0 {
            RegCloseKey(k);
        }
        match RegDeleteTreeW(HKEY_LOCAL_MACHINE, path.as_ptr()) {
            0 => KeyDelete::Deleted,
            ERROR_FILE_NOT_FOUND => KeyDelete::Absent,
            e => KeyDelete::Failed(e),
        }
    }
}

fn reg_string(key: HKEY, value: &str) -> Option<String> {
    let name = wide(value);
    unsafe {
        let mut size = 0u32;
        if RegGetValueW(key, null(), name.as_ptr(), RRF_RT_REG_SZ, null_mut(), null_mut(), &mut size) != 0 || size < 2 {
            return None;
        }
        let mut buf = vec![0u16; (size as usize).div_ceil(2)];
        let mut size2 = (buf.len() * 2) as u32;
        if RegGetValueW(key, null(), name.as_ptr(), RRF_RT_REG_SZ, null_mut(), buf.as_mut_ptr() as *mut c_void, &mut size2) != 0 {
            return None;
        }
        Some(from_wide(&buf))
    }
}

pub struct UninstallEntry {
    pub name: String,
    pub version: String,
    pub uninstall: String,
}

/// First installed program whose DisplayName starts with one of `prefixes` (case-insensitive).
pub fn find_uninstall_entry(prefixes: &[&str]) -> Option<UninstallEntry> {
    const PATHS: [&str; 2] = [
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
    ];
    for path in PATHS {
        let p = wide(path);
        unsafe {
            let mut root: HKEY = null_mut();
            if RegOpenKeyExW(HKEY_LOCAL_MACHINE, p.as_ptr(), 0, KEY_READ, &mut root) != 0 {
                continue;
            }
            let mut idx = 0u32;
            let mut found = None;
            loop {
                let mut name = [0u16; 256];
                let mut len = name.len() as u32;
                if RegEnumKeyExW(root, idx, name.as_mut_ptr(), &mut len, null_mut(), null_mut(), null_mut(), null_mut()) != 0 {
                    break;
                }
                idx += 1;
                let mut sub: HKEY = null_mut();
                if RegOpenKeyExW(root, name.as_ptr(), 0, KEY_READ, &mut sub) != 0 {
                    continue;
                }
                if let Some(dn) = reg_string(sub, "DisplayName") {
                    let l = dn.to_ascii_lowercase();
                    if prefixes.iter().any(|pre| l.starts_with(&pre.to_ascii_lowercase())) {
                        found = Some(UninstallEntry {
                            version: reg_string(sub, "DisplayVersion").unwrap_or_default(),
                            uninstall: reg_string(sub, "UninstallString").unwrap_or_default(),
                            name: dn,
                        });
                    }
                }
                RegCloseKey(sub);
                if found.is_some() {
                    break;
                }
            }
            RegCloseKey(root);
            if found.is_some() {
                return found;
            }
        }
    }
    None
}
