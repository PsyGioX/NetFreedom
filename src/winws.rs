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

//! Starting and stopping winws (zapret) and its WinDivert driver.

use std::os::windows::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use crate::paths::Layout;
use crate::sys::{self, Removal, SvcState};

const CREATE_NEW_CONSOLE: u32 = 0x0000_0010;
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
/// Same effect as the old PowerShell `PriorityClass = 'High'` step, applied at creation time.
const HIGH_PRIORITY_CLASS: u32 = 0x0000_0080;

pub const SERVICES: [&str; 3] = ["zapret", "WinDivert", "WinDivert14"];

pub fn spawn(layout: &Layout, args: &[String], show_console: bool) -> std::io::Result<Child> {
    let window = if show_console { CREATE_NEW_CONSOLE } else { CREATE_NO_WINDOW };
    // winws writes its complaints (bad option, WinDivert refused, ...) to stdout/stderr; they used
    // to go nowhere, so a broken strategy looked like "the internet stopped working"
    let (out, err) = match std::fs::create_dir_all(&layout.utils).and_then(|_| std::fs::File::create(layout.utils.join("winws.log"))) {
        Ok(f) => match f.try_clone() {
            Ok(f2) => (Stdio::from(f), Stdio::from(f2)),
            Err(_) => (Stdio::from(f), Stdio::null()),
        },
        Err(_) => (Stdio::null(), Stdio::null()),
    };
    Command::new(layout.winws_exe())
        .args(args)
        .current_dir(&layout.bin)
        .creation_flags(window | HIGH_PRIORITY_CLASS)
        .stdin(Stdio::null())
        .stdout(out)
        .stderr(err)
        .spawn()
}

/// Waits until winws has opened the WinDivert driver (service state RUNNING) instead of sleeping
/// a fixed 3 s. Returns `false` if winws exited early; after `max` it assumes success, like the
/// old launcher did.
pub fn wait_ready(child: &mut Child, max: Duration) -> bool {
    let t0 = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return false,
            Ok(None) => {}
            Err(_) => return false,
        }
        if sys::service_state("WinDivert") == SvcState::Running {
            std::thread::sleep(Duration::from_millis(150)); // let the filter settle
            return matches!(child.try_wait(), Ok(None));
        }
        if t0.elapsed() >= max {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Stop the zapret service, kill winws,
/// stop and delete the WinDivert driver services.
pub fn remove_services() -> Vec<(&'static str, Removal)> {
    crate::native::stop(); // the in-process engine holds a WinDivert handle
    let mut out = Vec::with_capacity(SERVICES.len());
    out.push(("zapret", sys::service_remove("zapret")));
    sys::kill_by_name("winws.exe");
    out.push(("WinDivert", sys::service_remove("WinDivert")));
    out.push(("WinDivert14", sys::service_remove("WinDivert14")));
    out
}

/// Zapret needs TCP timestamps; the classic profiles rely on it (LEAN does not touch TCP).
pub fn enable_tcp_timestamps() {
    let _ = Command::new("netsh")
        .args(["interface", "tcp", "set", "global", "timestamps=enabled"])
        .creation_flags(CREATE_NO_WINDOW)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

pub fn disable_tcp_timestamps() -> bool {
    Command::new("netsh")
        .args(["interface", "tcp", "set", "global", "timestamps=disabled"])
        .creation_flags(CREATE_NO_WINDOW)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}
