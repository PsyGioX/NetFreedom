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

//! The WinDivert driver side of the Windows engine: removing its services, and the TCP timestamp
//! setting the `ts` fooling depends on. (The packet engine itself is `engine.rs` + `native.rs`.)

use std::os::windows::process::CommandExt;
use std::process::{Command, Stdio};

use crate::sys::{self, Removal};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// `zapret` is a service of installs made by older versions; it is removed if it is still there.
pub const SERVICES: [&str; 3] = ["zapret", "WinDivert", "WinDivert14"];

/// Stops the in-process engine and deletes the WinDivert driver services (and, for installs made
/// by older versions, the `zapret` service and a leftover `winws.exe`).
pub fn remove_services() -> Vec<(&'static str, Removal)> {
    crate::native::stop(); // the engine holds a WinDivert handle
    crate::native::stop_other_instances(); // ... and so does the engine of another NetFreedom process
    let mut out = Vec::with_capacity(SERVICES.len());
    out.push(("zapret", sys::service_remove("zapret")));
    sys::kill_by_name("winws.exe");
    out.push(("WinDivert", sys::service_remove("WinDivert")));
    out.push(("WinDivert14", sys::service_remove("WinDivert14")));
    out
}

/// The `ts` fooling edits the TCP timestamp option, so Windows must put one into its packets.
pub fn enable_tcp_timestamps() {
    let _ = Command::new(crate::util::system_tool("netsh"))
        .args(["interface", "tcp", "set", "global", "timestamps=enabled"])
        .creation_flags(CREATE_NO_WINDOW)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

pub fn disable_tcp_timestamps() -> bool {
    Command::new(crate::util::system_tool("netsh"))
        .args(["interface", "tcp", "set", "global", "timestamps=disabled"])
        .creation_flags(CREATE_NO_WINDOW)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}
