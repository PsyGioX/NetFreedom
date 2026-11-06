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

//! One interface over the two engines: winws + WinDivert (Windows) and nfqws + nftables (Linux).

use std::time::Duration;

use crate::paths::Layout;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Done,
    Absent,
    Failed(String),
}

/// Is the engine binary there?
pub fn check_engine(layout: &Layout) -> Result<(), String> {
    #[cfg(windows)]
    {
        if layout.winws_exe().is_file() {
            Ok(())
        } else {
            Err(format!("{} not found: keep the executable next to the bin\\ and lists\\ folders.", layout.winws_exe().display()))
        }
    }
    #[cfg(unix)]
    {
        layout.nfqws_exe().map(|_| ()).ok_or_else(|| "nfqws not found: put it into bin/ (or bin/linux-<arch>/) or install it into PATH.".to_string())
    }
}

/// Is an engine of ours already running (so that a second start must be refused)?
/// Last lines of the engine's own output (winws.log / nfqws log), for failure messages.
pub fn engine_log_tail(layout: &Layout, lines: usize) -> String {
    #[cfg(windows)]
    let path = layout.utils.join("winws.log");
    #[cfg(unix)]
    let path = crate::nfqws::log_path();
    let _ = layout;
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let all: Vec<&str> = text.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    all[all.len().saturating_sub(lines)..].join(" | ")
}

pub fn engine_running() -> bool {
    #[cfg(windows)]
    {
        crate::sys::is_running("winws.exe")
    }
    #[cfg(unix)]
    {
        crate::sys::is_running("nfqws")
    }
}

/// Windows classic profiles rely on TCP timestamps; nothing to do on Linux.
pub fn prepare_classic() {
    #[cfg(windows)]
    crate::winws::enable_tcp_timestamps();
}

/// Starts the engine for an expanded profile command line and returns when it is ready.
pub fn start(layout: &Layout, args: &[String], show_console: bool) -> Result<(), String> {
    #[cfg(windows)]
    {
        let mut child = crate::winws::spawn(layout, args, show_console).map_err(|e| format!("cannot start winws.exe: {e}"))?;
        if !crate::winws::wait_ready(&mut child, Duration::from_secs(3)) {
            return Err("winws.exe did not start. Check antivirus and WinDivert, then try another profile.".into());
        }
        Ok(())
    }
    #[cfg(unix)]
    {
        let _ = (show_console, Duration::ZERO);
        crate::nfqws::start(layout, args, false)
    }
}

/// Stops everything the engine installed. Safe to call repeatedly.
pub fn stop_all() -> Vec<(String, Outcome)> {
    #[cfg(windows)]
    {
        use crate::sys::Removal;
        crate::winws::remove_services()
            .into_iter()
            .map(|(n, r)| {
                let o = match r {
                    Removal::Removed => Outcome::Done,
                    Removal::NotInstalled => Outcome::Absent,
                    Removal::Failed(e) => Outcome::Failed(format!("error {e}")),
                };
                (format!("service {n}"), o)
            })
            .collect()
    }
    #[cfg(unix)]
    {
        crate::nfqws::stop_all()
    }
}

// ---- experimental in-process engine (Windows only) ----------------------------------------

/// `Ok(true)`: native engine started; `Ok(false)`: not applicable, use the normal engine.
pub fn native_try(layout: &Layout, args: &[String]) -> Result<bool, String> {
    #[cfg(windows)]
    {
        let plan = crate::engine::Plan::from_args(args, &|p| std::fs::read(p))?;
        crate::native::start(&layout.bin, plan)?;
        Ok(true)
    }
    #[cfg(unix)]
    {
        let _ = (layout, args);
        Err("the native engine exists on Windows only (on Linux nfqws is used)".into())
    }
}

pub fn native_active() -> bool {
    #[cfg(windows)]
    {
        crate::native::is_active()
    }
    #[cfg(unix)]
    {
        false
    }
}

pub fn native_stop() -> Option<crate::engine::Stats> {
    #[cfg(windows)]
    {
        crate::native::stop()
    }
    #[cfg(unix)]
    {
        None
    }
}
