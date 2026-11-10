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

//! One interface over the two engines: the built-in one on the WinDivert driver (Windows) and
//! nfqws + nftables (Linux).

use crate::paths::Layout;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Done,
    Absent,
    Failed(String),
}

/// Is everything the engine needs there?
pub fn check_engine(layout: &Layout) -> Result<(), String> {
    #[cfg(windows)]
    {
        for f in ["WinDivert.dll", "WinDivert64.sys"] {
            let p = std::path::PathBuf::from(&layout.bin).join(f);
            if !p.is_file() {
                return Err(format!("{} not found: keep the executable next to the bin\\ and lists\\ folders.", p.display()));
            }
        }
        Ok(())
    }
    #[cfg(unix)]
    {
        layout.nfqws_exe().map(|_| ()).ok_or_else(|| "nfqws not found: put it into bin/ (or bin/linux-<arch>/) or install it into PATH.".to_string())
    }
}

/// Last lines of the engine's own output (nfqws log on Linux), for failure messages. The Windows
/// engine reports its errors directly, so there is no log to read.
pub fn engine_log_tail(layout: &Layout, lines: usize) -> String {
    let _ = layout;
    #[cfg(unix)]
    {
        let text = std::fs::read_to_string(crate::nfqws::log_path()).unwrap_or_default();
        let all: Vec<&str> = text.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
        all[all.len().saturating_sub(lines)..].join(" | ")
    }
    #[cfg(windows)]
    {
        let _ = lines;
        String::new()
    }
}

/// Is an engine of ours already running (so that a second start must be refused)?
pub fn engine_running() -> bool {
    #[cfg(windows)]
    {
        crate::native::is_active() || crate::native::other_instance_running()
    }
    #[cfg(unix)]
    {
        crate::sys::is_running("nfqws")
    }
}

/// Windows classic profiles rely on TCP timestamps (the `ts` fooling); nothing to do on Linux.
pub fn prepare_classic() {
    #[cfg(windows)]
    crate::windivert::enable_tcp_timestamps();
}

/// Starts the engine for an expanded profile command line and returns when it is ready. On
/// Windows a strategy the engine cannot run exactly is an error with the reason, not a fallback.
pub fn start(layout: &Layout, args: &[String]) -> Result<(), String> {
    #[cfg(windows)]
    {
        let plan = crate::engine::Plan::from_args(args, &|p| std::fs::read(p)).map_err(|e| format!("this strategy cannot run on the built-in engine: {e}"))?;
        crate::native::start(&layout.bin, plan)
    }
    #[cfg(unix)]
    {
        crate::nfqws::start(layout, args, false)
    }
}

/// Stops everything the engine installed. Safe to call repeatedly.
pub fn stop_all() -> Vec<(String, Outcome)> {
    #[cfg(windows)]
    {
        use crate::sys::Removal;
        crate::windivert::remove_services()
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
