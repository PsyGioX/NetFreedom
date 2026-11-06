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

//! Cloudflare WARP control through the official `warp-cli` (Windows and Linux).

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub struct Warp {
    cli: PathBuf,
    #[cfg(windows)]
    app: PathBuf,
}

pub fn status_is_connected(text: &str) -> bool {
    text.contains("Status update: Connected")
}

pub fn status_is_disconnected(text: &str) -> bool {
    text.contains("Status update: Disconnected") || text.contains("Disconnected")
}

/// The reason line of a non-connected status (`Reason: ...`), for readable failure messages.
pub fn status_reason(text: &str) -> String {
    text.lines().map(str::trim).find(|l| l.to_ascii_lowercase().starts_with("reason")).unwrap_or("").to_owned()
}

impl Warp {
    #[cfg(windows)]
    pub fn locate() -> Option<Self> {
        let pf = std::env::var_os("ProgramFiles").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("C:\\Program Files"));
        let dir = pf.join("Cloudflare").join("Cloudflare WARP");
        let cli = dir.join("warp-cli.exe");
        cli.is_file().then(|| Self { app: dir.join("Cloudflare WARP.exe"), cli })
    }

    #[cfg(unix)]
    pub fn locate() -> Option<Self> {
        crate::util::find_in(&crate::util::SYSTEM_DIRS, "warp-cli").map(|cli| Self { cli })
    }

    /// Runs `warp-cli <args>` without a console window. Returns (success, combined output).
    pub fn run(&self, args: &[&str]) -> (bool, String) {
        let mut cmd = Command::new(&self.cli);
        cmd.args(args).stdin(Stdio::null());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
        }
        match cmd.output() {
            Ok(o) => {
                let mut s = String::from_utf8_lossy(&o.stdout).into_owned();
                s.push_str(&String::from_utf8_lossy(&o.stderr));
                (o.status.success(), s.trim().to_owned())
            }
            Err(e) => (false, e.to_string()),
        }
    }

    /// Linux: make sure the `warp-svc` daemon runs and the client is registered.
    /// Windows: nothing to do (the installer sets everything up). Returns a note for the user.
    pub fn prepare(&self) -> Result<Option<String>, String> {
        #[cfg(windows)]
        {
            Ok(None)
        }
        #[cfg(unix)]
        {
            let mut note = None;
            // without the daemon warp-cli prints "Unable to connect to CloudflareWARP daemon"
            let alive = |s: &Self| !s.run(&["status"]).1.contains("Unable to connect");
            if !alive(self) {
                if crate::util::system_tool("systemctl").is_absolute() {
                    let _ = Command::new(crate::util::system_tool("systemctl")).args(["start", "warp-svc"]).status();
                }
                let t0 = Instant::now();
                while !alive(self) {
                    if t0.elapsed() > Duration::from_secs(10) {
                        return Err("the warp-svc daemon does not answer: try `sudo systemctl enable --now warp-svc`".into());
                    }
                    std::thread::sleep(Duration::from_millis(300));
                }
            }
            let (ok, reg) = self.run(&["registration", "show"]);
            if !ok || reg.contains("Missing") {
                let (ok2, out) = self.run(&["--accept-tos", "registration", "new"]);
                if !ok2 {
                    return Err(format!("warp-cli registration new failed: {out}"));
                }
                note = Some("registered a new free WARP identity".to_owned());
            }
            Ok(note)
        }
    }

    pub fn set_masque(&self) -> (bool, String) {
        self.run(&["tunnel", "protocol", "set", "MASQUE"])
    }

    /// Opens the WARP tray application (Windows only; the service works without it).
    pub fn launch_app(&self) {
        #[cfg(windows)]
        if self.app.is_file() && !crate::sys::is_running("Cloudflare WARP.exe") {
            let _ = Command::new(&self.app).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn();
        }
    }

    pub fn connect(&self) -> (bool, String) {
        self.run(&["connect"])
    }

    pub fn disconnect(&self) -> (bool, String) {
        self.run(&["disconnect"])
    }

    /// Polls `warp-cli status` (300 ms steps) until connected or `timeout`.
    /// Returns (connected, last status output).
    pub fn wait_connected(&self, timeout: Duration) -> (bool, String) {
        let t0 = Instant::now();
        loop {
            let text = self.run(&["status"]).1;
            if status_is_connected(&text) {
                return (true, text);
            }
            if t0.elapsed() >= timeout {
                return (false, text);
            }
            std::thread::sleep(Duration::from_millis(300));
        }
    }

    /// Current `warp-cli status` text.
    pub fn status_text(&self) -> String {
        self.run(&["status"]).1
    }

    /// `warp-cli` says "Connected". That is NOT proof that traffic flows (see `health`).
    pub fn is_connected(&self) -> bool {
        status_is_connected(&self.status_text())
    }

    /// Polls until the daemon reports it is really disconnected (not just "asked to").
    /// Reconnecting while the previous session is still winding down is what made successive
    /// attempts slower and flakier.
    pub fn wait_disconnected(&self, timeout: Duration) -> bool {
        let t0 = Instant::now();
        loop {
            let text = self.status_text();
            if status_is_disconnected(&text) {
                return true;
            }
            if t0.elapsed() >= timeout {
                return false;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }

    pub fn tunnel_stats(&self) -> String {
        self.run(&["tunnel", "stats"]).1
    }

    /// Closes the tray application (Windows only).
    pub fn close_app(&self) {
        #[cfg(windows)]
        crate::sys::kill_by_name("Cloudflare WARP.exe");
    }
}

#[cfg(test)]
mod status_tests {
    use super::*;

    #[test]
    fn status_parsing() {
        assert!(status_is_connected("Status update: Connected\nNetwork: healthy"));
        assert!(!status_is_connected("Status update: Disconnected. Reason: Manual Disconnection"));
        assert!(status_is_disconnected("Status update: Disconnected. Reason: Manual Disconnection"));
        assert!(!status_is_disconnected("Status update: Connecting"));
        assert_eq!(status_reason("Status update: Disconnected\nReason: Registration Missing"), "Reason: Registration Missing");
    }
}
