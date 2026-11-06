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

//! Linux engine: nfqws (zapret) fed by an nftables NFQUEUE ruleset.

use std::fs::{self, File};
use std::io::Write;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::backend::Outcome;
use crate::nftrules::{self, FWMARK, QNUM, TABLE};
use crate::paths::Layout;
use crate::sys;

static CHILD: Mutex<Option<Child>> = Mutex::new(None);
const ACCT: &str = "/proc/sys/net/netfilter/nf_conntrack_acct";
const STATE: &str = "/run/netfreedom.state";
const LOG_DIR: &str = "/run/netfreedom";

/// Engine output. It lives in a root-owned 0700 directory under /run: the former
/// `/tmp/netfreedom-nfqws.log` could be pre-created by any local user as a symlink, and the
/// root-run `File::create` would then overwrite whatever file it pointed to.
pub fn log_path() -> std::path::PathBuf {
    std::path::Path::new(LOG_DIR).join("nfqws.log")
}

fn open_log() -> Result<File, String> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
    let dir = std::path::Path::new(LOG_DIR);
    let _ = fs::DirBuilder::new().mode(0o700).create(dir);
    let md = fs::symlink_metadata(dir).map_err(|e| format!("cannot use {LOG_DIR}: {e}"))?;
    if !md.is_dir() || md.uid() != 0 || md.mode() & 0o022 != 0 {
        return Err(format!("{LOG_DIR} is not a private directory owned by root: refusing to write there"));
    }
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(log_path())
        .map_err(|e| format!("cannot create {}: {e}", log_path().display()))
}

fn nft_bin() -> Result<std::path::PathBuf, String> {
    crate::util::find_in(&crate::util::SYSTEM_DIRS, "nft")
        .ok_or_else(|| "nft not found: install the nftables package".to_string())
}

fn run_nft(script: &str) -> Result<(), String> {
    let mut c = Command::new(nft_bin()?)
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot run nft: {e}"))?;
    c.stdin.take().expect("piped").write_all(script.as_bytes()).map_err(|e| e.to_string())?;
    let out = c.wait_with_output().map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!("nft rejected the ruleset: {}", String::from_utf8_lossy(&out.stderr).trim()))
    }
}

/// Enables conntrack byte/packet accounting (needed by `ct original packets`). Remembers the old
/// value in /run so that `stop` can restore it. Returns whether the limit can be used.
fn enable_ct_accounting() -> bool {
    match fs::read_to_string(ACCT) {
        Ok(v) if v.trim() == "1" => true,
        Ok(v) => {
            if fs::write(ACCT, "1").is_ok() {
                let _ = fs::write(STATE, format!("acct_prev={}\n", v.trim()));
                true
            } else {
                false
            }
        }
        Err(_) => false,
    }
}

fn restore_ct_accounting() -> bool {
    let Ok(s) = fs::read_to_string(STATE) else { return false };
    let prev = s.lines().find_map(|l| l.strip_prefix("acct_prev=")).unwrap_or("0").to_owned();
    let _ = fs::write(ACCT, prev);
    let _ = fs::remove_file(STATE);
    true
}

fn queue_is_bound() -> bool {
    fs::read_to_string("/proc/net/netfilter/nfnetlink_queue")
        .is_ok_and(|t| t.lines().any(|l| l.split_whitespace().next() == Some(&QNUM.to_string())))
}

fn log_tail() -> String {
    let t = fs::read_to_string(log_path()).unwrap_or_default();
    let lines: Vec<&str> = t.lines().collect();
    lines[lines.len().saturating_sub(6)..].join("\n")
}

/// Starts nfqws, waits until it has bound the queue, then installs the nft rules.
pub fn start(layout: &Layout, args: &[String], include_lo: bool) -> Result<(), String> {
    // ZW_NFT_INCLUDE_LO=1 is a test hook: lets a network namespace without real NICs exercise the rules.
    let include_lo = include_lo || std::env::var_os("ZW_NFT_INCLUDE_LO").is_some();
    let exe = layout.nfqws_exe().ok_or("nfqws not found: put it into bin/ (or bin/linux-<arch>/) or install it into PATH")?;
    let (cap, nf_args) = nftrules::split_args(args)?;
    nft_bin()?;
    stop_all(); // never stack on top of a previous run

    let log = open_log()?;
    let log2 = log.try_clone().map_err(|e| e.to_string())?;
    let child = Command::new(&exe)
        .arg(format!("--qnum={QNUM}"))
        .arg(format!("--dpi-desync-fwmark={FWMARK}"))
        .args(&nf_args)
        .current_dir(&layout.bin)
        .stdin(Stdio::null())
        .stdout(log)
        .stderr(log2)
        .spawn()
        .map_err(|e| format!("cannot start {}: {e}", exe.display()))?;
    *CHILD.lock().map_err(|_| "poisoned lock")? = Some(child);

    let t0 = Instant::now();
    loop {
        {
            let mut g = CHILD.lock().map_err(|_| "poisoned lock")?;
            if let Some(c) = g.as_mut() {
                if let Ok(Some(st)) = c.try_wait() {
                    g.take();
                    return Err(format!("nfqws exited ({st}). {}", log_tail()));
                }
            }
        }
        if queue_is_bound() {
            break;
        }
        if t0.elapsed() > Duration::from_secs(3) {
            // some kernels do not expose the proc file: trust a process that stays alive
            std::thread::sleep(Duration::from_millis(200));
            break;
        }
        std::thread::sleep(Duration::from_millis(40));
    }

    let ct = (cap.tcp.is_some() || cap.udp.is_some()) && enable_ct_accounting();
    if let Err(e) = run_nft(&nftrules::ruleset(&cap, QNUM, ct, !include_lo)) {
        stop_all();
        return Err(e);
    }
    Ok(())
}

/// Removes the nft table, stops nfqws and restores the conntrack setting.
pub fn stop_all() -> Vec<(String, Outcome)> {
    let mut out = Vec::new();
    // 1. rules first, so traffic flows normally while the daemon goes away
    let had_table = nft_bin()
        .map(|nft| Command::new(nft).args(["delete", "table", "inet", TABLE]).stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok_and(|s| s.success()))
        .unwrap_or(false);
    out.push((format!("nft table {TABLE}"), if had_table { Outcome::Done } else { Outcome::Absent }));
    // a table left behind by the 2.x launcher (it was called zapret_warp) must not outlive an upgrade
    if let Ok(nft) = nft_bin() {
        let _ = Command::new(nft).args(["delete", "table", "inet", "zapret_warp"]).stdout(Stdio::null()).stderr(Stdio::null()).status();
    }
    // 2. our own child (reaps it), then any stray nfqws
    let mut stopped = false;
    if let Some(mut c) = CHILD.lock().ok().and_then(|mut g| g.take()) {
        let _ = c.kill();
        let _ = c.wait();
        stopped = true;
    }
    stopped |= sys::kill_by_name("nfqws") > 0;
    out.push(("nfqws".into(), if stopped { Outcome::Done } else { Outcome::Absent }));
    if restore_ct_accounting() {
        out.push(("conntrack accounting".into(), Outcome::Done));
    }
    out
}

pub fn dump_log() -> String {
    log_tail()
}

#[cfg(test)]
mod log_tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, symlink};

    #[test]
    fn log_is_private_and_never_follows_a_symlink() {
        if unsafe { libc::geteuid() } != 0 {
            return; // the log directory lives in /run and belongs to root
        }
        let f = open_log().expect("opens in a private root-owned directory");
        drop(f);
        assert_eq!(fs::metadata(log_path()).unwrap().mode() & 0o777, 0o600);
        // a planted symlink must be refused, not followed
        let victim = std::env::temp_dir().join(format!("nf-victim-{}", std::process::id()));
        fs::write(&victim, "precious").unwrap();
        let _ = fs::remove_file(log_path());
        symlink(&victim, log_path()).unwrap();
        assert!(open_log().is_err(), "O_NOFOLLOW must refuse the symlink");
        assert_eq!(fs::read_to_string(&victim).unwrap(), "precious");
        let _ = fs::remove_file(log_path());
        let _ = fs::remove_file(&victim);
    }
}
