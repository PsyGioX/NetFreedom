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

//! A panic must never make the window just disappear.
//!
//! The 2.x release profile used `panic = "abort"` and had no hook: any panic (a failed `println!`
//! on a broken console, an unexpected reply from a helper program, ...) ended the process
//! instantly, the window closed, and the user saw nothing, not even that something went wrong.
//! Now: panics unwind, the hook records the message and appends it to `utils/crash.log`, `main`
//! turns it into a readable error plus a pause, and long jobs (`tune`) catch it per scenario and
//! carry on with the next one.

use std::fs::OpenOptions;
use std::io::Write;
use std::panic::{self, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::util::fmt_utc;

static LAST: Mutex<Option<String>> = Mutex::new(None);
static LOG: Mutex<Option<PathBuf>> = Mutex::new(None);

/// Installs the recording hook. `log` is where details are appended (created on demand).
pub fn install(log: PathBuf) {
    if let Ok(mut l) = LOG.lock() {
        *l = Some(log);
    }
    panic::set_hook(Box::new(|info| {
        let text = format!("{info}");
        if let Ok(mut last) = LAST.lock() {
            *last = Some(text.clone());
        }
        let path = LOG.lock().ok().and_then(|l| l.clone());
        if let Some(path) = path {
            if let Some(dir) = path.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path) {
                let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
                let _ = writeln!(f, "[{}] {} {}\n{text}\n", fmt_utc(now), env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
            }
        }
    }));
}

/// Message of the most recent panic, if any.
pub fn last() -> Option<String> {
    LAST.lock().ok().and_then(|l| l.clone())
}

/// Runs `f`; a panic becomes `Err(message)` instead of unwinding further.
pub fn guard<T>(f: impl FnOnce() -> T) -> Result<T, String> {
    panic::catch_unwind(AssertUnwindSafe(f)).map_err(|p| {
        last().or_else(|| p.downcast_ref::<&str>().map(|s| (*s).to_owned())).or_else(|| p.downcast_ref::<String>().cloned()).unwrap_or_else(|| "unknown panic".into())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_panic_becomes_an_error_and_the_next_call_still_works() {
        let r: Result<(), String> = guard(|| panic!("boom {}", 7));
        assert!(r.unwrap_err().contains("boom 7"));
        assert_eq!(guard(|| 41 + 1), Ok(42));
    }
}
