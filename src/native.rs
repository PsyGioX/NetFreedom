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

//! WinDivert binding for the native engine (EXPERIMENTAL, opt-in via `--native`).
//!
//! `WinDivert.dll` is loaded at run time from `bin\` (the DLL looks for `WinDivert64.sys` next to
//! itself), so nothing is linked statically and the same files shipped for winws are reused.

use std::ffi::{c_void, CString};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows_sys::Win32::System::Threading::{GetCurrentThread, SetThreadPriority, THREAD_PRIORITY_HIGHEST};

use crate::engine::{Addr, Engine, PacketIo, Plan, Stats};
use crate::sys::wide;

type FnOpen = unsafe extern "C" fn(*const u8, i32, i16, u64) -> HANDLE;
type FnRecv = unsafe extern "C" fn(HANDLE, *mut c_void, u32, *mut u32, *mut Addr) -> BOOL;
type FnSend = unsafe extern "C" fn(HANDLE, *const c_void, u32, *mut u32, *const Addr) -> BOOL;
type FnClose = unsafe extern "C" fn(HANDLE) -> BOOL;
type FnShutdown = unsafe extern "C" fn(HANDLE, i32) -> BOOL;
type FnCalc = unsafe extern "C" fn(*mut c_void, u32, *mut Addr, u64) -> BOOL;

struct Api {
    recv: FnRecv,
    send: FnSend,
    close: FnClose,
    shutdown: Option<FnShutdown>,
    calc: Option<FnCalc>,
}

struct Shared {
    api: Api,
    handle: HANDLE,
}
// The WinDivert handle may be used from several threads (documented as thread-safe).
unsafe impl Send for Shared {}
unsafe impl Sync for Shared {}

struct WdIo(Arc<Shared>);

impl PacketIo for WdIo {
    fn recv(&mut self, buf: &mut [u8]) -> Option<(usize, Addr)> {
        let s = &*self.0;
        let mut failures = 0;
        loop {
            let mut n = 0u32;
            let mut a = Addr::default();
            let ok = unsafe { (s.api.recv)(s.handle, buf.as_mut_ptr() as *mut c_void, buf.len() as u32, &mut n, &mut a) };
            if ok != 0 {
                return Some((n as usize, a));
            }
            match unsafe { GetLastError() } {
                // handle shut down / closed: leave the loop
                ERROR_NO_DATA | ERROR_INVALID_HANDLE | ERROR_OPERATION_ABORTED => return None,
                _ => {
                    failures += 1;
                    if failures > 1000 {
                        return None;
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
        }
    }

    fn send(&mut self, pkt: &[u8], addr: &Addr) {
        let s = &*self.0;
        unsafe { (s.api.send)(s.handle, pkt.as_ptr() as *const c_void, pkt.len() as u32, std::ptr::null_mut(), addr) };
    }

    fn finalize(&mut self, pkt: &mut [u8], addr: &mut Addr) {
        if let Some(calc) = self.0.api.calc {
            unsafe { calc(pkt.as_mut_ptr() as *mut c_void, pkt.len() as u32, addr, 0) };
        }
    }
}

pub struct Native {
    shared: Arc<Shared>,
    thread: Option<JoinHandle<Stats>>,
}

static ACTIVE: Mutex<Option<Native>> = Mutex::new(None);

fn explain(code: u32) -> &'static str {
    match code {
        2 => "WinDivert64.sys not found next to WinDivert.dll",
        5 => "access denied: run as administrator",
        87 => "the WinDivert filter was rejected",
        577 => "the driver signature was rejected by Windows",
        1275 => "the driver was blocked (antivirus, Memory Integrity / HVCI or Secure Boot policy)",
        1060 => "the WinDivert driver service is missing",
        _ => "see the Windows system error code",
    }
}

/// Opens the filter and starts the engine thread. `bin_dir` ends with a backslash.
pub fn start(bin_dir: &str, plan: Plan) -> Result<(), String> {
    let mut slot = ACTIVE.lock().map_err(|_| "poisoned lock")?;
    if slot.is_some() {
        return Err("native engine is already running".into());
    }
    let dll = wide(format!("{bin_dir}WinDivert.dll"));
    let lib = unsafe { LoadLibraryW(dll.as_ptr()) };
    if lib.is_null() {
        return Err(format!("cannot load {bin_dir}WinDivert.dll (error {})", unsafe { GetLastError() }));
    }
    macro_rules! sym {
        ($name:literal, $t:ty) => {
            unsafe { GetProcAddress(lib, concat!($name, "\0").as_ptr()).map(|p| std::mem::transmute::<_, $t>(p)) }
        };
    }
    let open: FnOpen = sym!("WinDivertOpen", FnOpen).ok_or("WinDivertOpen is missing in WinDivert.dll")?;
    let api = Api {
        recv: sym!("WinDivertRecv", FnRecv).ok_or("WinDivertRecv is missing")?,
        send: sym!("WinDivertSend", FnSend).ok_or("WinDivertSend is missing")?,
        close: sym!("WinDivertClose", FnClose).ok_or("WinDivertClose is missing")?,
        shutdown: sym!("WinDivertShutdown", FnShutdown),
        calc: sym!("WinDivertHelperCalcChecksums", FnCalc),
    };
    let filter = CString::new(plan.filter.as_str()).map_err(|_| "filter contains NUL")?;
    // layer 0 = WINDIVERT_LAYER_NETWORK, priority 0, flags 0
    let handle = unsafe { open(filter.as_ptr() as *const u8, 0, 0, 0) };
    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        let e = unsafe { GetLastError() };
        return Err(format!("WinDivertOpen failed (error {e}: {})", explain(e)));
    }

    let shared = Arc::new(Shared { api, handle });
    let io_shared = shared.clone();
    let seed = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.subsec_nanos()).unwrap_or(0x9E37_79B9);
    let thread = std::thread::Builder::new()
        .name("native-engine".into())
        .spawn(move || {
            unsafe { SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST) };
            let mut io = WdIo(io_shared);
            let mut engine = Engine::new(plan.rules, seed);
            let t0 = Instant::now();
            engine.run(&mut io, &|| t0.elapsed().as_millis() as u64);
            engine.stats
        })
        .map_err(|e| format!("cannot start the engine thread: {e}"))?;
    *slot = Some(Native { shared, thread: Some(thread) });
    Ok(())
}

pub fn is_active() -> bool {
    ACTIVE.lock().map(|s| s.is_some()).unwrap_or(false)
}

/// Stops the engine (if running) and returns its counters.
pub fn stop() -> Option<Stats> {
    let mut n = ACTIVE.lock().ok()?.take()?;
    let s = &*n.shared;
    unsafe {
        match s.api.shutdown {
            Some(sd) => {
                sd(s.handle, 3); // WINDIVERT_SHUTDOWN_BOTH: pending recv returns, no new packets
            }
            None => {
                (s.api.close)(s.handle);
            }
        }
    }
    let stats = n.thread.take().and_then(|t| t.join().ok());
    if s.api.shutdown.is_some() {
        unsafe { (s.api.close)(s.handle) };
    }
    stats
}
