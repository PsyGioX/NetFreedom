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

//! The running session: what is active, since when, and the live health numbers.
//!
//! Starting no longer blocks the console on "press Enter". The session lives in the background
//! (engine + WARP + a watchdog thread, see `monitor`) and the main menu stays available, showing
//! this state. It is stopped from the menu or by closing the window (the console / signal handler
//! calls `cleanup`).

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::health::Trace;
use crate::probe::Via;
use crate::paths::Layout;
use crate::run::Plan;
use crate::stats::Window;
use crate::web::WebResult;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Games through WARP (engine protects the handshake).
    Warp,
    /// Unblocking without WARP.
    Bypass,
}

#[derive(Clone)]
pub struct Active {
    pub mode: Mode,
    pub plan: Plan,
    pub layout: Layout,
    pub started: Instant,
    /// Host whose latency is watched.
    pub target: String,
}

pub struct Health {
    pub trace: Option<Trace>,
    pub trace_err: Option<String>,
    pub warp_connected: Option<bool>,
    pub engine_alive: bool,
    pub window: Window,
    /// How the latency is measured right now (ICMP, or TCP 443 when the host ignores ICMP).
    pub via: Option<Via>,
    pub web: Vec<WebResult>,
    pub web_at: Option<Instant>,
    pub events: VecDeque<(Instant, String)>,
    pub engine_restarts: u32,
    pub reconnects: u32,
    /// Seconds of the session during which the tunnel was verified `warp=on`.
    pub verified_secs: u64,
}

impl Health {
    const fn new() -> Self {
        Self {
            trace: None,
            trace_err: None,
            warp_connected: None,
            engine_alive: true,
            window: Window::new(60),
            via: None,
            web: Vec::new(),
            web_at: None,
            events: VecDeque::new(),
            engine_restarts: 0,
            reconnects: 0,
            verified_secs: 0,
        }
    }
}

static ACTIVE: Mutex<Option<Active>> = Mutex::new(None);
static HEALTH: Mutex<Health> = Mutex::new(Health::new());
static STOP: AtomicBool = AtomicBool::new(false);
static WARP_OWNED: AtomicBool = AtomicBool::new(false);
static MONITOR: Mutex<Option<JoinHandle<()>>> = Mutex::new(None);

fn lock<T>(m: &'static Mutex<T>) -> std::sync::MutexGuard<'static, T> {
    // a panicked monitor must never take the menu down with it
    m.lock().unwrap_or_else(|e| e.into_inner())
}

pub fn active() -> Option<Active> {
    lock(&ACTIVE).clone()
}

pub fn target() -> Option<String> {
    lock(&ACTIVE).as_ref().map(|a| a.target.clone())
}

/// Changes the watched host of the running session (the monitor picks it up within a second).
pub fn set_target(t: &str) {
    if let Some(a) = lock(&ACTIVE).as_mut() {
        a.target = t.to_owned();
    }
    lock(&HEALTH).window.clear();
}

pub fn is_active() -> bool {
    lock(&ACTIVE).is_some()
}

pub fn with_health<R>(f: impl FnOnce(&mut Health) -> R) -> R {
    f(&mut lock(&HEALTH))
}

pub fn stopping() -> bool {
    STOP.load(Ordering::SeqCst)
}

/// WARP was connected by us in this process, so cleanup must disconnect it.
pub fn set_warp_owned(on: bool) {
    WARP_OWNED.store(on, Ordering::SeqCst);
}

pub fn event(msg: impl Into<String>) {
    let mut h = lock(&HEALTH);
    if h.events.len() >= 6 {
        h.events.pop_front();
    }
    h.events.push_back((Instant::now(), msg.into()));
}

/// Registers the session and starts the watchdog.
pub fn begin(a: Active) {
    *lock(&HEALTH) = Health::new();
    STOP.store(false, Ordering::SeqCst);
    *lock(&ACTIVE) = Some(a);
    event(crate::ui::tr("Сессия запущена", "Session started").to_owned());
    let h = std::thread::Builder::new().name("monitor".into()).spawn(crate::monitor::run).ok();
    *lock(&MONITOR) = h;
}

/// Stops the watchdog and forgets the session. Does not touch the engine / WARP.
pub fn end() -> Option<Active> {
    STOP.store(true, Ordering::SeqCst);
    let handle = lock(&MONITOR).take();
    if let Some(h) = handle {
        // the monitor sleeps in 100 ms steps; a probe in flight is bounded by its own timeout
        let t0 = Instant::now();
        while !h.is_finished() && t0.elapsed() < Duration::from_secs(12) {
            std::thread::sleep(Duration::from_millis(50));
        }
        if h.is_finished() {
            let _ = h.join();
        }
    }
    lock(&ACTIVE).take()
}

pub fn warp_owned() -> bool {
    WARP_OWNED.load(Ordering::SeqCst)
}

/// What the console / signal handler runs on Ctrl+C, closing the window, logoff, shutdown:
/// undo everything we did. Idempotent and quick; never joins threads.
pub fn cleanup() {
    STOP.store(true, Ordering::SeqCst);
    if WARP_OWNED.swap(false, Ordering::SeqCst) {
        if let Some(w) = crate::warp::Warp::locate() {
            w.disconnect();
            w.close_app();
        }
    }
    crate::backend::native_stop();
    crate::backend::stop_all();
    crate::dns::cleanup();
}
