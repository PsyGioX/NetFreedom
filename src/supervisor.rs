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


//! Supervisor of a running session. It only looks at LOCAL state and sends no probes of its own:
//!
//!   * every 5 s  - is the packet engine alive (restart it, with a back-off, if not); is WARP still
//!                  connected (reconnect, with a back-off, if not);
//!   * every 15 s - encrypted DNS: is the resolver port reachable (the DNS module decides whether
//!                  to switch provider).
//!
//! There is deliberately no latency sampler, no Cloudflare trace and no periodic download test:
//! a client that pings fixed hosts every second and fetches fixed pages every few minutes has a
//! recognisable traffic signature, and the project is open source, so that signature is public.
//! Measurements happen only when the user asks for them (`check`, `doctor`, `tune`, menu item 3).

use std::time::{Duration, Instant};

use crate::backend;
use crate::run::{self, StartArgs};
use crate::session::{self, Active, Mode};
use crate::ui::tr;
use crate::warp::{self, Warp};

const MAX_ENGINE_RESTARTS: u32 = 5;

fn engine_alive() -> bool {
    backend::engine_running() || backend::native_active()
}

/// Seconds to wait before the next reconnect attempt: 15, 30, 45, 60, 60, ...
pub fn backoff_secs(attempts: u32) -> u64 {
    15 * u64::from(attempts.clamp(1, 4))
}

/// Sleeps out the rest of a one-second tick (in 100 ms steps, so that a stop is noticed quickly).
fn finish_tick(t0: Instant) {
    while t0.elapsed() < Duration::from_secs(1) && !session::stopping() {
        std::thread::sleep(Duration::from_millis(100));
    }
}

pub fn run() {
    let Some(a) = session::active() else { return };
    supervise(&a);
}

fn supervise(a: &Active) {
    let warp = if a.mode == Mode::Warp { Warp::locate() } else { None };
    let mut tick: u64 = 0;
    let mut next_engine_try = Instant::now();
    let mut next_reconnect = Instant::now();
    let mut warp_up: Option<bool> = None;
    let mut engine_up = true;

    while !session::stopping() {
        let t0 = Instant::now();
        tick += 1;

        if tick % 5 == 0 && !session::stopping() {
            // ---- engine
            let alive = engine_alive();
            session::with_health(|h| h.engine_alive = alive);
            if !alive {
                if engine_up {
                    session::event(tr("Движок остановился, перезапускаю…", "The packet engine stopped, restarting…").to_owned());
                }
                engine_up = false;
                let tried = session::with_health(|h| h.engine_restarts);
                if Instant::now() >= next_engine_try && tried < MAX_ENGINE_RESTARTS && !session::stopping() {
                    next_engine_try = Instant::now() + Duration::from_secs(10);
                    session::with_health(|h| h.engine_restarts += 1);
                    match run::launch(&a.layout, &a.plan, &StartArgs::default(), true) {
                        Ok(()) => {
                            engine_up = true;
                            session::event(tr("Движок перезапущен", "Packet engine restarted").to_owned());
                        }
                        Err(e) => session::event(format!("{}: {}", tr("Не удалось перезапустить движок", "Engine restart failed"), e.lines().next().unwrap_or(""))),
                    }
                } else if tried >= MAX_ENGINE_RESTARTS && tried == MAX_ENGINE_RESTARTS {
                    session::with_health(|h| h.engine_restarts += 1);
                    session::event(tr("Движок не запускается: остановите режим и запустите заново", "The engine keeps failing: stop and start again").to_owned());
                }
            } else {
                engine_up = true;
            }

            // ---- WARP daemon (local status query of warp-cli, no network traffic of our own)
            if let Some(w) = &warp {
                let st = w.status_text();
                let up = warp::status_is_connected(&st);
                session::with_health(|h| h.warp_connected = Some(up));
                if warp_up != Some(up) {
                    if warp_up.is_some() {
                        session::event(if up { tr("WARP снова подключён", "WARP is connected again") } else { tr("WARP отключился", "WARP disconnected") }.to_owned());
                    }
                    warp_up = Some(up);
                }
                if !up && warp::status_is_disconnected(&st) && Instant::now() >= next_reconnect && !session::stopping() {
                    let n = session::with_health(|h| {
                        h.reconnects += 1;
                        h.reconnects
                    });
                    next_reconnect = Instant::now() + Duration::from_secs(backoff_secs(n));
                    w.connect();
                    session::event(format!("{} #{n}", tr("Переподключаю WARP", "Reconnecting WARP")));
                }
            }
        }

        // ---- encrypted DNS: is the resolver reachable? (switches provider only in bypass mode: with
        // WARP up, names are resolved inside the tunnel, so a failing check says nothing about it)
        if tick % 15 == 7 && !session::stopping() {
            if let Some(ev) = crate::dns::health_step(&a.layout, a.mode == Mode::Bypass) {
                session::event(ev);
            }
        }

        finish_tick(t0);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn reconnect_backoff_grows_and_caps() {
        assert_eq!(super::backoff_secs(0), 15);
        assert_eq!(super::backoff_secs(1), 15);
        assert_eq!(super::backoff_secs(3), 45);
        assert_eq!(super::backoff_secs(50), 60);
    }
}
