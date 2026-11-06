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

//! Watchdog of a running session. One thread, one tick per second:
//!
//!   * every tick   - one latency sample to the watched host (feeds the live panel: median, jitter, loss
//!                    over the last minute);
//!   * every 5 s    - is the packet engine alive (restart it, with a back-off, if not); is WARP still
//!                    connected (reconnect, with a back-off, if not);
//!   * every 20 s   - Cloudflare trace: is the traffic REALLY going through the tunnel;
//!   * every 5 min  - (bypass only) a real download test of the unblocked sites.
//!
//! This is what the commercial game boosters do on the client side: keep measuring the path and
//! react when it degrades instead of trusting the state that was true at connect time.

use std::time::{Duration, Instant};

use crate::backend;
use crate::health;
use crate::probe;
use crate::run::{self, StartArgs};
use crate::session::{self, Mode};
use crate::ui::tr;
use crate::warp::{self, Warp};
use crate::web;

const MAX_ENGINE_RESTARTS: u32 = 5;

fn engine_alive() -> bool {
    backend::engine_running() || backend::native_active()
}

/// Seconds to wait before the next reconnect attempt: 15, 30, 45, 60, 60, ...
pub fn backoff_secs(attempts: u32) -> u64 {
    15 * u64::from(attempts.clamp(1, 4))
}

pub fn run() {
    let Some(a) = session::active() else { return };
    let warp = if a.mode == Mode::Warp { Warp::locate() } else { None };
    let mut cur_target = a.target.clone();
    let mut ip = probe::resolve_v4(&cur_target);
    let mut pinger = ip.and_then(|ip| probe::Pinger::new(ip, 1000));
    let mut tick: u64 = 0;
    let mut next_engine_try = Instant::now();
    let mut next_reconnect = Instant::now();
    let mut through: Option<bool> = None;
    let mut warp_up: Option<bool> = None;
    let mut engine_up = true;

    while !session::stopping() {
        let t0 = Instant::now();
        tick += 1;

        // the player may point the monitor at another server while the session runs
        if let Some(t) = session::target().filter(|t| *t != cur_target) {
            ip = probe::resolve_v4(&t);
            pinger = ip.and_then(|ip| probe::Pinger::new(ip, 1000));
            cur_target = t;
        }
        let sample = match (&mut pinger, ip) {
            (Some(p), _) => p.ping(),
            (None, Some(ip)) => probe::tcp_sample(ip, 1000),
            _ => None,
        };
        session::with_health(|h| h.window.push(sample));

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
                    match run::launch(&a.layout, &a.plan, &StartArgs::default(), a.native, true) {
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

            // ---- WARP daemon
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

        // ---- is the traffic really inside the tunnel?
        if warp.is_some() && (tick == 3 || tick % 20 == 0) && !session::stopping() {
            match health::fetch_trace(6) {
                Ok(t) => {
                    let now = t.warp.through_tunnel();
                    if through != Some(now) {
                        if through.is_some() || !now {
                            session::event(if now {
                                tr("Трафик снова идёт через туннель", "Traffic is inside the tunnel again").to_owned()
                            } else {
                                tr("Трафик идёт МИМО туннеля (warp=off)", "Traffic bypasses the tunnel (warp=off)").to_owned()
                            });
                        }
                        through = Some(now);
                    }
                    session::with_health(|h| {
                        if now {
                            h.verified_secs += 20;
                        }
                        h.trace = Some(t);
                        h.trace_err = None;
                    });
                }
                Err(e) => {
                    session::with_health(|h| h.trace_err = Some(e));
                    if through == Some(true) {
                        through = None;
                    }
                }
            }
        }

        // ---- bypass: do the sites really open?
        if a.mode == Mode::Bypass && tick % 300 == 60 && !session::stopping() && web::curl_available() {
            let r = web::probe(Duration::from_secs(10));
            session::with_health(|h| {
                h.web = r;
                h.web_at = Some(Instant::now());
            });
        }

        while t0.elapsed() < Duration::from_secs(1) && !session::stopping() {
            std::thread::sleep(Duration::from_millis(100));
        }
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
