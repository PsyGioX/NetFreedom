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

//! Watchdog of a running session. Two threads, so that a slow check can never stall the latency
//! samples (before, one thread did everything: a `curl` trace waiting up to 6 s or a `warp-cli`
//! call left a hole in the "last minute" window right when something was going wrong):
//!
//!   * sampler (1 Hz)   - one latency sample to the watched host (feeds the live panel: median,
//!                        jitter, loss over the last minute). Falls back from ICMP to TCP 443 when
//!                        the host does not answer ICMP;
//!   * watchdog, every 5 s  - is the packet engine alive (restart it, with a back-off, if not); is
//!                        WARP still connected (reconnect, with a back-off, if not);
//!   * watchdog, every 20 s - Cloudflare trace: is the traffic REALLY going through the tunnel;
//!   * watchdog, every 5 min - (bypass only) a real download test of the unblocked sites.
//!
//! This is what the commercial game boosters do on the client side: keep measuring the path and
//! react when it degrades instead of trusting the state that was true at connect time.

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use crate::backend;
use crate::health;
use crate::probe::{self, MethodSwitch, Via};
use crate::run::{self, StartArgs};
use crate::session::{self, Active, Mode};
use crate::ui::tr;
use crate::warp::{self, Warp};
use crate::web;

const MAX_ENGINE_RESTARTS: u32 = 5;

/// Hosts the monitor falls back to when the DEFAULT target stays silent. Some Russian providers
/// drop or throttle ICMP and TCP to 1.1.1.1 (the panel then showed "no replies" for a working
/// connection). A target the player chose himself is never replaced.
pub const DEFAULT_TARGETS: [&str; 4] = ["1.1.1.1", "8.8.8.8", "9.9.9.9", "77.88.8.8"];

/// Consecutive lost samples (about 12-24 s) after which a default target is swapped.
const SILENT_SWITCH: u32 = 12;

/// The next fallback after `cur`, if `cur` is one of the default targets and not the last one.
pub fn next_default_target(cur: &str) -> Option<&'static str> {
    let i = DEFAULT_TARGETS.iter().position(|t| *t == cur)?;
    DEFAULT_TARGETS.get(i + 1).copied()
}

/// Bypass: first real download test this many seconds after the start, then every `WEB_EVERY`.
/// (It was 60 s and 300 s, so the panel said "not checked" for a minute and then went stale.)
const WEB_FIRST_TICK: u64 = 8;
const WEB_EVERY: u64 = 120;

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
    std::thread::scope(|s| {
        // Slow checks live on their own thread. If it cannot be spawned the samples still flow.
        let watchdog = std::thread::Builder::new().name("watchdog".into()).spawn_scoped(s, || watchdog(&a));
        sampler(&a);
        if let Ok(h) = watchdog {
            let _ = h.join();
        }
    });
}

/// Resolves the watched host and opens the ICMP socket for it.
fn setup(target: &str) -> (Option<Ipv4Addr>, Option<probe::Pinger>) {
    let ip = probe::resolve_v4(target);
    let pinger = ip.and_then(|ip| probe::Pinger::new(ip, 1000));
    session::with_health(|h| h.via = Some(Via::Icmp));
    (ip, pinger)
}

fn sampler(a: &Active) {
    let mut cur_target = a.target.clone();
    let (mut ip, mut pinger) = setup(&cur_target);
    let mut method = MethodSwitch::new();
    let mut silent: u32 = 0;

    while !session::stopping() {
        let t0 = Instant::now();

        // the player may point the monitor at another server while the session runs
        if let Some(t) = session::target().filter(|t| *t != cur_target) {
            (ip, pinger) = setup(&t);
            method = MethodSwitch::new();
            cur_target = t;
        }
        let (sample, switched) = match ip {
            Some(ip) => probe::live_sample(&mut method, || pinger.as_mut().and_then(|p| p.ping()), || probe::tcp_sample(ip, 1000)),
            None => (None, false),
        };
        if switched {
            // the ICMP probes that were counted as lost were not losses: the host just ignores ping
            session::with_health(|h| {
                h.window.clear();
                h.via = Some(Via::Tcp443);
            });
            session::event(tr("Узел не отвечает на ICMP, меряю по TCP 443", "The host ignores ICMP, measuring via TCP 443").to_owned());
        }
        session::with_health(|h| h.window.push(sample));

        // a silent DEFAULT target: try the next public host instead of drawing "no replies" forever
        silent = if sample.is_some() { 0 } else { silent + 1 };
        if silent >= SILENT_SWITCH {
            if let Some(next) = next_default_target(&cur_target) {
                session::event(format!("{} {cur_target}: {} {next}", tr("Нет ответа от", "No answer from"), tr("пробую", "trying")));
                session::set_target(next);
            }
            silent = 0;
        }

        finish_tick(t0);
    }
}

fn watchdog(a: &Active) {
    let warp = if a.mode == Mode::Warp { Warp::locate() } else { None };
    let mut tick: u64 = 0;
    let mut next_engine_try = Instant::now();
    let mut next_reconnect = Instant::now();
    let mut through: Option<bool> = None;
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

        // ---- encrypted DNS: is the resolver reachable? (switches provider only in bypass mode: with
        // WARP up, names are resolved inside the tunnel, so a failing check says nothing about it)
        if tick % 15 == 7 && !session::stopping() {
            if let Some(ev) = crate::dns::health_step(&a.layout, a.mode == Mode::Bypass) {
                session::event(ev);
            }
        }

        // ---- bypass: do the sites really open?
        if a.mode == Mode::Bypass && tick % WEB_EVERY == WEB_FIRST_TICK && !session::stopping() && web::curl_available() {
            let r = web::probe(Duration::from_secs(8));
            session::with_health(|h| {
                h.web = r;
                h.web_at = Some(Instant::now());
            });
        }

        finish_tick(t0);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_silent_default_target_falls_back_but_a_chosen_one_never_does() {
        assert_eq!(super::next_default_target("1.1.1.1"), Some("8.8.8.8"));
        assert_eq!(super::next_default_target("77.88.8.8"), None, "the last fallback stays");
        assert_eq!(super::next_default_target("203.0.113.7"), None, "the player's own server is never replaced");
    }

    #[test]
    fn reconnect_backoff_grows_and_caps() {
        assert_eq!(super::backoff_secs(0), 15);
        assert_eq!(super::backoff_secs(1), 15);
        assert_eq!(super::backoff_secs(3), 45);
        assert_eq!(super::backoff_secs(50), 60);
    }
}
