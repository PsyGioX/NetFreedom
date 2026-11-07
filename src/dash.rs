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

//! The status panel shown at the top of the main menu and in the live monitor.

use std::time::Instant;

use crate::backend;
use crate::session::{self, Mode};
use crate::ui::{self, clip, dot, kv, paint, tr, DIM, GREEN, RED, YELLOW};
use crate::util::{fmt_dur, fmt_ms};

/// `35 s` / `4 min` / `2 h` ago.
pub fn ago(secs: u64) -> String {
    if secs < 60 {
        format!("{secs} {}", tr("с", "s"))
    } else if secs < 3600 {
        format!("{} {}", secs / 60, tr("мин", "min"))
    } else {
        format!("{} {}", secs / 3600, tr("ч", "h"))
    }
}

/// Colour class of a median latency for games.
pub fn latency_color(ms: f64) -> &'static str {
    if ms <= 60.0 {
        GREEN
    } else if ms <= 120.0 {
        YELLOW
    } else {
        RED
    }
}

fn mode_name(m: Mode) -> &'static str {
    match m {
        Mode::Warp => tr("Игры через WARP", "Games via WARP"),
        Mode::Bypass => tr("Обход блокировок", "Unblocking"),
    }
}

pub fn lines() -> Vec<String> {
    let Some(a) = session::active() else {
        let mut v = vec![format!("{} {}", dot(DIM), paint(DIM, tr("ОСТАНОВЛЕНО — выберите режим ниже", "STOPPED: pick a mode below")))];
        if backend::engine_running() {
            v.push(format!("{} {}", dot(YELLOW), tr("Движок запущен другим окном или после сбоя — пункт «Остановить всё» (S)", "An engine is running (other window or a crash): use “Stop everything” (S)")));
        }
        return v;
    };
    let h = session::with_health(|h| {
        (
            h.trace.clone(),
            h.trace_err.clone(),
            h.warp_connected,
            h.engine_alive,
            h.window.summary(),
            h.window.loss_pct(),
            h.window.len(),
            h.via,
            h.web.clone(),
            h.web_at,
            h.events.iter().rev().take(3).map(|(t, m)| (t.elapsed().as_secs(), m.clone())).collect::<Vec<_>>(),
            h.engine_restarts,
            h.reconnects,
        )
    });
    let (trace, trace_err, warp_up, engine_alive, win, loss, n, via, web, web_at, events, restarts, reconnects) = h;
    let secs = a.started.elapsed().as_secs();
    let mut v = vec![format!(
        "{} {}  {} · {} · {}",
        dot(GREEN),
        paint(GREEN, tr("АКТИВНО", "ACTIVE")),
        mode_name(a.mode),
        a.plan.profile.name,
        fmt_dur(secs)
    )];

    match a.mode {
        Mode::Warp => {
            let t = match (&trace, &trace_err) {
                (Some(t), _) if t.warp.through_tunnel() => format!("{} warp=on · {} {} · IP {}", dot(GREEN), tr("дата-центр", "data centre"), clip(&t.colo, 6), clip(&t.ip, 20)),
                (Some(_), _) => format!("{} {}", dot(RED), paint(RED, tr("трафик идёт МИМО туннеля (warp=off)", "traffic bypasses the tunnel (warp=off)"))),
                (None, Some(e)) => format!("{} {}", dot(YELLOW), clip(e, 52)),
                _ => format!("{} {}", dot(DIM), tr("проверяется…", "checking...")),
            };
            v.push(kv(tr("Туннель", "Tunnel"), &t));
        }
        Mode::Bypass => {
            let s = if web.is_empty() {
                format!("{} {}", dot(DIM), tr("первая проверка через несколько секунд…", "first check in a few seconds..."))
            } else {
                let ok = web.iter().filter(|w| w.ok).count();
                let c = if ok == web.len() { GREEN } else if ok * 2 >= web.len() { YELLOW } else { RED };
                let when = web_at.map(|t: Instant| ago(t.elapsed().as_secs())).unwrap_or_default();
                format!("{} {ok}/{} {} · {when} {}", dot(c), web.len(), tr("открываются", "open"), tr("назад", "ago"))
            };
            v.push(kv(tr("Сайты", "Sites"), &s));
            // name the sites that do not open: "4/9 open" alone does not say what to fix
            let failing: Vec<&str> = web.iter().filter(|w| !w.ok).map(|w| w.name.as_str()).collect();
            if !failing.is_empty() {
                v.push(kv(tr("Не открыты", "Closed"), &clip(&failing.join(", "), 52)));
                if web.iter().any(crate::web::connect_blocked) {
                    v.push(kv("", &paint(DIM, &clip(tr("часть: блокировка по IP/DNS, стратегией не лечится", "some: IP/DNS block, a strategy cannot fix it"), 52))));
                }
            }
        }
    }

    match &win {
        Some(s) => {
            let c = latency_color(s.median);
            v.push(kv(tr("Задержка", "Latency"), &format!("{} {}", paint(c, &format!("{:>6} ms", fmt_ms(s.median))), ui::latency_bar(s.median, 20.0, 150.0))));
            let lc = match crate::stats::level(s) {
                crate::stats::Level::Bad => RED,
                crate::stats::Level::Fair => YELLOW,
                crate::stats::Level::Good => GREEN,
            };
            v.push(kv(
                tr("Качество", "Quality"),
                &format!("{} {} {} ms · {} {}% · {} {} {}", dot(lc), tr("джиттер", "jitter"), fmt_ms(s.jitter), tr("потери", "loss"), loss, tr("окно", "window"), n, tr("с", "s")),
            ));
        }
        None if n > 0 => v.push(kv(tr("Задержка", "Latency"), &format!("{} {}", dot(RED), paint(RED, tr("нет ответов от сервера", "no replies from the host"))))),
        None => v.push(kv(tr("Задержка", "Latency"), &format!("{} {}", dot(DIM), tr("измеряется…", "measuring...")))),
    }
    let host = match via {
        Some(m) => format!("{} · {}", clip(&a.target, 40), m.label()),
        None => clip(&a.target, 48),
    };
    v.push(kv(tr("Сервер", "Host"), &host));

    let eng = if engine_alive { format!("{} {}", dot(GREEN), tr("работает", "running")) } else { format!("{} {}", dot(RED), tr("остановлен", "stopped")) };
    let mut row = format!("{eng}  ({} {restarts})", tr("перезапусков", "restarts"));
    if let Some(up) = warp_up {
        row.push_str(&format!("   WARP {} ({reconnects})", if up { dot(GREEN) } else { dot(RED) }));
    }
    v.push(kv(tr("Движок", "Engine"), &row));

    for (age, msg) in events {
        v.push(kv(tr("Событие", "Event"), &format!("{} · {}", paint(DIM, &format!("{:>6}", ago(age))), clip(&msg, 46))));
    }
    v
}

pub fn print() {
    let title = format!("NetFreedom {}", env!("CARGO_PKG_VERSION"));
    ui::panel(&title, &lines());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn age_formatting_and_colours() {
        crate::ui::set_ru(false);
        assert_eq!(ago(5), "5 s");
        assert_eq!(ago(130), "2 min");
        assert_eq!(ago(7300), "2 h");
        assert_eq!(latency_color(30.0), GREEN);
        assert_eq!(latency_color(100.0), YELLOW);
        assert_eq!(latency_color(300.0), RED);
        crate::ui::set_ru(true);
    }

    #[test]
    fn idle_panel_fits_the_frame() {
        for l in lines() {
            assert!(crate::ui::visible_len(&l) <= crate::ui::PANEL_W - 4, "{l}");
        }
    }
}
