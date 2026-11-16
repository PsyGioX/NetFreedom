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

//! The status panel shown at the top of the main menu: mode, uptime, DNS, engine / WARP state, events.

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
    let (warp_up, engine_alive, events, restarts, reconnects) = session::with_health(|h| {
        (
            h.warp_connected,
            h.engine_alive,
            h.events.iter().rev().take(3).map(|(t, m)| (t.elapsed().as_secs(), m.clone())).collect::<Vec<_>>(),
            h.engine_restarts,
            h.reconnects,
        )
    });
    let secs = a.started.elapsed().as_secs();
    let mut v = vec![format!(
        "{} {}  {} · {} · {}",
        dot(GREEN),
        paint(GREEN, tr("АКТИВНО", "ACTIVE")),
        mode_name(a.mode),
        a.plan.profile.name,
        fmt_dur(secs)
    )];

    if let Some((p, t, rtt, fails)) = crate::dns::summary() {
        let (c, state) = match (rtt, fails) {
            (_, f) if f >= 3 => (RED, tr("не отвечает", "unreachable").to_owned()),
            (Some(ms), 0) => (GREEN, format!("{} ms", fmt_ms(ms))),
            (None, 0) => (DIM, tr("проверяется…", "checking...").to_owned()),
            (_, _) => (YELLOW, tr("сбои проверки", "check failing").to_owned()),
        };
        v.push(kv("DNS", &format!("{} {} · {} · {}", dot(c), p.title, t.label(), state)));
    }

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
    fn age_formatting() {
        crate::ui::set_ru(false);
        assert_eq!(ago(5), "5 s");
        assert_eq!(ago(130), "2 min");
        assert_eq!(ago(7300), "2 h");
        crate::ui::set_ru(true);
    }

    #[test]
    fn idle_panel_fits_the_frame() {
        for l in lines() {
            assert!(crate::ui::visible_len(&l) <= crate::ui::PANEL_W - 4, "{l}");
        }
    }
}
