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

//! Console helpers: prompts and coloured status lines.

use std::io::{self, BufRead, Write};

const RESET: &str = "\x1b[0m";

use std::sync::atomic::{AtomicBool, Ordering};

/// Colours on? `true` until [`init_color`] decides otherwise (tests and library users get colours).
static COLOR: AtomicBool = AtomicBool::new(true);
/// 256-colour palette available (the accent colour of the theme); otherwise the 8 basic colours.
static RICH: AtomicBool = AtomicBool::new(false);
/// Rounded box corners (`╭╮╰╯`): terminals with a modern font; the legacy console font may lack them.
static ROUND: AtomicBool = AtomicBool::new(false);

/// Colour policy. Off when `NO_COLOR` is set (https://no-color.org), when `NETFREEDOM_COLOR=0`,
/// when `TERM=dumb`, or when stdout is not a terminal (a log file, a pipe: escape codes in a file
/// are noise). `NETFREEDOM_COLOR=1` forces colours on.
pub fn resolve_color(no_color: bool, force: Option<&str>, term: Option<&str>, is_tty: bool) -> bool {
    match force.map(str::trim) {
        Some("0") => return false,
        Some("1") => return true,
        _ => {}
    }
    !no_color && term != Some("dumb") && is_tty
}

pub fn init_color() {
    use std::io::IsTerminal;
    let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
    let on = resolve_color(env("NO_COLOR").is_some(), env("NETFREEDOM_COLOR").as_deref(), env("TERM").as_deref(), io::stdout().is_terminal());
    COLOR.store(on, Ordering::Relaxed);
    let term = env("TERM").unwrap_or_default();
    // Windows 10+ consoles with virtual-terminal mode understand 256 colours; so do the usual Unix terminals
    RICH.store(cfg!(windows) || term.contains("256") || env("COLORTERM").is_some() || env("TERM_PROGRAM").is_some(), Ordering::Relaxed);
    ROUND.store(!cfg!(windows) || env("WT_SESSION").is_some() || env("TERM_PROGRAM").is_some(), Ordering::Relaxed);
}

pub fn color_on() -> bool {
    COLOR.load(Ordering::Relaxed)
}

pub fn color(code: &str, msg: &str) {
    println!("{}", paint(code, msg));
}
pub fn info(msg: &str) {
    println!("{msg}");
}
pub fn cyan(msg: &str) {
    color("36", msg);
}
pub fn ok(msg: &str) {
    println!("  {} {msg}", paint(GREEN, "[OK]"));
}
pub fn skip(msg: &str) {
    println!("  [--] {msg}");
}
pub fn warn(msg: &str) {
    println!("  {} {msg}", paint(YELLOW, "[WARN]"));
}
pub fn error(msg: &str) {
    eprintln!("{} {msg}", paint(RED, "ERROR:"));
}

fn flush() {
    let _ = io::stdout().flush();
}

/// Reads one trimmed line; `None` on EOF (closed stdin).
pub fn read_line_opt() -> Option<String> {
    flush();
    let mut s = String::new();
    match io::stdin().lock().read_line(&mut s) {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(s.trim().to_owned()),
    }
}

/// Reads one trimmed line. Returns an empty string on EOF.
pub fn read_line() -> String {
    read_line_opt().unwrap_or_default()
}

/// `prompt [Enter = default]: ` - returns `default` when the user just presses Enter.
pub fn ask(prompt: &str, default: &str) -> String {
    if default.is_empty() {
        print!("{prompt}: ");
    } else {
        print!("{prompt} [Enter = {default}]: ");
    }
    let s = read_line();
    if s.is_empty() { default.to_owned() } else { s }
}

/// Asks until the answer starts with one of `keys` (case-insensitive); returns it upper-cased.
/// On EOF the last key is taken (by convention the safest one: Q / N).
pub fn choice(prompt: &str, keys: &str) -> char {
    loop {
        print!("{prompt}");
        match read_line_opt() {
            None => return keys.chars().last().unwrap_or(' '),
            Some(s) => {
                if let Some(c) = s.chars().next().map(|c| fold_key(c).to_ascii_uppercase()) {
                    if keys.contains(c) {
                        return c;
                    }
                }
            }
        }
    }
}

/// The same physical key on the Russian layout: someone who types `ы` meant `S`, `н` meant `Y`.
pub fn fold_key(c: char) -> char {
    const RU_MAP: [(char, char); 26] = [
        ('й', 'q'), ('ц', 'w'), ('у', 'e'), ('к', 'r'), ('е', 't'), ('н', 'y'), ('г', 'u'), ('ш', 'i'), ('щ', 'o'), ('з', 'p'),
        ('ф', 'a'), ('ы', 's'), ('в', 'd'), ('а', 'f'), ('п', 'g'), ('р', 'h'), ('о', 'j'), ('л', 'k'), ('д', 'l'),
        ('я', 'z'), ('ч', 'x'), ('с', 'c'), ('м', 'v'), ('и', 'b'), ('т', 'n'), ('ь', 'm'),
    ];
    let lower = c.to_lowercase().next().unwrap_or(c);
    RU_MAP.iter().find(|(r, _)| *r == lower).map(|(_, e)| *e).unwrap_or(c)
}

pub fn yes_no(prompt: &str) -> bool {
    choice(&format!("{prompt} [Y/N]: "), "YN") == 'Y'
}

/// Keeps the window open when it would vanish on exit (double-click / UAC launch / a terminal that
/// was opened just for this program), so the output can always be read.
pub fn pause_if_own_console() {
    if crate::sys::owns_console() {
        print!("\nPress Enter to close this window...");
        read_line();
    }
}

/// Flushes stdout and ignores errors: `println!` panics on a broken console, this never does.
pub fn say(msg: &str) {
    let mut o = io::stdout().lock();
    let _ = writeln!(o, "{msg}");
    let _ = o.flush();
}

// ------------------------------------------------------------------------------------ language



static RU: AtomicBool = AtomicBool::new(true);

/// Language rule: the saved choice wins, then `NETFREEDOM_LANG`, then the system locale on Unix;
/// Windows defaults to Russian (the project's audience), one key switches it in the menu.
pub fn resolve_lang_ru(saved: &str, env_nf: Option<&str>, env_locale: Option<&str>, windows: bool) -> bool {
    let pick = |s: &str| match s.trim().to_ascii_lowercase().as_str() {
        "ru" => Some(true),
        "en" => Some(false),
        _ => None,
    };
    if let Some(v) = pick(saved).or_else(|| env_nf.and_then(pick)) {
        return v;
    }
    if windows {
        return true;
    }
    env_locale.is_some_and(|l| l.to_ascii_lowercase().starts_with("ru"))
}

pub fn init_lang(saved: &str) {
    let loc = std::env::var("LC_ALL").ok().filter(|s| !s.is_empty()).or_else(|| std::env::var("LANG").ok());
    let ru = resolve_lang_ru(saved, std::env::var("NETFREEDOM_LANG").ok().as_deref(), loc.as_deref(), cfg!(windows));
    RU.store(ru, Ordering::Relaxed);
}

pub fn is_ru() -> bool {
    RU.load(Ordering::Relaxed)
}

pub fn set_ru(ru: bool) {
    RU.store(ru, Ordering::Relaxed);
}

/// Picks the Russian or English text.
pub fn tr<'a>(ru: &'a str, en: &'a str) -> &'a str {
    if is_ru() { ru } else { en }
}

// ------------------------------------------------------------------------------------- layout

pub const GREEN: &str = "32";
pub const YELLOW: &str = "33";
pub const RED: &str = "31";
pub const CYAN: &str = "36";
pub const DIM: &str = "90";
pub const BOLD: &str = "1";

pub fn paint(code: &str, s: &str) -> String {
    if color_on() { format!("\x1b[{code}m{s}{RESET}") } else { s.to_owned() }
}

/// The accent colour of the theme (the blue of the logo): 256-colour where available.
pub fn accent() -> &'static str {
    if RICH.load(Ordering::Relaxed) { "38;5;75" } else { CYAN }
}

/// Accent colour for headings, bold.
pub fn accent_bold(s: &str) -> String {
    paint(&format!("1;{}", accent()), s)
}

/// A key cap for the menu: ` 1 ` on the accent colour; `[1]` without colours.
pub fn badge(key: &str) -> String {
    if !color_on() {
        return format!("[{key}]");
    }
    let code = if RICH.load(Ordering::Relaxed) { "1;38;5;16;48;5;75" } else { "1;30;46" };
    paint(code, &format!(" {key} "))
}

/// `── TITLE ─────────`: a dim section rule inside the menu (`width` columns).
pub fn section(title: &str, width: usize) -> String {
    let head = format!("── {title} ");
    let fill = width.saturating_sub(visible_len(&head));
    paint(DIM, &format!("{head}{}", "─".repeat(fill)))
}

/// A bar of `cells` cells filled to `frac` (0..1) with the given colour.
pub fn meter(frac: f64, cells: usize, code: &str) -> String {
    let filled = ((frac.clamp(0.0, 1.0) * cells as f64).round() as usize).min(cells);
    format!("{}{}", paint(code, &"█".repeat(filled)), paint(DIM, &"░".repeat(cells - filled)))
}

/// Uplink burst of a strategy as a bar: a full bar is the old 15 KB, green up to ~2 KB, yellow up
/// to ~8 KB, red above.
pub fn load_bar(bytes: usize) -> String {
    let code = if bytes <= 2_000 { GREEN } else if bytes <= 8_000 { YELLOW } else { RED };
    // never an empty bar for a non-zero load: the smallest burst is still a burst
    let frac = if bytes == 0 { 0.0 } else { (bytes as f64 / 15_000.0).max(0.1) };
    meter(frac, 8, code)
}

/// Clears the screen and homes the cursor (only on a real terminal).
pub fn clear() {
    use std::io::IsTerminal;
    if io::stdout().is_terminal() {
        print!("\x1b[2J\x1b[H");
        flush();
    }
}

/// Cursor to the top-left without clearing: redraw in place, no flicker.
pub fn home() {
    use std::io::IsTerminal;
    if io::stdout().is_terminal() {
        print!("\x1b[H");
    }
}

/// Erases everything below the cursor (leftovers of a longer previous frame).
pub fn clear_below() {
    use std::io::IsTerminal;
    if io::stdout().is_terminal() {
        print!("\x1b[J");
        flush();
    }
}

/// Visible rows of the console window (not the scrollback buffer); 24 when it cannot be told.
/// Used to cut long lists into pages that fit on one screen: a list taller than the window
/// scrolls its top away, and the Windows console is bad at scrolling back.
#[cfg(windows)]
pub fn term_rows() -> usize {
    use windows_sys::Win32::System::Console::*;
    unsafe {
        let mut info: CONSOLE_SCREEN_BUFFER_INFO = std::mem::zeroed();
        if GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &mut info) != 0 {
            let rows = i32::from(info.srWindow.Bottom) - i32::from(info.srWindow.Top) + 1;
            if rows > 0 {
                return rows as usize;
            }
        }
    }
    24
}

#[cfg(unix)]
pub fn term_rows() -> usize {
    unsafe {
        let mut ws: libc::winsize = std::mem::zeroed();
        if libc::ioctl(1, libc::TIOCGWINSZ, &mut ws) == 0 && ws.ws_row > 0 {
            return ws.ws_row as usize;
        }
    }
    24
}

/// Number of columns a string takes on screen (escape sequences are not counted).
pub fn visible_len(s: &str) -> usize {
    let mut n = 0;
    let mut in_esc = false;
    for c in s.chars() {
        match (in_esc, c) {
            (false, '\x1b') => in_esc = true,
            (true, 'm') => in_esc = false,
            (true, _) => {}
            (false, _) => n += 1,
        }
    }
    n
}

pub fn pad(s: &str, width: usize) -> String {
    let l = visible_len(s);
    format!("{s}{}", " ".repeat(width.saturating_sub(l)))
}

/// Cuts plain text to `max` columns with an ellipsis (call BEFORE painting).
pub fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_owned();
    }
    let mut t: String = s.chars().take(max.saturating_sub(1)).collect();
    t.push('…');
    t
}

/// Greedy word wrap of plain text (call BEFORE painting).
pub fn wrap(s: &str, width: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for w in s.split_whitespace() {
        if !cur.is_empty() && cur.chars().count() + 1 + w.chars().count() > width {
            out.push(std::mem::take(&mut cur));
        }
        if !cur.is_empty() {
            cur.push(' ');
        }
        cur.push_str(w);
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

pub const PANEL_W: usize = 72;

/// A box with a title: `╭─ title ───╮ │ line │ ╰────╯` (square corners on a legacy console font).
pub fn panel(title: &str, lines: &[String]) {
    let inner = PANEL_W - 4;
    let (tl, tr, bl, br) = if ROUND.load(Ordering::Relaxed) { ("╭", "╮", "╰", "╯") } else { ("┌", "┐", "└", "┘") };
    let head = format!(" {title} ");
    let fill = (PANEL_W - 2).saturating_sub(visible_len(&head) + 1);
    let edge = |s: &str| paint(DIM, s);
    let mut out = format!("{}{}{}{}\n", edge(&format!("{tl}─")), accent_bold(&head), edge(&"─".repeat(fill)), edge(tr));
    for l in lines {
        out.push_str(&format!("{} {} {}\n", edge("│"), pad(l, inner), edge("│")));
    }
    out.push_str(&edge(&format!("{bl}{}{br}", "─".repeat(PANEL_W - 2))));
    say(&out);
}

pub fn dot(code: &str) -> String {
    paint(code, "●")
}

pub fn kv(label: &str, value: &str) -> String {
    format!("{} {}", paint(DIM, &pad(label, 11)), value)
}

pub fn heading(text: &str) {
    say(&format!("\n{}", accent_bold(text)));
}

/// Latency as a 10-cell bar: full = fast. `good` ms or less fills it, `bad` ms or more empties it.
pub fn latency_bar(ms: f64, good: f64, bad: f64) -> String {
    let t = ((bad - ms) / (bad - good)).clamp(0.0, 1.0);
    let filled = (t * 10.0).round() as usize;
    let code = if t > 0.66 { GREEN } else if t > 0.33 { YELLOW } else { RED };
    format!("{}{}", paint(code, &"█".repeat(filled)), paint(DIM, &"░".repeat(10 - filled)))
}

/// Waits for `poll` to return `Some`, drawing a spinner with the elapsed seconds.
pub fn wait_spin<T>(label: &str, timeout: std::time::Duration, mut poll: impl FnMut() -> Option<T>) -> Option<T> {
    use std::io::IsTerminal;
    let tty = io::stdout().is_terminal();
    let frames = ['|', '/', '-', '\\'];
    let t0 = std::time::Instant::now();
    let mut i = 0;
    let res = loop {
        if let Some(v) = poll() {
            break Some(v);
        }
        if t0.elapsed() >= timeout {
            break None;
        }
        if tty {
            print!("\r  {} {label} ({} с)  ", paint(CYAN, &frames[i % 4].to_string()), t0.elapsed().as_secs());
            flush();
        }
        i += 1;
        std::thread::sleep(std::time::Duration::from_millis(250));
    };
    if tty {
        print!("\r{}\r", " ".repeat(visible_len(label) + 24));
        flush();
    }
    res
}

/// Runs `work` on another thread and shows a spinner with the elapsed seconds until it is done.
/// For jobs that print nothing for a long while: a screen that does not change for half a minute
/// is taken for a freeze (and people press keys). A panic inside `work` goes on in the caller.
pub fn spin_task<T: Send>(label: &str, work: impl FnOnce() -> T + Send) -> T {
    use std::io::IsTerminal;
    let tty = io::stdout().is_terminal();
    let frames = ['|', '/', '-', '\\'];
    std::thread::scope(|s| {
        let job = s.spawn(work);
        let t0 = std::time::Instant::now();
        let mut i = 0;
        while !job.is_finished() {
            if tty {
                print!("\r  {} {label} ({} с)  ", paint(CYAN, &frames[i % 4].to_string()), t0.elapsed().as_secs());
                flush();
            }
            i += 1;
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
        if tty {
            print!("\r{}\r", " ".repeat(visible_len(label) + 24));
            flush();
        }
        match job.join() {
            Ok(v) => v,
            Err(e) => std::panic::resume_unwind(e),
        }
    })
}

#[cfg(test)]
mod ui_tests {
    use super::*;

    #[test]
    fn spin_task_returns_the_result_and_passes_a_panic_on() {
        assert_eq!(spin_task("t", || 6 * 7), 42);
        let r = std::panic::catch_unwind(|| spin_task("t", || -> u8 { panic!("boom") }));
        assert!(r.is_err());
    }

    #[test]
    fn visible_width_ignores_colours() {
        assert_eq!(visible_len("abc"), 3);
        assert_eq!(visible_len(&paint(GREEN, "abc")), 3);
        assert_eq!(visible_len(&format!("{} x", dot(RED))), 3);
        assert_eq!(visible_len(&pad(&paint(RED, "ab"), 6)), 6);
        assert_eq!(clip("abcdef", 4), "abc…");
        assert_eq!(clip("abc", 4), "abc");
        assert_eq!(wrap("aa bb cc dd", 5), vec!["aa bb", "cc dd"]);
        assert_eq!(wrap("", 5), Vec::<String>::new());
    }

    #[test]
    fn russian_layout_keys_map_to_latin() {
        assert_eq!(fold_key('ы'), 's');
        assert_eq!(fold_key('Н'), 'y');
        assert_eq!(fold_key('д'), 'l');
        assert_eq!(fold_key('1'), '1');
        assert_eq!(fold_key('g'), 'g');
    }

    #[test]
    fn language_choice() {
        assert!(!resolve_lang_ru("en", None, Some("ru_RU.UTF-8"), true), "saved choice wins");
        assert!(resolve_lang_ru("", Some("ru"), Some("en_US"), false), "env override");
        assert!(resolve_lang_ru("", None, None, true), "Windows defaults to Russian");
        assert!(resolve_lang_ru("", None, Some("ru_RU.UTF-8"), false));
        assert!(!resolve_lang_ru("", None, Some("en_US.UTF-8"), false));
    }

    #[test]
    fn latency_bar_scales() {
        assert_eq!(visible_len(&latency_bar(10.0, 20.0, 120.0)), 10);
        assert!(latency_bar(10.0, 20.0, 120.0).contains("██████████"));
        assert!(latency_bar(500.0, 20.0, 120.0).contains("░░░░░░░░░░"));
    }

    #[test]
    fn colour_policy() {
        assert!(!resolve_color(true, None, Some("xterm"), true), "NO_COLOR wins");
        assert!(!resolve_color(false, None, Some("dumb"), true));
        assert!(!resolve_color(false, None, Some("xterm"), false), "a pipe gets no escape codes");
        assert!(resolve_color(false, None, Some("xterm"), true));
        assert!(resolve_color(true, Some("1"), None, false), "NETFREEDOM_COLOR=1 forces colour");
        assert!(!resolve_color(false, Some("0"), Some("xterm"), true));
    }

    #[test]
    fn bars_and_badges_have_fixed_width() {
        for b in [0, 100, 1500, 7200, 15_000, 40_000] {
            assert_eq!(visible_len(&load_bar(b)), 8, "{b}");
        }
        assert_eq!(visible_len(&badge("1")), 3);
        assert_eq!(visible_len(&section("TITLE", PANEL_W)), PANEL_W);
    }
}
