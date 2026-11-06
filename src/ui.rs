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

pub fn color(code: &str, msg: &str) {
    println!("\x1b[{code}m{msg}{RESET}");
}
pub fn info(msg: &str) {
    println!("{msg}");
}
pub fn cyan(msg: &str) {
    color("36", msg);
}
pub fn ok(msg: &str) {
    println!("  \x1b[32m[OK]{RESET} {msg}");
}
pub fn skip(msg: &str) {
    println!("  [--] {msg}");
}
pub fn warn(msg: &str) {
    println!("  \x1b[33m[WARN]{RESET} {msg}");
}
pub fn error(msg: &str) {
    eprintln!("\x1b[31mERROR:{RESET} {msg}");
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

use std::sync::atomic::{AtomicBool, Ordering};

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
    format!("\x1b[{code}m{s}{RESET}")
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

pub const PANEL_W: usize = 70;

/// A box with a title: `┌─ title ───┐ │ line │ └────┘`.
pub fn panel(title: &str, lines: &[String]) {
    let inner = PANEL_W - 4;
    let head = format!(" {title} ");
    let fill = (PANEL_W - 2).saturating_sub(visible_len(&head) + 1);
    let mut out = format!("┌─{}{}┐\n", paint(CYAN, &paint(BOLD, &head)), "─".repeat(fill));
    for l in lines {
        out.push_str(&format!("│ {} │\n", pad(l, inner)));
    }
    out.push_str(&format!("└{}┘", "─".repeat(PANEL_W - 2)));
    say(&out);
}

pub fn dot(code: &str) -> String {
    paint(code, "●")
}

pub fn kv(label: &str, value: &str) -> String {
    format!("{} {}", paint(DIM, &pad(label, 10)), value)
}

pub fn heading(text: &str) {
    say(&format!("\n{}", paint(BOLD, &paint(CYAN, text))));
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

#[cfg(test)]
mod ui_tests {
    use super::*;

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
}
