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
                if let Some(c) = s.chars().next().map(|c| c.to_ascii_uppercase()) {
                    if keys.contains(c) {
                        return c;
                    }
                }
            }
        }
    }
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
