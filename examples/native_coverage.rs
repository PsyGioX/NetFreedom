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

//! Which built-in strategies can the native engine run today, and why not the others?
//! `cargo run --example native_coverage`

use std::collections::BTreeMap;

use nf::capture::{expand, Vars};
use nf::engine::Plan;
use nf::profiles::{PROFILES, WFRAW};

fn main() {
    let v = Vars { bin: "B/", lists: "L/", wfraw: WFRAW, gf_tcp: "12", gf_udp: "500,1701,4443,4500,8095,8443" };
    let read = |p: &str| -> std::io::Result<Vec<u8>> {
        let path = if let Some(f) = p.strip_prefix("B/") { format!("dist/windows/bin/{f}") } else if let Some(f) = p.strip_prefix("L/") { format!("dist/windows/lists/{f}") } else { p.to_string() };
        std::fs::read(path)
    };
    let (mut ok, mut total) = (0, 0);
    let mut reasons: BTreeMap<String, Vec<&str>> = BTreeMap::new();
    for p in PROFILES {
        for args in [p.lean, p.classic] {
            let Some(a) = args else { continue };
            total += 1;
            match Plan::from_args(&expand(a, &v), &read) {
                Ok(_) => ok += 1,
                Err(e) => reasons.entry(e).or_default().push(p.name),
            }
        }
    }
    println!("native engine accepts {ok} of {total} strategy variants (first blocker per refused variant):\n");
    let mut r: Vec<_> = reasons.into_iter().collect();
    r.sort_by_key(|(_, v)| std::cmp::Reverse(v.len()));
    for (why, names) in r {
        println!("{:>3}  {}", names.len(), why);
    }

    // The same, per rule (`--new` section), so the real blockers are visible instead of only
    // the first one in each strategy.
    let mut seg_reasons: BTreeMap<String, usize> = BTreeMap::new();
    let (mut seg_ok, mut seg_total) = (0, 0);
    for p in PROFILES {
        for a in [p.lean, p.classic].into_iter().flatten() {
            let exp = expand(a, &v);
            for seg in exp.split(|x| x == "--new") {
                let mut args = vec!["--wf-raw=x".to_string()];
                args.extend(seg.iter().filter(|x| !x.starts_with("--wf-raw")).cloned());
                seg_total += 1;
                match Plan::from_args(&args, &read) {
                    Ok(_) => seg_ok += 1,
                    // a rule that can never change a packet (TCP cutoff <= n2) builds no capture filter
                    Err(e) if e == "the profile has no rules" => seg_ok += 1,
                    Err(e) => *seg_reasons.entry(e).or_default() += 1,
                }
            }
        }
    }
    println!("\nrule by rule: {seg_ok} of {seg_total} rules are supported; blockers:\n");
    let mut r: Vec<_> = seg_reasons.into_iter().collect();
    r.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
    for (why, n) in r {
        println!("{n:>4}  {why}");
    }
}
