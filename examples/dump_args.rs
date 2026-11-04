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

//! Developer helper: prints the nfqws argument list of every profile variant (one per line,
//! arguments NUL-separated) so they can be validated with `nfqws --dry-run`.
use nf::capture::{expand, GameFilter, Vars};
use nf::nftrules::split_args;
use nf::profiles::{PROFILES, WFRAW};

fn main() {
    let bin = std::env::args().nth(1).expect("bin dir");
    let lists = std::env::args().nth(2).expect("lists dir");
    for p in PROFILES {
        for (kind, tpl) in [("lean", p.lean), ("classic", p.classic)] {
            let Some(tpl) = tpl else { continue };
            let gf = GameFilter::low_latency();
            let (t, u) = gf.effective();
            let args = expand(tpl, &Vars { bin: &bin, lists: &lists, wfraw: WFRAW, gf_tcp: t, gf_udp: u });
            let (_, rest) = split_args(&args).expect("translatable");
            println!("{}|{}|{}", p.name, kind, rest.join("\u{1f}"));
        }
    }
}
