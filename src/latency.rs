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

//! Uplink burst of a strategy: how many bytes of fake packets leave the machine when a flow starts.
//!
//! A strategy only runs while a connection is being set up, never on the packets of a running
//! game. The one thing it can still do to ping and jitter is the burst it sends at that moment:
//! on a slow or shared uplink a few kilobytes of fakes sit in front of every other packet. The
//! number here is computed from the very arguments the engine receives (not from a table that
//! could drift away from them), so the menus can show it and the tests can pin it.
//!
//! How the engine counts (see `engine.rs`): every fake *file* is sent `repeats` times, and
//! `cutoff=nN` stops the fakes after packet N-1 of a flow, so `n2` means the first packet only.

/// Bytes of fake packets per new flow, by kind of rule.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Burst {
    /// QUIC Initial / TLS ClientHello fakes: what every new connection pays (WARP handshake, a page).
    pub connect: usize,
    /// Game and fallback-port fakes (`--dpi-desync-any-protocol`): what a new game flow pays.
    pub game: usize,
    /// Discord voice / STUN fakes.
    pub voice: usize,
}

impl Burst {
    /// The largest of the three: the number that a single worst flow start puts on the uplink.
    pub fn worst(&self) -> usize {
        self.connect.max(self.game).max(self.voice)
    }
}

/// Size used for a fake that has no file (the engine builds it): the built-in ClientHello is 680
/// bytes, a built-in QUIC Initial 1200.
const BUILTIN_TLS: usize = 680;
const BUILTIN_QUIC: usize = 1200;

fn value<'a>(seg: &'a [String], key: &str) -> Option<&'a str> {
    seg.iter().find_map(|a| a.strip_prefix(key).and_then(|r| r.strip_prefix('=')))
}

fn values<'a>(seg: &'a [String], key: &str) -> Vec<&'a str> {
    seg.iter().filter_map(|a| a.strip_prefix(key).and_then(|r| r.strip_prefix('='))).collect()
}

/// Computes the burst of an expanded argument list. `size_of(path)` is the length of a fake file.
pub fn burst(args: &[String], size_of: &dyn Fn(&str) -> Option<usize>) -> Burst {
    let mut segs: Vec<&[String]> = Vec::new();
    let mut start = 0;
    for (i, a) in args.iter().enumerate() {
        if a == "--new" {
            segs.push(&args[start..i]);
            start = i + 1;
        }
    }
    segs.push(&args[start..]);

    let mut out = Burst::default();
    for seg in segs {
        let desync = value(seg, "--dpi-desync").unwrap_or("");
        if !desync.split(',').any(|m| m == "fake") {
            continue; // splits and `hostfakesplit` re-cut the real packet, they add no fake of their own
        }
        let repeats: usize = value(seg, "--dpi-desync-repeats").and_then(|v| v.parse().ok()).unwrap_or(1).max(1);
        let masked = seg.iter().any(|a| a.starts_with("--nf-mask="));
        let udp = seg.iter().any(|a| a.starts_with("--filter-udp="));
        // `cutoff=nN` -> the first N-1 packets get fakes
        let packets: usize = value(seg, "--dpi-desync-cutoff").and_then(|v| v.strip_prefix('n')).and_then(|v| v.parse::<usize>().ok()).map_or(1, |n| n.saturating_sub(1).max(1));
        let any = value(seg, "--dpi-desync-any-protocol").is_some();

        let keys: &[&str] = if udp {
            &["--dpi-desync-fake-quic", "--dpi-desync-fake-unknown-udp", "--dpi-desync-fake-discord", "--dpi-desync-fake-stun"]
        } else {
            &["--dpi-desync-fake-tls", "--dpi-desync-fake-unknown"]
        };
        // every key whose file is listed contributes its files; keys that are absent use the built-in fake
        let mut sizes: Vec<usize> = Vec::new();
        for k in keys {
            sizes.extend(values(seg, k).into_iter().filter_map(size_of));
        }
        if sizes.is_empty() {
            sizes.push(if udp { BUILTIN_QUIC } else { BUILTIN_TLS });
        }
        // a pattern file for `seqovl` is not a fake: it is cut off in front of the real data
        let mut total: usize = sizes.iter().sum::<usize>() * repeats * packets;
        if masked && udp {
            // masked QUIC: every copy is a fresh Initial of ~1250 bytes, one batch per listed file
            total = sizes.len().max(1) * repeats * packets * 1250;
        }
        let voice = udp && (seg.iter().any(|a| a.starts_with("--filter-l7=")) || value(seg, "--dpi-desync-fake-discord").is_some());
        if voice {
            out.voice = out.voice.max(total);
        } else if any {
            out.game += total;
        } else {
            out.connect = out.connect.max(total);
        }
    }
    out
}

/// Time that `bytes` occupy an uplink of `mbit` Mbit/s, in milliseconds.
pub fn uplink_ms(bytes: usize, mbit: f64) -> f64 {
    bytes as f64 * 8.0 / (mbit * 1000.0)
}

/// `0,2 КБ` / `7,2 КБ` / `12 Б`: short size for menus (`ru` uses a comma and Cyrillic units).
pub fn fmt_bytes(bytes: usize, ru: bool) -> String {
    if bytes < 1000 {
        return format!("{bytes} {}", if ru { "Б" } else { "B" });
    }
    let kb = bytes as f64 / 1000.0;
    let s = if kb < 10.0 { format!("{kb:.1}") } else { format!("{kb:.0}") };
    let s = if ru { s.replace('.', ",") } else { s };
    format!("{s} {}", if ru { "КБ" } else { "KB" })
}

/// Burst of a strategy as the engine would get it: `bin` is the directory of the fake files.
pub fn of_profile(p: &crate::profiles::Profile, bin: &str) -> Burst {
    let Some(tpl) = p.lean.or(p.classic) else { return Burst::default() };
    let args = crate::capture::expand_with(tpl, &crate::capture::Vars { bin, lists: "", wfraw: "", gf_tcp: "12", gf_udp: crate::capture::WARP_UDP_PORTS }, crate::capture::full_fakes());
    burst(&args, &|path| std::fs::metadata(path).ok().map(|m| m.len() as usize))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profiles::{find, PROFILES};

    fn bin() -> String {
        format!("{}/dist/windows/bin/", env!("CARGO_MANIFEST_DIR"))
    }

    fn of(name: &str) -> Burst {
        of_profile(find(name).unwrap(), &bin())
    }

    fn a(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn counts_files_times_repeats_and_the_cutoff() {
        let size = |p: &str| Some(if p.ends_with("a.bin") { 1000 } else { 100 });
        // one file, 6 repeats, one packet (cutoff n2)
        let g = burst(&a(&["--filter-udp=500", "--dpi-desync=fake", "--dpi-desync-repeats=6", "--dpi-desync-any-protocol=1", "--dpi-desync-cutoff=n2", "--dpi-desync-fake-unknown-udp=a.bin"]), &size);
        assert_eq!(g, Burst { connect: 0, game: 6000, voice: 0 });
        // n3 = two packets; two files are both sent `repeats` times
        let m = burst(&a(&["--filter-udp=443", "--dpi-desync=fake", "--dpi-desync-repeats=3", "--dpi-desync-fake-quic=a.bin", "--dpi-desync-fake-quic=b.bin"]), &size);
        assert_eq!(m.connect, (1000 + 100) * 3);
        let c = burst(&a(&["--filter-udp=500", "--dpi-desync=fake", "--dpi-desync-repeats=1", "--dpi-desync-any-protocol=1", "--dpi-desync-cutoff=n3", "--dpi-desync-fake-unknown-udp=b.bin"]), &size);
        assert_eq!(c.game, 200);
        // splits and hostfakesplit add no fake packet
        assert_eq!(burst(&a(&["--filter-tcp=443", "--dpi-desync=multisplit"]), &size), Burst::default());
        assert_eq!(burst(&a(&["--filter-tcp=443", "--dpi-desync=hostfakesplit"]), &size), Burst::default());
        // a masked QUIC fake is a fresh ~1250-byte Initial each time
        let k = burst(&a(&["--filter-udp=443", "--dpi-desync=fake", "--dpi-desync-repeats=4", "--nf-mask=ya.ru"]), &size);
        assert_eq!(k.connect, 4 * 1250);
    }

    #[test]
    fn formatting() {
        assert_eq!(fmt_bytes(200, true), "200 Б");
        assert_eq!(fmt_bytes(7200, true), "7,2 КБ");
        assert_eq!(fmt_bytes(15_000, false), "15 KB");
        assert!((uplink_ms(7200, 5.0) - 11.52).abs() < 0.01);
    }

    /// The numbers in the README follow from the strategies; this pins them.
    #[test]
    fn warp_strategies_have_the_documented_burst() {
        // QUIC fakes on UDP 443 (connect) and the fallback ports (game field)
        assert_eq!((of("warp").connect, of("warp").game), (6 * 1200, 6 * 100));
        assert_eq!((of("warp-esports").connect, of("warp-esports").game), (3 * 1200, 4 * 100));
        assert_eq!((of("warp-lowburst").connect, of("warp-lowburst").game), (4 * 1200, 6 * 100));
        assert_eq!((of("warp-min").connect, of("warp-min").game), (2 * 1200, 3 * 100));
        // the heavy variant keeps the 1250-byte payload on the fallback ports (cutoff n4 = 3 packets)
        assert_eq!(of("warp-heavy").game, 10 * 1250 * 3);
        // two different fakes, 3 copies each
        assert_eq!(of("warp-mix").connect, (1200 + 1357) * 3);
    }

    #[test]
    fn every_warp_strategy_except_heavy_is_lean_on_the_fallback_ports() {
        for p in PROFILES.iter().filter(|p| p.is_dedicated_lean() && p.name != "warp-heavy") {
            let b = of_profile(p, &bin());
            assert!(b.game <= 600, "{}: fallback-port fakes are {} bytes", p.name, b.game);
            assert!(b.connect <= 8000, "{}: handshake burst is {} bytes", p.name, b.connect);
        }
    }

    #[test]
    fn game_scenarios_send_a_smaller_burst_than_the_default() {
        let d = of("warp");
        for n in ["warp-esports", "warp-esports-ttl", "warp-lowburst", "warp-min"] {
            let b = of(n);
            assert!(b.connect < d.connect && b.game <= d.game, "{n}: {b:?} must be below {d:?}");
        }
        assert!(of("warp-min").worst() < of("warp-esports").worst());
    }

    #[test]
    fn game_flows_in_every_bypass_strategy_cost_next_to_nothing() {
        for p in PROFILES.iter().filter(|p| p.is_bypass()) {
            let tpl = p.classic.unwrap();
            let args = crate::capture::expand_with(tpl, &crate::capture::Vars { bin: &bin(), lists: "L/", wfraw: "", gf_tcp: "1024-65535", gf_udp: "1024-65535" }, false);
            let game: Vec<String> = {
                let mut v = Vec::new();
                let mut seg: Vec<String> = Vec::new();
                for x in args.iter().chain(std::iter::once(&"--new".to_string())) {
                    if x == "--new" {
                        if seg.iter().any(|s| s == "--dpi-desync-any-protocol=1") {
                            v.extend(seg.drain(..));
                            v.push("--new".into());
                        }
                        seg.clear();
                    } else {
                        seg.push(x.clone());
                    }
                }
                v
            };
            let b = burst(&game, &|path| std::fs::metadata(path).ok().map(|m| m.len() as usize));
            assert!(b.game <= 600, "{}: a new game flow puts {} bytes on the uplink", p.name, b.game);
        }
        // `burst=full` restores the old 1250-byte payload: 6 x 1250 for UDP
        let args = crate::capture::expand_with(find("hostfake").unwrap().classic.unwrap(), &crate::capture::Vars { bin: &bin(), lists: "L/", wfraw: "", gf_tcp: "1024-65535", gf_udp: "1024-65535" }, true);
        assert!(args.iter().any(|x| x == &format!("--dpi-desync-fake-unknown-udp={}ACTIVE_GAME_UDP.bin", bin())));
        assert!(args.iter().any(|x| x == "--dpi-desync-repeats=6"));
    }
}
