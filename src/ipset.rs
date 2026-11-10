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

//! IP lists for the native engine (`--ipset`, `--ipset-exclude`): IPv4/IPv6 addresses and CIDR
//! blocks, stored as sorted merged ranges (8 bytes per IPv4 block) and searched by bisection.

use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Default, Clone)]
pub struct IpSet {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

fn merge<T: Copy + Ord + Saturating1>(v: &mut Vec<(T, T)>) {
    v.sort_unstable();
    let mut out: Vec<(T, T)> = Vec::with_capacity(v.len());
    for &(s, e) in v.iter() {
        match out.last_mut() {
            Some(l) if s <= l.1.sat_inc() => l.1 = l.1.max(e),
            _ => out.push((s, e)),
        }
    }
    out.shrink_to_fit();
    *v = out;
}

trait Saturating1 {
    fn sat_inc(self) -> Self;
}
impl Saturating1 for u32 {
    fn sat_inc(self) -> u32 {
        self.saturating_add(1)
    }
}
impl Saturating1 for u128 {
    fn sat_inc(self) -> u128 {
        self.saturating_add(1)
    }
}

impl IpSet {
    /// One address or `addr/len` per line; `#` comments and malformed lines are skipped.
    pub fn parse(text: &str) -> IpSet {
        let mut l = IpSet::default();
        for line in text.lines() {
            let t = line.trim().trim_start_matches('\u{feff}');
            if t.is_empty() || t.starts_with('#') {
                continue;
            }
            let (a, len) = match t.split_once('/') {
                Some((a, n)) => match n.trim().parse::<u32>() {
                    Ok(n) => (a.trim(), Some(n)),
                    Err(_) => continue,
                },
                None => (t, None),
            };
            if let Ok(ip) = a.parse::<Ipv4Addr>() {
                let len = len.unwrap_or(32);
                if len > 32 {
                    continue;
                }
                let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
                let s = u32::from(ip) & mask;
                l.v4.push((s, s | !mask));
            } else if let Ok(ip) = a.parse::<Ipv6Addr>() {
                let len = len.unwrap_or(128);
                if len > 128 {
                    continue;
                }
                let mask = if len == 0 { 0 } else { u128::MAX << (128 - len) };
                let s = u128::from(ip) & mask;
                l.v6.push((s, s | !mask));
            }
        }
        merge(&mut l.v4);
        merge(&mut l.v6);
        l
    }

    pub fn merge(&mut self, o: IpSet) {
        self.v4.extend(o.v4);
        self.v6.extend(o.v6);
        merge(&mut self.v4);
        merge(&mut self.v6);
    }

    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// `ip` is the 16-byte address field used by the engine (IPv4 in the first 4 bytes).
    pub fn contains(&self, ip: &[u8; 16], v6: bool) -> bool {
        if v6 {
            let x = u128::from_be_bytes(*ip);
            let i = self.v6.partition_point(|r| r.0 <= x);
            i > 0 && self.v6[i - 1].1 >= x
        } else {
            let x = u32::from_be_bytes([ip[0], ip[1], ip[2], ip[3]]);
            let i = self.v4.partition_point(|r| r.0 <= x);
            i > 0 && self.v4[i - 1].1 >= x
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(a: [u8; 4]) -> [u8; 16] {
        let mut x = [0u8; 16];
        x[..4].copy_from_slice(&a);
        x
    }

    #[test]
    fn cidr_single_and_merging() {
        let l = IpSet::parse("# c\r\n10.0.0.0/24\n10.0.1.0/24\n192.168.1.5\nbad\n300.1.1.1\n1.2.3.4/33\n");
        assert_eq!(l.len(), 2, "adjacent /24s merge, bad lines are skipped");
        assert!(l.contains(&v4([10, 0, 0, 0]), false) && l.contains(&v4([10, 0, 1, 255]), false));
        assert!(!l.contains(&v4([10, 0, 2, 0]), false) && !l.contains(&v4([9, 255, 255, 255]), false));
        assert!(l.contains(&v4([192, 168, 1, 5]), false) && !l.contains(&v4([192, 168, 1, 6]), false));
    }

    #[test]
    fn ipv6_and_extremes() {
        let l = IpSet::parse("2606:4700::/32\n0.0.0.0/0\n");
        let a = "2606:4700:1::1".parse::<Ipv6Addr>().unwrap().octets();
        let b = "2606:4701::1".parse::<Ipv6Addr>().unwrap().octets();
        assert!(l.contains(&a, true) && !l.contains(&b, true));
        assert!(l.contains(&v4([255, 255, 255, 255]), false));
    }

    #[test]
    fn the_shipped_ipset_loads() {
        let l = IpSet::parse(include_str!("../dist/windows/lists/ipset-all.txt"));
        assert!(l.len() > 1000 && l.len() <= 33_100);
        assert!(l.contains(&v4([1, 1, 1, 7]), false), "1.1.1.0/24 is the first line of the file");
    }
}
