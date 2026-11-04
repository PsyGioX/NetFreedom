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

//! Latency / jitter / loss statistics (same definitions as the old `warp-quality.ps1`).

#[derive(Debug, Clone, PartialEq)]
pub struct Summary {
    pub sent: u32,
    pub received: u32,
    pub loss_pct: f64,
    pub min: f64,
    pub median: f64,
    pub avg: f64,
    pub p95: f64,
    pub max: f64,
    pub stdev: f64,
    /// Mean absolute difference between consecutive replies.
    pub jitter: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Excellent,
    Good,
    HighJitter,
    Loss,
}

fn round1(x: f64) -> f64 {
    (x * 10.0).round() / 10.0
}

/// `times` are round-trip times of the replies that arrived, in arrival order.
pub fn summarize(times: &[f64], sent: u32) -> Option<Summary> {
    let n = times.len();
    if n == 0 {
        return None;
    }
    let mut sorted = times.to_vec();
    sorted.sort_by(|a, b| a.total_cmp(b));
    let avg = times.iter().sum::<f64>() / n as f64;
    let median = if n % 2 == 1 { sorted[n / 2] } else { (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0 };
    let rank = ((0.95 * n as f64).ceil() as usize).max(1);
    let var = times.iter().map(|t| (t - avg).powi(2)).sum::<f64>() / n as f64;
    let jitter = if n > 1 {
        times.windows(2).map(|w| (w[1] - w[0]).abs()).sum::<f64>() / (n - 1) as f64
    } else {
        0.0
    };
    let lost = sent.saturating_sub(n as u32);
    Some(Summary {
        sent,
        received: n as u32,
        loss_pct: round1(100.0 * lost as f64 / sent.max(1) as f64),
        min: sorted[0],
        median,
        avg: round1(avg),
        p95: sorted[rank - 1],
        max: sorted[n - 1],
        stdev: round1(var.sqrt()),
        jitter: round1(jitter),
    })
}

pub fn verdict(s: &Summary) -> Verdict {
    let lost = s.sent - s.received;
    if lost > 0 {
        Verdict::Loss
    } else if s.jitter <= 5.0 {
        Verdict::Excellent
    } else if s.jitter <= 10.0 {
        Verdict::Good
    } else {
        Verdict::HighJitter
    }
}

/// Ranking used by `tune` (lower is better): typical latency, plus jitter and loss penalties,
/// plus a small cost for slow connection set-up and for heavier capture modes.
pub fn score(s: &Summary, connect_s: f64, penalty: f64) -> f64 {
    s.median + 2.0 * s.jitter + 30.0 * s.loss_pct + 3.0 * connect_s + penalty
}

/// Ranking for games: a game feels jitter and spikes much more than a slightly higher median, and
/// a lost packet is a rubber-band. Weights: jitter x3, the tail (p95 - median) x0.5, loss x50.
pub fn score_games(s: &Summary, connect_s: f64, penalty: f64) -> f64 {
    s.median + 3.0 * s.jitter + 0.5 * (s.p95 - s.median).max(0.0) + 50.0 * s.loss_pct + 3.0 * connect_s + penalty
}

/// True when the tail is long enough to deserve a hint about periodic spikes.
pub fn long_tail(s: &Summary) -> bool {
    s.received > 1 && s.p95 - s.median > 15.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_statistics() {
        let s = summarize(&[10.0, 12.0, 11.0, 30.0], 5).unwrap();
        assert_eq!((s.received, s.sent), (4, 5));
        assert_eq!(s.loss_pct, 20.0);
        assert_eq!((s.min, s.max), (10.0, 30.0));
        assert_eq!(s.median, 11.5);
        assert_eq!(s.avg, 15.8);
        assert_eq!(s.p95, 30.0); // nearest rank: ceil(0.95*4)=4
        assert_eq!(s.jitter, 7.3); // (2+1+19)/3 = 7.33
        assert_eq!(verdict(&s), Verdict::Loss);
    }

    #[test]
    fn score_orders_scenarios_sensibly() {
        let fast = summarize(&[20.0, 21.0, 20.0, 22.0], 4).unwrap();
        let slow = summarize(&[60.0, 61.0, 60.0, 62.0], 4).unwrap();
        let lossy = summarize(&[20.0, 21.0, 20.0], 4).unwrap();
        assert!(score(&fast, 2.0, 0.0) < score(&slow, 2.0, 0.0));
        assert!(score(&fast, 2.0, 0.0) < score(&lossy, 2.0, 0.0), "25% loss must hurt a lot");
        assert!(score(&fast, 2.0, 0.0) < score(&fast, 2.0, 5.0), "heavier capture modes lose ties");
        assert!(score(&fast, 1.0, 0.0) < score(&fast, 9.0, 0.0), "faster connect wins ties");
    }

    #[test]
    fn games_prefer_steady_over_fast() {
        let steady = summarize(&[40.0, 41.0, 40.0, 41.0, 40.0], 5).unwrap();
        let fast_spiky = summarize(&[25.0, 25.0, 90.0, 25.0, 25.0], 5).unwrap();
        assert!(score_games(&steady, 1.0, 0.0) < score_games(&fast_spiky, 1.0, 0.0), "the games score is not");
    }

    #[test]
    fn verdicts() {
        let good = summarize(&[10.0, 12.0, 10.0, 11.0], 4).unwrap();
        assert_eq!(verdict(&good), Verdict::Excellent);
        let jittery = summarize(&[10.0, 30.0, 10.0, 30.0], 4).unwrap();
        assert_eq!(verdict(&jittery), Verdict::HighJitter);
        assert!(summarize(&[], 4).is_none());
        assert_eq!(summarize(&[7.0], 1).unwrap().jitter, 0.0);
    }
}
