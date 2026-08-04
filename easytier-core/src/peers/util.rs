use std::hash::Hash;

use dashmap::DashMap;

pub(crate) fn shrink_dashmap<K: Eq + Hash, V>(map: &DashMap<K, V>, threshold: Option<usize>) {
    let threshold = threshold.unwrap_or(16);
    if map.capacity() - map.len() > threshold {
        map.shrink_to_fit();
    }
}

#[inline]
fn isqrt(n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    let mut x = n;
    let mut y = (x + 1) / 2;
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}

#[inline]
pub(crate) fn loss_adjusted_cost(latency: u64, loss_permille: u64, weight: u64) -> u64 {
    let effective_loss = loss_permille.saturating_sub(10);
    if effective_loss == 0 || weight == 0 {
        return latency;
    }
    let sqrt_val = isqrt(effective_loss.saturating_mul(10));
    let penalty = sqrt_val.saturating_mul(weight);
    latency.saturating_mul(100u64.saturating_add(penalty)) / 100
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_penalty_when_loss_at_or_below_baseline() {
        assert_eq!(loss_adjusted_cost(100, 0, 7), 100);
        assert_eq!(loss_adjusted_cost(100, 10, 7), 100);
        assert_eq!(loss_adjusted_cost(100, 30, 0), 100);
    }

    #[test]
    fn penalty_increases_with_sqrt_of_loss() {
        let w = 7;
        let c20 = loss_adjusted_cost(100, 20, w);
        let c30 = loss_adjusted_cost(100, 30, w);
        let c50 = loss_adjusted_cost(100, 50, w);
        let c100 = loss_adjusted_cost(100, 100, w);
        assert_eq!(c20, 170);
        assert_eq!(c30, 198);
        assert_eq!(c50, 240);
        assert_eq!(c100, 310);
        assert!(c20 < c30 && c30 < c50 && c50 < c100);
    }

    #[test]
    fn lossy_direct_prefers_relay() {
        let w = 7;
        // 125ms/3% direct vs 5+124ms/0% relay
        assert!(loss_adjusted_cost(125, 30, w) > loss_adjusted_cost(5, 0, w) + loss_adjusted_cost(124, 0, w));
        // 80ms/2% direct vs 130ms/0% relay
        assert!(loss_adjusted_cost(80, 20, w) > loss_adjusted_cost(130, 0, w));
    }

    #[test]
    fn large_latency_gap_keeps_direct() {
        let w = 7;
        // 60ms/3% direct vs 120ms/0%: direct still wins (latency gap too large)
        assert!(loss_adjusted_cost(60, 30, w) < loss_adjusted_cost(120, 0, w));
        // 50ms/2% direct vs 130ms/0%: direct wins
        assert!(loss_adjusted_cost(50, 20, w) < loss_adjusted_cost(130, 0, w));
    }

    #[test]
    fn multi_hop_relay_cost_is_additive() {
        let w = 7;
        // A→B(10ms/2%) + B→C(20ms/1%) + C→D(15ms/0%)
        let hop1 = loss_adjusted_cost(10, 20, w);
        let hop2 = loss_adjusted_cost(20, 10, w);
        let hop3 = loss_adjusted_cost(15, 0, w);
        let total = hop1 + hop2 + hop3;
        // Each hop computed independently; 1% (10 permille) hops are free
        assert_eq!(hop2, 20);
        assert_eq!(hop3, 15);
        assert_eq!(total, hop1 + 20 + 15);
    }

    #[test]
    fn extreme_inputs_no_overflow() {
        assert!(loss_adjusted_cost(100, 1000, 7) < u64::MAX / 2);
        assert!(loss_adjusted_cost(u32::MAX as u64, 500, 100) < u64::MAX / 2);
    }
}
