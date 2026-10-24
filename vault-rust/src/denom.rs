//! Denominations, coin selection and change-making helpers (pure functions).
//!
//! A proof's face value is derived from the keyset id it was signed under
//! (`go-mvp-00` = 1, `go-mvp-d<N>` = N), never from a field the holder controls.

use crate::types::Proof;
use std::collections::HashMap;

pub const DENOMINATIONS: [u64; 9] = [500, 200, 100, 50, 20, 10, 5, 2, 1];
pub const LEGACY_KEYSET_ID: &str = "go-mvp-00";
/// Largest amount for exact-subset search (keeps the search bounded on a small device).
pub const MAX_EXACT_TARGET: u64 = 100_000;
/// Most proofs one split may produce.
pub const MAX_SPLIT_PROOFS: usize = 1000;

pub fn keyset_id_for(amount: u64) -> String {
    if amount == 1 {
        LEGACY_KEYSET_ID.to_string()
    } else {
        format!("go-mvp-d{amount}")
    }
}

pub fn denomination_of(keyset_id: &str) -> Option<u64> {
    if keyset_id == LEGACY_KEYSET_ID {
        return Some(1);
    }
    let n: u64 = keyset_id.strip_prefix("go-mvp-d")?.parse().ok()?;
    DENOMINATIONS.contains(&n).then_some(n)
}

/// Face value of a stored proof. Proofs with an unknown or missing keyset id count as 1
/// for local bookkeeping only; every proof is verified against a pinned keyset before it is
/// stored, and the kiosk decides the real value at settlement.
pub fn proof_value(p: &Proof) -> u64 {
    p.keyset_id.as_deref().and_then(denomination_of).unwrap_or(1)
}

/// Greedy split of `amount` into the available denominations (largest first).
/// `None` if it cannot be made exactly or would need too many proofs.
pub fn split_amount(amount: u64, available: &[u64]) -> Option<Vec<u64>> {
    let mut avail: Vec<u64> = available.iter().copied().filter(|d| *d > 0).collect();
    avail.sort_unstable_by(|a, b| b.cmp(a));
    avail.dedup();
    let mut rest = amount;
    let mut out = Vec::new();
    for d in avail {
        while rest >= d {
            out.push(d);
            rest -= d;
            if out.len() > MAX_SPLIT_PROOFS {
                return None;
            }
        }
    }
    (rest == 0).then_some(out)
}

/// Indices into `values` of a subset summing exactly to `target` (each index used once).
/// Pass `values` sorted descending so larger coins are preferred.
pub fn exact_subset(values: &[u64], target: u64) -> Option<Vec<usize>> {
    if target == 0 {
        return Some(vec![]);
    }
    if target > MAX_EXACT_TARGET {
        return None;
    }
    // reach[sum] = (previous sum, index of the value added to get here)
    let mut reach: HashMap<u64, (u64, usize)> = HashMap::new();
    reach.insert(0, (0, usize::MAX));
    for (i, &v) in values.iter().enumerate() {
        if v == 0 || v > target {
            continue;
        }
        let sums: Vec<u64> = reach.keys().copied().collect();
        for s in sums {
            let ns = s + v;
            if ns <= target && !reach.contains_key(&ns) {
                reach.insert(ns, (s, i));
            }
        }
        if reach.contains_key(&target) {
            break;
        }
    }
    if !reach.contains_key(&target) {
        return None;
    }
    let mut idx = Vec::new();
    let mut cur = target;
    while cur != 0 {
        let (prev, i) = reach[&cur];
        idx.push(i);
        cur = prev;
    }
    Some(idx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyset_ids_roundtrip() {
        for d in DENOMINATIONS {
            assert_eq!(denomination_of(&keyset_id_for(d)), Some(d));
        }
        assert_eq!(keyset_id_for(1), "go-mvp-00");
        assert_eq!(denomination_of("go-mvp-d3"), None);
        assert_eq!(denomination_of("go-mvp-dx"), None);
        assert_eq!(denomination_of("evil"), None);
    }

    #[test]
    fn split_is_exact_and_greedy() {
        let all = DENOMINATIONS;
        assert_eq!(split_amount(237, &all), Some(vec![200, 20, 10, 5, 2]));
        assert_eq!(split_amount(0, &all), Some(vec![]));
        assert_eq!(split_amount(7, &[5, 2]), Some(vec![5, 2]));
        assert_eq!(split_amount(3, &[2, 5]), None); // not representable
        assert_eq!(split_amount(10_000_000, &[1]), None); // too many proofs
    }

    #[test]
    fn exact_subset_finds_or_refuses() {
        let vals = [200, 20, 10, 5, 2];
        let sum = |idx: &[usize]| idx.iter().map(|&i| vals[i]).sum::<u64>();
        let mut idx = exact_subset(&vals, 37).unwrap();
        idx.sort();
        idx.dedup();
        assert_eq!(sum(&idx), 37);
        assert_eq!(idx.len(), 4); // 20+10+5+2
        assert!(exact_subset(&vals, 40).is_none()); // needs change
        assert_eq!(sum(&exact_subset(&vals, 200).unwrap()), 200);
        assert!(exact_subset(&vals, 1_000_000).is_none());
        assert_eq!(exact_subset(&vals, 0), Some(vec![]));
        // never reuses an index
        let v2 = [5, 5, 5];
        let mut i2 = exact_subset(&v2, 10).unwrap();
        i2.sort();
        assert_eq!(i2.len(), 2);
        assert_ne!(i2[0], i2[1]);
        assert!(exact_subset(&v2, 20).is_none());
    }
}
