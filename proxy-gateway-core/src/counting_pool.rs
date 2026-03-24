//! A generic pool that tracks per-item usage counts and selects the
//! least-used item with random tie-breaking.
//!
//! This is a domain-agnostic building block — it knows nothing about proxies,
//! only about counting and selection.

use std::sync::atomic::{AtomicU64, Ordering};

/// A fixed-size pool of items with atomic usage counters.
///
/// [`CountingPool::next`] always returns the item with the lowest use-count,
/// breaking ties randomly.  This gives even load distribution without any
/// locking.
pub struct CountingPool<T> {
    entries: Vec<Entry<T>>,
}

struct Entry<T> {
    value: T,
    use_count: AtomicU64,
}

impl<T: std::fmt::Debug> std::fmt::Debug for CountingPool<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CountingPool")
            .field("len", &self.entries.len())
            .finish()
    }
}

impl<T> CountingPool<T> {
    /// Create a pool from a list of items.  Each item starts with a use-count
    /// of zero.
    pub fn new(items: Vec<T>) -> Self {
        let entries = items
            .into_iter()
            .map(|value| Entry {
                value,
                use_count: AtomicU64::new(0),
            })
            .collect();
        Self { entries }
    }

    /// Return a reference to the least-used item and increment its counter.
    ///
    /// Returns `None` only if the pool is empty.
    pub fn next(&self) -> Option<&T> {
        if self.entries.is_empty() {
            return None;
        }
        let idx = pick_least_used(&self.entries);
        let entry = &self.entries[idx];
        entry.use_count.fetch_add(1, Ordering::Relaxed);
        Some(&entry.value)
    }

    /// Like [`next`](Self::next), but tries to avoid returning an item equal
    /// to `exclude`.
    ///
    /// If all items match `exclude` (e.g. a single-entry pool), it falls back
    /// to returning that item — the caller always gets *something* from a
    /// non-empty pool.
    pub fn next_excluding(&self, exclude: &T) -> Option<&T>
    where
        T: PartialEq,
    {
        if self.entries.is_empty() {
            return None;
        }

        let non_excluded: Vec<usize> = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, e)| e.value != *exclude)
            .map(|(i, _)| i)
            .collect();

        let idx = if non_excluded.is_empty() {
            pick_least_used(&self.entries)
        } else {
            pick_least_used_indices(&self.entries, &non_excluded)
        };

        let entry = &self.entries[idx];
        entry.use_count.fetch_add(1, Ordering::Relaxed);
        Some(&entry.value)
    }

    /// Number of items in the pool.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the pool is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Selection helpers
// ---------------------------------------------------------------------------

/// Pick least-used among a subset of indices.
fn pick_least_used_indices<T>(entries: &[Entry<T>], indices: &[usize]) -> usize {
    let min_count = indices
        .iter()
        .map(|&i| entries[i].use_count.load(Ordering::Relaxed))
        .min()
        .unwrap_or(0);

    let candidates: Vec<usize> = indices
        .iter()
        .copied()
        .filter(|&i| entries[i].use_count.load(Ordering::Relaxed) == min_count)
        .collect();

    if candidates.len() == 1 {
        candidates[0]
    } else {
        candidates[cheap_random() as usize % candidates.len()]
    }
}

fn pick_least_used<T>(entries: &[Entry<T>]) -> usize {
    let min_count = entries
        .iter()
        .map(|e| e.use_count.load(Ordering::Relaxed))
        .min()
        .unwrap_or(0);

    let candidates: Vec<usize> = entries
        .iter()
        .enumerate()
        .filter(|(_, e)| e.use_count.load(Ordering::Relaxed) == min_count)
        .map(|(i, _)| i)
        .collect();

    if candidates.len() == 1 {
        candidates[0]
    } else {
        candidates[cheap_random() as usize % candidates.len()]
    }
}

/// Fast, good-enough random using a thread-local xorshift64.
fn cheap_random() -> u64 {
    use std::cell::Cell;
    thread_local! {
        static STATE: Cell<u64> = Cell::new({
            let t = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64;
            let tid = std::thread::current().id();
            let tid_bits = format!("{:?}", tid);
            let tid_hash = tid_bits
                .bytes()
                .fold(0u64, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u64));
            t ^ tid_hash ^ 0x517cc1b727220a95
        });
    }
    STATE.with(|s| {
        let mut x = s.get();
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        s.set(x);
        x
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};

    #[test]
    fn test_empty_pool_returns_none() {
        let pool: CountingPool<i32> = CountingPool::new(vec![]);
        assert!(pool.next().is_none());
        assert!(pool.is_empty());
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn test_single_item_always_returned() {
        let pool = CountingPool::new(vec!["only"]);
        for _ in 0..10 {
            assert_eq!(pool.next(), Some(&"only"));
        }
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn test_distributes_evenly() {
        let pool = CountingPool::new(vec!["a", "b", "c", "d"]);
        let mut counts: HashMap<&str, usize> = HashMap::new();
        for _ in 0..400 {
            let item = pool.next().unwrap();
            *counts.entry(item).or_default() += 1;
        }
        // Each should get exactly 100.
        for (item, count) in &counts {
            assert_eq!(*count, 100, "item '{item}' got {count}, expected 100");
        }
    }

    #[test]
    fn test_next_excluding_avoids_item() {
        let pool = CountingPool::new(vec!["a", "b"]);
        for _ in 0..10 {
            assert_eq!(pool.next_excluding(&"a"), Some(&"b"));
        }
    }

    #[test]
    fn test_next_excluding_falls_back_when_all_excluded() {
        let pool = CountingPool::new(vec!["only"]);
        assert_eq!(pool.next_excluding(&"only"), Some(&"only"));
    }

    #[test]
    fn test_next_excluding_distributes_among_remaining() {
        let pool = CountingPool::new(vec!["a", "b", "c"]);
        let mut counts: HashMap<&str, usize> = HashMap::new();
        for _ in 0..200 {
            let item = pool.next_excluding(&"a").unwrap();
            assert_ne!(*item, "a");
            *counts.entry(item).or_default() += 1;
        }
        assert_eq!(counts["b"], 100);
        assert_eq!(counts["c"], 100);
    }

    #[test]
    fn test_next_excluding_empty_pool() {
        let pool: CountingPool<&str> = CountingPool::new(vec![]);
        assert!(pool.next_excluding(&"x").is_none());
    }

    #[test]
    fn test_random_varies() {
        // The internal cheap_random should produce different values.
        let mut values = HashSet::new();
        for _ in 0..100 {
            values.insert(cheap_random());
        }
        assert!(
            values.len() > 1,
            "cheap_random should not return the same value every time"
        );
    }
}
