use crate::config::{ProxySet, UpstreamProxy};

use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

/// A proxy rotator that manages multiple proxy sets.
/// Each set picks the least-used proxy (with random tie-breaking)
/// and supports per-request session affinity. The affinity key is the raw
/// base64 username string (which encodes the full JSON object), so identical
/// inputs always resolve to the same sticky session.
///
/// Sessions are assigned a monotonically-incrementing `session_id` (starting at 0)
/// for internal identification and observability.
pub struct Rotator {
    sets: Vec<RotatorSet>,
    /// Global session ID counter. Incremented atomically on each new affinity entry.
    next_session_id: AtomicU64,
}

struct RotatorSet {
    name: String,
    proxies: Vec<ProxyEntry>,
    /// Dynamic affinity table: keyed by the raw username_b64 string, which
    /// encodes the full JSON (set, minutes, meta), so it uniquely identifies
    /// a session without any further parsing.
    affinity_map: DashMap<String, AffinityEntry>,
}

struct ProxyEntry {
    proxy: UpstreamProxy,
    use_count: AtomicU64,
}

struct AffinityEntry {
    /// Monotonically-incrementing identifier assigned at session creation.
    session_id: u64,
    proxy_index: usize,
    /// Monotonic instant when the session was created — used for TTL expiry checks.
    started_at: Instant,
    /// Pre-formatted ISO 8601 UTC string of the session creation time. Never changes.
    created_at: String,
    /// Wall time when the current proxy assignment expires — exposed as `next_rotation_at`.
    /// Reset to `now + duration` on every `force_rotate`.
    next_rotation_at: SystemTime,
    /// Wall time of the most recent proxy assignment. Equals creation time initially;
    /// updated to `SystemTime::now()` on every `force_rotate`.
    last_rotation_at: SystemTime,
    duration: Duration,
    /// The decoded, validated metadata object from the base64-JSON username segment.
    metadata: serde_json::Map<String, serde_json::Value>,
}

/// The resolved upstream proxy for a request.
#[derive(Debug, Clone)]
pub struct ResolvedProxy {
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

/// Info about an active session, returned by the API.
#[derive(Debug, Clone, serde::Serialize, utoipa::ToSchema)]
pub struct SessionInfo {
    /// Internal session identifier, assigned at creation (starts at 0, increments per session).
    #[schema(example = 0)]
    pub session_id: u64,
    /// The full username: `<proxyset>-<minutes>-<base64json>`
    #[schema(example = "residential-5-eyJhcHAiOiJteWFwcCIsInVzZXIiOiJhbGljZSJ9")]
    pub username: String,
    /// The proxy set name.
    #[schema(example = "residential")]
    pub proxy_set: String,
    /// The upstream proxy address (host:port).
    #[schema(example = "198.51.100.1:6658")]
    pub upstream: String,
    /// Session start time — when the session was first created (ISO 8601 UTC). Never changes.
    #[schema(example = "2026-02-23T21:00:00Z")]
    pub created_at: String,
    /// When the current proxy assignment expires (ISO 8601 UTC). Reset on force_rotate.
    #[schema(example = "2026-02-23T22:00:00Z")]
    pub next_rotation_at: String,
    /// When the proxy was last assigned — equals created_at unless force_rotate was called (ISO 8601 UTC).
    #[schema(example = "2026-02-23T21:00:00Z")]
    pub last_rotation_at: String,
    /// The decoded metadata object from the base64-JSON username segment.
    pub metadata: serde_json::Map<String, serde_json::Value>,
}

/// Error response body.
#[derive(Debug, Clone, serde::Serialize, utoipa::ToSchema)]
pub struct ApiError {
    /// Error message.
    #[schema(example = "No active session for 'residential-5-eyJhcHAiOiJteWFwcCJ9'")]
    pub error: String,
}

/// Result of a username verification check.
#[derive(Debug, Clone, serde::Serialize, utoipa::ToSchema)]
pub struct VerifyResult {
    /// Whether all checks passed.
    #[schema(example = true)]
    pub ok: bool,
    /// The proxy set name parsed from the username.
    #[schema(example = "residential")]
    pub proxy_set: String,
    /// Affinity minutes parsed from the username.
    #[schema(example = 60)]
    pub minutes: u16,
    /// The decoded metadata object from the username.
    pub metadata: serde_json::Map<String, serde_json::Value>,
    /// The upstream proxy that would be used (host:port).
    #[schema(example = "198.51.100.1:6658")]
    pub upstream: String,
    /// The outbound IP address as seen by the internet, fetched through the proxy.
    #[schema(example = "198.51.100.1")]
    pub ip: String,
    /// Error message if any check failed, absent when ok=true.
    #[schema(example = "Unknown proxy set 'badset'")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Rotator {
    /// Build from loaded proxy sets.
    pub fn new(sets: Vec<ProxySet>) -> Self {
        let sets = sets
            .into_iter()
            .map(|ps| {
                let proxies = ps
                    .proxies
                    .into_iter()
                    .map(|p| ProxyEntry {
                        proxy: p,
                        use_count: AtomicU64::new(0),
                    })
                    .collect();
                RotatorSet {
                    name: ps.name,
                    proxies,
                    affinity_map: DashMap::new(),
                }
            })
            .collect();
        Self {
            sets,
            next_session_id: AtomicU64::new(0),
        }
    }

    /// Find a proxy set by name and return the next proxy.
    /// `affinity_minutes` controls sticky session duration (0 = no affinity).
    /// `meta_b64` is the raw base64 segment used as the affinity map key.
    /// `metadata` is the decoded, validated JSON fields stored in the session entry.
    pub fn next_proxy(
        &self,
        set_name: &str,
        affinity_minutes: u16,
        meta_b64: &str,
        metadata: serde_json::Map<String, serde_json::Value>,
    ) -> Option<ResolvedProxy> {
        let set = self.sets.iter().find(|s| s.name == set_name)?;
        let proxy = set.pick(affinity_minutes, meta_b64, metadata, &self.next_session_id);
        Some(ResolvedProxy {
            host: proxy.host.clone(),
            port: proxy.port,
            username: proxy.username.clone(),
            password: proxy.password.clone(),
        })
    }

    /// Force-rotate the upstream proxy for an existing session.
    ///
    /// Picks a new upstream via least-used selection and resets the session's
    /// start/end times to now + original duration. The session_id, metadata,
    /// and duration are preserved. Returns the updated SessionInfo, or None if
    /// no active session exists for the given username.
    pub fn force_rotate(&self, username: &str) -> Option<SessionInfo> {
        for set in &self.sets {
            if let Some(mut entry) = set.affinity_map.get_mut(username) {
                if entry.started_at.elapsed() >= entry.duration {
                    return None; // expired — treat as not found
                }
                let new_idx = set.pick_least_used();
                let now = SystemTime::now();
                entry.proxy_index = new_idx;
                entry.last_rotation_at = now;
                entry.next_rotation_at = now + entry.duration;

                let proxy = &set.proxies[new_idx].proxy;

                return Some(SessionInfo {
                    session_id: entry.session_id,
                    username: username.to_string(),
                    proxy_set: set.name.clone(),
                    upstream: format!("{}:{}", proxy.host, proxy.port),
                    created_at: entry.created_at.clone(),
                    next_rotation_at: format_system_time(entry.next_rotation_at),
                    last_rotation_at: format_system_time(entry.last_rotation_at),
                    metadata: entry.metadata.clone(),
                });
            }
        }
        None
    }

    /// Pick a proxy from a named set without creating an affinity entry.
    /// Used for pre-flight verification checks.
    pub fn pick_any(&self, set_name: &str) -> Option<ResolvedProxy> {
        let set = self.sets.iter().find(|s| s.name == set_name)?;
        let idx = set.pick_least_used();
        let proxy = &set.proxies[idx].proxy;
        Some(ResolvedProxy {
            host: proxy.host.clone(),
            port: proxy.port,
            username: proxy.username.clone(),
            password: proxy.password.clone(),
        })
    }

    /// List all available proxy set names.
    pub fn set_names(&self) -> Vec<&str> {
        self.sets.iter().map(|s| s.name.as_str()).collect()
    }

    /// Get stats about a proxy set: proxy count.
    pub fn set_info(&self, name: &str) -> Option<usize> {
        self.sets
            .iter()
            .find(|s| s.name == name)
            .map(|s| s.proxies.len())
    }

    /// Get session info for a specific username.
    ///
    /// The username is the raw base64 string that was used as the
    /// `Proxy-Authorization` username — i.e. `base64({"meta":{...},"minutes":N,"set":"..."})`.
    /// It is used directly as the affinity map key, so no parsing is needed here.
    ///
    /// Returns None if there is no active (non-expired) session for this key.
    pub fn get_session(&self, username: &str) -> Option<SessionInfo> {
        // The username_b64 is the affinity map key directly.
        // We search all sets for a matching entry.
        for set in &self.sets {
            if let Some(entry) = set.affinity_map.get(username) {
                if entry.started_at.elapsed() >= entry.duration {
                    return None;
                }
                let proxy = &set.proxies[entry.proxy_index].proxy;

                return Some(SessionInfo {
                    session_id: entry.session_id,
                    username: username.to_string(),
                    proxy_set: set.name.clone(),
                    upstream: format!("{}:{}", proxy.host, proxy.port),
                    created_at: entry.created_at.clone(),
                    next_rotation_at: format_system_time(entry.next_rotation_at),
                    last_rotation_at: format_system_time(entry.last_rotation_at),
                    metadata: entry.metadata.clone(),
                });
            }
        }
        None
    }

    /// List all active (non-expired) sessions across all proxy sets.
    pub fn list_sessions(&self) -> Vec<SessionInfo> {
        let mut sessions = Vec::new();
        for set in &self.sets {
            for entry_ref in set.affinity_map.iter() {
                let affinity_key = entry_ref.key();
                let entry = entry_ref.value();

                // Skip expired entries.
                if entry.started_at.elapsed() >= entry.duration {
                    continue;
                }

                // The affinity key IS the username_b64.
                let username = affinity_key.clone();

                let proxy = &set.proxies[entry.proxy_index].proxy;

                sessions.push(SessionInfo {
                    session_id: entry.session_id,
                    username,
                    proxy_set: set.name.clone(),
                    upstream: format!("{}:{}", proxy.host, proxy.port),
                    created_at: entry.created_at.clone(),
                    next_rotation_at: format_system_time(entry.next_rotation_at),
                    last_rotation_at: format_system_time(entry.last_rotation_at),
                    metadata: entry.metadata.clone(),
                });
            }
        }
        sessions
    }
}

impl RotatorSet {
    /// Pick the upstream proxy for a request.
    ///
    /// When `affinity_minutes > 0`, the same `username_b64` key always resolves
    /// to the same proxy for the duration of the session. A new `session_id` is
    /// allocated from `id_counter` only when a fresh entry is created.
    fn pick(
        &self,
        affinity_minutes: u16,
        username_b64: &str,
        metadata: serde_json::Map<String, serde_json::Value>,
        id_counter: &AtomicU64,
    ) -> &UpstreamProxy {
        if affinity_minutes == 0 {
            // No affinity — pure least-used selection.
            let idx = self.pick_least_used();
            return &self.proxies[idx].proxy;
        }

        let duration = Duration::from_secs(affinity_minutes as u64 * 60);

        // Check for a valid existing affinity entry.
        if let Some(entry) = self.affinity_map.get(username_b64) {
            if entry.started_at.elapsed() < entry.duration {
                let idx = entry.proxy_index;
                self.proxies[idx].use_count.fetch_add(1, Ordering::Relaxed);
                return &self.proxies[idx].proxy;
            }
        }

        // Assign via least-used selection and allocate a new session ID.
        let idx = self.pick_least_used();
        let session_id = id_counter.fetch_add(1, Ordering::Relaxed);
        let now_wall = SystemTime::now();
        self.affinity_map.insert(
            username_b64.to_string(),
            AffinityEntry {
                session_id,
                proxy_index: idx,
                started_at: Instant::now(),
                created_at: format_system_time(now_wall),
                next_rotation_at: now_wall + duration,
                last_rotation_at: now_wall,
                duration,
                metadata,
            },
        );
        &self.proxies[idx].proxy
    }

    /// Pick the proxy with the lowest use_count.
    /// When multiple proxies share the minimum count, pick one at random.
    fn pick_least_used(&self) -> usize {
        let min_count = self
            .proxies
            .iter()
            .map(|p| p.use_count.load(Ordering::Relaxed))
            .min()
            .unwrap_or(0);

        let candidates: Vec<usize> = self
            .proxies
            .iter()
            .enumerate()
            .filter(|(_, p)| p.use_count.load(Ordering::Relaxed) == min_count)
            .map(|(i, _)| i)
            .collect();

        let idx = if candidates.len() == 1 {
            candidates[0]
        } else {
            let r = cheap_random() as usize % candidates.len();
            candidates[r]
        };

        self.proxies[idx].use_count.fetch_add(1, Ordering::Relaxed);
        idx
    }
}

/// Format a SystemTime as ISO 8601 (UTC) without external crate.
fn format_system_time(t: SystemTime) -> String {
    let dur = t.duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default();
    let secs = dur.as_secs();

    // Manual UTC breakdown.
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Days since 1970-01-01 → year/month/day.
    let (year, month, day) = days_to_ymd(days as i64);

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, minutes, seconds
    )
}

fn days_to_ymd(mut days: i64) -> (i64, u32, u32) {
    // Algorithm from http://howardhinnant.github.io/date_algorithms.html
    days += 719468;
    let era = if days >= 0 { days } else { days - 146096 } / 146097;
    let doe = (days - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Fast, good-enough random using thread-local xorshift64.
fn cheap_random() -> u64 {
    use std::cell::Cell;
    thread_local! {
        static STATE: Cell<u64> = Cell::new(
            {
                let t = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos() as u64;
                let tid = std::thread::current().id();
                let tid_bits = format!("{:?}", tid);
                let tid_hash = tid_bits.bytes().fold(0u64, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u64));
                t ^ tid_hash ^ 0x517cc1b727220a95
            }
        );
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

/// Periodically clean up expired affinity entries.
pub fn spawn_affinity_cleanup(rotator: Arc<Rotator>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            for set in &rotator.sets {
                let before = set.affinity_map.len();
                set.affinity_map
                    .retain(|_, entry| entry.started_at.elapsed() < entry.duration);
                let removed = before - set.affinity_map.len();
                if removed > 0 {
                    tracing::debug!(
                        "Cleaned {removed} expired affinity entries from set '{}'",
                        set.name
                    );
                }
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Helpers for tests
// ---------------------------------------------------------------------------

/// Build the base64 username string as the proxy client would — encodes the
/// full `{"meta":{...},"minutes":N,"set":"..."}` JSON object.
#[cfg(test)]
pub fn make_username_b64(set: &str, minutes: u16, meta_pairs: &[(&str, &str)]) -> String {
    use base64::Engine;
    let mut meta = serde_json::Map::new();
    for (k, v) in meta_pairs {
        meta.insert(k.to_string(), serde_json::Value::String(v.to_string()));
    }
    let json = serde_json::json!({
        "meta": meta,
        "minutes": minutes,
        "set": set,
    });
    base64::engine::general_purpose::STANDARD.encode(json.to_string())
}

#[cfg(test)]
pub fn empty_metadata() -> serde_json::Map<String, serde_json::Value> {
    serde_json::Map::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ProxySet, UpstreamProxy};
    use std::collections::HashMap;

    fn make_test_set(n: usize) -> ProxySet {
        let proxies = (0..n)
            .map(|i| UpstreamProxy {
                host: format!("proxy{i}.example.com"),
                port: 8080,
                username: Some("testuser".to_string()),
                password: Some("testpass".to_string()),
            })
            .collect();
        ProxySet {
            name: "test".to_string(),
            proxies,
        }
    }

    #[test]
    fn test_least_used_distributes_evenly() {
        let rotator = Rotator::new(vec![make_test_set(4)]);
        let b64 = make_username_b64("test", 0, &[("k", "v")]);

        let mut counts: HashMap<String, usize> = HashMap::new();
        for _ in 0..400 {
            let p = rotator
                .next_proxy("test", 0, &b64, empty_metadata())
                .unwrap();
            *counts.entry(p.host.clone()).or_default() += 1;
        }

        assert_eq!(counts.len(), 4);
        for (host, count) in &counts {
            assert!(*count == 100, "Expected 100 for {host}, got {count}");
        }
    }

    #[test]
    fn test_credentials_from_proxy_entry() {
        let rotator = Rotator::new(vec![make_test_set(1)]);
        let b64 = make_username_b64("test", 0, &[("k", "v")]);
        let p = rotator
            .next_proxy("test", 0, &b64, empty_metadata())
            .unwrap();
        assert_eq!(p.username.as_deref(), Some("testuser"));
        assert_eq!(p.password.as_deref(), Some("testpass"));
    }

    #[test]
    fn test_session_affinity_with_minutes() {
        let rotator = Rotator::new(vec![make_test_set(4)]);
        let b64 = make_username_b64("test", 5, &[("session", "sess1")]);

        let p1a = rotator
            .next_proxy("test", 5, &b64, empty_metadata())
            .unwrap();
        let p1b = rotator
            .next_proxy("test", 5, &b64, empty_metadata())
            .unwrap();
        assert_eq!(p1a.host, p1b.host, "Same session key should get same proxy");

        let b64_2 = make_username_b64("test", 5, &[("session", "sess2")]);
        let p2 = rotator
            .next_proxy("test", 5, &b64_2, empty_metadata())
            .unwrap();
        assert!(p2.host.starts_with("proxy"));
    }

    #[test]
    fn test_zero_minutes_no_affinity() {
        let rotator = Rotator::new(vec![make_test_set(4)]);
        let b64 = make_username_b64("test", 0, &[("k", "samekey")]);

        let mut hosts = Vec::new();
        for _ in 0..4 {
            let p = rotator
                .next_proxy("test", 0, &b64, empty_metadata())
                .unwrap();
            hosts.push(p.host);
        }
        hosts.sort();
        hosts.dedup();
        assert_eq!(
            hosts.len(),
            4,
            "0 minutes should distribute across all proxies"
        );
    }

    #[test]
    fn test_different_session_keys_independent_affinity() {
        let rotator = Rotator::new(vec![make_test_set(4)]);
        let b64_a = make_username_b64("test", 10, &[("session", "sessA")]);
        let b64_b = make_username_b64("test", 10, &[("session", "sessB")]);

        let pa1 = rotator
            .next_proxy("test", 10, &b64_a, empty_metadata())
            .unwrap();
        let pa2 = rotator
            .next_proxy("test", 10, &b64_a, empty_metadata())
            .unwrap();
        assert_eq!(pa1.host, pa2.host, "Same session should get same proxy");

        let pb1 = rotator
            .next_proxy("test", 10, &b64_b, empty_metadata())
            .unwrap();
        let pb2 = rotator
            .next_proxy("test", 10, &b64_b, empty_metadata())
            .unwrap();
        assert_eq!(pb1.host, pb2.host, "Same session should get same proxy");
    }

    #[test]
    fn test_unknown_set_returns_none() {
        let rotator = Rotator::new(vec![make_test_set(2)]);
        let b64 = make_username_b64("nonexistent", 0, &[("k", "v")]);
        assert!(rotator
            .next_proxy("nonexistent", 0, &b64, empty_metadata())
            .is_none());
    }

    #[test]
    fn test_cheap_random_varies() {
        let mut vals = Vec::new();
        for _ in 0..100 {
            vals.push(cheap_random());
        }
        vals.sort();
        vals.dedup();
        assert!(
            vals.len() > 50,
            "Expected varied random output, got {} unique values",
            vals.len()
        );
    }

    #[test]
    fn test_get_session_active() {
        let rotator = Rotator::new(vec![make_test_set(4)]);
        let b64 = make_username_b64("test", 5, &[("session", "mysess")]);

        let p = rotator
            .next_proxy("test", 5, &b64, empty_metadata())
            .unwrap();

        // get_session uses the username_b64 directly as the key.
        let info = rotator.get_session(&b64).unwrap();
        assert_eq!(info.proxy_set, "test");
        assert_eq!(info.username, b64);
        assert_eq!(info.upstream, format!("{}:{}", p.host, p.port));
        assert!(!info.created_at.is_empty());
        assert!(!info.next_rotation_at.is_empty());
    }

    #[test]
    fn test_get_session_no_affinity_returns_none() {
        let rotator = Rotator::new(vec![make_test_set(4)]);
        let b64 = make_username_b64("test", 0, &[("session", "nosess")]);

        rotator
            .next_proxy("test", 0, &b64, empty_metadata())
            .unwrap();
        assert!(rotator.get_session(&b64).is_none());
    }

    #[test]
    fn test_get_session_unknown_returns_none() {
        let rotator = Rotator::new(vec![make_test_set(4)]);
        assert!(rotator.get_session("unknownkey").is_none());
        assert!(rotator.get_session("").is_none());
    }

    #[test]
    fn test_list_sessions() {
        let rotator = Rotator::new(vec![make_test_set(4)]);
        let b64_a = make_username_b64("test", 5, &[("session", "sessA")]);
        let b64_b = make_username_b64("test", 10, &[("session", "sessB")]);
        let b64_noaff = make_username_b64("test", 0, &[("session", "noaff")]);

        rotator
            .next_proxy("test", 5, &b64_a, empty_metadata())
            .unwrap();
        rotator
            .next_proxy("test", 10, &b64_b, empty_metadata())
            .unwrap();
        rotator
            .next_proxy("test", 0, &b64_noaff, empty_metadata())
            .unwrap(); // won't appear

        let sessions = rotator.list_sessions();
        assert_eq!(sessions.len(), 2);

        let usernames: Vec<&str> = sessions.iter().map(|s| s.username.as_str()).collect();
        assert!(usernames.contains(&b64_a.as_str()));
        assert!(usernames.contains(&b64_b.as_str()));
    }

    #[test]
    fn test_session_ids_are_unique() {
        let rotator = Rotator::new(vec![make_test_set(4)]);
        let b64_a = make_username_b64("test", 5, &[("session", "a")]);
        let b64_b = make_username_b64("test", 5, &[("session", "b")]);
        let b64_c = make_username_b64("test", 5, &[("session", "c")]);

        rotator
            .next_proxy("test", 5, &b64_a, empty_metadata())
            .unwrap();
        rotator
            .next_proxy("test", 5, &b64_b, empty_metadata())
            .unwrap();
        rotator
            .next_proxy("test", 5, &b64_c, empty_metadata())
            .unwrap();

        let mut sessions = rotator.list_sessions();
        sessions.sort_by_key(|s| s.session_id);

        let ids: Vec<u64> = sessions.iter().map(|s| s.session_id).collect();
        let mut deduped = ids.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(ids.len(), deduped.len(), "Session IDs must be unique");
    }

    #[test]
    fn test_session_id_increments() {
        let rotator = Rotator::new(vec![make_test_set(4)]);
        let b64_a = make_username_b64("test", 5, &[("session", "a")]);
        let b64_b = make_username_b64("test", 5, &[("session", "b")]);
        let b64_c = make_username_b64("test", 5, &[("session", "c")]);

        rotator
            .next_proxy("test", 5, &b64_a, empty_metadata())
            .unwrap();
        rotator
            .next_proxy("test", 5, &b64_b, empty_metadata())
            .unwrap();
        rotator
            .next_proxy("test", 5, &b64_c, empty_metadata())
            .unwrap();

        let mut sessions = rotator.list_sessions();
        sessions.sort_by_key(|s| s.session_id);

        assert_eq!(sessions[0].session_id, 0);
        assert_eq!(sessions[1].session_id, 1);
        assert_eq!(sessions[2].session_id, 2);
    }

    #[test]
    fn test_force_rotate_changes_upstream() {
        // With 4 proxies and one session, force_rotate must pick a different proxy
        // at least sometimes. Run it multiple times to confirm it can change.
        let rotator = Rotator::new(vec![make_test_set(4)]);
        let b64 = make_username_b64("test", 60, &[("session", "rot")]);

        let original = rotator
            .next_proxy("test", 60, &b64, empty_metadata())
            .unwrap();

        // Force-rotate until we get a different proxy (or give up after 20 tries).
        let mut rotated_upstream = original.host.clone();
        for _ in 0..20 {
            let info = rotator.force_rotate(&b64).unwrap();
            rotated_upstream = info.upstream.split(':').next().unwrap().to_string();
            if rotated_upstream != original.host {
                break;
            }
        }
        // The rotator has 4 proxies; it's overwhelmingly likely we get a new one.
        assert_ne!(
            rotated_upstream, original.host,
            "force_rotate should assign a different upstream"
        );
    }

    #[test]
    fn test_force_rotate_preserves_session_id_and_metadata() {
        let rotator = Rotator::new(vec![make_test_set(4)]);
        let b64 = make_username_b64("test", 60, &[("session", "preserve")]);

        rotator
            .next_proxy("test", 60, &b64, empty_metadata())
            .unwrap();
        let before = rotator.get_session(&b64).unwrap();

        rotator.force_rotate(&b64).unwrap();
        let after = rotator.get_session(&b64).unwrap();

        assert_eq!(
            before.session_id, after.session_id,
            "session_id must be preserved"
        );
        assert_eq!(before.proxy_set, after.proxy_set);
        assert_eq!(before.username, after.username);
    }

    #[test]
    fn test_force_rotate_resets_ttl() {
        let rotator = Rotator::new(vec![make_test_set(4)]);
        let b64 = make_username_b64("test", 60, &[("session", "ttl")]);

        rotator
            .next_proxy("test", 60, &b64, empty_metadata())
            .unwrap();
        let before = rotator.get_session(&b64).unwrap();

        // Small sleep to ensure wall time advances
        std::thread::sleep(std::time::Duration::from_millis(10));

        rotator.force_rotate(&b64).unwrap();
        let after = rotator.get_session(&b64).unwrap();

        assert!(
            after.next_rotation_at >= before.next_rotation_at,
            "next_rotation_at should not move backwards"
        );
    }

    #[test]
    fn test_force_rotate_unknown_returns_none() {
        let rotator = Rotator::new(vec![make_test_set(4)]);
        assert!(rotator.force_rotate("nosuchkey").is_none());
    }

    #[test]
    fn test_format_system_time_epoch() {
        let epoch = SystemTime::UNIX_EPOCH;
        assert_eq!(format_system_time(epoch), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn test_format_system_time_known_date() {
        // 2025-06-15T15:10:45Z = 1750000245 seconds since epoch
        let t = SystemTime::UNIX_EPOCH + Duration::from_secs(1750000245);
        assert_eq!(format_system_time(t), "2025-06-15T15:10:45Z");
    }
}
