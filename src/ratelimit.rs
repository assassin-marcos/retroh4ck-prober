//! Per-netloc rate limiting via `governor`.
//!
//! Off by default — only constructed when `--rate-limit > 0`. A separate
//! limiter is created per host so one slow site doesn't starve the others.

use governor::{
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter,
};
use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::Arc;
use tokio::sync::Mutex;

type Limiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;

/// Map of host -> per-host limiter. Behind a Mutex for the rare case of
/// concurrent first-touch on a host.
#[derive(Debug, Default)]
pub struct HostRateLimiter {
    rps: u32,
    map: Mutex<HashMap<String, Arc<Limiter>>>,
}

impl HostRateLimiter {
    pub fn new(rps: u32) -> Self {
        Self {
            rps,
            map: Mutex::new(HashMap::new()),
        }
    }

    pub fn enabled(&self) -> bool {
        self.rps > 0
    }

    /// Acquire a permit for `host`. Returns immediately when rate-limiting
    /// is disabled.
    pub async fn acquire(&self, host: &str) {
        if !self.enabled() {
            return;
        }
        let limiter = {
            let mut map = self.map.lock().await;
            if let Some(l) = map.get(host) {
                l.clone()
            } else {
                let q = Quota::per_second(
                    NonZeroU32::new(self.rps).unwrap_or(NonZeroU32::new(1).unwrap()),
                );
                let l = Arc::new(RateLimiter::direct(q));
                map.insert(host.to_string(), l.clone());
                l
            }
        };
        limiter.until_ready().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn disabled_when_rps_zero() {
        let r = HostRateLimiter::new(0);
        assert!(!r.enabled());
        // Returns instantly — no sleep.
        let started = std::time::Instant::now();
        r.acquire("example.com").await;
        assert!(started.elapsed().as_millis() < 50);
    }

    #[tokio::test]
    async fn paces_when_rps_low() {
        let r = HostRateLimiter::new(2); // 2 rps
        let started = std::time::Instant::now();
        // 3 consecutive acquires at 2 rps should take at least ~500 ms total
        // (first burst is free, then 1 / rps delay applies).
        r.acquire("h").await;
        r.acquire("h").await;
        r.acquire("h").await;
        assert!(started.elapsed().as_millis() >= 400);
    }
}
