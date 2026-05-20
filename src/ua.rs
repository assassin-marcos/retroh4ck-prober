//! User-Agent pool — compile-time-embedded `data/user_agents.json` with a
//! per-family pick function so the UA family always matches the TLS
//! impersonation family.

use rand::seq::SliceRandom;
use serde::Deserialize;
use std::sync::OnceLock;

/// Browser family — wreq's `Emulation` enum maps onto these four buckets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Family {
    Chrome,
    Firefox,
    Safari,
    Edge,
}

impl Family {
    #[allow(dead_code)]
    pub fn as_str(&self) -> &'static str {
        match self {
            Family::Chrome => "chrome",
            Family::Firefox => "firefox",
            Family::Safari => "safari",
            Family::Edge => "edge",
        }
    }

    #[allow(dead_code)]
    pub fn all() -> [Family; 4] {
        [Family::Chrome, Family::Firefox, Family::Safari, Family::Edge]
    }
}

/// On-disk JSON layout for `data/user_agents.json`.
#[derive(Debug, Deserialize)]
struct RawPool {
    chrome: Vec<String>,
    firefox: Vec<String>,
    safari: Vec<String>,
    edge: Vec<String>,
}

/// In-memory UA pool keyed by family.
#[derive(Debug)]
pub struct UaPool {
    chrome: Vec<String>,
    firefox: Vec<String>,
    safari: Vec<String>,
    edge: Vec<String>,
}

impl UaPool {
    pub fn family(&self, f: Family) -> &[String] {
        match f {
            Family::Chrome => &self.chrome,
            Family::Firefox => &self.firefox,
            Family::Safari => &self.safari,
            Family::Edge => &self.edge,
        }
    }

    pub fn random(&self, f: Family) -> &str {
        let pool = self.family(f);
        let mut rng = rand::thread_rng();
        pool.choose(&mut rng)
            .map(|s| s.as_str())
            .unwrap_or("Mozilla/5.0 (compatible; retroh4ck-prober/0.1)")
    }
}

/// Compile-time include of the UA dataset.
const UA_JSON: &str = include_str!("../data/user_agents.json");

static UA_POOL: OnceLock<UaPool> = OnceLock::new();

/// Return the global UA pool. Parsed once on first call.
pub fn pool() -> &'static UaPool {
    UA_POOL.get_or_init(|| {
        let raw: RawPool = serde_json::from_str(UA_JSON)
            .expect("compile-time data/user_agents.json must be valid JSON");
        UaPool {
            chrome: raw.chrome,
            firefox: raw.firefox,
            safari: raw.safari,
            edge: raw.edge,
        }
    })
}

/// Convenience — pick a random UA for the given family.
pub fn pick(f: Family) -> &'static str {
    pool().random(f)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_families_have_uas() {
        let p = pool();
        assert!(p.family(Family::Chrome).len() >= 10);
        assert!(p.family(Family::Firefox).len() >= 10);
        assert!(p.family(Family::Safari).len() >= 10);
        assert!(p.family(Family::Edge).len() >= 10);
    }

    #[test]
    fn ua_strings_start_with_mozilla() {
        let p = pool();
        for f in Family::all() {
            for ua in p.family(f) {
                assert!(
                    ua.starts_with("Mozilla/5.0"),
                    "non-mozilla UA in {:?}: {}",
                    f,
                    ua
                );
            }
        }
    }

    #[test]
    fn pick_returns_correct_family_marker() {
        // Chrome UAs do NOT contain "Firefox/" — sanity check the family routing.
        for _ in 0..10 {
            let chrome = pick(Family::Chrome);
            assert!(!chrome.contains("Firefox/"));
            assert!(chrome.contains("Chrome/"));
        }
        for _ in 0..10 {
            let firefox = pick(Family::Firefox);
            assert!(firefox.contains("Firefox/"));
            assert!(!firefox.contains("Chrome/"));
        }
    }
}
