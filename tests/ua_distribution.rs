//! Compile-time UA dataset sanity checks. Catches accidental dataset breakage
//! at `cargo test` time before it ships.

use serde::Deserialize;
use std::collections::HashSet;

#[derive(Debug, Deserialize)]
struct Pool {
    chrome: Vec<String>,
    firefox: Vec<String>,
    safari: Vec<String>,
    edge: Vec<String>,
}

fn load_pool() -> Pool {
    let raw = include_str!("../data/user_agents.json");
    serde_json::from_str(raw).expect("data/user_agents.json must be valid JSON")
}

#[test]
fn each_family_has_at_least_10_entries() {
    let p = load_pool();
    assert!(p.chrome.len() >= 10, "chrome UA count = {}", p.chrome.len());
    assert!(p.firefox.len() >= 10, "firefox UA count = {}", p.firefox.len());
    assert!(p.safari.len() >= 10, "safari UA count = {}", p.safari.len());
    assert!(p.edge.len() >= 10, "edge UA count = {}", p.edge.len());
}

#[test]
fn no_duplicates_within_a_family() {
    let p = load_pool();
    for (name, list) in [
        ("chrome", &p.chrome),
        ("firefox", &p.firefox),
        ("safari", &p.safari),
        ("edge", &p.edge),
    ] {
        let set: HashSet<&String> = list.iter().collect();
        assert_eq!(
            set.len(),
            list.len(),
            "{name} has duplicates: {} unique vs {} total",
            set.len(),
            list.len()
        );
    }
}

#[test]
fn every_ua_starts_with_mozilla_5_0() {
    let p = load_pool();
    for list in [&p.chrome, &p.firefox, &p.safari, &p.edge] {
        for ua in list {
            assert!(
                ua.starts_with("Mozilla/5.0"),
                "non-Mozilla UA: {}",
                ua
            );
        }
    }
}

#[test]
fn family_markers_match_browser() {
    let p = load_pool();
    // Chrome UAs must contain "Chrome/" but not "Firefox/", not "Edg/"
    for ua in &p.chrome {
        assert!(ua.contains("Chrome/"), "chrome missing marker: {}", ua);
        assert!(!ua.contains("Firefox/"), "chrome leaks Firefox: {}", ua);
        assert!(!ua.contains("Edg/"), "chrome leaks Edge: {}", ua);
    }
    for ua in &p.firefox {
        assert!(ua.contains("Firefox/"), "firefox missing marker: {}", ua);
        assert!(!ua.contains("Chrome/"), "firefox leaks Chrome: {}", ua);
    }
    for ua in &p.safari {
        assert!(ua.contains("Safari/"), "safari missing marker: {}", ua);
        // Safari UA contains Version/<n> too — sanity-check it.
        assert!(ua.contains("Version/"), "safari missing Version/: {}", ua);
    }
    for ua in &p.edge {
        // Edge UAs always contain "Edg/" (NOT "Edge/" — Chromium-based Edge).
        assert!(ua.contains("Edg/"), "edge missing Edg/ marker: {}", ua);
        // Edge is also Chromium so it has Chrome/ — sanity check.
        assert!(ua.contains("Chrome/"), "edge missing Chrome/ base: {}", ua);
    }
}
