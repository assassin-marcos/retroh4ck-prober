//! Small utilities — path normalisation, random hex strings, body-preview
//! HTML-entity encoding (httpx-parity), elapsed time helpers.
//!
//! The encoding rules here are the **single critical compatibility surface**
//! with `httpx_probe_engine.py:1480+` — production runs `html.unescape()`
//! before regex matching, so we must encode the same set of characters in
//! the same order.

use rand::Rng;

/// Maximum body bytes the prober reads from the wire.
/// Bigger than that and we let the connection drop — SPEC §"Body capture cap".
pub const BODY_READ_CAP: usize = 256 * 1024;

/// Title regex is run against at most this many bytes of the body — plenty
/// for any sane `<title>` and keeps the per-probe parse cost bounded.
pub const TITLE_SCAN_CAP: usize = 64 * 1024;

/// Hard cap on the title's final length (chars, not bytes). SPEC says 300.
pub const TITLE_MAX_CHARS: usize = 300;

/// Normalise a wordlist entry to a path:
/// - trim whitespace
/// - empty → `/`
/// - collapse leading `//+` to a single `/`
/// - prepend `/` when missing
pub fn normalize_path(raw: &str) -> String {
    let s = raw.trim();
    if s.is_empty() {
        return "/".to_string();
    }
    let bytes = s.as_bytes();
    if bytes[0] == b'/' {
        // Count leading slashes
        let mut i = 0usize;
        while i < bytes.len() && bytes[i] == b'/' {
            i += 1;
        }
        if i > 1 {
            return format!("/{}", &s[i..]);
        }
        s.to_string()
    } else {
        format!("/{}", s)
    }
}

/// Normalise a host line: trim, strip trailing `/`, drop if empty.
/// Returns `None` for empty/blank entries.
pub fn normalize_host(raw: &str) -> Option<String> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    let trimmed = s.trim_end_matches('/');
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Random hex path of length `n`, prefixed with `/`.
/// Used by the wildcard detector to ask the server "do you 200 for ANY path?".
pub fn random_hex_path(n: usize) -> String {
    let mut rng = rand::thread_rng();
    let mut out = String::with_capacity(n + 1);
    out.push('/');
    for _ in 0..n {
        let nibble: u8 = rng.gen_range(0..16);
        let c = if nibble < 10 {
            (b'0' + nibble) as char
        } else {
            (b'a' + (nibble - 10)) as char
        };
        out.push(c);
    }
    out
}

/// Trim error strings to first 120 chars, replace newlines with spaces.
pub fn short_err(s: &str) -> String {
    let mut buf: String = s.chars().take(120).collect();
    if buf.contains('\n') || buf.contains('\r') {
        buf = buf.replace('\n', " ").replace('\r', " ");
    }
    buf
}

/// HTML-entity-encode a body preview the same way httpx does so that
/// `html.unescape()` in production round-trips correctly.
///
/// **Order matters** — `&` must be replaced FIRST. Otherwise the entities
/// we introduce (`&#34;`, `&lt;`, `&gt;`) get their leading `&` re-encoded.
pub fn html_escape_body_preview(s: &str) -> String {
    // Pre-grow buffer to roughly the worst case (×6 if every char is `&`).
    // In practice growth is tiny — we just want one allocation.
    let mut out = String::with_capacity(s.len() + 16);
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&#34;"),
            other => out.push(other),
        }
    }
    out
}

/// Truncate a byte slice to `max_bytes` on a UTF-8 character boundary, then
/// return as `String` (lossy — invalid sequences become U+FFFD).
pub fn truncate_to_string_lossy(body: &[u8], max_bytes: usize) -> String {
    let end = body.len().min(max_bytes);
    let slice = &body[..end];
    String::from_utf8_lossy(slice).into_owned()
}

/// Squash internal whitespace into single spaces and trim ends.
/// Stops accumulating once the resulting char count hits `max_chars`.
pub fn squash_whitespace(input: &str, max_chars: usize) -> String {
    let trimmed = input.trim();
    let mut out = String::with_capacity(trimmed.len().min(max_chars * 4));
    let mut prev_space = false;
    let mut chars_emitted = 0usize;
    for ch in trimmed.chars() {
        if chars_emitted >= max_chars {
            break;
        }
        if ch.is_whitespace() {
            if !prev_space {
                out.push(' ');
                prev_space = true;
                chars_emitted += 1;
            }
        } else {
            out.push(ch);
            prev_space = false;
            chars_emitted += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_path_cases() {
        assert_eq!(normalize_path(""), "/");
        assert_eq!(normalize_path("   "), "/");
        assert_eq!(normalize_path("admin"), "/admin");
        assert_eq!(normalize_path("/admin"), "/admin");
        assert_eq!(normalize_path("//admin"), "/admin");
        assert_eq!(normalize_path("///admin/x"), "/admin/x");
        assert_eq!(normalize_path("  /env  "), "/env");
    }

    #[test]
    fn normalize_host_cases() {
        assert_eq!(normalize_host(""), None);
        assert_eq!(normalize_host("   "), None);
        assert_eq!(normalize_host("https://x.com"), Some("https://x.com".to_string()));
        assert_eq!(normalize_host("https://x.com/"), Some("https://x.com".to_string()));
        assert_eq!(normalize_host("https://x.com///"), Some("https://x.com".to_string()));
    }

    #[test]
    fn html_escape_order_matters() {
        // The classic bug: encode `&` last → `&lt;` becomes `&amp;lt;`.
        // Our impl encodes `&` first, so this round-trip works.
        assert_eq!(html_escape_body_preview("<a>"), "&lt;a&gt;");
        assert_eq!(html_escape_body_preview("\"foo\""), "&#34;foo&#34;");
        assert_eq!(html_escape_body_preview("a & b"), "a &amp; b");
        assert_eq!(
            html_escape_body_preview("<p class=\"x\">&"),
            "&lt;p class=&#34;x&#34;&gt;&amp;"
        );
    }

    #[test]
    fn random_hex_path_is_well_formed() {
        for _ in 0..32 {
            let p = random_hex_path(32);
            assert_eq!(p.len(), 33); // "/" + 32 hex chars
            assert!(p.starts_with('/'));
            assert!(p[1..].chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        }
    }

    #[test]
    fn squash_whitespace_caps() {
        assert_eq!(squash_whitespace("   hello   world   ", 100), "hello world");
        let many = "x ".repeat(500);
        let out = squash_whitespace(&many, 10);
        // Each "x " is 2 chars after squash; 10 chars → 5 "x " pairs
        assert!(out.chars().count() <= 10);
    }
}
