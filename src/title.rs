//! Case-insensitive `<title>` extraction with whitespace squashing.

use crate::util::{squash_whitespace, TITLE_MAX_CHARS, TITLE_SCAN_CAP};
use regex::Regex;
use std::sync::OnceLock;

static TITLE_RE: OnceLock<Regex> = OnceLock::new();

fn re() -> &'static Regex {
    TITLE_RE.get_or_init(|| {
        // (?is) — case-insensitive + dotall (so . matches newlines).
        // [\s\S] kept anyway for engines that don't honour dotall consistently.
        Regex::new(r"(?is)<title[^>]*>([\s\S]*?)</title>")
            .expect("title regex must compile")
    })
}

/// Extract a `<title>` from the first 64 KB of body and return up to 300
/// whitespace-squashed chars. Returns an empty string if no title is found
/// or if the body is not decodable UTF-8 within the scan window.
pub fn extract(body: &[u8]) -> String {
    let end = body.len().min(TITLE_SCAN_CAP);
    let slice = &body[..end];
    // from_utf8_lossy is cheap when the slice IS valid UTF-8 (Cow::Borrowed).
    let text = String::from_utf8_lossy(slice);
    if let Some(cap) = re().captures(&text) {
        if let Some(m) = cap.get(1) {
            return squash_whitespace(m.as_str(), TITLE_MAX_CHARS);
        }
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_simple_title() {
        let body = b"<html><head><title>Welcome</title></head></html>";
        assert_eq!(extract(body), "Welcome");
    }

    #[test]
    fn case_insensitive() {
        let body = b"<HTML><HEAD><TITLE>Yo</TITLE></HEAD></HTML>";
        assert_eq!(extract(body), "Yo");
    }

    #[test]
    fn handles_attrs_on_title_tag() {
        let body = br#"<title data-foo="bar">Page</title>"#;
        assert_eq!(extract(body), "Page");
    }

    #[test]
    fn squashes_internal_whitespace() {
        let body = b"<title>  hello\n\n\n   world  </title>";
        assert_eq!(extract(body), "hello world");
    }

    #[test]
    fn caps_at_300_chars() {
        let huge = "x".repeat(500);
        let body = format!("<title>{}</title>", huge).into_bytes();
        let t = extract(&body);
        assert_eq!(t.chars().count(), 300);
    }

    #[test]
    fn empty_when_missing() {
        let body = b"<html><body>no title here</body></html>";
        assert_eq!(extract(body), "");
    }

    #[test]
    fn dotall_handles_newlines_inside_title() {
        let body = b"<title>line\none\nline two</title>";
        // After whitespace squash: "line one line two"
        assert_eq!(extract(body), "line one line two");
    }
}
