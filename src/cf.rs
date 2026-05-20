//! Cloudflare challenge detection.
//!
//! A response is flagged `cf_challenge:true` when ANY of:
//! - Status 403 AND `Server: cloudflare` AND body contains `cf-chl-bypass` or
//!   `__cf_chl_jschl_tk__`
//! - Status 503 AND body contains `Just a moment...` AND body contains
//!   `cf-error-details`
//! - `cf-mitigated` response header is present (always — record value too)

/// Outcome of CF detection.
#[derive(Debug, Clone, Default)]
pub struct CfVerdict {
    pub challenge: bool,
    pub mitigated: Option<String>,
}

impl CfVerdict {
    pub fn none() -> Self {
        Self::default()
    }
}

/// Detect CF challenge from response signals.
///
/// `headers_iter` should iterate over `(name_lowercase, value)` pairs.
/// `body_head` should be the first ~2 KB of body in lossy UTF-8.
pub fn detect<'a, H>(status: u16, server: &str, body_head: &str, headers: H) -> CfVerdict
where
    H: IntoIterator<Item = (&'a str, &'a str)>,
{
    let mut mitigated: Option<String> = None;
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("cf-mitigated") {
            mitigated = Some(value.to_string());
            break;
        }
    }

    let server_is_cf = server.to_ascii_lowercase().contains("cloudflare");

    let chal_403 = status == 403
        && server_is_cf
        && (body_head.contains("cf-chl-bypass") || body_head.contains("__cf_chl_jschl_tk__"));

    let chal_503 = status == 503
        && body_head.contains("Just a moment...")
        && body_head.contains("cf-error-details");

    let challenge = chal_403 || chal_503 || mitigated.is_some();

    CfVerdict { challenge, mitigated }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_response_is_not_flagged() {
        let v = detect(200, "nginx", "<html>ok</html>", std::iter::empty());
        assert!(!v.challenge);
        assert!(v.mitigated.is_none());
    }

    #[test]
    fn challenge_403_pattern() {
        let v = detect(
            403,
            "cloudflare",
            "<html>... cf-chl-bypass ...</html>",
            std::iter::empty(),
        );
        assert!(v.challenge);
    }

    #[test]
    fn challenge_503_pattern() {
        let v = detect(
            503,
            "cloudflare",
            "<html>Just a moment... cf-error-details</html>",
            std::iter::empty(),
        );
        assert!(v.challenge);
    }

    #[test]
    fn cf_mitigated_header_flags_challenge() {
        let h = vec![("cf-mitigated", "challenge")];
        let v = detect(200, "cloudflare", "", h);
        assert!(v.challenge);
        assert_eq!(v.mitigated.as_deref(), Some("challenge"));
    }

    #[test]
    fn case_insensitive_mitigated_header() {
        let h = vec![("CF-Mitigated", "block")];
        let v = detect(200, "", "", h);
        assert!(v.challenge);
        assert_eq!(v.mitigated.as_deref(), Some("block"));
    }

    #[test]
    fn cf_marker_alone_without_cloudflare_server_not_flagged() {
        let v = detect(
            403,
            "nginx",
            "<html>cf-chl-bypass</html>",
            std::iter::empty(),
        );
        assert!(!v.challenge);
    }
}
