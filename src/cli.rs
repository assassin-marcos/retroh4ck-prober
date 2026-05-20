//! Command-line interface — every flag the SPEC §"CLI surface" defines, with
//! short-flag aliases that match httpx where the mapping is unambiguous.

use clap::{Parser, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum WildcardPolicy {
    /// Suppress wildcard hits from the output (default).
    Strict,
    /// Emit wildcard hits but tag `is_wildcard:true`.
    Mark,
    /// Don't run wildcard detection at all.
    Off,
}

impl WildcardPolicy {
    pub fn as_str(&self) -> &'static str {
        match self {
            WildcardPolicy::Strict => "strict",
            WildcardPolicy::Mark => "mark",
            WildcardPolicy::Off => "off",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ImpersonateMode {
    /// Rotate per host across chrome/firefox/safari/edge (default).
    Auto,
    Chrome,
    Firefox,
    Safari,
    Edge,
    /// Disable TLS impersonation entirely — vanilla rustls.
    Off,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OnOff {
    On,
    Off,
}

impl OnOff {
    pub fn is_on(&self) -> bool {
        matches!(self, OnOff::On)
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "retroh4ck-prober",
    version = env!("CARGO_PKG_VERSION"),
    about = "Async directory/path prober with TLS-fingerprint impersonation (drop-in httpx replacement)",
    long_about = "retroh4ck-prober — Rust async path prober for web-prober pipelines.\n\
                  Drop-in JSONL replacement for ProjectDiscovery httpx with TLS \
                  impersonation (wreq) + reqwest fallback."
)]
pub struct Cli {
    /// Path to hosts file (one URL per line, scheme+netloc only).
    #[arg(short = 'l', long = "list", alias = "hosts")]
    pub list: PathBuf,

    /// Path to wordlist file (one path per line).
    #[arg(long = "paths", alias = "wordlist", short = 'p')]
    pub paths: PathBuf,

    /// Output JSONL file. Parent directory will be created if missing.
    #[arg(short = 'o', long = "output")]
    pub output: PathBuf,

    /// Total concurrency budget (default 200 = httpx parity).
    #[arg(short = 't', long = "threads", default_value_t = 200)]
    pub threads: usize,

    /// Per-request timeout in seconds.
    #[arg(long = "timeout", default_value_t = 5)]
    pub timeout: u64,

    /// Retry count on network error.
    #[arg(long = "retries", default_value_t = 1)]
    pub retries: u32,

    /// Comma-separated list of status codes to emit.
    #[arg(long = "match-codes", alias = "mc", default_value = "200,301,302,307,308,401,403")]
    pub match_codes: String,

    /// Body preview length in bytes (default 8192, matches httpx -body-preview=8192).
    #[arg(long = "body-preview", default_value_t = 8192)]
    pub body_preview: usize,

    /// Disable wildcard detection. Shorthand for --wildcard-policy off.
    #[arg(long = "no-wildcard", default_value_t = false)]
    pub no_wildcard: bool,

    /// Wildcard policy — strict (suppress), mark (emit with is_wildcard:true), off.
    #[arg(long = "wildcard-policy", value_enum, default_value_t = WildcardPolicy::Strict)]
    pub wildcard_policy: WildcardPolicy,

    /// TLS impersonation mode.
    #[arg(long = "impersonate", value_enum, default_value_t = ImpersonateMode::Auto)]
    pub impersonate: ImpersonateMode,

    /// Retry once with vanilla reqwest if the impersonated client errors.
    #[arg(long = "tls-fallback", value_enum, default_value_t = OnOff::On)]
    pub tls_fallback: OnOff,

    /// Rotate User-Agent strings per request (within the chosen TLS family).
    #[arg(long = "ua-rotation", value_enum, default_value_t = OnOff::On)]
    pub ua_rotation: OnOff,

    /// Explicit User-Agent — overrides --ua-rotation.
    #[arg(long = "user-agent")]
    pub user_agent: Option<String>,

    /// Detect Cloudflare challenge pages and tag findings.
    #[arg(long = "cf-detect", value_enum, default_value_t = OnOff::On)]
    pub cf_detect: OnOff,

    /// HTTP/SOCKS5 proxy URL — applies to BOTH impersonated and fallback clients.
    #[arg(long = "proxy")]
    pub proxy: Option<String>,

    /// Per-host requests/sec ceiling. 0 = disabled (default).
    #[arg(long = "rate-limit", default_value_t = 0)]
    pub rate_limit: u32,

    /// Emit status_code=0 records (connection errors). Default off.
    #[arg(long = "include-errors", value_enum, default_value_t = OnOff::Off)]
    pub include_errors: OnOff,

    /// Increase verbosity (-v=info, -vv=debug).
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count)]
    pub verbose: u8,
}

impl Cli {
    /// Effective wildcard policy after considering --no-wildcard.
    pub fn effective_wildcard_policy(&self) -> WildcardPolicy {
        if self.no_wildcard {
            WildcardPolicy::Off
        } else {
            self.wildcard_policy
        }
    }

    /// Parse `--match-codes` into a Vec<u16>.
    pub fn parsed_match_codes(&self) -> Vec<u16> {
        self.match_codes
            .split(',')
            .filter_map(|s| s.trim().parse::<u16>().ok())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn defaults_match_httpx_baseline() {
        let cli = Cli::parse_from([
            "retroh4ck-prober",
            "--list",
            "/tmp/hosts.txt",
            "--paths",
            "/tmp/wl.txt",
            "--output",
            "/tmp/out.jsonl",
        ]);
        assert_eq!(cli.threads, 200);
        assert_eq!(cli.timeout, 5);
        assert_eq!(cli.retries, 1);
        assert_eq!(cli.match_codes, "200,301,302,307,308,401,403");
        assert_eq!(cli.body_preview, 8192);
        assert_eq!(cli.parsed_match_codes(), vec![200, 301, 302, 307, 308, 401, 403]);
        assert_eq!(cli.effective_wildcard_policy(), WildcardPolicy::Strict);
    }

    #[test]
    fn short_flag_aliases_work() {
        let cli = Cli::parse_from([
            "retroh4ck-prober",
            "-l",
            "/tmp/hosts.txt",
            "-p",
            "/tmp/wl.txt",
            "-o",
            "/tmp/out.jsonl",
            "-t",
            "50",
            "--mc",
            "200,403",
        ]);
        assert_eq!(cli.threads, 50);
        assert_eq!(cli.match_codes, "200,403");
    }

    #[test]
    fn no_wildcard_overrides_policy() {
        let cli = Cli::parse_from([
            "retroh4ck-prober",
            "--list",
            "h",
            "--paths",
            "w",
            "--output",
            "o",
            "--wildcard-policy",
            "mark",
            "--no-wildcard",
        ]);
        assert_eq!(cli.effective_wildcard_policy(), WildcardPolicy::Off);
    }
}
