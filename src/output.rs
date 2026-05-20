//! Async buffered JSONL writer + `ProbeRecord` struct.
//!
//! Field names MUST match what `httpx_probe_engine.py:_parse()` reads — see
//! SPEC §"Output JSONL — must match httpx exactly". In particular:
//!
//! - `status_code` (int) — NOT `status`
//! - `input` — original host (scheme+netloc)
//! - `content_type` — NOT `mime`
//! - `body_preview` — NOT `body`
//! - `webserver` — production parser reads `j.get("webserver")` (matches the
//!   ProjectDiscovery httpx field name). We emit BOTH `server` (per SPEC table)
//!   and `webserver` (alias for parser compatibility) so consumers reading
//!   either field name see the same value.

use serde::Serialize;
use std::path::Path;
use std::sync::Arc;
use tokio::fs::File;
use tokio::io::{AsyncWriteExt, BufWriter};
use tokio::sync::Mutex;

/// JSONL record emitted by the prober — one line per finding.
#[derive(Debug, Serialize)]
pub struct ProbeRecord {
    /// Full URL probed.
    pub url: String,
    /// Original host (scheme+netloc only).
    pub input: String,
    /// Path component (leading `/`).
    pub path: String,
    /// netloc only — for diagnostics.
    pub host: String,
    /// HTTP status — `0` on connection error.
    pub status_code: u16,
    /// `Content-Length` header value, else body length, else `-1` on error.
    pub content_length: i64,
    /// Raw `Content-Type` header value.
    pub content_type: String,
    /// `<title>` content, whitespace-squashed, up to 300 chars.
    pub title: String,
    /// `Location` header (only on 3xx).
    pub location: String,
    /// `Server` header — SPEC §"Output JSONL" field name.
    pub server: String,
    /// `Server` header — alias matching ProjectDiscovery httpx field name.
    /// Production `httpx_probe_engine.py:_parse()` reads `j.get("webserver")`.
    pub webserver: String,
    /// First N bytes of body, HTML-entity-encoded.
    pub body_preview: String,
    /// Optional — left empty `[]`.
    pub tech: Vec<String>,
    /// Always `"GET"`.
    pub method: &'static str,
    /// Whether this hit matched the per-host wildcard signature.
    pub is_wildcard: bool,
    /// Which wildcard policy was in effect when this record was produced.
    pub wildcard_policy: String,
    /// Whether the request went via `--proxy`.
    pub via_proxy: bool,
    /// `1 + retries actually used`.
    pub attempts: u32,
    /// Total request time, milliseconds.
    pub elapsed_ms: u64,
    /// MD5 of `body[:200]` — lowercase hex. Empty string on error.
    pub snippet_md5: String,
    /// TLS impersonation profile actually used (e.g. `"chrome-131"` /
    /// `"vanilla"` / `"fallback:vanilla"`).
    pub tls_impersonation: String,
    /// The exact User-Agent string sent.
    pub user_agent: String,
    /// Cloudflare challenge detected (per `cf.rs` rules).
    pub cf_challenge: bool,
    /// Value of `cf-mitigated` header, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cf_mitigated: Option<String>,
    /// Set when `status_code = 0`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// ISO-8601 UTC timestamp.
    pub timestamp: String,
    /// Prober identifier — `"retroh4ck-prober/0.1.0"`.
    pub prober: &'static str,
}

pub const PROBER_TAG: &str = concat!("retroh4ck-prober/", env!("CARGO_PKG_VERSION"));

impl ProbeRecord {
    pub fn now_iso8601() -> String {
        chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
    }
}

/// Async buffered JSONL writer wrapped in a tokio Mutex so multiple worker
/// tasks can write concurrently without interleaving lines.
pub type JsonlWriter = Arc<Mutex<BufWriter<File>>>;

/// Create the output file (and parent directory) and return a wrapped writer.
pub async fn open_writer(out: &Path) -> anyhow::Result<JsonlWriter> {
    if let Some(parent) = out.parent() {
        if !parent.as_os_str().is_empty() {
            tokio::fs::create_dir_all(parent).await?;
        }
    }
    let file = File::create(out).await?;
    Ok(Arc::new(Mutex::new(BufWriter::with_capacity(1 << 20, file))))
}

/// Serialise and write one record. Failure to serialise drops the record
/// silently (per Rule 0 — we'd rather skip than emit half-records); failure
/// to write is also dropped (caller already has stderr logging on the path).
pub async fn write(writer: &JsonlWriter, rec: &ProbeRecord) {
    let line = match serde_json::to_string(rec) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, url = %rec.url, "JSONL serialisation failed");
            return;
        }
    };
    let mut w = writer.lock().await;
    if let Err(e) = w.write_all(line.as_bytes()).await {
        tracing::warn!(error = %e, url = %rec.url, "JSONL write failed");
        return;
    }
    let _ = w.write_all(b"\n").await;
}

/// Flush the writer — called from the signal handler and at end of run.
pub async fn flush(writer: &JsonlWriter) {
    let mut w = writer.lock().await;
    let _ = w.flush().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_serialises_with_httpx_field_names() {
        let rec = ProbeRecord {
            url: "https://x.com/a".into(),
            input: "https://x.com".into(),
            path: "/a".into(),
            host: "x.com".into(),
            status_code: 200,
            content_length: 42,
            content_type: "text/plain".into(),
            title: "T".into(),
            location: "".into(),
            server: "nginx".into(),
            webserver: "nginx".into(),
            body_preview: "&#34;ok&#34;".into(),
            tech: vec![],
            method: "GET",
            is_wildcard: false,
            wildcard_policy: "strict".into(),
            via_proxy: false,
            attempts: 1,
            elapsed_ms: 5,
            snippet_md5: "abc".into(),
            tls_impersonation: "chrome-131".into(),
            user_agent: "ua".into(),
            cf_challenge: false,
            cf_mitigated: None,
            error: None,
            timestamp: "2026-05-20T12:00:00.000Z".into(),
            prober: PROBER_TAG,
        };
        let s = serde_json::to_string(&rec).unwrap();
        // SPOT-check the load-bearing field NAMES (not values).
        assert!(s.contains("\"status_code\":200"));
        assert!(s.contains("\"content_type\":\"text/plain\""));
        assert!(s.contains("\"body_preview\":\"&#34;ok&#34;\""));
        assert!(s.contains("\"input\":\"https://x.com\""));
        assert!(s.contains("\"webserver\":\"nginx\""));
        assert!(s.contains("\"server\":\"nginx\""));
        assert!(s.contains("\"tls_impersonation\":\"chrome-131\""));
    }

    #[test]
    fn prober_tag_includes_version() {
        assert!(PROBER_TAG.starts_with("retroh4ck-prober/"));
        assert!(PROBER_TAG.contains(env!("CARGO_PKG_VERSION")));
    }
}
