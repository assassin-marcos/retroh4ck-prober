//! Per-(host, path) probe worker.
//!
//! Drives the hybrid client, parses status/headers/body, builds a
//! `ProbeRecord` honoring the wildcard policy + status filter, and ships it
//! to the JSONL writer.

use anyhow::Result;
use md5::{Digest, Md5};
use std::sync::Arc;
use std::time::Instant;

use crate::cf;
use crate::cli::WildcardPolicy;
use crate::client::{ClientError, SharedClient, TlsProfile};
use crate::output::{self, JsonlWriter, ProbeRecord, PROBER_TAG};
use crate::title;
use crate::ua::{self, Family};
use crate::util::{
    html_escape_body_preview, truncate_to_string_lossy, BODY_READ_CAP,
};
use crate::wildcard::{WildcardMap, WildcardSig};

/// Per-host context — shared across all probes for that host.
pub struct HostCtx {
    pub input: String,         // "https://example.com"
    pub host: String,          // "example.com"
}

/// Per-probe work item.
pub struct ProbeItem {
    pub ctx: Arc<HostCtx>,
    pub path: String,
}

/// Configuration carried by the worker pool.
pub struct ProbeConfig {
    pub match_codes: Vec<u16>,
    pub body_preview_bytes: usize,
    pub wildcard_policy: WildcardPolicy,
    pub include_errors: bool,
    pub cf_detect: bool,
    pub retries: u32,
    pub explicit_user_agent: Option<String>,
    pub ua_rotation: bool,
}

/// Run a single probe end to end: send request, parse, optionally write a record.
///
/// Returns `Ok(())` once the record has been written (or deliberately
/// dropped). `Err` is reserved for unrecoverable conditions (writer broken,
/// etc.) — per-request errors are encoded INTO the record as `status_code=0`
/// when `--include-errors on`.
#[allow(clippy::too_many_arguments)]
pub async fn run_one(
    client: SharedClient,
    item: ProbeItem,
    writer: JsonlWriter,
    cfg: Arc<ProbeConfig>,
    wildcards: Arc<WildcardMap>,
) -> Result<()> {
    let url = format!("{}{}", item.ctx.input, item.path);

    let started = Instant::now();
    let (resp_opt, profile, attempts, last_err) =
        send_with_retry(&client, &item.ctx, &url, &cfg).await;
    let elapsed_ms = started.elapsed().as_millis() as u64;

    match resp_opt {
        Some(parsed) => {
            // Possibly tag wildcard before deciding output policy.
            let mut is_wildcard = false;
            if !matches!(cfg.wildcard_policy, WildcardPolicy::Off)
                && wildcards.matches(
                    &item.ctx.input,
                    parsed.content_length,
                    &parsed.content_type,
                    &parsed.snippet_md5,
                )
            {
                is_wildcard = true;
            }

            // Status filter (BUT: redirects with location go through regardless).
            let status_ok = cfg.match_codes.contains(&parsed.status);
            if !status_ok {
                return Ok(());
            }

            // Wildcard suppress under strict policy.
            if is_wildcard && matches!(cfg.wildcard_policy, WildcardPolicy::Strict) {
                return Ok(());
            }

            let cf_verdict = if cfg.cf_detect {
                let head = &parsed.body_preview_full[..parsed
                    .body_preview_full
                    .len()
                    .min(2048)];
                let headers_iter = parsed
                    .headers
                    .iter()
                    .map(|(k, v)| (k.as_str(), v.as_str()));
                cf::detect(parsed.status, &parsed.server, head, headers_iter)
            } else {
                cf::CfVerdict::none()
            };
            if cf_verdict.challenge {
                tracing::warn!(
                    url = %url,
                    status = parsed.status,
                    mitigated = ?cf_verdict.mitigated,
                    "Cloudflare challenge detected"
                );
            }

            let rec = ProbeRecord {
                url: url.clone(),
                input: item.ctx.input.clone(),
                path: item.path.clone(),
                host: item.ctx.host.clone(),
                status_code: parsed.status,
                content_length: parsed.content_length,
                content_type: parsed.content_type,
                title: parsed.title,
                location: parsed.location,
                server: parsed.server.clone(),
                webserver: parsed.server,
                body_preview: parsed.body_preview_for_output,
                tech: Vec::new(),
                method: "GET",
                is_wildcard,
                wildcard_policy: cfg.wildcard_policy.as_str().to_string(),
                via_proxy: client.via_proxy(),
                attempts,
                elapsed_ms,
                snippet_md5: parsed.snippet_md5,
                tls_impersonation: profile.tag().to_string(),
                user_agent: parsed.user_agent,
                cf_challenge: cf_verdict.challenge,
                cf_mitigated: cf_verdict.mitigated,
                error: None,
                timestamp: ProbeRecord::now_iso8601(),
                prober: PROBER_TAG,
            };
            output::write(&writer, &rec).await;
            Ok(())
        }
        None => {
            if !cfg.include_errors {
                return Ok(());
            }
            let rec = ProbeRecord {
                url: url.clone(),
                input: item.ctx.input.clone(),
                path: item.path.clone(),
                host: item.ctx.host.clone(),
                status_code: 0,
                content_length: -1,
                content_type: String::new(),
                title: String::new(),
                location: String::new(),
                server: String::new(),
                webserver: String::new(),
                body_preview: String::new(),
                tech: Vec::new(),
                method: "GET",
                is_wildcard: false,
                wildcard_policy: cfg.wildcard_policy.as_str().to_string(),
                via_proxy: client.via_proxy(),
                attempts,
                elapsed_ms,
                snippet_md5: String::new(),
                tls_impersonation: profile.tag().to_string(),
                user_agent: String::new(),
                cf_challenge: false,
                cf_mitigated: None,
                error: last_err,
                timestamp: ProbeRecord::now_iso8601(),
                prober: PROBER_TAG,
            };
            output::write(&writer, &rec).await;
            Ok(())
        }
    }
}

/// Parsed-but-not-yet-shaped response fields.
struct ParsedResponse {
    status: u16,
    headers: Vec<(String, String)>,
    content_length: i64,
    content_type: String,
    title: String,
    location: String,
    server: String,
    body_preview_full: String, // lossy UTF-8 body up to BODY_READ_CAP
    body_preview_for_output: String, // truncated + html-entity-encoded
    snippet_md5: String,
    user_agent: String,
}

/// Try a request, retry up to `cfg.retries` times on network error.
async fn send_with_retry(
    client: &SharedClient,
    ctx: &HostCtx,
    url: &str,
    cfg: &ProbeConfig,
) -> (Option<ParsedResponse>, TlsProfile, u32, Option<String>) {
    let mut attempts = 0u32;
    let mut last_err: Option<String> = None;
    let max_attempts = cfg.retries.saturating_add(1).max(1);
    // Seed last_profile with the host's STICKY profile so the very first UA
    // pick matches the TLS family — not the default Vanilla→Chrome fallback.
    // Without this every first request goes out as <random non-Chrome JA3> +
    // Chrome UA, which is the textbook bot-fingerprint mismatch.
    let mut last_profile = client.pick_profile(&ctx.input).await;

    while attempts < max_attempts {
        attempts += 1;
        let user_agent = pick_user_agent(cfg, last_profile);
        match client.dispatch(&ctx.input, url, &user_agent).await {
            Ok(resp) => {
                last_profile = resp.tls;
                let parsed = parse_response(resp, cfg.body_preview_bytes, user_agent);
                return (Some(parsed), last_profile, attempts, None);
            }
            Err(ClientError { message }) => {
                last_err = Some(crate::util::short_err(&message));
                tracing::debug!(url = %url, attempt = attempts, error = %message, "probe error");
            }
        }
    }
    (None, last_profile, attempts, last_err)
}

/// Pick a UA based on rotation flag + family that matches the TLS profile.
fn pick_user_agent(cfg: &ProbeConfig, profile: TlsProfile) -> String {
    if let Some(explicit) = cfg.explicit_user_agent.as_deref() {
        return explicit.to_string();
    }
    if cfg.ua_rotation {
        return ua::pick(profile.ua_family()).to_string();
    }
    // No rotation, no explicit UA — pick a single deterministic one per family.
    let pool = ua::pool();
    let family = match profile {
        TlsProfile::Chrome131 => Family::Chrome,
        TlsProfile::Firefox133 => Family::Firefox,
        TlsProfile::Safari182 => Family::Safari,
        TlsProfile::Edge131 => Family::Edge,
        _ => Family::Chrome,
    };
    pool.family(family)
        .first()
        .cloned()
        .unwrap_or_else(|| "Mozilla/5.0 (compatible; retroh4ck-prober/0.1)".to_string())
}

/// Convert the wire response into a parsed shape.
fn parse_response(
    resp: crate::client::ProbedResponse,
    body_preview_bytes: usize,
    user_agent: String,
) -> ParsedResponse {
    let status = resp.status;

    let mut content_type = String::new();
    let mut header_cl: Option<i64> = None;
    let mut location = String::new();
    let mut server = String::new();
    for (k, v) in resp.headers.iter() {
        let lk = k.to_ascii_lowercase();
        match lk.as_str() {
            "content-type" if content_type.is_empty() => content_type = v.clone(),
            "content-length" if header_cl.is_none() => {
                if let Ok(n) = v.parse::<i64>() {
                    header_cl = Some(n);
                }
            }
            "location" if location.is_empty() => location = v.clone(),
            "server" if server.is_empty() => server = v.clone(),
            _ => {}
        }
    }

    // Read body up to BODY_READ_CAP (full bytes already in Bytes — slice it).
    let body_bytes = resp.body;
    let body_full_len = body_bytes.len();
    let read_end = body_full_len.min(BODY_READ_CAP);
    let read_slice = &body_bytes[..read_end];

    let content_length: i64 = header_cl.unwrap_or(body_full_len as i64);

    // snippet_md5 = md5(body[:200])
    let snip_end = read_slice.len().min(200);
    let mut hasher = Md5::new();
    hasher.update(&read_slice[..snip_end]);
    let snippet_md5 = hex::encode(hasher.finalize());

    // Title — runs against the first 64 KB.
    let title = title::extract(read_slice);

    // Body preview for the output JSONL: first N bytes lossy → entity-encode.
    let preview_end = read_slice.len().min(body_preview_bytes);
    let body_preview_full = truncate_to_string_lossy(read_slice, BODY_READ_CAP);
    let body_preview_raw = truncate_to_string_lossy(read_slice, preview_end);
    let body_preview_for_output = html_escape_body_preview(&body_preview_raw);

    ParsedResponse {
        status,
        headers: resp.headers,
        content_length,
        content_type,
        title,
        location,
        server,
        body_preview_full,
        body_preview_for_output,
        snippet_md5,
        user_agent,
    }
}

/// Run the wildcard pre-flight probe for one host. Returns a signature if
/// the probe came back with body content (the 200/3xx-with-body criterion).
pub async fn detect_wildcard(
    client: &SharedClient,
    ctx: &HostCtx,
) -> Option<WildcardSig> {
    let path = crate::util::random_hex_path(32);
    let url = format!("{}{}", ctx.input, path);
    // Match UA family to the host's sticky TLS profile — same reason as
    // send_with_retry: a Chrome UA + Firefox JA3 is the textbook bot signal.
    let host_profile = client.pick_profile(&ctx.input).await;
    let user_agent = pick_user_agent(
        &ProbeConfig {
            match_codes: vec![],
            body_preview_bytes: 2048,
            wildcard_policy: WildcardPolicy::Strict,
            include_errors: false,
            cf_detect: false,
            retries: 0,
            explicit_user_agent: None,
            ua_rotation: true,
        },
        host_profile,
    );
    let resp = match client.dispatch(&ctx.input, &url, &user_agent).await {
        Ok(r) => r,
        Err(_) => return None,
    };
    // We accept 200 + 3xx with body — these are the "ANY path resolves"
    // patterns; 404/410 with body are NOT wildcards by the strict definition.
    if !matches!(resp.status, 200..=399) {
        return None;
    }
    let parsed = parse_response(resp, 2048, user_agent);
    // No body → can't fingerprint.
    if parsed.content_length == 0 || parsed.snippet_md5.is_empty() {
        return None;
    }
    Some(WildcardSig {
        content_length: parsed.content_length,
        content_type: parsed.content_type,
        snippet_md5: parsed.snippet_md5,
    })
}
