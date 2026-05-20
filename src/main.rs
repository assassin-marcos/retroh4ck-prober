//! retroh4ck-prober — Rust async path prober with TLS-fingerprint impersonation.
//!
//! Drop-in JSONL replacement for ProjectDiscovery httpx in RetroH4ck
//! Stage 15. See SPEC.md for the authoritative interface contract.

mod cf;
mod cli;
mod client;
mod output;
mod probe;
mod ratelimit;
mod title;
mod ua;
mod util;
mod wildcard;

use anyhow::{Context, Result};
use clap::Parser;
use futures::stream::{FuturesUnordered, StreamExt};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::Semaphore;

use crate::cli::{Cli, WildcardPolicy};
use crate::client::HybridClient;
use crate::output::flush as flush_writer;
use crate::probe::{detect_wildcard, run_one, HostCtx, ProbeConfig, ProbeItem};
use crate::ratelimit::HostRateLimiter;
use crate::wildcard::WildcardMap;

// Exit codes — must match SPEC §"Exit codes".
const EXIT_OK: i32 = 0;
const EXIT_INPUT_UNREADABLE: i32 = 3;
const EXIT_OUTPUT_UNWRITABLE: i32 = 4;
const EXIT_ALL_FAILED: i32 = 5;

fn install_tracing(verbose: u8) {
    use tracing_subscriber::{fmt, EnvFilter};
    let default_level = match verbose {
        0 => "warn",
        1 => "info",
        _ => "debug",
    };
    let filter = EnvFilter::try_from_env("RETROH4CK_LOG")
        .unwrap_or_else(|_| EnvFilter::new(default_level));
    fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .init();
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let cli = Cli::parse();
    install_tracing(cli.verbose);

    match real_main(cli).await {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            tracing::error!("{:#}", e);
            std::process::exit(1);
        }
    }
}

async fn real_main(cli: Cli) -> Result<i32> {
    // ── Load inputs ────────────────────────────────────────────────────
    let hosts_raw = read_lines(&cli.list).await.with_context(|| {
        format!("reading hosts file {:?}", cli.list)
    });
    let hosts: Vec<String> = match hosts_raw {
        Ok(lines) => lines
            .iter()
            .filter_map(|l| util::normalize_host(l))
            .collect(),
        Err(e) => {
            tracing::error!("{:#}", e);
            return Ok(EXIT_INPUT_UNREADABLE);
        }
    };
    if hosts.is_empty() {
        tracing::error!("hosts file produced zero usable entries");
        return Ok(EXIT_INPUT_UNREADABLE);
    }

    let words_raw = read_lines(&cli.paths).await.with_context(|| {
        format!("reading wordlist {:?}", cli.paths)
    });
    let words: Vec<String> = match words_raw {
        Ok(lines) => lines
            .iter()
            .map(|s| util::normalize_path(s))
            .filter(|s| !s.is_empty())
            .collect(),
        Err(e) => {
            tracing::error!("{:#}", e);
            return Ok(EXIT_INPUT_UNREADABLE);
        }
    };
    if words.is_empty() {
        tracing::error!("wordlist file produced zero usable entries");
        return Ok(EXIT_INPUT_UNREADABLE);
    }

    // ── Build hybrid client ────────────────────────────────────────────
    let client = match HybridClient::build(
        Duration::from_secs(cli.timeout),
        cli.impersonate,
        cli.tls_fallback.is_on(),
        cli.proxy.as_deref(),
    ) {
        Ok(c) => Arc::new(c),
        Err(e) => {
            tracing::error!("building HTTP client: {:#}", e);
            return Ok(EXIT_ALL_FAILED);
        }
    };

    // ── Open output writer ─────────────────────────────────────────────
    let writer = match output::open_writer(&cli.output).await {
        Ok(w) => w,
        Err(e) => {
            tracing::error!("creating output {:?}: {:#}", cli.output, e);
            return Ok(EXIT_OUTPUT_UNWRITABLE);
        }
    };

    // ── Wildcard pre-flight (per host) ─────────────────────────────────
    let wildcard_policy = cli.effective_wildcard_policy();
    let mut wildcard_map = WildcardMap::new();
    if !matches!(wildcard_policy, WildcardPolicy::Off) {
        for h in hosts.iter() {
            let ctx = HostCtx {
                input: h.clone(),
                host: host_only(h),
            };
            if let Some(sig) = detect_wildcard(&client, &ctx).await {
                tracing::info!(
                    host = %h,
                    cl = sig.content_length,
                    md5 = %sig.snippet_md5,
                    "wildcard signature recorded"
                );
                wildcard_map.insert(h.clone(), sig);
            }
        }
    }
    let wildcards = Arc::new(wildcard_map);

    // ── Concurrency budget ─────────────────────────────────────────────
    let concurrency = cli.threads.max(1);
    let sem = Arc::new(Semaphore::new(concurrency));
    let rate_limiter = Arc::new(HostRateLimiter::new(cli.rate_limit));

    let cfg = Arc::new(ProbeConfig {
        match_codes: cli.parsed_match_codes(),
        body_preview_bytes: cli.body_preview,
        wildcard_policy,
        include_errors: cli.include_errors.is_on(),
        cf_detect: cli.cf_detect.is_on(),
        retries: cli.retries,
        explicit_user_agent: cli.user_agent.clone(),
        ua_rotation: cli.ua_rotation.is_on(),
    });

    // ── Signal handler — flush on Ctrl-C, exit cleanly ─────────────────
    {
        let writer = writer.clone();
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                tracing::warn!("Ctrl+C received — flushing JSONL and exiting");
                flush_writer(&writer).await;
                std::process::exit(130);
            }
        });
    }

    // ── Spawn one task per (host, path) ────────────────────────────────
    let mut tasks = FuturesUnordered::new();
    let total_probes = hosts.len() * words.len();
    let started = Instant::now();

    // Pre-build the host contexts so we don't reallocate them per probe.
    let host_ctxs: Vec<Arc<HostCtx>> = hosts
        .iter()
        .map(|h| {
            Arc::new(HostCtx {
                input: h.clone(),
                host: host_only(h),
            })
        })
        .collect();

    for ctx in host_ctxs.iter() {
        for path in words.iter() {
            let permit = match sem.clone().acquire_owned().await {
                Ok(p) => p,
                Err(_) => continue, // semaphore closed — should not happen
            };
            let client = client.clone();
            let writer = writer.clone();
            let cfg = cfg.clone();
            let wildcards = wildcards.clone();
            let ctx = ctx.clone();
            let path = path.clone();
            let limiter = rate_limiter.clone();
            let host_for_limit = ctx.input.clone();

            tasks.push(tokio::spawn(async move {
                let _p = permit; // released on drop
                if limiter.enabled() {
                    limiter.acquire(&host_for_limit).await;
                }
                let item = ProbeItem { ctx, path };
                let _ = run_one(client, item, writer, cfg, wildcards).await;
            }));
        }
    }

    // Drain
    let mut completed = 0usize;
    while tasks.next().await.is_some() {
        completed += 1;
        if cli.verbose > 0 && completed % 100 == 0 {
            tracing::info!(
                "progress: {} / {} ({:.1}%)",
                completed,
                total_probes,
                100.0 * completed as f64 / total_probes as f64
            );
        }
    }

    flush_writer(&writer).await;
    tracing::info!(
        "retroh4ck-prober: {} probes in {:.2}s ({} hosts × {} paths)",
        total_probes,
        started.elapsed().as_secs_f64(),
        hosts.len(),
        words.len(),
    );
    Ok(EXIT_OK)
}

async fn read_lines(path: &std::path::Path) -> Result<Vec<String>> {
    let f = File::open(path)
        .await
        .with_context(|| format!("opening {:?}", path))?;
    let mut reader = BufReader::new(f);
    let mut out = Vec::new();
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            break;
        }
        let trimmed = line.trim_end_matches(|c| c == '\n' || c == '\r').to_string();
        out.push(trimmed);
    }
    Ok(out)
}

/// Extract the netloc from a `scheme://host[:port][/...]` string.
fn host_only(input: &str) -> String {
    let after_scheme = input.split_once("://").map(|(_, rest)| rest).unwrap_or(input);
    let netloc = after_scheme
        .split(|c| c == '/' || c == '?' || c == '#')
        .next()
        .unwrap_or("");
    netloc.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_only_strips_path_and_query() {
        assert_eq!(host_only("https://x.com/foo?a=b"), "x.com");
        assert_eq!(host_only("http://x.com:8080/abc"), "x.com:8080");
        assert_eq!(host_only("https://x.com"), "x.com");
        assert_eq!(host_only("x.com"), "x.com");
    }
}
