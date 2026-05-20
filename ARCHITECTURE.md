# retroh4ck-prober — Architecture

Internal design reference for contributors. For user-facing flags see [`USAGE.md`](USAGE.md); for the high-level pitch see [`README.md`](README.md).

## Module layout

```
retroh4ck-prober/
+-- Cargo.toml
+-- Cargo.lock                    committed (binary crate)
+-- README.md
+-- LICENSE                       (GPL-3.0)
+-- CHANGELOG.md
+-- ARCHITECTURE.md
+-- USAGE.md
+-- .gitignore
+-- .github/
|   +-- workflows/
|   |   +-- ci.yml                cargo fmt + clippy + test on push/PR
|   |   +-- release.yml           cross-OS binaries on tag push
|   |   +-- bench.yml             optional weekly bench vs httpx
|   +-- dependabot.yml
+-- data/
|   +-- user_agents.json          ~80 real-browser UA strings
+-- src/
|   +-- main.rs                   CLI entrypoint
|   +-- cli.rs                    clap parser
|   +-- client.rs                 hybrid wreq + reqwest builder
|   +-- ua.rs                     UA database + rotation
|   +-- probe.rs                  per-request probe + retry
|   +-- wildcard.rs               per-host random-path detection
|   +-- output.rs                 JSONL writer with httpx-shaped record
|   +-- cf.rs                     Cloudflare challenge detection
|   +-- ratelimit.rs              governor wrapper
|   +-- title.rs                  <title> extraction with whitespace squash
|   +-- util.rs                   path normalisation, hex random, html escape
+-- tests/
    +-- integration_smoke.rs      golden-output test against a local mock
    +-- ua_distribution.rs        UA pool sanity (>= 4 families, >= 10 each)
```

## Hybrid TLS client

Two HTTP clients live for the lifetime of the process. Each request picks one based on the active impersonation profile and the per-host kill-switch state.

```
                              +------------------+
                              | input host list  |
                              +---------+--------+
                                        |
                                        v
                              +------------------+
                              | per-host TLS     |
                              | profile selector |   <-- wreq::Impersonate::Chrome131 / Firefox133 /
                              +---------+--------+       Safari18 / Edge131, or pinned via --impersonate
                                        |
                                        v
                  +---------------------+--------------------+
                  | per-host fail counter (3 strikes)        |
                  +---------------------+--------------------+
                                        |
                       no failures      |       3+ failures
                +-----------------------+----------------------+
                |                                              |
                v                                              v
        +-------+--------+                             +-------+--------+
        |  primary       |                             |  fallback      |
        |  wreq client   |                             |  reqwest +     |
        |  (BoringSSL    |                             |  rustls-tls    |
        |  impersonate)  |                             |  (vanilla)     |
        +-------+--------+                             +-------+--------+
                |                                              |
                |        transport error                        |
                +--------------> retry once -------------------->|
                |        (only when --tls-fallback on)          |
                v                                              v
            response                                       response
            tls_impersonation =                            tls_impersonation =
              "chrome-131" |                                 "vanilla" |
              "firefox-133" |                                "fallback:vanilla"
              "safari-18.2" |
              "edge-131"
```

Both clients share the same HTTP/2 settings (`pool_max_idle_per_host(8)`), the same timeout, the same retry budget, and the same proxy. Only the TLS layer differs.

## Per-host vs per-request rotation

Two rotation axes, intentionally on different cadences:

- **TLS profile — rotated per host.** Switching profiles inside a single host's request stream would break HTTP/2 connection coalescing, because each profile drives a fresh TLS handshake with a different ClientHello fingerprint. The connection pool would churn and the wall-clock would explode. Per-host rotation keeps the pool warm and still gives a different fingerprint for the next host.
- **User-Agent — rotated per request.** UA strings ride on top of the TLS layer and switching them is free. Rotating per request makes per-host traffic look like a heterogeneous user population. UA family is always pinned to the active TLS family for that host (no Chrome UA over Firefox JA3).

## Why wreq + reqwest, not pure-anything

- **Pure wreq:** loses the proven cross-OS rustls vanilla path and the well-tested reqwest connection pool. If `wreq` chokes on a host's specific TLS layer, the run is stuck on that host.
- **Pure reqwest:** no TLS-fingerprint impersonation. Cloudflare and similar edges drop the request before any HTTP semantics happen. Documented in the 2026-05-20 smoke: 22 `.well-known/security.txt` findings on `www.kayak.com.<TLD>` mirrors that ffuf could not reach are visible only because we ship a real browser fingerprint.
- **Hybrid:** primary path uses `wreq` impersonation; vanilla `reqwest` is the safety net. Best of both — the impersonation success rate buys the findings, the fallback prevents stuck-host runs. The `tls_impersonation` field in every output record tells the operator which path produced the result.

## JSONL schema rationale

The output is a stream of JSON objects, one per line, with field names that match ProjectDiscovery `httpx` exactly. This was a hard requirement: the production `httpx_probe_engine.py:_parse()` consumer is on the other side of the pipe and we did not want to maintain a fork of its parser.

Specific choices worth flagging:

- **`status_code` not `status`.** httpx uses `status_code`. Some Rust HTTP libraries default to `status`. We override the field name via serde to match httpx.
- **`body_preview` is HTML-entity-encoded.** httpx's `-body-preview` flag emits HTML-escaped bytes (`"` -> `&#34;`, `<` -> `&lt;`, etc.). The production parser calls `html.unescape()` on it. If we shipped raw bytes, validators that anchor on raw quote characters would misfire. Encoding is single-pass over the captured slice.
- **`snippet_md5` is MD5 of `body[:200]`.** Cheap, deterministic, and matches what the downstream dedup layer expects.
- **`tls_impersonation` is explicit.** Operators audit which client produced which finding — `chrome-131` vs `fallback:vanilla` is the difference between "Cloudflare let it through" and "Cloudflare let it through only after we dropped impersonation".
- **`tech` is reserved.** Always emitted as `[]`. Tech-stack fingerprinting is downstream's job.

Field order is not part of the contract — serde struct field order is what ships. Consumers must key on field names, not position.

## Concurrency model + back-pressure

```
                     +--------------------+
                     | host x path queue  |
                     +---------+----------+
                               |
                               v
                     +--------------------+
                     | tokio Semaphore    |   permits = --threads (default 200)
                     +---------+----------+
                               |
                               v
                +------------------------------+
                | governor token buckets        |   one per netloc when
                | (per-host rate limit)         |   --rate-limit > 0
                +---------+--------------------+
                          |
                          v
                +---------+--------+
                |  probe task      |
                |  (one tokio task |
                |   per probe)     |
                +---------+--------+
                          |
                          v
                +---------+--------+
                | wreq | reqwest   |
                | client (shared,  |
                | pooled)          |
                +---------+--------+
                          |
                          v
                +---------+--------+
                | JSONL writer     |
                | (mpsc channel,   |
                | single consumer) |
                +------------------+
```

Two back-pressure surfaces:

1. **Concurrency cap.** A `tokio::sync::Semaphore` with `threads` permits gates how many probe tasks can run at once. When all permits are taken, new tasks block on `acquire()` until one finishes. This is the load-shedding boundary that prevents memory blow-up on huge wordlists.
2. **Per-host rate limit.** Optional. When `--rate-limit RPS` is set, each netloc gets its own `governor` token bucket. Tasks call `until_ready()` on the bucket before issuing the HTTP request. Bucket state lives in a `DashMap<host, Arc<RateLimiter>>` keyed by netloc so the cost is one map lookup per request.

The JSONL writer is a single consumer fed by an `mpsc` channel from all probe tasks. Writing is sequential, which keeps the output file in a well-defined order per writer's POV and prevents interleaved partial lines.

## Wildcard fingerprint detection algorithm

```
on_first_probe_to_host(host):
    random_path = "/" + hex(rand_u128())          # 32 hex chars
    response = client.get(host + random_path).await
    if response.status in (200,) or (300..=399).contains(response.status):
        fingerprint[host] = (
            response.content_length,
            response.content_type,
            md5(response.body[:200]),
        )

on_normal_probe(host, path, response):
    if host in fingerprint:
        candidate = (
            response.content_length,
            response.content_type,
            md5(response.body[:200]),
        )
        if candidate == fingerprint[host]:
            record.is_wildcard = true
            if wildcard_policy == "strict":
                drop_record()
                return
    record.wildcard_policy = wildcard_policy
    emit(record)
```

Three-tuple fingerprint catches the common wildcard shapes:

- **Constant-body 404 with HTTP 200.** `rights.kayak.com` ships a 555-byte CrowdRiff page for every path with status 200. All three tuple components match.
- **Constant redirect.** `kiwi.kayak.com` serves an HTTP 307 to a kiwi.com 404 page. The body and headers are identical for every path.
- **Templated 404 with stable Content-Type and length.** A small body that includes a variable echo of the path can still fingerprint, because `body[:200]` is hashed (not the full body) and the prefix is usually static template text.

Trade-off: a host that serves a different `content_length` per path (e.g. an SPA that echoes a unique path string deep in the body) escapes detection. For those, the operator uses `--wildcard-policy mark` and post-filters downstream.

The `wildcard_policy` field on every record records which mode was in effect at emission time, so a result set can be re-interpreted later without re-running the scan.

## Cloudflare challenge detection

Three rules, evaluated in order, short-circuit on first match:

1. `status == 403` AND `Server: cloudflare` header AND body contains `cf-chl-bypass` or `__cf_chl_jschl_tk__`.
2. `status == 503` AND body contains `Just a moment...` AND body contains `cf-error-details`.
3. Any response carrying a `cf-mitigated` header — record its value in `cf_mitigated`.

A match sets `cf_challenge:true` and logs a WARN line to stderr (always, regardless of verbosity). The record is still emitted so downstream stages know which URLs need a different profile or proxy. Disable via `--cf-detect off` if the operator does not want the warnings.

## Error model

| Layer | Exit code | What it means |
|---|---|---|
| CLI parse | 2 | clap returned a usage error |
| Input file | 3 | host list or wordlist missing / unreadable |
| Output file | 4 | output path unwritable (permission, full disk, etc.) |
| Network | 5 | every probe failed at transport level (DNS, connect) — usually means no network |
| Normal | 0 | all probes attempted; per-request errors are reported in `error` when `--include-errors on` |

Transport errors at the per-request layer never abort the run. They either trigger the fallback client (impersonation error path) or, if `--include-errors on`, emit a `status_code:0` record carrying the error string and a null body.

## Logging

`tracing` with two stderr targets:

- **WARN+** is always on. Cloudflare detections, per-host kill-switch trips, output-channel back-pressure, and unexpected response shapes all surface here.
- **INFO/DEBUG** is opt-in via `-v` / `-vv` or `RETROH4CK_LOG=info|debug`. Per-probe timings, retry attempts, and fingerprint hits land here. Suitable for piping to a log aggregator during long runs.

Tracing initialisation is bound to the CLI flag at startup; no runtime reconfiguration.

## Build profile

```toml
[profile.release]
opt-level = 3
lto = "fat"
codegen-units = 1
strip = true
panic = "abort"
```

Target compile size is under 12 MB stripped on Linux x86_64. `panic = "abort"` is deliberate — there is no application-level state to clean up on panic; abort is the correct termination semantics for a CLI tool.
