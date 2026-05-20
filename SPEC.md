# retroh4ck-prober — Build SPEC

> Authoritative spec for the v0.1.0 rewrite. All parallel build agents read
> from this file. Do not bake decisions outside what is listed here.

## Project goals

1. **Drop-in replacement** for ProjectDiscovery `httpx` in RetroH4ck Stage 15
   (backup-path / API-doc / GraphQL probing). The production parser at
   `httpx_probe_engine.py:_parse()` must consume our JSONL with zero code
   changes.
2. **No-missing-true-positive priority** — speed is secondary.
3. **WAF / Cloudflare bypass** baked in via TLS-fingerprint impersonation,
   real-browser UA rotation, and HTTP/2 frame ordering.
4. **Standalone CLI tool** — pushable to anyone, no Python dependency.
5. **Cross-OS** — Linux (x86_64/aarch64), macOS (x86_64/aarch64), Windows
   (x86_64) static binaries via GitHub Actions on tag.

## CLI surface (httpx-parity flag names where possible)

```
retroh4ck-prober \
  --list HOSTS.txt          # -l       (alias --hosts retained for back-compat)
  --paths WORDLIST.txt      # -path    (alias --wordlist retained)
  --output OUT.jsonl        # -o
  --threads 200             # -threads
  --timeout 5               # -timeout (seconds)
  --retries 1               # -retries
  --match-codes 200,301,302,307,308,401,403   # -mc
  --body-preview 8192       # bytes captured for downstream regex (default 8192)
  --no-wildcard             # disable per-host wildcard auto-detect
  --wildcard-policy strict|mark|off   # strict=suppress (default), mark=emit
                                       with is_wildcard:true, off=ignore
  --impersonate auto|chrome|firefox|safari|edge|off
                            # auto = rotate across the four (default)
  --tls-fallback on|off     # default on — if impersonated client errors,
                            # retry once with vanilla reqwest+rustls
  --ua-rotation on|off      # default on — pick random real UA per request
  --user-agent <string>     # explicit UA, overrides --ua-rotation
  --cf-detect on|off        # default on — detect Cloudflare challenge,
                            # tag finding with cf_challenge:true
  --proxy <URL>             # http(s) or socks5 proxy
  --rate-limit <rps>        # per-host requests/sec ceiling (default off)
  --include-errors on|off   # default off — when on, emit status_code=0
                            # records with error string (for debug)
  --verbose / -v            # progress to stderr
```

Short-flag aliases (`-l`, `-o`, `-mc`, `-t`, etc.) match httpx where the
mapping is unambiguous.

## Output JSONL — must match httpx exactly

Each line is a single JSON object. Field names match what
`httpx_probe_engine.py:_parse()` reads:

| Field | Type | Notes |
|---|---|---|
| `url` | string | Full URL probed |
| `input` | string | Original host (scheme+netloc) |
| `path` | string | Path component (leading `/`) |
| `host` | string | netloc only — for diagnostics |
| `status_code` | int | HTTP status (NOT `status` — httpx uses `status_code`) |
| `content_length` | int | From `Content-Length` header, else body length |
| `content_type` | string | Raw `Content-Type` header value |
| `title` | string | `<title>` content, up to 300 chars, whitespace-collapsed |
| `location` | string | `Location` header (only on 3xx) |
| `server` | string | `Server` header |
| `body_preview` | string | First N bytes of body (default 8192), HTML-entity-encoded the same way httpx does (`"` → `&#34;`) so production parser's `html.unescape` round-trips |
| `tech` | array | Optional — leave empty `[]` |
| `method` | string | `"GET"` |
| `is_wildcard` | bool | Set by our wildcard detector |
| `wildcard_policy` | string | `"strict"`, `"mark"`, or `"off"` — record which mode was in effect |
| `via_proxy` | bool | Whether request went through `--proxy` |
| `attempts` | int | 1 + retries actually used |
| `elapsed_ms` | int | Total request time |
| `snippet_md5` | string | MD5 of `body[:200]` — used for fast dedup |
| `tls_impersonation` | string | `"chrome-131"`, `"firefox-133"`, `"safari-18.2"`, `"edge-131"`, `"vanilla"`, or `"fallback:vanilla"` |
| `user_agent` | string | The UA actually sent |
| `cf_challenge` | bool | Cloudflare challenge page detected |
| `cf_mitigated` | string | Value of `cf-mitigated` header if present |
| `error` | string\|null | Set when `status_code=0` |
| `timestamp` | string | ISO-8601 UTC |
| `prober` | string | `"retroh4ck-prober/0.1.0"` |

Order is not significant; serde struct order is fine.

### Body preview encoding (critical compatibility note)

ProjectDiscovery httpx HTML-entity-encodes `"` to `&#34;` in `-body-preview`
output. Production `httpx_probe_engine.py:1480+` calls `html.unescape()` on
the body before running validator regex. **The new prober must emit the
same entity-encoded form**, otherwise validators that match on raw quotes
will misfire.

Implementation: after capturing the first N bytes of body, replace `"` →
`&#34;`, `<` → `&lt;`, `>` → `&gt;`, `&` → `&amp;`. Order matters — encode
`&` last when building, or use a single pass.

## httpx parity — exact flag mapping

Production cmd in `httpx_probe_engine.py:423-441`:

```python
cmd = [
    HTTPX_BIN,
    "-json", "-silent", "-no-color",
    "-l", hosts_file,
    "-path", wordlist,
    "-threads", 200,
    "-timeout", 5,
    "-retries", 1,
    "-mc", "200,301,302,307,308,401,403",
    "-sc", "-cl", "-title", "-ct", "-location", "-server",
    "-body-preview=8192",
    "-stats", "-stats-interval", "10",
]
# +optional: -fep -fepp /dev/null (filter error pages — disabled in backup mode)
# +optional: -fd (dedup bodies — disabled in backup mode)
```

`-fep` (ML error-page filter) is **deliberately not implemented** —
production-side investigation showed it drops legitimate admin/login
panels (Codex Stage 15 findings round 2). Skip it.

`-fd` (dedup bodies) → we have `snippet_md5` per record + the production
parser handles dedup downstream. Skip it.

## Wildcard auto-detection (must keep — verified by kayak.com smoke 2026-05-20)

Per-host: probe `/<32 random hex chars>`. If response is 200/3xx with body,
fingerprint = `(content_length, content_type, snippet_md5)`. Any subsequent
hit on that host whose fingerprint matches is tagged `is_wildcard:true`.

Default policy `strict` suppresses wildcard records from output.

Empirical evidence (kayak.com smoke, 2026-05-20):
- `rights.kayak.com` returns identical 555-byte CrowdRiff 404 HTML for every
  path. The 4 "missed-by-rust" findings (`debug.log`, `error.log`,
  `errors.log`, `terraform.tfvars`) were ffuf **false positives** —
  validator regex coincidentally matched the wildcard 404 body.
- `kiwi.kayak.com` returns 307 → kiwi.com 404 page. Same wildcard FP burst
  on ffuf for `documentation/`, `nuxt.config.js`, `secrets.yaml`, etc.

Conclusion: wildcard detection makes the tool *better* than ffuf on these
hosts — not worse. Keep it. Allow override via `--wildcard-policy off` for
forensic deep-dives.

## TLS-fingerprint impersonation — hybrid + stable

**Primary** client: `wreq` crate (rustls + Boring impersonation, drop-in
reqwest API). Browser profile rotated per HOST (not per request, to keep
HTTP/2 connection coalescing intact).

**Fallback** client: `reqwest` + `rustls-tls`. Used when:
- Impersonated request returns a network error (`ConnectError`, TLS alert)
- User passes `--impersonate off`
- Per-host kill-switch trips after 3 consecutive impersonation failures
  (avoid burning time on a host whose TLS layer hates Chrome JA3)

Each output record carries `tls_impersonation` field so we can audit which
client found what.

Browser profile pool (top current major browsers):
- `chrome-131` (Chrome 131 on Windows 10)
- `firefox-133` (Firefox 133 on Windows 10)
- `safari-18` (Safari 18.2 on macOS 15)
- `edge-131` (Edge 131 on Windows 10)

`wreq` exposes these via `Impersonate::Chrome131`, etc. See crate docs.

## User-Agent rotation

A `data/user_agents.json` baked into the binary at compile-time via
`include_str!`. ~20 real UAs per browser family pulled from
[whatismybrowser.com] real-user samples (2026 Q1+). Picked randomly per
request unless `--user-agent` is explicit. UA family MUST match TLS
impersonation family (don't send a Chrome UA with Firefox JA3).

## Cloudflare detection

A response is flagged `cf_challenge:true` when ANY of:
- Status 403 AND `Server: cloudflare` header AND body contains
  `cf-chl-bypass` or `__cf_chl_jschl_tk__`
- Status 503 AND body contains `Just a moment...` and `cf-error-details`
- `cf-mitigated` response header present (record its value)

When detected, log to stderr (always) and emit the record with
`cf_challenge:true` so downstream stages know to retry with a different
profile or proxy.

## Validator-aware body capture

Body preview MUST be ≥ 8 KB (matches httpx `-body-preview=8192`). For
`backup` mode the production validators look up to 8 KB deep into env files
and JSON dumps — anything less is a silent gap.

Body capture cap: 256 KB raw (don't let multi-MB CSS/JS bundles balloon RAM).

## Concurrency model

- One global `wreq` client + one `reqwest` fallback client.
- `tokio::sync::Semaphore` capped at `threads` (default 200, matches httpx).
- Per-host fairness via `--rate-limit` (token bucket per netloc).
- HTTP/2 connection coalescing via `pool_max_idle_per_host(8)`.

## Crate baseline

```toml
[dependencies]
wreq = "6"                     # primary TLS-impersonation client
reqwest = { version = "0.12", default-features = false,
            features = ["rustls-tls", "gzip", "brotli", "stream"] }
tokio = { version = "1", features = ["rt-multi-thread", "macros", "fs",
                                     "io-util", "time", "sync", "signal"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
clap = { version = "4", features = ["derive"] }
md-5 = "0.10"
hex = "0.4"
rand = "0.8"
futures = "0.3"
anyhow = "1"
url = "2"
regex = "1"
chrono = { version = "0.4", features = ["serde"] }
governor = "0.6"               # rate limiting
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["fmt", "env-filter"] }

[profile.release]
opt-level = 3
lto = "fat"
codegen-units = 1
strip = true
panic = "abort"
```

(Compile size target: ≤ 12 MB stripped.)

## Project layout

```
retroh4ck-prober/
├── Cargo.toml
├── Cargo.lock
├── README.md
├── LICENSE                       (GPL-3.0)
├── CHANGELOG.md
├── ARCHITECTURE.md
├── USAGE.md
├── .gitignore
├── .github/
│   ├── workflows/
│   │   ├── ci.yml                cargo fmt + clippy + test on push/PR
│   │   ├── release.yml           cross-OS binaries on tag push
│   │   └── bench.yml             optional weekly bench vs httpx
│   └── dependabot.yml
├── data/
│   └── user_agents.json          ~80 real-browser UA strings
├── src/
│   ├── main.rs                   CLI entrypoint
│   ├── cli.rs                    clap parser
│   ├── client.rs                 hybrid wreq + reqwest builder
│   ├── ua.rs                     UA database + rotation
│   ├── probe.rs                  per-request probe + retry
│   ├── wildcard.rs               per-host random-path detection
│   ├── output.rs                 JSONL writer with httpx-shaped record
│   ├── cf.rs                     Cloudflare challenge detection
│   ├── ratelimit.rs              governor wrapper
│   ├── title.rs                  <title> extraction with whitespace squash
│   └── util.rs                   path normalisation, hex random, html escape
└── tests/
    ├── integration_smoke.rs      golden-output test against a local mock
    └── ua_distribution.rs        UA pool sanity (≥4 families, ≥10 each)
```

## Exit codes

- `0` — all probes attempted (some may have errored at request level)
- `2` — CLI parse error
- `3` — input file missing/unreadable
- `4` — output file unwritable
- `5` — all probes failed (network unreachable)

## Logging

`tracing` with `RETROH4CK_LOG=info` env var. Default: WARN on stderr.
`-v` flag → INFO, `-vv` → DEBUG.

## Non-goals (out of scope for v0.1.0)

- Distributed/cluster mode (single-binary single-node)
- Resume from checkpoint (rerun from scratch)
- Authenticated probing (no cookie jar, no session juggling)
- Recursive crawling (path lists only, no link extraction)
- Result deduplication across hosts (downstream's job)

## Verification before tagging v0.1.0

1. Run against `/tmp/bench_native_1779238076/smoke_kayak/hosts.txt`
   (86 kayak.com hosts) with the production backup wordlist.
2. Compare findings against the 2026-05-20 baseline:
   - ≥ 55 validator-confirmed findings (Rust baseline)
   - Zero connection-error rate
   - All "missed-by-rust" wildcard FPs from ffuf STAY suppressed
3. `cargo test` green on Linux + macOS (CI matrix).
4. `cargo clippy --all-targets --all-features -- -D warnings` clean.
5. Release binary builds for all 5 OS/arch targets without errors.
