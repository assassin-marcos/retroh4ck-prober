# retroh4ck-prober

A standalone Rust HTTP prober that emits `httpx`-shaped JSONL with TLS-fingerprint impersonation, real-browser UA rotation, per-host wildcard suppression, and Cloudflare challenge detection. Designed as a drop-in replacement for ProjectDiscovery `httpx` in backup-path / API-doc / GraphQL recon pipelines.

<!-- TODO: replace once published -->
![build](https://img.shields.io/badge/build-pending-lightgrey)
![license](https://img.shields.io/badge/license-GPL--3.0-blue)
![crates.io](https://img.shields.io/badge/crates.io-pending-lightgrey)

## Why

- **httpx-shape JSONL output** — every field (`url`, `status_code`, `content_length`, `body_preview`, `title`, `location`, `server`, ...) matches ProjectDiscovery httpx exactly. Existing parsers consume it with zero code changes.
- **Hybrid TLS impersonation** — primary client uses real Chrome / Firefox / Safari / Edge TLS fingerprints; falls back to a vanilla rustls client when impersonation errors out or is disabled. Both clients are configured once and reused.
- **Wildcard auto-suppression** — per-host probe of a random 32-hex path fingerprints the wildcard response; subsequent matches are flagged or dropped. Removes the noisy ffuf-style "every path returns 200" false positives on hosts like `rights.kayak.com` and `kiwi.kayak.com`.
- **Real-UA rotation** — ~20 real-browser User-Agents per family baked into the binary, picked per request, with the UA family always matching the impersonated TLS fingerprint.

## Install

### From crates.io

```bash
cargo install retroh4ck-prober
```

<!-- TODO: enable once published -->

### Pre-built binaries

Static binaries for Linux (x86_64, aarch64), macOS (x86_64, aarch64), and Windows (x86_64) are published on every tag. Download the matching archive from the [releases page](https://github.com/assassin-marcos/retroh4ck-prober/releases) <!-- TODO --> and drop the binary in your `$PATH`.

### From source

```bash
git clone https://github.com/assassin-marcos/retroh4ck-prober
cd retroh4ck-prober
cargo build --release
# binary: target/release/retroh4ck-prober
```

## Quickstart

```bash
# 1. Probe a host list against a wordlist
retroh4ck-prober -l hosts.txt -path backup_paths.txt -o out.jsonl

# 2. Pipe from subfinder, force Firefox impersonation, route through a proxy
subfinder -d target.com -silent | retroh4ck-prober -path backup_paths.txt \
    --impersonate firefox --proxy socks5://127.0.0.1:1080 -o out.jsonl

# 3. Forensic deep-dive: capture everything, including wildcard hits
retroh4ck-prober -l hosts.txt -path wordlist.txt -o out.jsonl \
    --wildcard-policy off --include-errors on -v
```

## Flags

| Flag | Alias | Default | Purpose |
|---|---|---|---|
| `--list FILE` | `-l`, `--hosts` | — | Host list (scheme + netloc per line) |
| `--paths FILE` | `-path`, `--wordlist` | — | Path wordlist |
| `--output FILE` | `-o` | stdout | JSONL output path |
| `--threads N` | `-threads` | 200 | Concurrency cap |
| `--timeout SEC` | `-timeout` | 5 | Per-request timeout |
| `--retries N` | `-retries` | 1 | Retry count on transport error |
| `--match-codes LIST` | `-mc` | `200,301,302,307,308,401,403` | Status codes to emit |
| `--body-preview N` | — | 8192 | Bytes of body captured |
| `--no-wildcard` | — | off | Disable per-host wildcard detection |
| `--wildcard-policy MODE` | — | `strict` | `strict` suppresses, `mark` emits with `is_wildcard:true`, `off` ignores detection |
| `--impersonate PROFILE` | — | `auto` | `auto` (rotate), `chrome`, `firefox`, `safari`, `edge`, `off` |
| `--tls-fallback on/off` | — | `on` | Retry once with vanilla rustls on impersonation error |
| `--ua-rotation on/off` | — | `on` | Pick a random real UA per request |
| `--user-agent STR` | — | — | Pin a UA, overrides rotation |
| `--cf-detect on/off` | — | `on` | Detect Cloudflare challenge pages and tag records |
| `--proxy URL` | — | — | HTTP(S) or SOCKS5 proxy |
| `--rate-limit RPS` | — | off | Per-host requests/sec ceiling |
| `--include-errors on/off` | — | `off` | Emit `status_code=0` error records |
| `--verbose` | `-v` | — | INFO to stderr (`-vv` for DEBUG) |

## Benchmark — kayak.com smoke test (2026-05-20)

86 kayak.com hosts x 433 backup-path wordlist entries = 37,238 probes per tool. Sequential wall-clock. Validator pass on top of raw responses produces the "real findings" column.

| Tool | Wall (s) | Records | Real findings | Notes |
|---|---|---|---|---|
| python (legacy) | 68.96 | 36,982 | 8 | Fastest, but misses anything that needs a real TLS handshake to bypass edge filtering. |
| retroh4ck-prober | 329.93 | 29,044 | **55** | Highest real-finding count; wildcard auto-suppress active. |
| ffuf | 586.51 | 22,667 | 43 | 10 of its 43 "findings" are wildcard FPs on `rights.kayak.com` / `kiwi.kayak.com`. |

Source: `/tmp/bench_native_1779238076/smoke_kayak/report.md` — full per-tool histograms and findings matrix.

The 10 ffuf findings that retroh4ck-prober deliberately suppresses are all on two wildcard hosts:

- `rights.kayak.com` returns an identical 555-byte CrowdRiff 404 HTML for every path. ffuf flags `debug.log`, `error.log`, `errors.log`, `terraform.tfvars` because the validator regex coincidentally matches that constant 404 body.
- `kiwi.kayak.com` returns a 307 redirect to kiwi.com's 404 page for every path. ffuf flags `documentation/`, `nuxt.config.js`, `redoc/`, `secrets.yaml`, `swagger-ui/`, `swagger-ui/index.html`.

These are not findings — they are constant responses on wildcard hosts. retroh4ck-prober's per-host wildcard fingerprint detects them and drops them under the default `strict` policy. Use `--wildcard-policy mark` if you want to see them tagged but not dropped, or `--wildcard-policy off` to bypass detection entirely.

The "Unique to rust (22)" entries in the same report are the inverse case — real `.well-known/security.txt` findings on `www.kayak.com.ar`, `.au`, `.br`, `.co`, ..., `.uy` that ffuf missed because it could not complete the TLS handshake without browser fingerprinting.

## Comparison

| Capability | retroh4ck-prober | ffuf | httpx |
|---|---|---|---|
| httpx-shape JSONL | yes | no (custom JSON) | native |
| TLS-fingerprint impersonation | yes (Chrome/Firefox/Safari/Edge) | no | no |
| Real-UA rotation per request | yes | no | static |
| Wildcard auto-detection | yes (per-host fingerprint) | partial (response-size filter only) | no |
| Cloudflare challenge tagging | yes | no | no |
| Proxy support (HTTP / SOCKS5) | yes | yes | yes |
| Single static binary | yes | yes | yes |

## Build from source

```bash
# Requires Rust stable 1.75 or newer.
cargo build --release
cargo test
cargo clippy --all-targets --all-features -- -D warnings
```

Release profile is `lto = "fat"`, `codegen-units = 1`, `panic = "abort"`, `strip = true`. Target binary size: under 12 MB stripped.

## Detection — how the WAF / CF bypass actually works

Three layers stacked:

1. **TLS fingerprint.** The primary HTTP client is the `wreq` crate, which uses BoringSSL under the hood to reproduce the exact TLS ClientHello a real Chrome, Firefox, Safari, or Edge build sends — cipher suites, extension order, supported groups, signature algorithms, ALPN list, GREASE values. Edge devices that filter on JA3/JA4 see a browser, not a Go or Python HTTP client. The browser profile rotates per host (not per request) so HTTP/2 connection coalescing stays intact.
2. **User-Agent.** A pool of ~20 real-world UA strings per browser family is baked into the binary at compile time. A new UA is drawn per request from the family that matches the active TLS profile — sending a Chrome UA over a Firefox JA3 is exactly the kind of mismatch a WAF flags, so we never do it.
3. **Cloudflare challenge detection.** When a response is HTTP 403 with `Server: cloudflare` and a `cf-chl-bypass` body marker, or HTTP 503 with `Just a moment...`, or any response with the `cf-mitigated` header, the record is tagged `cf_challenge:true` and `cf_mitigated` is preserved. Downstream stages can then route the URL through a different profile, a proxy, or skip it.

When the impersonated client returns a transport error (TLS alert, connect timeout against a host that hates one specific JA3), the prober falls back once to a vanilla rustls client and re-emits the record with `tls_impersonation:"fallback:vanilla"`. After three consecutive impersonation failures on the same host, that host's kill-switch trips and the rest of its probes go straight through the fallback client — saving time on edges that simply do not like browser fingerprints.

## License

GPL-3.0-or-later. See [`LICENSE`](LICENSE).
