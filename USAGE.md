# retroh4ck-prober — Usage Guide

End-to-end reference for operating the prober. For internal design see [`ARCHITECTURE.md`](ARCHITECTURE.md); for the elevator-pitch see [`README.md`](README.md).

## Common workflows

### 1. Recon — pipe from a subdomain discovery tool

```bash
subfinder -d target.com -silent \
  | retroh4ck-prober -path backup_paths.txt -o target_probe.jsonl
```

Subfinder emits `host` per line; the prober prepends `https://` when scheme is missing, falling back to `http://` on TLS failure (when `--tls-fallback on`, which is the default). The output JSONL is ready for any httpx-shape consumer.

### 2. Pentest — Firefox impersonation through a SOCKS5 tunnel

```bash
retroh4ck-prober -l in_scope.txt -path api_doc_paths.txt \
  --impersonate firefox \
  --proxy socks5://127.0.0.1:1080 \
  --threads 50 \
  -o pentest_probe.jsonl
```

Locks every request to the Firefox 133 TLS fingerprint and a matching Firefox UA. `via_proxy:true` is set on every emitted record. Lower thread count avoids saturating the SOCKS5 tunnel.

### 3. Forensic deep-dive — capture everything, including wildcards and errors

```bash
retroh4ck-prober -l hosts.txt -path wordlist.txt \
  --wildcard-policy off \
  --include-errors on \
  --body-preview 16384 \
  -vv \
  -o forensic.jsonl
```

`--wildcard-policy off` disables detection entirely, so every probe is emitted regardless of whether the host returns a constant body. `--include-errors on` adds `status_code:0` records with the underlying error string. `-vv` raises log level to DEBUG.

### 4. CI / smoke job — strict mode, fail loud on input error

```bash
retroh4ck-prober -l hosts.txt -path paths.txt -o out.jsonl \
  --timeout 8 --retries 2
echo "exit=$?"  # 0 on success, 3/4/5 on input/output/network failure
```

Exit codes: `0` all probes attempted, `2` CLI parse error, `3` input file missing, `4` output unwritable, `5` all probes failed.

## All flags — examples

### Input / output

```bash
# Explicit list
retroh4ck-prober --list hosts.txt --paths words.txt --output out.jsonl
# httpx-style short flags
retroh4ck-prober -l hosts.txt -path words.txt -o out.jsonl
# Read hosts from stdin
cat hosts.txt | retroh4ck-prober -path words.txt -o out.jsonl
```

### Concurrency and timeouts

```bash
# Default: 200 threads, 5 s timeout, 1 retry.
retroh4ck-prober -l hosts.txt -path words.txt -threads 200 -timeout 5 -retries 1
# Slow target, generous retries
retroh4ck-prober -l hosts.txt -path words.txt -threads 50 -timeout 15 -retries 3
```

### Status filtering and body preview

```bash
# Default match codes: 200,301,302,307,308,401,403
retroh4ck-prober -l hosts.txt -path words.txt -mc 200,403
# Capture more body for deep validators (default 8192)
retroh4ck-prober -l hosts.txt -path words.txt --body-preview 16384
```

### Wildcard policy

```bash
# Default: strict — drop wildcard matches silently
retroh4ck-prober -l hosts.txt -path words.txt --wildcard-policy strict
# Keep them but tag is_wildcard:true
retroh4ck-prober -l hosts.txt -path words.txt --wildcard-policy mark
# Disable detection entirely
retroh4ck-prober -l hosts.txt -path words.txt --wildcard-policy off
# Same as --wildcard-policy off
retroh4ck-prober -l hosts.txt -path words.txt --no-wildcard
```

### TLS impersonation

```bash
# Default: auto — rotate Chrome/Firefox/Safari/Edge per host
retroh4ck-prober -l hosts.txt -path words.txt --impersonate auto
# Lock to one profile
retroh4ck-prober -l hosts.txt -path words.txt --impersonate chrome
retroh4ck-prober -l hosts.txt -path words.txt --impersonate firefox
retroh4ck-prober -l hosts.txt -path words.txt --impersonate safari
retroh4ck-prober -l hosts.txt -path words.txt --impersonate edge
# Disable impersonation — use vanilla rustls
retroh4ck-prober -l hosts.txt -path words.txt --impersonate off
# Disable transport-error fallback
retroh4ck-prober -l hosts.txt -path words.txt --tls-fallback off
```

### User-Agent

```bash
# Default: rotate from the binary's UA pool, matching TLS family
retroh4ck-prober -l hosts.txt -path words.txt --ua-rotation on
# Disable rotation — uses a fixed UA per TLS family
retroh4ck-prober -l hosts.txt -path words.txt --ua-rotation off
# Pin a specific UA
retroh4ck-prober -l hosts.txt -path words.txt --user-agent "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
```

### Cloudflare detection

```bash
# Default: on — tag records with cf_challenge:true on match
retroh4ck-prober -l hosts.txt -path words.txt --cf-detect on
# Disable detection
retroh4ck-prober -l hosts.txt -path words.txt --cf-detect off
```

### Proxy and rate limiting

```bash
# HTTP / HTTPS proxy
retroh4ck-prober -l hosts.txt -path words.txt --proxy http://127.0.0.1:8080
# SOCKS5 proxy (e.g. SSH tunnel)
retroh4ck-prober -l hosts.txt -path words.txt --proxy socks5://127.0.0.1:1080
# Per-host rate limit — 10 requests/sec ceiling
retroh4ck-prober -l hosts.txt -path words.txt --rate-limit 10
```

### Debugging

```bash
# Include status_code:0 error records in the output
retroh4ck-prober -l hosts.txt -path words.txt --include-errors on
# INFO logging to stderr
retroh4ck-prober -l hosts.txt -path words.txt -v
# DEBUG logging to stderr
retroh4ck-prober -l hosts.txt -path words.txt -vv
# Or via env var
RETROH4CK_LOG=debug retroh4ck-prober -l hosts.txt -path words.txt
```

## JSON output schema

Each line of the output file is a single JSON object. Field names match ProjectDiscovery httpx so downstream parsers consume the output unchanged.

| Field | Type | Notes |
|---|---|---|
| `url` | string | Full URL probed |
| `input` | string | Original host line (scheme + netloc) |
| `path` | string | Path component including the leading `/` |
| `host` | string | Netloc only — diagnostics convenience |
| `status_code` | int | HTTP status (not `status` — httpx uses `status_code`) |
| `content_length` | int | `Content-Length` header value, else body length |
| `content_type` | string | Raw `Content-Type` header value |
| `title` | string | `<title>` content, up to 300 chars, whitespace-collapsed |
| `location` | string | `Location` header (only on 3xx) |
| `server` | string | `Server` header |
| `body_preview` | string | First N bytes of body (default 8192), HTML-entity-encoded (`"` -> `&#34;`, etc.) |
| `tech` | array | Reserved, always emitted as `[]` |
| `method` | string | `"GET"` |
| `is_wildcard` | bool | Set by the per-host wildcard detector |
| `wildcard_policy` | string | `"strict"`, `"mark"`, or `"off"` — policy in effect when this record was emitted |
| `via_proxy` | bool | Whether the request went through `--proxy` |
| `attempts` | int | `1 + retries actually used` |
| `elapsed_ms` | int | Total request time |
| `snippet_md5` | string | MD5 of `body[:200]` — used for downstream dedup |
| `tls_impersonation` | string | `"chrome-131"`, `"firefox-133"`, `"safari-18.2"`, `"edge-131"`, `"vanilla"`, or `"fallback:vanilla"` |
| `user_agent` | string | The UA actually sent |
| `cf_challenge` | bool | Cloudflare challenge page detected |
| `cf_mitigated` | string | Value of the `cf-mitigated` header if present |
| `error` | string\|null | Set when `status_code:0` |
| `timestamp` | string | ISO-8601 UTC |
| `prober` | string | `"retroh4ck-prober/0.1.0"` |

### Body preview encoding

The `body_preview` field is HTML-entity-encoded the same way ProjectDiscovery httpx does: `"` -> `&#34;`, `<` -> `&lt;`, `>` -> `&gt;`, `&` -> `&amp;`. Downstream parsers that call `html.unescape()` on the body round-trip cleanly. Do not double-decode.

## Wildcard policy — kayak.com case study

The 2026-05-20 smoke test against 86 kayak.com hosts demonstrates the behaviour concretely. Source: `/tmp/bench_native_1779238076/smoke_kayak/report.md`.

Two hosts are full wildcards:

- **`rights.kayak.com`** — every path returns an identical 555-byte CrowdRiff 404 HTML page. The body contains literal strings that happen to satisfy several validator regexes for `debug.log`, `error.log`, `errors.log`, `terraform.tfvars`.
- **`kiwi.kayak.com`** — every path returns a 307 redirect to a kiwi.com 404 page. Same coincidental validator matches for `documentation/`, `nuxt.config.js`, `redoc/`, `secrets.yaml`, `swagger-ui/`, `swagger-ui/index.html`.

ffuf flags all of these as findings. They are not — they are constant responses on wildcard hosts. retroh4ck-prober probes each host once with a random 32-hex path, fingerprints the response, and drops every subsequent match under the default `strict` policy. The 10 "missed by rust" entries in the comparison report are exactly these wildcard FPs.

If you need to inspect them anyway (for example, to confirm the host is in fact a wildcard, or because the wildcard fingerprint itself is what you're after), use `--wildcard-policy mark` to keep the records with `is_wildcard:true`, or `--wildcard-policy off` to disable detection entirely.

The opposite case shows in the same report: 22 `.well-known/security.txt` findings on `www.kayak.com.<TLD>` mirrors are unique to retroh4ck-prober. ffuf misses them because it cannot complete the TLS handshake without a real browser fingerprint.

## WAF / Cloudflare bypass walkthrough

1. **Run with default impersonation rotation.**

   ```bash
   retroh4ck-prober -l hosts.txt -path paths.txt -o out.jsonl
   ```

   The prober rotates through Chrome 131, Firefox 133, Safari 18.2, and Edge 131 TLS profiles per host. UA rotation picks a matching real-world string per request.

2. **Check for Cloudflare challenge records.**

   ```bash
   jq -c 'select(.cf_challenge == true)' out.jsonl | head
   ```

   Each match shows the host, the status code (403 or 503), and the `cf_mitigated` header if present.

3. **Retry the blocked hosts through a different profile.**

   ```bash
   jq -r 'select(.cf_challenge == true) | .input' out.jsonl | sort -u > blocked.txt
   retroh4ck-prober -l blocked.txt -path paths.txt --impersonate safari -o retry.jsonl
   ```

   Safari's TLS fingerprint frequently passes when Chrome's does not, because Cloudflare's bot management heuristics differ across browser fingerprints.

4. **If still blocked, add a proxy.**

   ```bash
   retroh4ck-prober -l blocked.txt -path paths.txt \
     --impersonate firefox \
     --proxy socks5://127.0.0.1:1080 \
     -o retry_proxied.jsonl
   ```

   A residential SOCKS5 proxy combined with Firefox impersonation handles most remaining edge cases. The output records carry `via_proxy:true` so you know which results came through the tunnel.

## Performance tuning

| Knob | Default | When to change |
|---|---|---|
| `--threads` | 200 | Lower (50-100) for slow targets, narrow proxies, or rate-limited APIs. Raise (300-500) on a fat-pipe single-target scan when wall-clock matters. |
| `--timeout` | 5 s | Raise on slow CDNs (10-15 s). Lower (2-3 s) when scanning many fast hosts and you want to drop dead targets quickly. |
| `--retries` | 1 | Raise to 2-3 for noisy networks. Set to 0 only for one-shot scans where retries would skew timing measurements. |
| `--rate-limit` | off | Set to 5-20 RPS per host when a target enforces per-IP rate limits or you're hitting a single sensitive backend. Token bucket is per-netloc, so it scales naturally across a multi-host list. |
| `--body-preview` | 8192 | Default matches httpx and is enough for every production backup-file validator. Raise to 16384-32768 only when a specific validator needs deeper context. Body cap is hardcoded at 256 KB to avoid RAM growth from large CSS/JS bundles. |

The `pool_max_idle_per_host` setting (8) is fixed and not exposed. It exists to keep HTTP/2 connection coalescing intact across the rotating TLS profiles.
