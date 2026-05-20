# Changelog

All notable changes to retroh4ck-prober are tracked in this file. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-05-20

Initial public release.

### Added

- **httpx-shape JSONL output.** Every field (`url`, `input`, `path`, `host`, `status_code`, `content_length`, `content_type`, `title`, `location`, `server`, `body_preview`, `tech`, `method`, `timestamp`) matches the ProjectDiscovery httpx schema so existing parsers consume the output with zero code changes. Body preview is HTML-entity-encoded (`"` -> `&#34;`) to match httpx's `-body-preview` encoding.
- **Hybrid TLS-fingerprint impersonation.** Primary client is the `wreq` crate with rotating Chrome 131 / Firefox 133 / Safari 18 / Edge 131 profiles; secondary client is `reqwest` + `rustls-tls` as a transport-error fallback. Each emitted record tags the `tls_impersonation` field with the client that produced it (`chrome-131`, `firefox-133`, `safari-18.2`, `edge-131`, `vanilla`, or `fallback:vanilla`).
- **Per-host wildcard auto-suppression.** Each host is probed with a random 32-hex path; the (`content_length`, `content_type`, `snippet_md5`) tuple of that response becomes the wildcard fingerprint. Subsequent matches are flagged `is_wildcard:true` and dropped under the default `strict` policy. `--wildcard-policy mark` keeps them in the output, `--wildcard-policy off` disables the detector.
- **Real User-Agent rotation.** ~20 real-browser UA strings per family baked into the binary via `include_str!`. A new UA is picked per request, always from the family that matches the active TLS profile. `--user-agent` pins a specific UA and overrides rotation; `--ua-rotation off` disables rotation.
- **Cloudflare challenge detection.** Responses matching the Cloudflare challenge signatures (403 + `Server: cloudflare` + `cf-chl-bypass` body, or 503 + `Just a moment...` body, or any `cf-mitigated` response header) are tagged with `cf_challenge:true` and `cf_mitigated:<value>` so downstream stages can route around them.
- **Proxy support.** `--proxy` accepts HTTP, HTTPS, and SOCKS5 URLs. Records sent through the proxy carry `via_proxy:true`.
- **Per-host rate limiting.** `--rate-limit RPS` enforces a token-bucket ceiling per netloc.
- **httpx-parity CLI flags.** `-l`, `-path`, `-o`, `-threads`, `-timeout`, `-retries`, `-mc`, `-body-preview` match the ProjectDiscovery httpx CLI surface. `--hosts`, `--wordlist` retained as aliases for backwards compatibility.
- **Cross-OS release artifacts.** Static binaries for Linux x86_64 / aarch64, macOS x86_64 / aarch64, and Windows x86_64 published on every tag.

### Baseline benchmark

- kayak.com smoke test (86 hosts x 433 backup-path entries, 37,238 probes):
  - 55 validator-confirmed real findings (highest of three tools tested).
  - Zero connection-error rate.
  - 10 ffuf "findings" deliberately suppressed as wildcard false positives on `rights.kayak.com` and `kiwi.kayak.com` (both hosts return constant 404 bodies for every path).
  - Source: `/tmp/bench_native_1779238076/smoke_kayak/report.md`.

[0.1.0]: https://github.com/assassin-marcos/retroh4ck-prober/releases/tag/v0.1.0
