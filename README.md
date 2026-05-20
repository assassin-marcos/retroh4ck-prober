# retroh4ck-prober

> **This project has merged into [httpxer](https://github.com/assassin-marcos/httpxer) as of `httpxer v0.3.0` (2026-05-20).**

`retroh4ck-prober` and `httpxer` shared the same TLS impersonation stack (`wreq` + BoringSSL) and the same drop-in `httpx`-shape JSONL output. Maintaining both as separate projects was duplicating ~80% of the codebase, so they were merged.

## Where the features went

| retroh4ck-prober feature | Now in httpxer |
|---|---|
| Path-fuzz (host × wordlist) | `httpxer -l hosts.txt -path words.txt -o out.jsonl` |
| Per-host wildcard auto-suppression | `--wildcard-policy strict\|mark\|off` (default `strict`) |
| Match-codes filter | `--match-codes 200,301,302,307,308,401,403` (httpx parity) |
| Body-preview capture | `--body-preview 8192` |
| Per-host rate limiting | `--rate-limit RPS` |
| Cloudflare challenge tag | `cf_challenge:true` in output records |
| TLS-fingerprint impersonation | always on (rotates Chrome/Firefox/Safari/Edge profiles per host) |
| Output JSONL schema | unchanged — every field name is identical |

Plus everything httpxer already had: enrichment mode (1 probe per host), Wappalyzer tech-detect, CDN tagging, self-update, install scripts, cross-OS release binaries.

## Migration

```bash
# Old (this repo, deprecated):
retroh4ck-prober -l hosts.txt -path backup_paths.txt -o out.jsonl

# New (httpxer v0.3.0+):
httpxer -l hosts.txt -path backup_paths.txt -o out.jsonl
```

Same flags, same default values, same JSONL output. Drop-in replacement.

## Install httpxer

```bash
# Linux / macOS
curl -sL https://raw.githubusercontent.com/assassin-marcos/httpxer/main/install.sh | bash

# Windows (PowerShell)
irm https://raw.githubusercontent.com/assassin-marcos/httpxer/main/install.ps1 | iex
```

## Archive status

This repository is **archived read-only**. No new commits, issues, or pull requests. The Git history is preserved for reference. All future work happens at [assassin-marcos/httpxer](https://github.com/assassin-marcos/httpxer).
