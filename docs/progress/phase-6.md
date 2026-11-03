# Phase 6 — Hardening

Covers: NFR-2, NFR-3, NFR-5, NFR-10, FR-4, FR-13, FR-15, FR-16, rule 2, rule 5.

## Tasks
| # | Task | Files |
|---|------|-------|
| 6.1 | Sandbox: Playwright, non-root, read-only rootfs, iptables egress firewall (refuses to start without it), per-hop public-IP check, service-name denylist, 20 s / 5 MB caps, downloads hashed + deleted | `sandbox/` |
| 6.2 | `/url/detonate` proxy + flags (`PAGE_ASKS_PIN_OTP_CARD`, `APK_DOWNLOAD`) | `analyzer/app/sandbox_client.py` |
| 6.3 | Rate limits (20/h) and dedupe | `analyzer/app/intake.py` |
| 6.4 | Injection suite (16 crafted messages + 10 injection fixtures) | `tests/security/test_injection.py` |
| 6.5 | SSRF suite (metadata IP, service names, RFC1918, loopback, IP encodings, DNS-to-private, redirect-to-metadata, non-http schemes) | `tests/security/test_ssrf.py` |
| 6.6 | Recipient-tampering suite (extra payload fields, recipient in text, groups/status, missing tokens, test-mode token, bridge send guards) | `tests/security/test_recipient_tampering.py` |
| 6.7 | Privacy jobs: salted sender hash, 7-day raw-text purge (analyzer loop + `40-campaigns`) | `analyzer/app/store.py`, `analyzer/app/main.py` |
| 6.8 | MCP admin agent tool-description hash check | **Not built** — the admin MCP agent is optional in the SRS and was not shipped (see FINAL.md) |

## Gate report (2026-11-04)

Command: `make security`
```
..................................................................       [100%]
66 passed in 67.10s
```

| Criterion | Result |
|---|---|
| Injection suite (≥15 crafted messages: 16 + 10 fixtures) — correct verdict, recipient unchanged, no tool misuse | PASS |
| SSRF suite (`169.254.169.254`, `postgres:5432`, service names, RFC1918, loopback, hex/decimal IPs, DNS→private, redirect→metadata, non-http schemes; expand + full) | PASS |
| Recipient-tampering suite | PASS |
| MCP admin-agent tool-hash check | NOT BUILT (optional admin agent not shipped) |

Attempts: first run failed 8 tests — 7 because FR-30 campaign alerts to ADMIN_JID (legitimate, code-set) were counted as tampering, 1 because the redirect test matched a substring of the original URL; tests corrected, no product change needed.
