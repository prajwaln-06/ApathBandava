# Phase 5 — Verdict + reply

Covers: FR-25..FR-29, FR-5, FR-7, FR-24, FR-30 (alert), NFR-7, NFR-10.

## Tasks
| # | Task | Files |
|---|------|-------|
| 5.1 | `/verdict` call; deterministic evidence ordered first so reasons are well-formed | `10-check`, `analyzer/app/verdict.py` |
| 5.2 | Composer agent (EN/HI) + `/reply/context` (sources, playbook advice, helpline, special UPI line, FR-7 hint) | `analyzer/app/reply.py`, `n8n/build_workflows.py` (`COMPOSER_PROMPT`) |
| 5.3 | `/reply/finalize`: ≤900 chars, correct verdict line, never "safe", no new links/numbers, defang non-official links; deterministic template fallback | `analyzer/app/reply.py` |
| 5.4 | Set node fixes recipient = `sender_jid`; send node; `checks`/`artifacts` write; 24 h cache; campaign alert to ADMIN_JID | `10-check`, `analyzer/app/store.py` |
| 5.5 | Language commands (`hindi`, `english`, `help`, `report`) | `analyzer/app/intake.py` |
| 5.6 | Demos D1–D5 via webhook test path; D8 campaign script | `tests/e2e/run_fixtures.py --only D1..D5`, `tests/e2e/demo_campaign.py` |

## Gate report (2026-11-04)

Command: `make demo` (D1–D5 via `run_fixtures.py --only D1..D5`, then `demo_campaign.py`).
```
D4 (S09) SCAM — process contradiction ✔, reporting steps ✔
D1 (I01) SCAM — not an official .bank.in/SBI domain ✔, sender ID mismatch ✔, policy quote with source ✔
D2 (I02) SCAM — says the QR sends ₹1,499 from your account ✔
D3 (I03) SCAM — PIN explanation ✔, reporting steps ✔
D5 (L01) NO_RED_FLAGS
admin alerts: 1 | campaign in admin view: True  -> D8 PASS
```

| Criterion | Result |
|---|---|
| Demos D1–D5 pass through the webhook test path | PASS |
| D8 campaign alert (bonus) | PASS |
| Cache hit < 2 s (NFR-7) | PASS (p50 1.70 s, max 1.84 s) |
| Live WhatsApp run | PENDING — QR login (human) |

Known gap: D4 "real helpline" cannot be shown until the LIC helpline is verified and added to the registry.
