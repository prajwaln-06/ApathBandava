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
