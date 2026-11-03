# Phase 7 — Eval + demo

Covers: NFR-6, NFR-7, NFR-12, NFR-13, FR-30 (D8), FR-32 (admin view), README / eval docs.

## Tasks
| # | Task | Files |
|---|------|-------|
| 7.1 | `make eval` on the 60 fixtures; tuning (model, reasoning effort, hedged calls, agent version, rules-first evidence, scoring definitions) | `tests/e2e/run_fixtures.py`, `llm-gateway/`, `n8n/build_workflows.py` |
| 7.2 | Cache-hit latency check | `tests/e2e/cache_latency.py` |
| 7.3 | Campaign detection + admin view (D8) | `analyzer/app/store.py`, `analyzer/app/admin.py`, `tests/e2e/demo_campaign.py` |
| 7.4 | `docs/eval.md`, README, traceability, FINAL | `docs/` |
| 7.5 | Demo video of D1–D8 live | **PENDING — needs QR login (human)** |

## Gate report (2026-11-04)

Command: `make eval`
```
recall 0.978, fpr 0.0, p50 5.94 s, p95 7.07 s
NFR-12 recall >= 90% PASS | NFR-12 FPR <= 10% PASS | NFR-6 p50 < 6 s PASS | NFR-6 p95 < 15 s PASS
Phase 4 schema-valid PASS | NFR-5 injection PASS | recipient unchanged PASS | never 'safe' PASS
NFR-7 cache hit: p50 1.70s, max 1.84s -> PASS
```

| Criterion | Result |
|---|---|
| `make eval` meets NFR-12 | PASS (recall 97.8 %, FPR 0 %) |
| `make eval` meets NFR-6 | PASS (p50 5.94 s, p95 7.07 s) — thin p50 margin, see `docs/eval.md` |
| `docs/eval.md` written | PASS |
| README done | PASS |
| D1–D8 live on WhatsApp | PENDING — QR login + registry review (human) |

Attempts on NFR-6 p50: 6.40 s → 6.20 s → 6.19 s → 5.87 s → 5.94 s (hedged LLM calls, agent v2.2, parallel registry tools, narrower detonation).
