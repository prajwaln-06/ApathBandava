# Phase 3 — Registry seed

Covers: FR-11 (aliases), FR-17, FR-18, FR-19, FR-20, FR-21 (registry + `never_does` policies), FR-23 (UPI handles), SRS 6.6 (seed format + CI rule).

## Tasks
| # | Task | Files |
|---|------|-------|
| 3.1 | 15 bank + 10 insurer YAML seeds drafted from web sources, each with `sources`, `status: needs_review`, review notes | `registry/seed/banks/*.yaml`, `registry/seed/insurers/*.yaml` |
| 3.2 | 15 playbooks (KYC, refund QR, collect request, courier fee, job tasks, electricity cut-off, insurance fee, loan app, lottery, digital arrest, fake customer care, sextortion lure, investment group, OTP request, SIM swap) with EN + HI advice | `registry/seed/playbooks/*.yaml` |
| 3.3 | Seed loader (upsert; approved entries are never downgraded) + registry/playbook loading | `analyzer/app/db.py`, `analyzer/app/registry.py` |
| 3.4 | `/registry/match`, `/registry/policy`, `/playbooks/search` | `analyzer/app/main.py` |
| 3.5 | CI: policy without `quote` + `source_url` fails; counts enforced | `scripts/validate_seeds.py`, `.github/workflows/ci.yml`, `tests/unit/test_registry_playbooks.py` |

Rules followed: nothing was invented. Where no verifiable source was found, the field is left empty and the gap is written in `review_notes` (e.g. SBI SMS headers, LIC helpline, Bank of India/IDBI policy wording). Several quotes come from press coverage of the institution's own advisory and are marked as secondary in `review_notes`. **A human must verify every entry against the official site and approve it in the admin view** (`/admin?token=…` → approve).

## Gate report (2026-11-04)

```
$ python scripts/validate_seeds.py
seeds OK: 15 banks, 10 insurers, 15 playbooks, 18 policies (all with quote + source_url)
$ curl -s http://127.0.0.1:8000/health
{"status":"ok","ready":true,"entities":25,"playbooks":15}
$ pytest unit/test_registry_playbooks.py::test_ci_rejects_policy_without_quote_or_source  -> passed
```

| Criterion | Result |
|---|---|
| 25 entities loaded | PASS |
| 15 playbooks loaded | PASS |
| CI rejects a policy without `quote` + `source_url` | PASS (`SeedError` in loader, `validate_seeds.py` exits 1, unit test) |
| Registry facts checked by hand against official sites | **PENDING — human review** (all entries `needs_review`) |
