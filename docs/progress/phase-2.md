# Phase 2 — Analyzer core

Covers: FR-8, FR-9, FR-10, FR-11 (extraction), FR-12 (static URL checks), FR-14 (reputation adapters, mocked), FR-16 (download hashing via sandbox client), FR-22, FR-23, FR-24 (UPI), FR-25 (deterministic verdict), FR-26..28 (reply template + validator), FR-3..7 (intake guard), FR-29, FR-30 (cache, campaigns), NFR-8 (5 s per-feed timeout + fallback), NFR-10 (salted sender hash, 7-day purge).

## Tasks
| # | Task | Files |
|---|------|-------|
| 2.1 | `/extract` regex + Tesseract `eng+hin` OCR + pyzbar/OpenCV QR; media path guard | `analyzer/app/extract.py` |
| 2.2 | `/url/static` (punycode/homoglyph skeleton, brand in subdomain/path, lookalike edit distance, IP host, `@`, risky TLD, shorteners) | `analyzer/app/url_static.py` |
| 2.3 | `/url/reputation` with adapters (RDAP, crt.sh, Safe Browsing, URLhaus, OpenPhish, VirusTotal) + offline overlay for reserved test TLDs | `analyzer/app/reputation/` |
| 2.4 | `/upi/parse`, pay-as-receive, UPI ID flags, collect-request explanation | `analyzer/app/upi.py` |
| 2.5 | Signal enum + schema validator | `analyzer/app/signals.py`, `analyzer/app/schema.py` |
| 2.6 | Verdict engine + weights | `analyzer/app/verdict.py`, `analyzer/weights.yaml` |
| 2.7 | Deterministic baseline, intake guard, store, reply, admin, API | `analyzer/app/{rules,intake,store,reply,admin,main}.py` |
| 2.8 | pytest suite (real Postgres/Redis, mocked feeds) | `tests/conftest.py`, `tests/unit/*` |

## Gate report (2026-11-04)

Command: `sh scripts/tasks.sh test` (= `make test`)
```
Required test coverage of 90% reached. Total coverage: 98.42%
109 passed in 9.90s
Name                  Stmts   Miss Branch BrPart  Cover
/app/app/verdict.py      38      0     16      0   100%
EXIT=0
```

| Criterion | Result |
|---|---|
| pytest passes | PASS (109/109) |
| ≥ 90 % coverage on `analyzer/` | PASS (98.42 %, branch coverage on) |
| 100 % branch coverage on `verdict.py` | PASS |

Note: `main.py` lines 105-120 (`init_deps`, production start-up) are exercised by the running container (Phase 0 health check shows `ready: true`), not by unit tests.
