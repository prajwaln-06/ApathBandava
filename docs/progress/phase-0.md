# Phase 0 — Repo + stack

Covers: NFR-2 (sandbox network), NFR-4 (secrets in `.env`), NFR-14 (`docker compose up` brings up the stack).

## Tasks
| # | Task | Files |
|---|------|-------|
| 0.1 | Monorepo layout | `bridge/ analyzer/ sandbox/ llm-gateway/ n8n/ registry/seed/ db/migrations/ tests/ docs/` |
| 0.2 | Compose stack, healthcheck on every service, localhost-only host ports | `docker-compose.yml` |
| 0.3 | Networks: `core_net` (bridge, n8n, analyzer, llm-gateway, postgres, redis); `sandbox_net` (sandbox + analyzer only) | `docker-compose.yml` |
| 0.4 | Postgres 16 + pgvector; SRS 6.1 schema as migration 001 (applied by analyzer at startup, idempotent) | `db/migrations/001_init.sql` |
| 0.5 | Analyzer skeleton (FastAPI, Tesseract eng+hin, zbar, OpenCV) with `/health` | `analyzer/` |
| 0.6 | Sandbox skeleton (Playwright Chromium, non-root, read-only rootfs) with `/health` | `sandbox/` |
| 0.7 | Bridge skeleton (Go) with `/api/health` | `bridge/` |
| 0.8 | LLM gateway (OpenAI-compatible, provider from env) | `llm-gateway/` |
| 0.9 | n8n with generated encryption key; bootstrap imports credentials + workflows | `n8n/bootstrap/` |
| 0.10 | `.env.example`, generated `.env`, secret-scan hook | `.env.example`, `scripts/` |
| 0.11 | `make up/down/test/eval/demo-fixtures/logs` (Makefile → `scripts/tasks.sh`) | `Makefile`, `scripts/tasks.sh` |

## Gate
`make up` → every container reports `healthy` in `docker compose ps`.

## Gate report (2026-11-04)

Commands:
```
sh scripts/tasks.sh up        # identical to `make up` (Makefile wraps scripts/tasks.sh)
curl -s http://127.0.0.1:8000/health
curl -s http://127.0.0.1:8080/api/health
```
Output (trimmed):
```
waiting for containers to become healthy...
SERVICE       STATUS
analyzer      Up 54 seconds (healthy)
llm-gateway   Up 54 seconds (healthy)
n8n           Up 38 seconds (healthy)
postgres      Up 13 minutes (healthy)
redis         Up 13 minutes (healthy)
sandbox       Up 54 seconds (healthy)
wa-bridge     Up 54 seconds (healthy)
EXIT=0
{"status":"ok","ready":true,"entities":25,"playbooks":15}
{"connected":true,"logged_in":false,"status":"ok"}
```

| Criterion | Result |
|---|---|
| `make up` → all containers healthy | PASS (7/7 healthy) |
| Sandbox on its own network with egress firewall | PASS (entrypoint refuses to start without the iptables rules; container healthy) |
| Secrets only in `.env` (gitignored), `.env.example` complete | PASS (`scripts/check-secrets.sh` OK) |

Issues fixed during the gate: Docker storage was full on C: (moved to D:\DockerData by the owner); n8n 2.x cannot activate on import in regular mode → bootstrap now publishes each workflow; Docker cannot nest a bind mount inside a read-only volume → fixtures mounted at `/media-fixtures`.
