# Phase 1 — WhatsApp bridge

Covers: FR-1 (accept text/images/links), FR-3 (ignore groups/status, dedupe in Phase 4), NFR-9 (health check every 60 s), NFR-11 (bot reads only its own direct chats), NFR-14 (swappable adapter).

## Tasks
| # | Task | Files |
|---|------|-------|
| 1.1 | whatsmeow bridge (pinned `go.mau.fi/whatsmeow v0.0.0-20261102152715-54038813c47f`) with SRS 6.2 webhook, `POST /api/send`, `/api/health`, `/qr` | `bridge/main.go`, `bridge/go.mod`, `bridge/go.sum` |
| 1.2 | `WEBHOOK_URL` → n8n (`BRIDGE_WEBHOOK_PATH`, default `wa-inbound`; `wa-echo` for this gate) | `docker-compose.yml` |
| 1.3 | Defence in depth: `/api/send` needs `X-Bridge-Token`, direct chats only, recipient must have messaged the bot within 24 h (or be ADMIN_JID); dev `SENDER_ALLOWLIST` | `bridge/main.go` |
| 1.4 | n8n `00-echo` (webhook with header auth → Set recipient = sender_jid → HTTP send) | `n8n/build_workflows.py`, `n8n/workflows/00-echo.json` |
| 1.5 | n8n `20-health` (every 60 s, alert on unlink via ALERT_WEBHOOK_URL + ADMIN_JID) | `n8n/workflows/20-health.json` |
| 1.6 | Mock bridge for automated tests | `tests/mock_bridge/` |

## Gate report (2026-11-04)

Automated part (bridge mocked):
```
POST /webhook/wa-echo without token            -> 403
POST /webhook/wa-echo (bridge token, test token) -> 200 {"message":"Workflow was started"}
GET  mock-bridge /sent -> [{"recipient":"919999900001@s.whatsapp.net","message":"Echo: hello bot"}]
POST wa-bridge /api/send without token          -> 401 unauthorized
POST wa-bridge /api/send unknown recipient      -> 403 recipient has not messaged the bot within the reply window
POST wa-bridge /api/send to a group JID         -> 403 recipient must be a direct chat
GET  wa-bridge /qr                              -> 200 image/png (pairing QR available)
```

| Criterion | Result |
|---|---|
| `00-echo` replies to a test message (bridge mocked) | PASS |
| `00-echo` replies on live WhatsApp after QR scan | **PENDING — human step** (see below) |
| Health workflow published and polling every 60 s | PASS (published at bootstrap) |

### Human step to close this gate
1. In `.env` set `BRIDGE_WEBHOOK_PATH=wa-echo`, run `docker compose up -d wa-bridge`.
2. Open http://127.0.0.1:8080/qr (or `make qr`) and scan it from the **bot phone**: WhatsApp → Linked devices → Link a device.
3. From the other phone send "hello" to the bot number → expect "Echo: hello".
4. Set `BRIDGE_WEBHOOK_PATH=wa-inbound` again and `docker compose up -d wa-bridge`.

Per the execution protocol this criterion needs a human; work that does not depend on it continues (Phases 2–7 run with the bridge mocked).
