# Phase 4 — n8n agents

Covers: NFR-1 (tool allowlists), NFR-5 (untrusted wrapping, schema validation), NFR-13 (trace id, executions), FR-25 inputs, SRS 3.2 agents and 6.4 schema.

## Tasks
| # | Task | Files |
|---|------|-------|
| 4.1 | `10-check` in the brief's shape: Webhook → Set(trace, sender_jid, msg) → IF(group/status) → Redis rate limit (`/intake/guard`) → "Checking…" → `/extract` → cache lookup → IF(hit → composer) → 4 AI agents in parallel (+ deterministic rules) → Merge + Code(schema validation, drop unknown codes) → `/verdict` → composer → Set(recipient = sender_jid) → `/api/send` → Postgres write | `n8n/build_workflows.py`, `n8n/workflows/10-check.json` |
| 4.2 | `11-agents`: Webhook → Switch → Wording / Link / Impersonation / Scam-type AI Agent nodes, each with its own Chat Model, HTTP Request **tool** nodes (allowlist) and Structured Output Parser (SRS 6.4 schema); retry once on parser failure | `n8n/workflows/11-agents.json` |
| 4.3 | Shared anti-injection preamble + per-agent prompts from the brief; `<untrusted>` wrapping with tag-escape neutralised | `n8n/build_workflows.py` (`PREAMBLE`, `AGENT_PROMPTS`, `FANOUT_JS`) |
| 4.4 | Agent timeout: LLM call timeout 20 s; HTTP fan-out timeout 24 s → `{status:"unknown", signals:[]}`; verdict still runs | `MERGE_JS` |
| 4.5 | 60 fixtures (15 scam text, 10 scam image/QR, 10 impersonation, 15 legit, 10 injection) + generated images + offline reputation overlay for `.example` | `tests/fixtures/` |
| 4.6 | Eval runner through the webhook test path (bridge mocked) | `tests/e2e/run_fixtures.py`, `tests/mock_bridge/` |
| 4.7 | LLM via `llm-gateway` (Gemini 3.5 Flash-Lite on Vertex, reasoning `minimal`) | `llm-gateway/`, `.env.example` |
