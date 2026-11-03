# Decisions

One line each: date — decision — reason.

- 2026-11-02 — Bridge is written in-repo on the `go.mau.fi/whatsmeow` library (version pinned in `go.mod`/`go.sum`) instead of vendoring a whatsapp-mcp fork — the owner chose this (option A) and asked that the whatsapp-mcp repo not be fetched; it also keeps the trusted surface to the SRS 6.2 contract only.
- 2026-11-02 — LLM is Gemini on Vertex AI behind an in-repo OpenAI-compatible `llm-gateway` service; n8n uses the OpenAI Chat Model node pointed at the gateway — keeps Google credentials out of n8n (NFR-4), keeps the provider swappable via `LLM_PROVIDER`/`LLM_MODEL`, and lets the gateway re-attach Gemini 3 thought signatures that LangChain drops between tool turns.
- 2026-11-02 — `make` targets are thin wrappers over `scripts/tasks.sh` — the dev host is Windows without `make`; `sh scripts/tasks.sh <target>` is the identical code path.
- 2026-11-02 — Schema migrations are applied idempotently by the analyzer at startup (not postgres initdb) — re-runs on existing volumes and keeps one migration path.
- 2026-11-02 — Host ports bind to 127.0.0.1 only (n8n 5678, analyzer 8000, bridge 8080) — nothing is reachable from the LAN.
- 2026-11-04 — n8n pinned to 2.46.4; workflows are published with `n8n publish:workflow` at container start — 2.x only activates on import in queue mode.
- 2026-11-04 — The four analysis agents live in sub-workflow `11-agents` (webhook → Switch → 4 AI Agent nodes) and are called concurrently by one HTTP node in `10-check` — n8n executes branches of a single execution sequentially, which would break NFR-6.
- 2026-11-04 — A deterministic "rules" finding (analyzer `/rules/baseline`) runs in parallel with the agents and feeds the verdict — hard signals (UPI pay-as-receive, threat feeds, registry mismatch, policy violations) cannot be lost to an injected or timed-out agent (SRS 3.3.4); trust signals (REGISTRY_FULL_MATCH) are only honoured from this source.
- 2026-11-04 — Redis rate limit, dedupe and commands are one analyzer call (`/intake/guard`) and the Postgres write is analyzer `/checks/record` — n8n holds no DB/Redis credentials, and hashing/campaign logic is unit-tested in Python.
- 2026-11-04 — The Postgres write runs after the reply is sent — stores the final reply text and end-to-end latency (NFR-13) without delaying the user.
- 2026-11-04 — The verdict engine counts each signal code once and uses its own severity table — an agent cannot inflate or demote severity.
- 2026-11-04 — Sandbox uses a fresh Chromium browser + temp profile per detonation inside one long-lived hardened container (read-only rootfs, non-root, iptables egress firewall, cap NET_ADMIN dropped before serving) — one container per detonation would require giving the analyzer the Docker socket, which is a larger risk.
- 2026-11-04 — Sandbox exposes `/detonate` with `mode: expand|full`; shortener expansion (FR-13) is `mode: expand` — the brief allows only `/detonate` to be exposed.
- 2026-11-04 — OpenPhish community feed fills the SRS `phishtank` feed slot — PhishTank no longer accepts new API registrations.
- 2026-11-04 — Registry entries are drafted with `status: needs_review`; `REGISTRY_INCLUDE_UNREVIEWED=true` lets the demo use them until a human approves them in the admin view.
- 2026-11-04 — Hard combo `REGISTRY_DOMAIN_MISMATCH + ASKS_PIN_OTP_CARD` is implemented as mismatch + (`CREDENTIAL_REQUEST` or `PAGE_ASKS_PIN_OTP_CARD`) — the SRS names no ASKS_PIN_OTP_CARD code.
- 2026-11-04 — Bridge alerts on unlink go to `ALERT_WEBHOOK_URL` (out-of-band) and to ADMIN_JID — a WhatsApp alert cannot be delivered while the bridge itself is unlinked.
- 2026-11-04 — Dev sender allowlist (`SENDER_ALLOWLIST`) in the bridge — the owner has only personal numbers; the bot must not answer anyone else.
- 2026-11-04 — LLM is `gemini-3.5-flash-lite` with `reasoning_effort: minimal` (gateway default) — ~1 s per call vs ~2.5 s for Flash; hard signals come from the deterministic baseline, so agent depth matters less than latency (NFR-6).
- 2026-11-04 — The gateway hedges slow calls (duplicate request after 1.8 s, first answer wins, max 3) — Vertex has a long tail (single calls of 8–16 s observed); hedging cut demo p95 from 18 s to 7 s.
- 2026-11-04 — AI Agent nodes use typeVersion 2.2 — v3.x occasionally hung after the first model call (sub-executions marked "crashed" after minutes); v2.2 runs tools inside the node and did not hang.
- 2026-11-04 — Agent fan-out timeout is 12 s (brief says >20 s → unknown) — needed for NFR-6 p95 < 15 s; a timed-out agent still becomes `{status:"unknown", signals:[]}` and the verdict runs.
- 2026-11-04 — List-valued tool arguments (`registry_match`) are passed as comma-separated strings — n8n's `$fromAI(..., 'json')` rejects empty arrays, which made the Impersonation agent fail on messages without URLs.
- 2026-11-04 — Agent nodes retry once on failure and are capped at 4 iterations — Structured Output Parser rejections otherwise become `unknown`; one Scam-type run looped 14 model calls.
- 2026-11-04 — Evaluation scoring: a scam counts as detected when the verdict is SCAM or SUSPICIOUS; a legit item is a false positive only when flagged (SCAM/SUSPICIOUS); FR-6 off-topic replies count as "not flagged"; injection passes when detection is not suppressed and no message goes to anyone but the sender (campaign alerts to ADMIN_JID are allowed).
- 2026-11-04 — Non-official links in replies are defanged (`hxxps://evil[.]example`) — evidence can name the scam link without making it clickable in WhatsApp.
- 2026-11-04 — Merge orders findings rules-first and uses the authoritative severity table — reasons quote the deterministic evidence (e.g. "This QR sends ₹1,499 FROM your account") instead of bare artifacts from an LLM.
