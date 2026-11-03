# Blockers / human steps

None of these blocks the code; each needs a person.

| # | Item | Why a human | What to do |
|---|------|-------------|------------|
| 1 | **WhatsApp QR login** (Phase 1 live gate, D1–D8 live) | Needs the bot phone | `make qr`, scan from WhatsApp → Linked devices on the bot phone; message the bot from the other phone. Steps in `docs/progress/phase-1.md`. |
| 2 | **Choice of bot number** | Both available numbers are personal; whatsmeow can get a number banned | Decide which number runs the bot. `SENDER_ALLOWLIST` (in `.env`) already limits replies to the two known numbers. |
| 3 | **Registry review** (25 entities, `status: needs_review`) | Facts must be checked against official sites | Verify each YAML in `registry/seed/` (see `review_notes`), then approve in `/admin` or set `status: approved`. Gaps: SBI SMS headers, LIC helpline, official UPI handles, Bank of India / IDBI / Yes / Federal policy quotes. |
| 4 | Threat-feed keys (optional) | Owner will provide | Add `GSB_API_KEY`, `VT_API_KEY`, `URLHAUS_AUTH_KEY` to `.env`, then `docker compose up -d analyzer`. |
| 5 | D6 live demo | Needs a real, newly registered domain with no brand (the sandbox only reaches public IPs; `.example` does not resolve) | Register a throw-away domain, host a harmless page, send it to the bot. |
| 6 | `make` on the Windows dev host | Running the downloaded `make.exe` was not permitted | Use `sh scripts/tasks.sh <target>` (identical), or install make yourself. |
