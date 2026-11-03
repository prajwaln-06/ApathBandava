# ScamSaathi — final summary (2026-11-04)

## Phase gates

| Phase | Gate | Status |
|---|---|---|
| 0 Repo + stack | `make up` → all containers healthy | **PASS** (8/8 incl. test mock) |
| 1 WhatsApp bridge | `00-echo` replies to a test message | **PASS with bridge mocked**; live QR scan **pending (human)** |
| 2 Analyzer core | pytest, ≥90 % coverage, 100 % branch on `verdict.py` | **PASS** (117 tests, 98.46 %, 100 %) |
| 3 Registry seed | 25 entities + 15 playbooks; CI rejects policy without quote + source | **PASS**; hand verification of facts **pending (human)** |
| 4 n8n agents | 60 fixtures → schema-valid output from all 4 agents | **PASS** (232/232) |
| 5 Verdict + reply | D1–D5 via webhook test path | **PASS** (+ D8 campaign, cache hit < 2 s) |
| 6 Hardening | injection, SSRF, recipient-tampering suites | **PASS** (66/66) |
| 7 Eval + demo | NFR-12 and NFR-6 met; `docs/eval.md`; README | **PASS** (recall 97.8 %, FPR 0 %, p50 5.94 s, p95 7.07 s); live D1–D8 video **pending** |

## Done
- **All P0 FRs** are implemented and traced in `docs/traceability.md`. Most P1/P2 items are done too: rate limit, commands, SMS-screenshot hint, sender/phone/UPI-handle checks, detonation, campaigns, registry crawler with human review queue, admin view.
- **Stack:** `make up / test / eval / security / demo / demo-fixtures` work. On Windows without `make`, use `sh scripts/tasks.sh <target>`.
- **Security controls are enforced by tests:**
  - agents have no WhatsApp tools, and the tool allowlist is checked against the workflow JSON;
  - the recipient is fixed by code, and the bridge only replies to chats that wrote in the last 24 h;
  - all user, OCR and QR text is wrapped in `<untrusted>`, and outputs are schema-validated;
  - the verdict is deterministic, and trust signals only come from code;
  - the sandbox has an egress firewall and a public-IP-only check on every hop;
  - secrets are scanned in pre-commit and CI;
  - links in replies are defanged and the word "safe" is blocked.
- **Docs:** README (architecture, setup incl. QR login, limits, whatsmeow warning, Cloud API migration), `docs/decisions.md`, `docs/eval.md`, `docs/traceability.md`, and progress reports for every phase.

## Left (needs a human or a decision)
1. **QR login and live demos D1–D8.** Scan the QR from the bot phone (`make qr`), then record the demo video. See `BLOCKERS.md`.
2. **Bot number choice.** Both available numbers are personal. `SENDER_ALLOWLIST` currently restricts replies to the two known numbers.
3. **Registry review.** All 25 entries are `needs_review`. Gaps to fill from official sites:
   - SBI SMS headers and helplines (LIC included);
   - official UPI handles;
   - policy quotes for Bank of India, IDBI, Yes, Federal, HDFC Life, SBI Life, Bajaj Life, Star Health, New India and ICICI Lombard.

   Several quotes are secondary (press coverage), and `review_notes` marks which.
4. **Threat-feed keys.** Safe Browsing, VirusTotal and URLhaus each report `unknown` until a key is added to `.env`.
5. **Optional admin MCP agent and its tool-description hash check.** Not built. The SRS marks the agent optional; a read-only HTML admin view is shipped instead.
6. **D6 live demo.** It needs a real newly registered domain, because `.example` domains don't resolve.
7. **Push.** Done after the secret check if the owner approved (see the final message of the build session).

## Known risks
- **Number ban.** whatsmeow is unofficial and the number can be banned. Running on a personal number is risky.
- **Latency margin.** p50 is 5.94 s against a 6 s target and varies run to run (5.87–6.40 s). It depends on Vertex AI latency, which hedging mitigates but can't remove.
- **Registry correctness.** Matching uses `needs_review` entries (`REGISTRY_INCLUDE_UNREVIEWED=true`), so a wrong domain or header could cause false alarms or misses until reviewed. Set it to `false` after approval.
- **Synthetic eval.** The 60 fixtures were written alongside the system, so real-world accuracy will be lower. One known miss is E04, a wrong `-P` header alone, which stays below the SRS threshold.
- **The LLM can still be fooled.** Deterministic rules carry the hard signals, but an agent can be misled into omitting medium signals. The verdict can drop from SCAM to SUSPICIOUS, never below what the rules found.
- **Public repository.** Secrets stay in `.env` and `docs/` credentials, both gitignored and blocked by the hook. The WhatsApp session lives in a Docker volume, never in the repo.
- **Windows host specifics.** The repo lives in OneDrive and Docker data is on `D:\DockerData`. Moving the repo out of OneDrive is recommended.
