# Traceability — requirement → implementation → test

P0 requirements are in **bold**. "e2e" = `tests/e2e/run_fixtures.py` (`make eval`), "sec" = `tests/security/` (`make security`).

## Functional requirements

| ID | Pri | Implementation | Test |
|---|---|---|---|
| **FR-1** text, forwarded, images, links | P0 | `bridge/main.go` (`onMessage`, `saveImage`), n8n `10-check` webhook | e2e (text + 12 image fixtures), `tests/unit/test_extract.py::test_image_ocr_and_qr` |
| **FR-2** "Checking…" within 2 s | P0 | `10-check` node `Send "Checking…"` (right after the intake guard) | e2e execution logs (`scripts/n8n_last_exec.js`): guard + send < 150 ms |
| **FR-3** dedupe, ignore groups/status | P0 | bridge filter; `analyzer/app/intake.py` (`dedupe:` key); `10-check` IF `Direct chat?` | `test_intake_store_reply.py::test_guard_check_and_dedupe`, `::test_guard_groups_status_ignored`, sec `test_group_and_status_senders_get_nothing` |
| FR-4 20 checks/hour/sender | P1 | `intake.guard` Redis counter | `test_rate_limit_polite_once` |
| FR-5 help/hindi/english/report | P1 | `intake.TEXT`, `intake.COMMANDS` | `test_commands_and_language` |
| **FR-6** off-topic refusal | P0 | `intake.is_offtopic` | `test_offtopic_unsupported_hindi_detect` |
| FR-7 ask for screenshot when SMS has no sender ID | P1 | `reply.build_context` (`hint`) | `test_build_context` |
| **FR-8** OCR eng+hin | P0 | `extract.run_ocr` (Tesseract `eng+hin`), URL re-joining for wrapped screenshots | `test_extract.py::test_image_ocr_and_qr`, `::test_d1_fixture_image` |
| **FR-9** QR decode | P0 | `extract.decode_qr` (pyzbar, OpenCV fallback) | `::test_image_ocr_and_qr`, `::test_qr_opencv_fallback`, `::test_d2_fixture_qr` |
| **FR-10** URLs, upi://, UPI IDs, phones, sender IDs, amounts | P0 | `extract.extract`, `extract_urls`, `extract_phones` | `::test_text_artifacts`, `::test_special_numbers`, `::test_ip_literal_and_noise` |
| **FR-11** claimed brand via aliases | P0 | `registry.Registry.find_brands` (longest-match) | `::test_brand_longest_match` |
| **FR-12** static URL checks | P0 | `analyzer/app/url_static.py` | `test_url_upi.py::test_lookalike_and_brand_in_subdomain`, `::test_homoglyph_punycode`, `::test_ip_at_tld_shortener` |
| **FR-13** shortener expansion in sandbox only, ≤5 hops | P0 | `sandbox/app.py::expand`, `sandbox_client.expand`, `rules.baseline` | `test_rules_api.py::test_rules_shortener_expansion_threat_and_new_domain`, sec `test_ssrf.py` (expand mode) |
| **FR-14** reputation feeds | P0 | `analyzer/app/reputation/` (RDAP, crt.sh, GSB, URLhaus, OpenPhish, VT) | `test_reputation_sandbox.py::test_real_adapters_with_mocked_http`, `::test_flags_from_fake_adapters` |
| FR-15 detonation | P1 | `sandbox/app.py::detonate`, Link agent tool `url_detonate` | `test_reputation_sandbox.py::test_sandbox_client`, sec `test_ssrf.py` (full mode) |
| **FR-16** downloads hashed, never run | P0 | `sandbox/app.py` (download → sha256 → delete), `sandbox_client.with_flags` (`APK_DOWNLOAD`) | `::test_sandbox_client` |
| **FR-17** brand → registry entry | P0 | `Registry.match` | `test_registry_playbooks.py::test_match_bank_domain_header_phone`, `::test_match_infers_entity_from_header_or_domain` |
| **FR-18** domains vs `.bank.in` + legacy | P0 | `Registry.match` (url checks), `rules` `REGISTRY_DOMAIN_MISMATCH` | same + `test_rules_api.py::test_rules_d1_like_kyc_scam` |
| FR-19 SMS header + suffix | P1 | `Registry.match` (`SENDER_ID_RX`, `-P` on service content) | `::test_match_bank_domain_header_phone` |
| FR-20 phone numbers | P1 | `Registry.match`, `rules` `PHONE_NOT_OFFICIAL` (mobiles only) | same, `test_rules_shortener_expansion_threat_and_new_domain` |
| **FR-21** `never_does` with quote + source | P0 | `Registry.policy`, `registry.POLICY_DETECTORS`, seeds `registry/seed/**` | `::test_policy_violations`, `::test_ci_rejects_policy_without_quote_or_source`, `scripts/validate_seeds.py` |
| **FR-22** pay-as-receive is hard SCAM | P0 | `upi.parse`, `upi.pay_as_receive`, signal `UPI_PAY_AS_RECEIVE` (hard) | `test_url_upi.py::test_pay_as_receive_is_detected`, `test_verdict.py::test_hard_signal_forces_scam_and_ranks_first`, e2e D2 |
| FR-23 UPI ID brand/handle | P1 | `upi.upi_id_flags` | `::test_upi_id_flags` |
| **FR-24** collect-request explanation | P0 | `upi.collect_request`, `reply.build_context` special line | `::test_collect_request_explanation`, e2e D3 |
| **FR-25** deterministic verdict | P0 | `analyzer/app/verdict.py`, `analyzer/weights.yaml` | `tests/unit/test_verdict.py` (100 % branch) |
| **FR-26** reply contents | P0 | composer agent (`10-check`), `reply.build_context`, `reply.fallback_reply` | `test_intake_store_reply.py::test_fallback_reply_en_hi_and_limits`, e2e demo checks |
| **FR-27** EN/HI, ≤900 chars | P0 | `reply.VERDICT_LINE/STEPS` (EN+HI), `reply.validate_reply` | `::test_fallback_reply_en_hi_and_limits`, `::test_validate_reply_rejects_bad_composer_output` |
| **FR-28** never "safe" | P0 | `reply.BANNED`, `reply.finalize` fallback | `::test_validate_reply_rejects_bad_composer_output`, e2e gate "never says safe" |
| **FR-29** 24 h cache by artifact hash | P0 | `store.cache_key/cache_lookup/record`, `10-check` `Cache lookup` → `Cache hit?` | `::test_store_record_cache_campaign_purge`, `test_rules_api.py::test_pipeline_endpoints` |
| FR-30 campaigns (5 senders / 6 h) | P1 | `store._campaign`, `10-check` `Campaign alert?`, `40-campaigns` | `::test_store_record_cache_campaign_purge`, `tests/e2e/demo_campaign.py` (D8) |
| FR-31 registry crawler → review queue | P1 | n8n `30-registry-crawl`, analyzer `/registry/sources`, `/registry/review` (quote must be verbatim) | `test_rules_api.py::test_registry_crawler_endpoints` |
| FR-32 admin view | P2 | `analyzer/app/admin.py` (`/admin`) | `test_rules_api.py::test_admin` |

## Non-functional requirements

| ID | Implementation | Evidence |
|---|---|---|
| NFR-1 no WhatsApp/fs/shell tools for analysis agents | `n8n/build_workflows.py` `TOOL_ALLOWLIST` | `tests/unit/test_workflows.py` |
| NFR-2 sandbox network isolation | `docker-compose.yml` (`sandbox_net` only, read-only, cap-drop after iptables), `sandbox/entrypoint.sh` | sec `test_ssrf.py::test_network_layout`, `::test_sandbox_refuses_internal_targets` |
| NFR-3 user URLs fetched only in sandbox | analyzer has no URL fetch (reputation queries lookup services), `sandbox_client` | sec `test_ssrf.py::test_analyzer_static_and_reputation_never_fetch_internal` |
| NFR-4 secrets only in `.env` | `.gitignore`, `scripts/check-secrets.sh` (pre-commit + CI), `llm-gateway` holds LLM creds | `make check-secrets`, `test_workflows.py::test_no_secrets_in_workflows` |
| NFR-5 ≥15 injection cases | `tests/security/test_injection.py` (16 cases) + 10 injection fixtures | `make security`, `docs/eval.md` |
| NFR-6 latency | parallel agents (`11-agents`), flash-lite + minimal reasoning, deterministic baseline | `docs/eval.md` p50/p95 |
| NFR-7 cache hit < 2 s | `10-check` cache branch skips agents | `docs/eval.md` (cache run) |
| NFR-8 5 s per feed + fallback | `ReputationService._guard` | `test_failing_and_slow_feeds_degrade_to_unknown` |
| NFR-9 bridge health 60 s + alert | `20-health` workflow, bridge `/api/health` | workflow test, Phase 1 report |
| NFR-10 hashes, 7-day raw-text purge | `store.sender_hash`, `store.purge`, analyzer purge loop, `40-campaigns` | `test_store_record_cache_campaign_purge` |
| NFR-11 bot reads only its own chats | bridge ignores groups/status/newsletters; no admin MCP agent shipped | bridge code, sec `test_group_and_status_senders_get_nothing` |
| NFR-12 recall ≥ 90 %, FPR ≤ 10 % | whole pipeline | `docs/eval.md` |
| NFR-13 trace ID, per-agent latency/outputs | `intake` trace_id → `checks.trace_id`, n8n executions saved (`saveDataSuccessExecution: all`) | `scripts/n8n_last_exec.js` |
| NFR-14 compose up; swappable channel | `docker-compose.yml`, `bridge/` adapter contract | Phase 0 gate; README "Cloud API migration" |
