"""FR-3..7 intake, FR-29/30 cache + campaigns, NFR-10 privacy, FR-26..28 reply."""
from app import intake, reply, store

JID = "919000000001@s.whatsapp.net"


def msg(text="Your KYC expired, update at sbi-kyc.example", **kw):
    base = {"msg_id": kw.pop("msg_id", "M1"), "sender_jid": JID, "chat_type": "direct", "type": "text", "text": text}
    base.update(kw)
    return base


async def test_guard_check_and_dedupe(redis):
    first = await intake.guard(redis, msg(), "salt", 20)
    assert first["action"] == "check" and first["language"] == "en" and first["checking"]
    assert first["sender_hash"] == store.sender_hash(JID, "salt") and JID not in str(first)
    dup = await intake.guard(redis, msg(), "salt", 20)
    assert (dup["action"], dup["reason"]) == ("ignore", "duplicate")


async def test_guard_groups_status_ignored(redis):
    for jid in ("1203630@g.us", "status@broadcast", "123@newsletter", ""):
        assert (await intake.guard(redis, msg(sender_jid=jid, msg_id=jid + "x"), "s", 20))["action"] == "ignore"
    assert (await intake.guard(redis, msg(chat_type="group", msg_id="G"), "s", 20))["reason"] == "not_direct"


async def test_commands_and_language(redis):
    r = await intake.guard(redis, msg("hindi", msg_id="C1"), "s", 20)
    assert r["action"] == "reply" and r["language"] == "hi" and "हिंदी" in r["reply"]
    r = await intake.guard(redis, msg("help", msg_id="C2"), "s", 20)
    assert r["language"] == "hi" and "ScamSaathi" in r["reply"]
    r = await intake.guard(redis, msg("Report", msg_id="C3"), "s", 20)
    assert "1930" in r["reply"]
    r = await intake.guard(redis, msg("english", msg_id="C4"), "s", 20)
    assert r["language"] == "en"


async def test_rate_limit_polite_once(redis):
    actions = [(await intake.guard(redis, msg(msg_id=f"R{i}"), "s", 3)) for i in range(5)]
    assert [a["action"] for a in actions] == ["check", "check", "check", "reply", "ignore"]
    assert "1930" in actions[3]["reply"]


async def test_offtopic_unsupported_hindi_detect(redis):
    assert (await intake.guard(redis, msg("good morning, how are you?", msg_id="O1"), "s", 20))["reason"] == "offtopic"
    assert (await intake.guard(redis, msg("", type="audio", msg_id="A1"), "s", 20))["reason"] == "unsupported"
    r = await intake.guard(redis, msg("आपका खाता बंद हो जाएगा, तुरंत KYC करें", msg_id="H1"), "s", 20)
    assert r["action"] == "check" and r["language"] == "hi"
    assert (await intake.guard(redis, msg("", type="image", caption="", msg_id="I1"), "s", 20))["action"] == "check"
    assert not intake.is_offtopic("x" * 400)
    assert not intake.is_offtopic("call 9876543210")


async def test_store_record_cache_campaign_purge(clean_db):
    ext = {"urls": ["http://sbi-kyc.example/login"], "phones": ["1930"], "sender_ids": ["VM-ABCDEF"], "ocr_text": ""}
    key = store.cache_key(ext, "x")
    assert key == store.cache_key({"urls": ["HTTP://SBI-KYC.EXAMPLE/login/"], "phones": ["1930"], "sender_ids": ["VM-ABCDEF"]}, "")
    assert store.cache_key({}, "Hello  World") == store.cache_key({}, "hello world")
    assert await store.cache_lookup(clean_db, key, 24) is None
    verdict = {"verdict": "SCAM", "score": 80}
    alerts = []
    for i in range(5):
        res = await store.record(clean_db, {"sender_hash": f"h{i}", "input_type": "text", "raw_text": "t", "extract": ext,
                                            "findings": [], "verdict": verdict, "reply": "r", "latency_ms": 10,
                                            "trace_id": f"t{i}", "cache_key": key, "context": {"verdict": "SCAM"},
                                            "playbook_code": "KYC_UPDATE"}, threshold=5, window_hours=6)
        alerts += res["campaign_alerts"]
    assert len(alerts) == 1 and alerts[0]["sender_count"] == 5 and alerts[0]["kind"] == "url"
    hit = await store.cache_lookup(clean_db, key, 24)
    assert hit["verdict"]["verdict"] == "SCAM"
    await store.record(clean_db, {"sender_hash": "h9", "extract": ext, "verdict": verdict, "from_cache": True,
                                  "cache_key": key}, 5, 6)  # 6th sender: already alerted, cache untouched
    async with clean_db.connection() as conn:
        await conn.execute("UPDATE checks SET created_at = now() - interval '8 days'")
    assert await store.purge(clean_db, 7) == 5
    data = await store.recent(clean_db)
    assert len(data["checks"]) == 6 and len(data["campaigns"]) == 1 and len(data["unreviewed"]) == 25


def ctx(**kw):
    base = {"verdict": "SCAM", "reasons": ["link is not an official SBI domain", "asks for OTP", "matches KYC scam"],
            "sources": ["https://sbi.co.in/web/personal-banking/cyber-security"], "playbook_advice": "Banks never ask...",
            "helpline": {"institution": "HDFC Bank", "number": "18002026161"}, "language": "en", "special_line": None,
            "hint": None, "official_domains": ["hdfc.bank.in"]}
    base.update(kw)
    return base


def test_fallback_reply_en_hi_and_limits():
    en = reply.fallback_reply(ctx())
    assert en.startswith("🚫 SCAM") and "1930" in en and "18002026161" in en and len(en) <= 900
    assert not reply.BANNED.search(en)
    hi = reply.fallback_reply(ctx(language="hi", verdict="NO_RED_FLAGS", hint="टिप"))
    assert hi.startswith("✅") and "सावधान" in hi and "टिप" in hi
    sus = reply.fallback_reply(ctx(verdict="SUSPICIOUS", special_line="This QR sends ₹1,499 FROM your account", language="xx"))
    assert sus.startswith("⚠️") and "₹1,499" in sus
    long = reply.fallback_reply(ctx(reasons=["r" * 140] * 3, playbook_advice="a" * 160, hint="h" * 300,
                                    special_line="s" * 300))
    assert len(long) <= 900
    assert reply.fallback_reply({"verdict": "weird"}).startswith("⚠️")


def test_validate_reply_rejects_bad_composer_output():
    good = "🚫 SCAM\nThis link is not SBI's.\nCall 1930 or HDFC Bank 18002026161. See https://sbi.co.in/x and cybercrime.gov.in"
    assert reply.validate_reply(good, ctx()) == []
    assert "says_safe" in reply.validate_reply("🚫 SCAM\nThis is safe to ignore", ctx())
    assert "verdict_line" in reply.validate_reply("✅ No red flags found", ctx())
    assert "verdict_line" in reply.validate_reply("🚫 SCAM ✅", ctx())
    assert any(p.startswith("url:") for p in reply.validate_reply("🚫 SCAM visit evil.example", ctx()))
    assert any(p.startswith("number:") for p in reply.validate_reply("🚫 SCAM call 9876543210", ctx()))
    assert reply.validate_reply("🚫 SCAM pay ₹1,499 now? no.", ctx(reasons=["sends ₹1,499"])) == []
    assert reply.validate_reply("🚫 SCAM " + "x" * 900, ctx()) == ["too_long"]
    assert reply.validate_reply(None, ctx()) == ["empty"]
    assert reply.validate_reply("⚠️ SUSPICIOUS", {"verdict": "SUSPICIOUS"}) == []


def test_finalize():
    out = reply.finalize("🚫 SCAM looks safe", ctx())
    assert out["used_fallback"] and out["reply"].startswith("🚫 SCAM") and out["problems"]
    ok = reply.finalize("  🚫 SCAM\nDon't pay. Call 1930.  ", ctx())
    assert ok == {"reply": "🚫 SCAM\nDon't pay. Call 1930.", "used_fallback": False, "problems": []}


def test_build_context(registry, playbooks):
    findings = [{"agent": "rules", "signals": [
        {"code": "UPI_PAY_AS_RECEIVE", "evidence": "This QR/link sends ₹1,499 FROM your account"},
        {"code": "POLICY_VIOLATION", "evidence": "x", "source_url": "https://sbi.co.in/web/personal-banking/cyber-security"}]}, "junk"]
    c = reply.build_context({"verdict": "SCAM", "reasons": ["a", "b", "c", "d"]}, {"brands": ["HDFC Bank"]}, findings, "hi",
                            registry, playbooks, "image", "scan to receive refund qr upi pin cashback")
    assert c["special_line"].startswith("This QR") and c["sources"] == ["https://sbi.co.in/web/personal-banking/cyber-security"]
    assert c["helpline"]["number"] == "18002026161" and len(c["reasons"]) == 3 and c["language"] == "hi"
    assert c["playbook_advice"] and c["hint"] is None
    c2 = reply.build_context({"verdict": "NO_RED_FLAGS"}, {"brands": ["Canara Bank"]},
                             [{"signals": [{"code": "UPI_COLLECT_REQUEST"}]}], "fr", registry, playbooks, "text",
                             "Dear customer, Rs 500 debited from a/c")
    assert c2["sources"] == ["https://canarabank.bank.in/pages/Net-banking"] and c2["helpline"] is None
    assert c2["special_line"] == reply.COLLECT_EXPLANATION and c2["hint"] and c2["language"] == "en"


def test_defang_and_context_links():
    c = ctx(reasons=["sbi.bank.in-kyc-update.example is not an official SBI domain", "pay refund.desk7@ybl"])
    out = reply.finalize("🚫 SCAM\nhttps://sbi.bank.in-kyc-update.example/yono is fake; UPI refund.desk7@ybl. "
                         "Official: https://sbi.co.in/x, cybercrime.gov.in", c)
    assert not out["used_fallback"], out
    assert "hxxps://sbi[.]bank[.]in-kyc-update[.]example/yono" in out["reply"]
    assert "refund.desk7@ybl" in out["reply"] and "https://sbi.co.in/x" in out["reply"] and "cybercrime.gov.in" in out["reply"]
    assert reply.validate_reply("🚫 SCAM see other-new-site.example", c) == ["url:other-new-site.example"]
    fb = reply.fallback_reply(c)
    assert "sbi[.]bank[.]in-kyc-update[.]example" in fb


def test_defang_keeps_upi_ids_and_www_sources():
    c = ctx(sources=["https://www.business-standard.com/x"], reasons=["pay lic.maturity.desk@ybl"])
    assert reply.defang("pay lic.maturity.desk@ybl", c) == "pay lic.maturity.desk@ybl"
    assert reply.defang("see https://www.business-standard.com/x", c) == "see https://www.business-standard.com/x"
    assert reply.defang("see https://www.evil.example/x", c) == "see hxxps://www[.]evil[.]example/x"
