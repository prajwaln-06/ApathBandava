"""Deterministic baseline + every analyzer endpoint (SRS 6.3) through the ASGI app."""
from app import rules
from app.extract import extract
from app.verdict import decide
from conftest import FakeAge, FakeFeed, FakeSandbox


async def run_rules(text, registry, playbooks, rep, sandbox=None, weights=None):
    ext = extract(text, registry)
    out = await rules.baseline(ext, text, registry, rep, playbooks, sandbox or FakeSandbox())
    codes = {s["code"] for s in out["signals"]}
    return out, codes


async def test_rules_d1_like_kyc_scam(registry, playbooks, fake_reputation, weights):
    text = ("VM-SBIBNK-S Dear SBI customer your YONO KYC has expired and your account will be blocked today. "
            "Update PAN at http://sbi.bank.in.kyc-verify.example/login and share the OTP to confirm.")
    out, codes = await run_rules(text, registry, playbooks, fake_reputation)
    assert {"REGISTRY_DOMAIN_MISMATCH", "HOMOGLYPH_OR_BRAND_IN_SUBDOMAIN", "POLICY_VIOLATION", "CREDENTIAL_REQUEST",
            "URGENCY_LANGUAGE", "PLAYBOOK_MATCH"} <= codes
    pol = next(s for s in out["signals"] if s["code"] == "POLICY_VIOLATION")
    assert pol["source_url"].startswith("https://") and "SBI will never ask" in pol["evidence"]
    assert decide([out], weights)["verdict"] == "SCAM"


async def test_rules_refund_qr_and_collect(registry, playbooks, fake_reputation):
    _, codes = await run_rules("Scan to receive your refund upi://pay?pa=refund.help@ybl&pn=Refund&am=1499",
                               registry, playbooks, fake_reputation)
    assert "UPI_PAY_AS_RECEIVE" in codes
    _, codes = await run_rules("Ramesh has requested ₹5,000. Pay Decline. Enter UPI PIN", registry, playbooks, fake_reputation)
    assert "UPI_COLLECT_REQUEST" in codes


async def test_rules_legit_alert_full_match(registry, playbooks, fake_reputation, weights):
    text = "VM-HDFCBK-S Rs.2,000 debited from HDFC Bank A/c XX1234 to VPA ramesh@okicici. Not you? Call 18002026161"
    out, codes = await run_rules(text, registry, playbooks, fake_reputation)
    assert codes == {"REGISTRY_FULL_MATCH"}
    assert decide([out], weights)["verdict"] == "NO_RED_FLAGS"


async def test_rules_shortener_expansion_threat_and_new_domain(registry, playbooks):
    from app.reputation import ReputationService

    rep = ReputationService(registry, ages=[FakeAge("rdap", 3), FakeAge("crtsh", 2)], feeds=[FakeFeed("gsb", "hit")])
    sb = FakeSandbox(expand_to="https://hdfc-secure-login.xyz/a")
    out, codes = await run_rules("HDFC Bank: verify now bit.ly/abc123 or call 9876543210, install AnyDesk. You won a prize",
                                 registry, playbooks, rep, sb)
    assert {"SHORTENER", "LOOKALIKE_DOMAIN", "RISKY_TLD", "THREAT_FEED_HIT", "DOMAIN_AGE_LT_30D", "CERT_AGE_LT_30D",
            "PHONE_NOT_OFFICIAL", "REMOTE_ACCESS_REQUEST", "REWARD_LURE", "REGISTRY_DOMAIN_MISMATCH"} <= codes


async def test_rules_sender_mismatch_threat_and_personal_upi(registry, playbooks, fake_reputation):
    text = "AD-HDFCBN-P HDFC Bank OTP alert: your account kyc is pending, electricity disconnected. Pay Rs 10 to help.desk@ybl"
    _, codes = await run_rules(text, registry, playbooks, fake_reputation)
    assert {"SENDER_ID_MISMATCH", "PERSONAL_UPI_PAYMENT", "UPI_HANDLE_NOT_OFFICIAL"} <= codes
    _, codes = await run_rules("your electricity connection will be disconnected", registry, playbooks, fake_reputation)
    assert "URGENCY_LANGUAGE" in codes


async def test_rules_no_brand(registry, playbooks, fake_reputation):
    out, codes = await run_rules("hello friend, lunch at 2?", registry, playbooks, fake_reputation)
    assert codes == set() and out["status"] == "ok"


# ---------------- API -----------------------------------------------------------------
async def test_health_and_auth(client):
    r = await client.get("/health")
    assert r.json()["entities"] == 25 and r.json()["playbooks"] == 15
    r = await client.post("/upi/parse", json={"uri": "upi://pay?pa=a@b"}, headers={"X-Internal-Token": "wrong"})
    assert r.status_code == 401


async def test_endpoints_contracts(client, tmp_path):
    r = (await client.post("/extract", json={"text": "visit sbi-kyc.example now"})).json()
    assert set(r) == {"urls", "upi_uris", "upi_ids", "phones", "sender_ids", "amounts", "brands", "ocr_text", "qr_payloads"}
    assert (await client.post("/extract", json={"text": "", "image_path": "/etc/passwd"})).status_code == 400
    r = (await client.post("/url/static", json={"url": "bit.ly/x"})).json()
    assert set(r) >= {"host", "registrable_domain", "tld", "punycode", "homoglyph_of", "brand_in_subdomain", "shortener",
                      "ip_host", "flags"}
    r = (await client.post("/url/reputation", json={"url": "https://example.org"})).json()
    assert set(r) == {"domain_age_days", "first_cert_days", "feeds", "flags"}
    assert set(r["feeds"]) == {"gsb", "urlhaus", "phishtank", "vt"}
    r = (await client.post("/url/detonate", json={"url": "https://example.org"})).json()
    assert {"final_url", "redirects", "title", "screenshot_path", "forms", "brand_logos", "download"} <= set(r)
    r = (await client.post("/upi/parse", json={"uri": "upi://pay?pa=x@ybl&am=5"})).json()
    assert set(r) == {"pa", "pn", "am", "tn", "intent"}
    m = (await client.post("/registry/match", json={"brands": ["SBI"], "urls": ["https://sbi-kyc.example"]})).json()
    assert m["entity"]["name"] == "State Bank of India" and m["checks"][0]["status"] == "mismatch"
    p = (await client.post("/registry/policy", json={"entity_id": m["entity"]["id"], "text": "send OTP now"})).json()
    assert p["violations"][0]["quote"]
    s = (await client.post("/playbooks/search", json={"text": "You won KBC lucky draw lottery prize, pay tax to claim"})).json()
    assert s["matches"][0]["code"] == "LOTTERY"
    v = (await client.post("/verdict", json={"findings": [{"agent": "rules", "status": "ok", "summary": "",
                                                           "signals": [{"code": "THREAT_FEED_HIT", "evidence": "gsb"}]}]})).json()
    assert v["verdict"] == "SCAM" and set(v) == {"verdict", "score", "hard_signals", "reasons"}
    f = (await client.post("/findings/validate", json={"findings": [{"agent": "link", "status": "ok", "signals": [{"code": "NOPE"}]}]})).json()
    assert f["findings"][0]["signals"] == []


async def test_pipeline_endpoints(client):
    g = (await client.post("/intake/guard", json={"msg_id": "API1", "sender_jid": "91900@s.whatsapp.net", "chat_type": "direct",
                                                   "type": "text", "text": "KYC update sbi-kyc.example"})).json()
    assert g["action"] == "check"
    ext = (await client.post("/extract", json={"text": "SBI KYC update sbi-kyc.example share OTP"})).json()
    base = (await client.post("/rules/baseline", json={"extract": ext, "text": "SBI KYC update sbi-kyc.example share OTP"})).json()
    assert base["agent"] == "rules" and base["signals"]
    c = (await client.post("/cache/lookup", json={"extract": ext, "text": ""})).json()
    assert c["hit"] is False and c["cache_key"]
    v = (await client.post("/verdict", json={"findings": [base]})).json()
    ctx = (await client.post("/reply/context", json={"verdict": v, "extract": ext, "findings": [base], "language": "en",
                                                     "input_type": "text", "text": "x"})).json()
    fin = (await client.post("/reply/finalize", json={"text": None, "context": ctx})).json()
    assert fin["used_fallback"] and fin["reply"].startswith("🚫")
    rec = (await client.post("/checks/record", json={"sender_hash": g["sender_hash"], "extract": ext, "verdict": v,
                                                     "reply": fin["reply"], "cache_key": c["cache_key"], "context": ctx})).json()
    assert rec["check_id"]
    assert (await client.post("/cache/lookup", json={"extract": ext, "text": ""})).json()["hit"] is True
    assert (await client.post("/maintenance/purge", json={})).json() == {"purged": 0}
    assert (await client.post("/campaigns/digest", json={"hours": 1})).json() == {"campaigns": []}


async def test_registry_crawler_endpoints(client, deps):
    srcs = (await client.post("/registry/sources", json={})).json()["sources"]
    assert srcs and all(s["url"].startswith("https://") for s in srcs)
    s0 = srcs[0]
    body = {"entity_id": s0["entity_id"], "source_url": s0["url"], "page_text": "We will NEVER ask for your OTP or PIN.",
            "facts": [{"field": "never_does", "value": "otp", "quote": "We will never ask for your OTP or PIN."},
                      {"field": "domains", "value": "evil.example", "quote": "invented sentence not on the page"},
                      {"field": "x", "value": "y", "quote": "short"}]}
    assert (await client.post("/registry/review", json=body)).json() == {"queued": 1}
    bad = dict(body, source_url="https://attacker.example/page")
    assert (await client.post("/registry/review", json=bad)).status_code == 400


async def test_admin(client, deps, monkeypatch):
    assert (await client.get("/admin")).status_code == 403
    r = await client.get("/admin", params={"token": "test-admin"})
    assert r.status_code == 200 and "Registry entries awaiting review" in r.text and "unreachable" in r.text
    s = (await client.get("/admin/api/summary", headers={"X-Admin-Token": "test-admin"})).json()
    assert s["unreviewed"] == 25
    assert (await client.get("/admin/api/summary")).status_code == 403
    assert (await client.post("/admin/registry/1/approve")).status_code == 403
    r = await client.post("/admin/registry/1/approve", headers={"X-Admin-Token": "test-admin"})
    assert r.json() == {"approved": 1} and deps.registry.by_id(1)["status"] == "approved"

    import app.admin as admin_mod

    class Resp:
        def json(self):
            return {"status": "ok", "logged_in": True}

    class Client:
        def __init__(self, **_):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url):
            return Resp()

    monkeypatch.setattr(admin_mod.httpx, "AsyncClient", Client)
    assert (await admin_mod.bridge_health("http://x"))["logged_in"] is True
