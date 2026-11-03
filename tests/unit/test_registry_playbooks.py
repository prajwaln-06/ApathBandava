"""FR-17..21 registry matching/policies, Phase 3 seed rules, playbook search."""
import pytest
import yaml

from app import patterns
from app.registry import Registry, SeedError, load_seed_dir, normalize_phone, validate_entity


def test_phase3_seed_counts(seeds):
    entities, playbooks = seeds
    assert len(entities) == 25
    assert sum(e["kind"] == "bank" for e in entities) == 15
    assert sum(e["kind"] == "insurer" for e in entities) == 10
    assert len(playbooks) == 15
    for e in entities:
        assert e["status"] in ("needs_review", "approved")
        assert e["sources"], f"{e['name']} has no source URLs"
        for p in e["policies"]:
            assert p["quote"] and p["source_url"].startswith("https://")
        if e["kind"] == "bank":
            assert any(d.endswith(".bank.in") for d in e["domains"]), e["name"]


def test_ci_rejects_policy_without_quote_or_source(tmp_path):
    base = {"name": "Test Bank", "kind": "bank", "never_does": [{"rule_code": "NEVER_ASKS_OTP_PIN", "source_url": "https://x"}]}
    with pytest.raises(SeedError, match="quote and source_url"):
        validate_entity(base)
    base["never_does"] = [{"rule_code": "NEVER_ASKS_OTP_PIN", "quote": "q"}]
    with pytest.raises(SeedError):
        validate_entity(base)
    base["never_does"] = [{"rule_code": "MADE_UP", "quote": "q", "source_url": "https://x"}]
    with pytest.raises(SeedError, match="unknown rule_code"):
        validate_entity(base)
    with pytest.raises(SeedError):
        validate_entity({"name": "X", "kind": "casino"})
    (tmp_path / "playbooks").mkdir()
    (tmp_path / "playbooks" / "bad.yaml").write_text(yaml.safe_dump({"code": "X"}))
    with pytest.raises(SeedError, match="playbook missing"):
        load_seed_dir(tmp_path)


def test_validate_entity_defaults():
    ent = validate_entity({"name": "Y", "kind": "wallet", "last_verified": "2026-01-01", "status": "approved",
                           "never_does": [{"rule_code": "NEVER_ASKS_OTP_PIN", "quote": "q", "source_url": "https://y",
                                           "last_verified": "2026-02-02"}]})
    assert ent["policies"][0]["last_verified"] == "2026-02-02" and ent["aliases"] == []


def test_match_bank_domain_header_phone(registry):
    m = registry.match(["HDFC Bank"], ["https://hdfc-kyc.example/x", "https://www.hdfc.bank.in/a"],
                       ["VM-HDFCBK-S", "AD-HDFCBK-P", "JD-SBIINB"], ["+919876543210", "18002026161", "1930"], ["x@ybl"],
                       "Rs 500 debited from a/c")
    by = {(c["field"], c["value"]): c["status"] for c in m["checks"]}
    assert m["entity"]["name"] == "HDFC Bank"
    assert by[("url", "https://hdfc-kyc.example/x")] == "mismatch"
    assert by[("url", "https://www.hdfc.bank.in/a")] == "match"
    assert by[("sender_id", "VM-HDFCBK-S")] == "match"
    assert by[("sender_id", "AD-HDFCBK-P")] == "mismatch"  # FR-19 promotional suffix on an alert
    assert by[("sender_id", "JD-SBIINB")] == "mismatch"
    assert by[("phone", "+919876543210")] == "mismatch"
    assert by[("phone", "18002026161")] == "match"
    assert by[("phone", "1930")] == "unknown"
    assert by[("upi_id", "x@ybl")] == "mismatch"


def test_match_infers_entity_from_header_or_domain(registry):
    assert registry.match([], [], ["VM-HDFCBK-S"], [], [])["entity"]["name"] == "HDFC Bank"
    assert registry.match([], ["https://www.icici.bank.in"], [], [], [])["entity"]["name"] == "ICICI Bank"
    none = registry.match([], ["https://random.example"], ["XX-ABCDEF"], ["+919999999999"], ["a@b"])
    assert none["entity"] is None and {c["status"] for c in none["checks"]} == {"unknown"}
    assert registry.match(["Unknown Brand"], [], [], [], [])["entity"] is None


def test_policy_violations(registry):
    sbi = registry.by_name("SBI")
    v = registry.policy(sbi["id"], "Share the OTP sent to your phone to complete KYC")["violations"]
    assert v and v[0]["rule_code"] == "NEVER_ASKS_OTP_PIN" and v[0]["source_url"].startswith("https://")
    assert registry.policy(sbi["id"], "Never share your OTP with anyone. -SBI")["violations"] == []
    assert registry.policy(99999, "share otp")["violations"] == []


def test_registry_status_filter_and_tokens():
    ents = [{"name": "A Bank", "kind": "bank", "aliases": ["ABK"], "domains": ["abank.bank.in"], "legacy_domains": [],
             "status": "approved", "policies": []},
            {"name": "B Bank", "kind": "bank", "aliases": ["BBK"], "domains": ["bbank.bank.in"], "legacy_domains": [],
             "status": "needs_review", "policies": []}]
    strict = Registry([dict(e) for e in ents], include_unreviewed=False)
    assert [e["name"] for e in strict.active()] == ["A Bank"]
    assert strict.find_brands("BBK and ABK") == ["A Bank"]
    assert "abank" in strict.brand_tokens() and "bbank" not in strict.brand_tokens()
    assert strict.by_id(2) is None


def test_normalize_phone():
    assert normalize_phone("+91 98765-43210") == "9876543210"
    assert normalize_phone("09876543210") == "9876543210"
    assert normalize_phone("1800 202 6161") == "18002026161"


@pytest.mark.parametrize("fn,text,hit", [
    (patterns.asks_credentials, "Please share the OTP received on your mobile", True),
    (patterns.asks_credentials, "OTP batayen turant", True),
    (patterns.asks_credentials, "apna otp share karein abhi", True),
    (patterns.asks_credentials, "Do not share your OTP with anyone", False),
    (patterns.remote_access, "install AnyDesk so our executive can help", True),
    (patterns.remote_access, "download update.apk now", True),
    (patterns.urgency, "Your account will be blocked today", True),
    (patterns.threat_block, "your electricity connection will be disconnected tonight", True),
    (patterns.reward, "You have won a lucky draw prize", True),
    (patterns.authority, "This is CBI officer calling", True),
    (patterns.kyc_update, "Update your KYC now or face suspension", True),
    (patterns.fee_for_payout, "pay processing fee to release your maturity amount", True),
    (patterns.pin_to_receive, "enter your UPI PIN to receive the refund", True),
    (patterns.pin_to_receive, "Scan this QR to receive cashback", True),
    (patterns.pay_to_upi, "pay Rs 500 to lic.help@ybl", True),
    (patterns.secrecy, "don't tell anyone about this call", True),
])
def test_patterns(fn, text, hit):
    assert bool(fn(text)) is hit


def test_scam_keywords():
    assert patterns.has_scam_keywords("update your KYC")
    assert not patterns.has_scam_keywords("good morning, how are you?")


def test_playbook_search(playbooks):
    res = playbooks.search("Your parcel is held at customs due to incomplete address. Pay small fee for re-delivery via India Post tracking")
    top = res["matches"][0]
    assert top["code"] == "COURIER_FEE" and top["score"] > 0.7 and top["matched"]
    assert playbooks.search("hello there")["matches"] == []
    assert playbooks.get("KYC_UPDATE")["advice"]
    assert playbooks.get("NOPE") is None
