"""FR-25/FR-28, SRS 6.5: verdict engine — every branch of app/verdict.py."""
from app.verdict import decide, load_weights

W = load_weights()


def f(agent, *codes, evidence="ev"):
    return {"agent": agent, "status": "ok", "summary": "",
            "signals": [{"code": c, "severity": "low", "evidence": evidence, "source_url": None} for c in codes]}


def test_no_findings_is_no_red_flags():
    out = decide([], W)
    assert out == {"verdict": "NO_RED_FLAGS", "score": 0, "hard_signals": [], "reasons": []}


def test_hard_signal_forces_scam_and_ranks_first():
    out = decide([f("link", "SHORTENER", "UPI_PAY_AS_RECEIVE", evidence="")], W)
    assert out["verdict"] == "SCAM"
    assert out["hard_signals"] == ["UPI_PAY_AS_RECEIVE"]
    assert out["reasons"][0] == "UPI_PAY_AS_RECEIVE"  # empty evidence falls back to the code


def test_same_hard_code_from_two_agents_listed_once():
    out = decide([f("link", "THREAT_FEED_HIT"), f("rules", "THREAT_FEED_HIT")], W)
    assert out["hard_signals"] == ["THREAT_FEED_HIT"]


def test_domain_mismatch_plus_credential_request_is_hard_combo():
    out = decide([f("impersonation", "REGISTRY_DOMAIN_MISMATCH"), f("wording", "CREDENTIAL_REQUEST")], W)
    assert out["verdict"] == "SCAM"
    assert "REGISTRY_DOMAIN_MISMATCH+ASKS_PIN_OTP_CARD" in out["hard_signals"]


def test_domain_mismatch_alone_is_suspicious():
    out = decide([f("impersonation", "REGISTRY_DOMAIN_MISMATCH")], W)
    assert (out["verdict"], out["score"]) == ("SUSPICIOUS", 35)


def test_score_threshold_scam():
    out = decide([f("impersonation", "POLICY_VIOLATION"), f("link", "DOMAIN_AGE_LT_30D")], W)
    assert (out["verdict"], out["score"]) == ("SCAM", 65)


def test_low_signals_stay_no_red_flags():
    out = decide([f("wording", "URGENCY_LANGUAGE"), f("link", "SHORTENER")], W)
    assert (out["verdict"], out["score"]) == ("NO_RED_FLAGS", 15)


def test_trust_signal_ignored_from_llm_agent():
    out = decide([f("impersonation", "REGISTRY_FULL_MATCH"), f("link", "DOMAIN_AGE_LT_30D")], W)
    assert out["score"] == 25 and out["verdict"] == "SUSPICIOUS"


def test_trust_signal_from_rules_lowers_score_never_below_zero():
    out = decide([f("rules", "REGISTRY_FULL_MATCH", "URGENCY_LANGUAGE")], W)
    assert out["verdict"] == "NO_RED_FLAGS" and out["score"] == 0
    assert out["reasons"] == ["ev"]  # trust signals are not reasons


def test_duplicate_code_counted_once_and_keeps_strongest():
    out = decide([f("wording", "URGENCY_LANGUAGE", evidence="a"), f("rules", "URGENCY_LANGUAGE", evidence="b")], W)
    assert out["score"] == 10 and out["reasons"] == ["a"]


def test_trust_from_llm_then_rules():
    out = decide([f("wording", "REGISTRY_FULL_MATCH"), f("rules", "REGISTRY_FULL_MATCH", "SHORTENER")], W)
    assert out["score"] == 0 and out["verdict"] == "NO_RED_FLAGS"


def test_unknown_codes_and_garbage_dropped():
    out = decide([{"agent": "link", "status": "ok", "signals": [{"code": "MAKE_IT_SAFE"}], "summary": ""},
                  "not a dict", {"agent": "wording", "status": "weird", "signals": []}], W)
    assert out["verdict"] == "NO_RED_FLAGS" and out["score"] == 0


def test_agent_claimed_severity_is_ignored():
    sig = {"agent": "wording", "status": "ok", "summary": "",
           "signals": [{"code": "URGENCY_LANGUAGE", "severity": "hard", "evidence": "x"}]}
    assert decide([sig], W)["verdict"] == "NO_RED_FLAGS"


def test_reasons_capped_at_five_and_sorted_by_weight():
    codes = ["SHORTENER", "POLICY_VIOLATION", "URGENCY_LANGUAGE", "REWARD_LURE", "RISKY_TLD", "IP_HOST", "AT_IN_URL"]
    sig = {"agent": "rules", "status": "ok", "summary": "",
           "signals": [{"code": c, "severity": "low", "evidence": c.lower()} for c in codes]}
    out = decide([sig], W)
    assert len(out["reasons"]) == 5 and out["reasons"][0] == "policy_violation"


def test_weights_file_has_all_srs_table_codes():
    for code, w in {"POLICY_VIOLATION": 40, "REGISTRY_DOMAIN_MISMATCH": 35, "PAGE_ASKS_PIN_OTP_CARD": 35,
                    "HOMOGLYPH_OR_BRAND_IN_SUBDOMAIN": 30, "DOMAIN_AGE_LT_30D": 25, "SENDER_ID_MISMATCH": 20,
                    "APK_DOWNLOAD": 25, "PLAYBOOK_MATCH": 20, "URGENCY_LANGUAGE": 10, "SHORTENER": 5,
                    "REGISTRY_FULL_MATCH": -30}.items():
        assert W["weights"][code] == w
    assert W["thresholds"] == {"scam": 60, "suspicious": 25}
