"""SRS 6.4: agent output validation and the fixed signal enum."""
from app.schema import AGENT_OUTPUT_JSON_SCHEMA, unknown, validate_agent_output
from app.signals import AGENTS, CODES, HARD, SEVERITY, Signal


def test_enum_and_severity_tables_agree():
    assert CODES == set(SEVERITY) == {s.value for s in Signal}
    assert HARD == {"UPI_PAY_AS_RECEIVE", "THREAT_FEED_HIT"}
    assert set(AGENT_OUTPUT_JSON_SCHEMA["properties"]["agent"]["enum"]) == set(AGENTS)


def test_valid_output_normalised():
    raw = {"agent": "link", "status": "ok", "summary": "  s  ",
           "signals": [{"code": "SHORTENER", "severity": "hard", "evidence": "bit.ly", "source_url": "https://x.example/a"}]}
    out = validate_agent_output(raw)
    assert out["signals"][0]["severity"] == "low"  # authoritative table wins
    assert out["signals"][0]["source_url"] == "https://x.example/a"
    assert out["summary"] == "s"


def test_bad_source_url_and_unknown_code_dropped():
    raw = {"agent": "link", "status": "ok", "summary": 3,
           "signals": [{"code": "SHORTENER", "evidence": None, "source_url": "javascript:alert(1)"},
                       {"code": "TOTALLY_SAFE"}, "junk"]}
    out = validate_agent_output(raw)
    assert out["signals"] == [{"code": "SHORTENER", "severity": "low", "evidence": "", "source_url": None}]
    assert out["summary"] == ""


def test_malformed_becomes_unknown():
    assert validate_agent_output(None, "wording") == unknown("wording")
    assert validate_agent_output({"agent": "link", "status": "bad", "signals": []})["status"] == "unknown"
    assert validate_agent_output({"agent": "link", "status": "ok", "signals": "x"})["status"] == "unknown"


def test_agent_name_forced_and_signals_capped():
    raw = {"agent": "rules", "status": "ok", "summary": "x", "signals": [{"code": "SHORTENER", "evidence": "e"}] * 40}
    out = validate_agent_output(raw, "wording")
    assert out["agent"] == "wording" and len(out["signals"]) == 12
    assert validate_agent_output({"agent": "evil", "status": "ok", "signals": []})["agent"] == "unknown"


def test_long_strings_truncated():
    raw = {"agent": "link", "status": "ok", "summary": "s" * 500, "signals": [{"code": "SHORTENER", "evidence": "e" * 900}]}
    out = validate_agent_output(raw)
    assert len(out["summary"]) == 200 and len(out["signals"][0]["evidence"]) == 300
