"""FR-14 reputation (adapters behind interfaces, mocked), NFR-8 timeouts, sandbox client."""
import asyncio

import httpx
import pytest
import respx

from app.reputation import ReputationService
from app.reputation.adapters import CrtshAge, OpenPhish, RdapAge, SafeBrowsing, URLhaus, VirusTotal, _days_since
from app.sandbox_client import SandboxClient, with_flags
from conftest import FakeAge, FakeFeed


async def test_flags_from_fake_adapters(registry):
    svc = ReputationService(registry, ages=[FakeAge("rdap", 4), FakeAge("crtsh", 3)],
                            feeds=[FakeFeed("gsb", "hit"), FakeFeed("vt", None)], timeout=1)
    out = await svc.lookup("https://new-domain-offer.com/x")
    assert out["domain_age_days"] == 4 and out["first_cert_days"] == 3
    assert out["feeds"] == {"gsb": "hit", "urlhaus": "unknown", "phishtank": "unknown", "vt": "unknown"}
    assert out["flags"] == ["THREAT_FEED_HIT", "DOMAIN_AGE_LT_30D", "CERT_AGE_LT_30D"]
    assert await svc.lookup("https://new-domain-offer.com/x") is out  # cached


async def test_failing_and_slow_feeds_degrade_to_unknown(registry):
    class Slow:
        name = "urlhaus"

        async def check(self, client, url):
            await asyncio.sleep(5)

    svc = ReputationService(registry, ages=[FakeAge("rdap", RuntimeError("down"))], feeds=[Slow()], timeout=0.05)
    out = await svc.lookup("https://example.org")
    assert out["domain_age_days"] is None and out["feeds"]["urlhaus"] == "unknown" and out["flags"] == []


async def test_ip_host_skips_domain_lookups(registry):
    svc = ReputationService(registry, ages=[FakeAge("rdap", 1)], feeds=[], timeout=1)
    assert (await svc.lookup("http://8.8.8.8/x"))["domain_age_days"] is None


async def test_overlay_only_for_reserved_tlds(registry, tmp_path):
    ov = tmp_path / "ov.yaml"
    ov.write_text("sbi-kyc.example: {domain_age_days: 3, feeds: {gsb: hit}}\nsbi.bank.in: {domain_age_days: 1}\n")
    svc = ReputationService(registry, ages=[FakeAge("rdap", 999)], feeds=[], overlay_path=str(ov))
    out = await svc.lookup("http://sbi-kyc.example/login")
    assert out["domain_age_days"] == 3 and "THREAT_FEED_HIT" in out["flags"]
    assert (await svc.lookup("http://other.example"))["flags"] == []  # reserved TLD without overlay -> unknown
    assert (await svc.lookup("https://sbi.bank.in"))["domain_age_days"] == 999  # real domain never overlaid


def test_settings_wiring(registry):
    from app.config import Settings

    s = Settings()
    s.crtsh_enabled = False
    svc = ReputationService(registry, settings=s)
    assert [a.name for a in svc.ages] == ["rdap"]
    assert [f.name for f in svc.feeds] == ["gsb", "urlhaus", "phishtank", "vt"]


def test_days_since():
    assert _days_since("not a date") is None
    assert _days_since("2000-01-01T00:00:00Z") > 9000
    assert _days_since("2000-01-01T00:00:00") > 9000


@respx.mock
async def test_real_adapters_with_mocked_http():
    respx.get("https://rdap.org/domain/example.com").mock(return_value=httpx.Response(
        200, json={"events": [{"eventAction": "last changed", "eventDate": "2026-01-01T00:00:00Z"},
                              {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"}]}))
    respx.get("https://rdap.org/domain/noreg.com").mock(return_value=httpx.Response(200, json={"events": []}))
    respx.get("https://rdap.org/domain/missing.com").mock(return_value=httpx.Response(404))
    respx.get("https://crt.sh/").mock(side_effect=[httpx.Response(200, json=[{"not_before": "2020-01-01T00:00:00"},
                                                                            {"not_before": "2019-01-01T00:00:00"}]),
                                                   httpx.Response(200, json=[]), httpx.Response(502)])
    respx.post(url__startswith="https://safebrowsing.googleapis.com").mock(
        side_effect=[httpx.Response(200, json={"matches": [{}]}), httpx.Response(200, json={}), httpx.Response(500)])
    respx.post("https://urlhaus-api.abuse.ch/v1/url/").mock(
        side_effect=[httpx.Response(200, json={"query_status": "ok"}), httpx.Response(200, json={"query_status": "no_results"}),
                     httpx.Response(200, json={"query_status": "invalid_url"}), httpx.Response(403)])
    respx.get("https://openphish.com/feed.txt").mock(side_effect=[httpx.Response(200, text="https://bad.example/x\n"),
                                                                  httpx.Response(500)])
    respx.get(url__startswith="https://www.virustotal.com").mock(
        side_effect=[httpx.Response(200, json={"data": {"attributes": {"last_analysis_stats": {"malicious": 5}}}}),
                     httpx.Response(404), httpx.Response(429)])
    async with httpx.AsyncClient() as c:
        assert await RdapAge().days(c, "example.com") > 10000
        assert await RdapAge().days(c, "noreg.com") is None
        assert await RdapAge().days(c, "missing.com") is None
        assert await CrtshAge().days(c, "example.com") > 2000
        assert await CrtshAge().days(c, "example.com") is None
        assert await CrtshAge().days(c, "example.com") is None
        gsb = SafeBrowsing("k")
        assert [await gsb.check(c, "u") for _ in range(3)] == ["hit", "clean", "unknown"]
        assert await SafeBrowsing("").check(c, "u") == "unknown"
        uh = URLhaus("k")
        assert [await uh.check(c, "u") for _ in range(4)] == ["hit", "clean", "unknown", "unknown"]
        assert await URLhaus("").check(c, "u") == "unknown"
        op = OpenPhish(True)
        assert await op.check(c, "https://bad.example/x/") == "hit"
        assert await op.check(c, "https://good.example") == "clean"  # cached feed, no second fetch
        op._at = 0
        assert await op.check(c, "https://good.example") == "unknown"  # refresh failed
        assert await OpenPhish(False).check(c, "u") == "unknown"
        vt = VirusTotal("k")
        assert [await vt.check(c, "https://x") for _ in range(3)] == ["hit", "clean", "unknown"]
        assert await VirusTotal("").check(c, "u") == "unknown"


@respx.mock
async def test_sandbox_client():
    route = respx.post("http://sandbox:9000/detonate")
    route.side_effect = [
        httpx.Response(200, json={"final_url": "https://x.example", "redirects": ["https://bit.ly/a"]}),
        httpx.Response(200, json={"final_url": "https://x.example", "forms": {"otp": True}, "download": {"type": "apk", "sha256": "ab"}}),
        httpx.Response(422, json={"detail": "blocked"}),
        httpx.ConnectError("down"),
    ]
    sb = SandboxClient("http://sandbox:9000")
    assert (await sb.expand("https://bit.ly/a"))["final_url"] == "https://x.example"
    det = await sb.detonate("https://x.example")
    assert det["flags"] == ["PAGE_ASKS_PIN_OTP_CARD", "APK_DOWNLOAD"] and det["status"] == "ok"
    assert (await sb.detonate("http://169.254.169.254"))["status"] == "unknown"
    assert await sb.expand("https://x") is None
    assert await SandboxClient("http://sandbox:9000", enabled=False).expand("x") is None
    assert with_flags({"forms": {}, "download": {"type": "pdf"}})["flags"] == []
