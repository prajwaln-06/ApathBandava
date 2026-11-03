"""FR-12 static URL checks, FR-22..24 UPI."""
from app import upi
from app.url_static import analyze, host_of, skeleton


def flags(url, registry):
    return set(analyze(url, registry)["flags"])


def test_official_domain_is_clean(registry):
    out = analyze("https://www.sbi.bank.in/web/personal-banking", registry)
    assert out["registrable_domain"] == "sbi.bank.in" and out["flags"] == []
    assert analyze("https://netbanking.hdfcbank.com/x", registry)["flags"] == []


def test_lookalike_and_brand_in_subdomain(registry):
    assert "HOMOGLYPH_OR_BRAND_IN_SUBDOMAIN" in flags("http://sbi.bank.in.kyc-verify.example/login", registry)
    out = analyze("http://secure-login.hdfc.verify-now.example", registry)
    assert out["brand_in_subdomain"] == "HDFC Bank"
    assert "LOOKALIKE_DOMAIN" in flags("https://sbi-kyc-update.example", registry)
    assert "LOOKALIKE_DOMAIN" in flags("https://hdfcbnak.com", registry)  # edit distance to hdfcbank
    assert "HOMOGLYPH_OR_BRAND_IN_SUBDOMAIN" in flags("https://login.example/icici/update", registry)  # brand in path


def test_homoglyph_punycode(registry):
    url = "https://xn--" + "sbі".encode("punycode").decode() + ".bank.in/"  # Cyrillic і in "sbі"
    out = analyze(url, registry)
    assert out["punycode"] and "PUNYCODE" in out["flags"]
    assert out["homoglyph_of"] == "sbi.bank.in"
    assert skeleton("hdfcbаnk") == "hdfcbank"


def test_ip_at_tld_shortener(registry):
    out = analyze("http://192.168.0.5/login", registry)
    assert out["ip_host"] and out["flags"] == ["IP_HOST"]
    assert "IP_HOST" in flags("http://3232235777/", registry)
    assert {"AT_IN_URL"} <= flags("http://www.sbi.co.in@evil-site.xyz/", registry)
    assert "RISKY_TLD" in flags("https://claim-reward.xyz", registry)
    out = analyze("bit.ly/3abcXYZ", registry)
    assert out["shortener"] and "SHORTENER" in out["flags"]


def test_lenient_punycode_fallback():
    from app.url_static import _to_unicode

    assert _to_unicode("xn--zz-!!.example") == "xn--zz-!!.example"
    assert _to_unicode("xn--" + "sbі".encode("punycode").decode() + ".bank.in").startswith("sb")


def test_empty_and_bad_urls(registry):
    assert analyze("http://", registry)["host"] == ""
    assert analyze("http://[::1", registry)["host"] == ""
    assert host_of("http://[::1") == ""
    assert host_of("Example.COM.") == "example.com"


def test_upi_parse_pay_and_collect():
    p = upi.parse("upi://pay?pa=refund.help@ybl&pn=Refund%20Desk&am=1499.00&tn=Cashback%20refund&cu=INR")
    assert p == {"pa": "refund.help@ybl", "pn": "Refund Desk", "am": 1499.0, "tn": "Cashback refund", "intent": "pay"}
    assert upi.parse("upi://collect?pa=x@ybl")["intent"] == "collect"
    assert upi.parse("upi://pay?pn=NoPayee")["intent"] == "unknown"
    assert upi.parse("upi://pay?pa=x@y&am=abc")["am"] is None
    assert upi.parse("https://example.org")["intent"] == "unknown"
    assert upi.parse("upi://[bad")["intent"] == "unknown"


def test_pay_as_receive_is_detected():
    p = upi.parse("upi://pay?pa=refund.help@ybl&pn=Refund%20Desk&am=1499")
    ev = upi.pay_as_receive(p, "")
    assert ev and "₹1,499 FROM your account" in ev
    assert upi.pay_as_receive(upi.parse("upi://pay?pa=shop@ybl&pn=Kirana&am=200"), "Scan to receive cashback")
    assert upi.pay_as_receive(upi.parse("upi://pay?pa=shop@ybl&pn=Kirana&am=200"), "pay for groceries") is None
    assert upi.pay_as_receive({"intent": "collect"}, "refund") is None


def test_inr_format():
    assert upi.inr(None) == "money"
    assert upi.inr(245000) == "₹2,45,000"
    assert upi.inr(999) == "₹999"


def test_upi_id_flags(registry):
    assert upi.upi_id_flags("sbi.refund@ybl", registry, [])[0]["code"] == "UPI_HANDLE_NOT_OFFICIAL"
    assert upi.upi_id_flags("ramesh@okicici", registry, ["HDFC Bank"]) == []  # counterparty in an alert
    assert upi.upi_id_flags("ramesh@okicici", registry, ["HDFC Bank"], asks_payment=True)
    assert upi.upi_id_flags("ramesh@okicici", registry, []) == []


def test_collect_request_explanation():
    assert "SENDS money out" in upi.collect_request("Ramesh has requested ₹5,000. Pay  Decline")
    assert upi.collect_request("Paid ₹500 to Ramesh") is None
