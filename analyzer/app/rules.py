"""Deterministic baseline findings (agent name "rules").

Runs alongside the four LLM agents and returns the same SRS 6.4 shape. It applies the analyzer's
own tools to the extracted artifacts without any model in the loop, so a prompt-injected or
timed-out agent can never remove a hard signal (SRS 3.3.4). Trust signals
(REGISTRY_FULL_MATCH) are only accepted from this source.
"""
from __future__ import annotations

from typing import Any

from . import patterns, upi
from .playbooks import Playbooks
from .registry import Registry, is_mobile, normalize_phone
from .reputation import ReputationService
from .sandbox_client import SandboxClient
from .url_static import analyze

MAX_URLS = 3
STATIC_EVIDENCE = {
    "SHORTENER": "uses a link shortener that hides the real destination",
    "RISKY_TLD": "uses a domain ending often abused by scammers",
    "IP_HOST": "link points to a bare IP address instead of a domain",
    "AT_IN_URL": "link hides its real destination after an '@'",
    "PUNYCODE": "link uses look-alike (punycode) characters",
    "HOMOGLYPH_OR_BRAND_IN_SUBDOMAIN": "puts a brand name in a domain it doesn't own",
    "LOOKALIKE_DOMAIN": "domain imitates an official brand domain",
}


class Collector:
    def __init__(self) -> None:
        self.signals: list[dict[str, Any]] = []

    def add(self, code: str, evidence: str, source_url: str | None = None) -> None:
        if not any(s["code"] == code for s in self.signals):
            self.signals.append({"code": code, "severity": "", "evidence": evidence[:300], "source_url": source_url})


async def baseline(ext: dict[str, Any], text: str, registry: Registry, reputation: ReputationService,
                   playbooks: Playbooks, sandbox: SandboxClient) -> dict[str, Any]:
    out = Collector()
    corpus = "\n".join(x for x in [text or "", ext.get("ocr_text") or ""] if x)

    # --- links (FR-12..14) -------------------------------------------------------------
    urls = list(ext.get("urls") or [])[:MAX_URLS]
    final_urls = list(urls)
    for url in urls:
        st = analyze(url, registry)
        if st["shortener"]:
            exp = await sandbox.expand(url)
            final = (exp or {}).get("final_url")
            if final and final != url:
                final_urls.append(final)
                st2 = analyze(final, registry)
                for f in st2["flags"]:
                    out.add(f, f"{final} {STATIC_EVIDENCE.get(f, '')}".strip())
        for f in st["flags"]:
            out.add(f, f"{st['host']} {STATIC_EVIDENCE.get(f, '')}".strip())
    for url in final_urls[: MAX_URLS + 1]:
        rep = await reputation.lookup(url)
        if "THREAT_FEED_HIT" in rep["flags"]:
            hits = ", ".join(k for k, v in rep["feeds"].items() if v == "hit")
            out.add("THREAT_FEED_HIT", f"{url} is listed by threat feeds ({hits})")
        if "DOMAIN_AGE_LT_30D" in rep["flags"]:
            out.add("DOMAIN_AGE_LT_30D", f"domain registered {rep['domain_age_days']} days ago")
        if "CERT_AGE_LT_30D" in rep["flags"]:
            out.add("CERT_AGE_LT_30D", f"first HTTPS certificate only {rep['first_cert_days']} days old")

    # --- UPI (FR-22..24) ---------------------------------------------------------------
    for uri in ext.get("upi_uris") or []:
        parsed = upi.parse(uri)
        ev = upi.pay_as_receive(parsed, corpus)
        if ev:
            out.add("UPI_PAY_AS_RECEIVE", ev)
    collect = upi.collect_request(corpus)
    if collect:
        out.add("UPI_COLLECT_REQUEST", collect)
    asks_payment = bool(patterns.pay_to_upi(corpus))
    for uid in ext.get("upi_ids") or []:
        for f in upi.upi_id_flags(uid, registry, ext.get("brands") or [], asks_payment):
            out.add(f["code"], f["evidence"])

    # --- registry (FR-17..21) ----------------------------------------------------------
    match = registry.match(ext.get("brands") or [], final_urls, ext.get("sender_ids") or [], ext.get("phones") or [],
                           [], corpus)
    ent = match["entity"]
    if ent:
        mism = {c["field"]: c["value"] for c in match["checks"] if c["status"] == "mismatch"}
        if "url" in mism:
            out.add("REGISTRY_DOMAIN_MISMATCH", f"{mism['url']} is not an official {ent['name']} domain "
                    f"(official: {', '.join(ent['domains'][:2]) or 'see registry'})")
        if "sender_id" in mism:
            out.add("SENDER_ID_MISMATCH", f"SMS header {mism['sender_id']} is not a registered {ent['name']} header")
        mobile_mismatch = [c["value"] for c in match["checks"]
                           if c["field"] == "phone" and c["status"] == "mismatch" and is_mobile(normalize_phone(c["value"]))]
        if mobile_mismatch:
            out.add("PHONE_NOT_OFFICIAL", f"{mobile_mismatch[0]} is a personal mobile number, not an official {ent['name']} line")
        for v in registry.policy(ent["id"], corpus)["violations"]:
            out.add("POLICY_VIOLATION", f"{ent['name']} says: \"{v['quote']}\"", v["source_url"])
        strong = [c for c in match["checks"] if c["field"] in ("url", "sender_id")]
        if strong and all(c["status"] == "match" for c in strong) and not mobile_mismatch and not out.signals:
            out.add("REGISTRY_FULL_MATCH", f"links/sender match {ent['name']}'s official registry entry")

    # --- wording heuristics (conservative) ----------------------------------------------
    for code, fn in (("CREDENTIAL_REQUEST", patterns.asks_credentials), ("REMOTE_ACCESS_REQUEST", patterns.remote_access),
                     ("URGENCY_LANGUAGE", patterns.urgency), ("REWARD_LURE", patterns.reward)):
        m = fn(corpus)
        if m:
            out.add(code, f"message says '{m}'")
    if not any(s["code"] == "URGENCY_LANGUAGE" for s in out.signals) and (m := patterns.threat_block(corpus)):
        out.add("URGENCY_LANGUAGE", f"threatens: '{m}'")
    if asks_payment and (ext.get("brands") or patterns.authority(corpus)):
        out.add("PERSONAL_UPI_PAYMENT", f"asks you to pay a UPI ID: '{patterns.pay_to_upi(corpus)}'")

    # --- playbooks ---------------------------------------------------------------------
    for m in playbooks.search(corpus, limit=2)["matches"]:
        if m["score"] > 0.7:
            out.add("PLAYBOOK_MATCH", f"matches the '{m['name']}' scam ({m['code']}, score {m['score']}): "
                    + ", ".join(m["matched"][:3]))
            break

    summary = f"{len(out.signals)} deterministic signal(s)" + (f"; claimed brand {ent['name']}" if ent else "")
    return {"agent": "rules", "status": "ok", "signals": out.signals, "summary": summary[:200]}
