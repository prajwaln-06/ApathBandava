"""Reply context, deterministic fallback template, and reply validation (FR-26..28, FR-7, FR-24).

The composer agent only words the verdict. Its text is accepted only if it passes
`validate_reply`; otherwise the deterministic template is sent. The validator blocks the
word "safe", unexpected links or phone numbers (a composer tricked into adding a scammer's
number), a wrong verdict line, and replies over 900 characters.
"""
from __future__ import annotations

import re
from typing import Any

from .playbooks import Playbooks
from .registry import Registry, digits
from .upi import COLLECT_EXPLANATION

MAX_LEN = 900
VERDICT_LINE = {
    "en": {"SCAM": "🚫 SCAM", "SUSPICIOUS": "⚠️ SUSPICIOUS", "NO_RED_FLAGS": "✅ No red flags found"},
    "hi": {"SCAM": "🚫 धोखाधड़ी (SCAM)", "SUSPICIOUS": "⚠️ संदिग्ध (SUSPICIOUS)", "NO_RED_FLAGS": "✅ कोई खतरे का संकेत नहीं मिला"},
}
EMOJI = {"SCAM": "🚫", "SUSPICIOUS": "⚠️", "NO_RED_FLAGS": "✅"}
ALLOWED_HOSTS = {"cybercrime.gov.in", "sancharsaathi.gov.in", "www.cybercrime.gov.in", "www.sancharsaathi.gov.in"}
BANNED = re.compile(r"\bsafe(ly|ty)?\b|सुरक्षित", re.I)
URL_IN_TEXT = re.compile(r"(?:https?://)?(?:www\.)?((?:[a-z0-9\-]+\.)+[a-z]{2,})(?:/[^\s]*)?", re.I)
NUM_IN_TEXT = re.compile(r"(?<![\d₹,.])(?:\+?\d[\d\s\-]{2,16}\d)(?![\d,.])")
SMS_LIKE = re.compile(r"\b(dear\s+customer|a/c|acct|debited|credited|otp|txn|kyc|your\s+account)\b", re.I)

STEPS = {
    "en": {
        "SCAM": ["Don't pay, scan, click or share OTP/PIN.", "Lost money? Call 1930 now / cybercrime.gov.in",
                 "Report it on Sanchar Saathi → Chakshu"],
        "SUSPICIOUS": ["Don't pay or share OTP/PIN until you verify it.", "Verify only via the official app/website",
                       "If money is lost: call 1930 / cybercrime.gov.in; report on Sanchar Saathi → Chakshu"],
        "NO_RED_FLAGS": ["Still, never share OTP/PIN with anyone.", "Unsure? Verify via the official app or helpline."],
    },
    "hi": {
        "SCAM": ["पैसे न भेजें, QR स्कैन न करें, OTP/PIN किसी को न बताएं।", "पैसे गए? अभी 1930 पर कॉल करें / cybercrime.gov.in",
                 "संचार साथी → चक्षु पर रिपोर्ट करें"],
        "SUSPICIOUS": ["जाँच किए बिना पैसे न भेजें, OTP/PIN न बताएं।", "सिर्फ़ आधिकारिक ऐप/वेबसाइट से पुष्टि करें",
                       "पैसे गए हों तो 1930 / cybercrime.gov.in; संचार साथी → चक्षु पर रिपोर्ट करें"],
        "NO_RED_FLAGS": ["फिर भी OTP/PIN किसी को न बताएं।", "शक हो तो आधिकारिक ऐप या हेल्पलाइन से पुष्टि करें।"],
    },
}
CAUTION = {"en": "This doesn't guarantee it's genuine — stay alert.", "hi": "इसका मतलब यह नहीं कि यह पक्का असली है — सावधान रहें।"}
HINT_SMS = {"en": "Tip: a pasted SMS loses its sender ID. Send a screenshot that shows the sender for a better check.",
            "hi": "सुझाव: कॉपी किए गए SMS में भेजने वाले की ID नहीं होती। बेहतर जाँच के लिए भेजने वाले वाला स्क्रीनशॉट भेजें।"}
WHY = {"en": "Why:", "hi": "कारण:"}
SOURCE = {"en": "Official source:", "hi": "आधिकारिक स्रोत:"}
TODO = {"en": "What to do:", "hi": "क्या करें:"}
HELPLINE = {"en": "{name} official helpline: {num}", "hi": "{name} की आधिकारिक हेल्पलाइन: {num}"}


def build_context(verdict: dict[str, Any], ext: dict[str, Any], findings: list[dict[str, Any]], language: str,
                  registry: Registry, playbooks: Playbooks, input_type: str = "text", text: str = "") -> dict[str, Any]:
    language = language if language in VERDICT_LINE else "en"
    signals = [s for f in findings if isinstance(f, dict) for s in f.get("signals", []) if isinstance(s, dict)]
    codes = {s.get("code") for s in signals}
    sources = [s["source_url"] for s in signals if s.get("code") == "POLICY_VIOLATION" and s.get("source_url")]
    match = registry.match(ext.get("brands") or [], [], [], [], [], "")
    ent = match["entity"]
    if ent and not sources and ent.get("sources"):
        sources = [ent["sources"][0]]
    helpline = {"institution": ent["name"], "number": ent["support_numbers"][0]} if ent and ent.get("support_numbers") else None
    special = None
    pay = next((s.get("evidence") for s in signals if s.get("code") == "UPI_PAY_AS_RECEIVE"), None)
    if pay:
        special = pay
    elif "UPI_COLLECT_REQUEST" in codes:
        special = COLLECT_EXPLANATION
    corpus = (text or "") + "\n" + (ext.get("ocr_text") or "")
    top = playbooks.search(corpus, limit=1)["matches"]
    pb = playbooks.get(top[0]["code"]) if top and top[0]["score"] >= 0.5 else None
    advice = None
    if pb:
        advice = (pb.get("advice_hi") or pb["advice"]) if language == "hi" else pb["advice"]
    hint = None
    if input_type == "text" and not ext.get("sender_ids") and SMS_LIKE.search(text or "") and verdict.get("verdict") != "SCAM":
        hint = HINT_SMS[language]
    return {
        "verdict": verdict.get("verdict", "SUSPICIOUS"),
        "reasons": list(verdict.get("reasons") or [])[:3],
        "sources": sources[:1],
        "playbook_advice": advice,
        "helpline": helpline,
        "language": language,
        "special_line": special,
        "hint": hint,
        "official_domains": (ent or {}).get("domains", [])[:3],
    }


def fallback_reply(ctx: dict[str, Any]) -> str:
    lang = ctx.get("language") if ctx.get("language") in VERDICT_LINE else "en"
    v = ctx.get("verdict") if ctx.get("verdict") in EMOJI else "SUSPICIOUS"
    lines = [VERDICT_LINE[lang][v]]
    if ctx.get("special_line"):
        lines.append(ctx["special_line"])
    if v == "NO_RED_FLAGS":
        lines.append(CAUTION[lang])
    if ctx.get("reasons") and v != "NO_RED_FLAGS":
        lines.append(WHY[lang])
        lines += [f"• {r[:140]}" for r in ctx["reasons"][:3]]
    if ctx.get("sources"):
        lines.append(f"{SOURCE[lang]} {ctx['sources'][0]}")
    if ctx.get("playbook_advice") and v != "NO_RED_FLAGS":
        lines.append(ctx["playbook_advice"][:160])
    lines.append(TODO[lang])
    lines += [f"• {s}" for s in STEPS[lang][v]]
    if ctx.get("helpline"):
        lines.append("• " + HELPLINE[lang].format(name=ctx["helpline"]["institution"], num=ctx["helpline"]["number"]))
    if ctx.get("hint"):
        lines.append(ctx["hint"])
    text = "\n".join(lines)
    while len(text) > MAX_LEN and len(lines) > 3:
        lines.pop(-2 if ctx.get("hint") else 1)
        text = "\n".join(lines)
    return text[:MAX_LEN]


def validate_reply(text: Any, ctx: dict[str, Any]) -> list[str]:
    """Return a list of problems; empty means the composer reply may be sent."""
    if not isinstance(text, str) or not text.strip():
        return ["empty"]
    problems = []
    v = ctx.get("verdict", "SUSPICIOUS")
    if len(text) > MAX_LEN:
        problems.append("too_long")
    first = text.strip().splitlines()[0]
    if EMOJI.get(v, "") not in first or any(e in first for k, e in EMOJI.items() if k != v):
        problems.append("verdict_line")
    if BANNED.search(text):
        problems.append("says_safe")
    allowed_hosts = set(ALLOWED_HOSTS)
    for src in ctx.get("sources") or []:
        allowed_hosts.add(re.sub(r"^https?://", "", src).split("/")[0].lower())
    allowed_hosts |= {d.lower() for d in ctx.get("official_domains") or []}
    for m in URL_IN_TEXT.finditer(text):
        host = m.group(1).lower()
        if host not in allowed_hosts and not any(host.endswith("." + h) for h in allowed_hosts):
            problems.append(f"url:{host}")
    allowed_nums = {"1930"}
    if ctx.get("helpline"):
        allowed_nums.add(digits(ctx["helpline"]["number"]))
    ctx_text = " ".join([*(ctx.get("reasons") or []), ctx.get("special_line") or "", ctx.get("playbook_advice") or ""])
    allowed_nums |= set(re.findall(r"\d{4,}", re.sub(r"(?<=\d)[,\s\-](?=\d)", "", ctx_text)))
    for m in NUM_IN_TEXT.finditer(text):
        num = digits(m.group(0))
        if len(num) >= 4 and num not in allowed_nums and not any(num in a or a in num for a in allowed_nums if len(a) >= 4):
            problems.append(f"number:{num}")
    return problems


def finalize(text: Any, ctx: dict[str, Any]) -> dict[str, Any]:
    problems = validate_reply(text, ctx)
    if problems:
        return {"reply": fallback_reply(ctx), "used_fallback": True, "problems": problems}
    return {"reply": text.strip(), "used_fallback": False, "problems": []}
