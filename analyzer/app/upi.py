"""UPI checks: FR-22 pay-intent parsing, FR-23 UPI ID analysis, FR-24 collect-request explanation."""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qs, urlsplit

from . import patterns
from .registry import Registry

RECEIVE_WORDS = re.compile(
    r"\b(receive|receiving|refund|prize|cash\s*back|reward|won|winning|claim|credited|credit|bonus|lottery|gift|"
    r"get\s+(money|paid|rs|₹)|paise\s+milenge|paisa\s+milega|रिफंड|इनाम|कैशबैक|प्राप्त)\b",
    re.I,
)
COLLECT_EXPLANATION = (
    "This is a UPI collect request: entering your UPI PIN SENDS money out of your account. "
    "You never need a PIN to receive money."
)


def parse(uri: str) -> dict[str, Any]:
    """Parse upi://pay?pa=..&pn=..&am=..&tn=.. (also QR payloads). intent: pay | collect | unknown."""
    out: dict[str, Any] = {"pa": None, "pn": None, "am": None, "tn": None, "intent": "unknown"}
    try:
        parts = urlsplit((uri or "").strip())
    except ValueError:
        return out
    if parts.scheme.lower() != "upi":
        return out
    q = {k.lower(): v[0] for k, v in parse_qs(parts.query, keep_blank_values=True).items()}
    action = (parts.netloc or parts.path.strip("/")).lower()
    out.update(pa=q.get("pa") or None, pn=q.get("pn") or None, tn=q.get("tn") or None)
    try:
        out["am"] = float(q["am"]) if q.get("am") else None
    except ValueError:
        out["am"] = None
    if action == "pay" and out["pa"]:
        out["intent"] = "pay"
    elif action in ("collect", "mandate"):
        out["intent"] = "collect"
    return out


def inr(amount: float | None) -> str:
    if amount is None:
        return "money"
    whole = int(round(amount))
    s = str(whole)
    if len(s) > 3:
        head, tail = s[:-3], s[-3:]
        head = re.sub(r"(\d)(?=(\d\d)+$)", r"\1,", head)
        s = f"{head},{tail}"
    return f"₹{s}"


def pay_as_receive(parsed: dict[str, Any], context: str = "") -> str | None:
    """FR-22: a pay intent presented as receive/refund/prize/cashback is a hard SCAM."""
    if parsed.get("intent") != "pay":
        return None
    for field in (parsed.get("tn"), parsed.get("pn"), context):
        m = RECEIVE_WORDS.search(field or "")
        if m:
            return (f"This QR/link sends {inr(parsed.get('am'))} FROM your account to {parsed.get('pa')}, "
                    f"but it is presented as '{m.group(0)}'.")
    return None


def upi_id_flags(upi_id: str, registry: Registry, claimed: list[str], asks_payment: bool = False) -> list[dict[str, str]]:
    """FR-23: a brand/bank name on an unrelated handle, or a payment to a claimed brand's
    non-official handle. A counterparty VPA in an ordinary debit alert is not flagged."""
    local, _, handle = upi_id.lower().partition("@")
    flags: list[dict[str, str]] = []
    tokens = registry.brand_tokens()
    named = next((name for tok, name in tokens.items() if re.search(rf"(?<![a-z]){re.escape(tok)}(?![a-z])", local)), None)
    targets = ([registry.by_name(named)] if named else []) + ([registry.by_name(b) for b in claimed] if asks_payment else [])
    for ent in filter(None, targets):
        handles = [h.lower().lstrip("@") for h in ent.get("official_upi_handles", [])]
        if handle not in handles:
            flags.append({"code": "UPI_HANDLE_NOT_OFFICIAL",
                          "evidence": f"UPI ID {upi_id} is not an official {ent['name']} UPI handle"})
            break
    return flags


def collect_request(text: str) -> str | None:
    """FR-24: explain a collect request seen in a screenshot."""
    m = patterns.collect_request(text)
    return f"{COLLECT_EXPLANATION} (seen: '{m}')" if m else None
