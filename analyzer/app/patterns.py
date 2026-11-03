"""Deterministic text detectors (English, Hinglish, Hindi).

Shared by registry `never_does` policies (FR-21), the deterministic wording heuristics in the
rules baseline, and off-topic detection (FR-6). Each detector returns the matched snippet
(evidence) or None. Warnings such as "never share your OTP" are not treated as requests.
"""
from __future__ import annotations

import re

_I = re.IGNORECASE

NEGATION = re.compile(
    r"(do\s*n[o']?t|never|don't|dont|mat|na\s+karein|naa?\s+kare|kabhi\s+na|nahi|नहीं|न\s+करें|कभी)\W+(\w+\W+){0,3}$",
    _I,
)

CREDENTIAL_REQUEST = re.compile(
    r"\b(share|send|tell|provide|give|enter|confirm|reply\s+with|forward|submit|batao|bataye|bhejo|bhejein|daalein|dalo)\b"
    r"[^.\n]{0,40}?\b(otp|o\.t\.p|upi\s*pin|atm\s*pin|m-?pin|pin|cvv|password|card\s+(number|details)|net\s*banking\s+(id|password)|ओटीपी|पिन)\b"
    r"|\b(otp|upi\s*pin|cvv|pin)\b[^.\n]{0,25}?\b(share\s+karein|share\s+karo|batayen|bataiye|bataye|batao|bata\s+do|bhejein|bhejo|send\s+karo|बताएं|भेजें)",
    _I,
)
REMOTE_ACCESS = re.compile(
    r"\b(anydesk|any\s*desk|teamviewer|team\s*viewer|quick\s*support|rustdesk|airdroid|screen\s*shar(e|ing)|remote\s+(access|app))\b"
    r"|\.apk\b|\binstall\b[^.\n]{0,30}\bapp\b[^.\n]{0,30}\b(link|below|this)\b",
    _I,
)
URGENCY = re.compile(
    r"\b(urgent(ly)?|immediately|within\s+\d+\s*(hours?|hrs?|minutes?|mins?)|today\s+(itself|only)|last\s+(date|day|chance|warning)|"
    r"expire[sd]?\s+(today|tonight|soon)|act\s+now|final\s+(notice|reminder|warning)|turant|abhi|aaj\s+hi|तुरंत|आज\s+ही|"
    r"will\s+be\s+(blocked|suspended|deactivated|disconnected|cut|closed|frozen)|(block|suspend|band|disconnect)\w*\s+(ho\s+jayega|kar\s+diya\s+jayega))\b",
    _I,
)
THREAT_BLOCK = re.compile(
    r"\b(account|card|kyc|pan|sim|connection|electricity|bijli|yono|net\s*banking|policy)\b[^.\n]{0,60}?"
    r"\b(block(ed)?|suspend(ed)?|deactivat(e|ed)|disconnect(ed)?|cut\s+off|freez(e|ed)|band\s+ho|बंद)\b",
    _I,
)
REWARD = re.compile(
    r"\b(you\s+(have\s+)?won|winner|lottery|lucky\s+draw|prize|cash\s*back|refund|reward|bonus|gift|"
    r"jackpot|claim\s+your|kbc|selected\s+for|earn\s+(rs\.?|₹|inr)?\s*\d|inaam|इनाम|रिफंड|कैशबैक)\b",
    _I,
)
AUTHORITY = re.compile(
    r"\b(rbi|reserve\s+bank|police|cbi|cyber\s*cell|customs|income\s*tax|trai|court|ed\s+officer|narcotics|"
    r"electricity\s+(board|department|office)|bijli\s+vibhag|courier|fedex|dhl|blue\s*dart|india\s*post|"
    r"bank\s+(manager|officer|executive)|kyc\s+department)\b",
    _I,
)
KYC_UPDATE = re.compile(
    r"\b(kyc|pan|aadhaa?r)\b[^.\n]{0,60}?\b(update|verify|verification|link|expire[sd]?|pending|complete|re-?kyc)\b"
    r"|\b(update|verify|complete)\b[^.\n]{0,30}?\b(kyc|pan)\b",
    _I,
)
FEE_FOR_PAYOUT = re.compile(
    r"\b(pay|deposit|transfer|send|processing|clearance|release|registration|gst|tax|charges?|fees?)\b[^.\n]{0,60}?"
    r"\b(maturity|claim|bonus|payout|refund|policy\s+(amount|money)|release|loan|prize|lottery|parcel|customs|job)\b"
    r"|\b(maturity|claim|bonus|payout|refund|loan|prize|parcel|job)\b[^.\n]{0,60}?\b(fee|fees|charge|charges|deposit|pay\s+(rs\.?|₹|inr))",
    _I,
)
PIN_TO_RECEIVE = re.compile(
    r"\b(enter|use|daalein|dalo|डालें)\b[^.\n]{0,25}?\b(upi\s*)?pin\b[^.\n]{0,40}?\b(receive|get|credit|claim|refund|cashback|prize|paise\s+aayenge|प्राप्त)\b"
    r"|\b(receive|get|claim|credit)\b[^.\n]{0,40}?\b(enter|use)\b[^.\n]{0,20}?\b(upi\s*)?pin\b"
    r"|\bscan\b[^.\n]{0,40}?\b(to\s+)?(receive|get|claim|credit)\b",
    _I,
)
PAY_TO_UPI = re.compile(
    r"\b(pay|send|transfer|deposit|bhejein|bhejo|bhugtan)\b(?:(?!\b(?:from|by)\b)[^\n]){0,60}?[\w.\-]+@[a-z][a-z0-9]{1,30}\b(?!\.[a-z])", _I)
COLLECT_REQUEST = re.compile(
    r"\b(collect\s+request|payment\s+request|money\s+request|has\s+requested|is\s+requesting|requested\s+(rs\.?|₹|inr)|"
    r"request(ed)?\s+(money|payment)|approve\s+(the\s+)?(request|payment)|pay\s+request|ने\s+अनुरोध)\b",
    _I,
)
COLLECT_UI = re.compile(r"\b(decline|reject|approve|pay|upi\s*pin|expires?\s+in)\b", _I)
SCAM_KEYWORDS = re.compile(
    r"\b(kyc|otp|pin|cvv|refund|prize|lottery|won|account|bank|blocked?|upi|link|pay|payment|loan|job|task|customs|parcel|courier|"
    r"electricity|bijli|police|arrest|insurance|policy|maturity|claim|cashback|reward|verify|update|aadhaa?r|pan|card|credit|debit|"
    r"sim|rs\.?|inr|₹|invest|trading|crypto|whatsapp\s+group|telegram|qr|scan|apk|install|anydesk|sbi|hdfc|icici|lic|rbi|"
    r"खाता|बैंक|ओटीपी|इनाम|बिजली|पुलिस)\b",
    _I,
)
SECRECY = re.compile(r"\b(don'?t\s+tell|keep\s+(this\s+)?(secret|confidential)|kisi\s+ko\s+mat\s+batana|किसी\s+को\s+न\s+बताएं)\b", _I)


def _first(rx: re.Pattern[str], text: str, skip_negated: bool = False) -> str | None:
    for m in rx.finditer(text or ""):
        if skip_negated and NEGATION.search(text[max(0, m.start() - 40): m.start()]):
            continue
        return m.group(0).strip()[:120]
    return None


def asks_credentials(text: str) -> str | None:
    return _first(CREDENTIAL_REQUEST, text, skip_negated=True)


def remote_access(text: str) -> str | None:
    return _first(REMOTE_ACCESS, text, skip_negated=True)


def urgency(text: str) -> str | None:
    return _first(URGENCY, text)


def threat_block(text: str) -> str | None:
    return _first(THREAT_BLOCK, text, skip_negated=True)


def reward(text: str) -> str | None:
    return _first(REWARD, text)


def authority(text: str) -> str | None:
    return _first(AUTHORITY, text)


def kyc_update(text: str) -> str | None:
    return _first(KYC_UPDATE, text, skip_negated=True)


def fee_for_payout(text: str) -> str | None:
    return _first(FEE_FOR_PAYOUT, text, skip_negated=True)


def pin_to_receive(text: str) -> str | None:
    return _first(PIN_TO_RECEIVE, text, skip_negated=True)


def pay_to_upi(text: str) -> str | None:
    return _first(PAY_TO_UPI, text)


def secrecy(text: str) -> str | None:
    return _first(SECRECY, text)


def collect_request(text: str) -> str | None:
    """FR-24: a collect-request screen (request wording plus Pay/Decline/PIN UI words)."""
    m = _first(COLLECT_REQUEST, text)
    if m and len(set(x.lower() for x in COLLECT_UI.findall(text or "") if isinstance(x, str))) >= 1:
        return m
    return None


def has_scam_keywords(text: str) -> bool:
    return bool(SCAM_KEYWORDS.search(text or ""))
