"""Fixed signal-code enum (SRS 6.4). Agents may only pick from it; unknown codes are dropped.

The severity here is authoritative: the verdict engine ignores whatever severity an agent
claims, so an injected agent cannot promote or demote a signal (SRS 3.3.4).
"""
from __future__ import annotations

from enum import Enum


class Signal(str, Enum):
    # hard -> SCAM regardless of score (SRS 6.5)
    UPI_PAY_AS_RECEIVE = "UPI_PAY_AS_RECEIVE"
    THREAT_FEED_HIT = "THREAT_FEED_HIT"
    # high
    POLICY_VIOLATION = "POLICY_VIOLATION"
    REGISTRY_DOMAIN_MISMATCH = "REGISTRY_DOMAIN_MISMATCH"
    PAGE_ASKS_PIN_OTP_CARD = "PAGE_ASKS_PIN_OTP_CARD"
    HOMOGLYPH_OR_BRAND_IN_SUBDOMAIN = "HOMOGLYPH_OR_BRAND_IN_SUBDOMAIN"
    UPI_COLLECT_REQUEST = "UPI_COLLECT_REQUEST"
    LOOKALIKE_DOMAIN = "LOOKALIKE_DOMAIN"
    REMOTE_ACCESS_REQUEST = "REMOTE_ACCESS_REQUEST"
    # medium
    DOMAIN_AGE_LT_30D = "DOMAIN_AGE_LT_30D"
    SENDER_ID_MISMATCH = "SENDER_ID_MISMATCH"
    APK_DOWNLOAD = "APK_DOWNLOAD"
    PLAYBOOK_MATCH = "PLAYBOOK_MATCH"
    CREDENTIAL_REQUEST = "CREDENTIAL_REQUEST"
    PERSONAL_UPI_PAYMENT = "PERSONAL_UPI_PAYMENT"
    UPI_HANDLE_NOT_OFFICIAL = "UPI_HANDLE_NOT_OFFICIAL"
    PHONE_NOT_OFFICIAL = "PHONE_NOT_OFFICIAL"
    IP_HOST = "IP_HOST"
    AT_IN_URL = "AT_IN_URL"
    REWARD_LURE = "REWARD_LURE"
    # low
    URGENCY_LANGUAGE = "URGENCY_LANGUAGE"
    SHORTENER = "SHORTENER"
    AUTHORITY_CLAIM = "AUTHORITY_CLAIM"
    RISKY_TLD = "RISKY_TLD"
    PUNYCODE = "PUNYCODE"
    CERT_AGE_LT_30D = "CERT_AGE_LT_30D"
    # trust
    REGISTRY_FULL_MATCH = "REGISTRY_FULL_MATCH"


SEVERITY: dict[str, str] = {
    "UPI_PAY_AS_RECEIVE": "hard",
    "THREAT_FEED_HIT": "hard",
    "POLICY_VIOLATION": "high",
    "REGISTRY_DOMAIN_MISMATCH": "high",
    "PAGE_ASKS_PIN_OTP_CARD": "high",
    "HOMOGLYPH_OR_BRAND_IN_SUBDOMAIN": "high",
    "UPI_COLLECT_REQUEST": "high",
    "LOOKALIKE_DOMAIN": "high",
    "REMOTE_ACCESS_REQUEST": "high",
    "DOMAIN_AGE_LT_30D": "medium",
    "SENDER_ID_MISMATCH": "medium",
    "APK_DOWNLOAD": "medium",
    "PLAYBOOK_MATCH": "medium",
    "CREDENTIAL_REQUEST": "medium",
    "PERSONAL_UPI_PAYMENT": "medium",
    "UPI_HANDLE_NOT_OFFICIAL": "medium",
    "PHONE_NOT_OFFICIAL": "medium",
    "IP_HOST": "medium",
    "AT_IN_URL": "medium",
    "REWARD_LURE": "medium",
    "URGENCY_LANGUAGE": "low",
    "SHORTENER": "low",
    "AUTHORITY_CLAIM": "low",
    "RISKY_TLD": "low",
    "PUNYCODE": "low",
    "CERT_AGE_LT_30D": "low",
    "REGISTRY_FULL_MATCH": "trust",
}

CODES: frozenset[str] = frozenset(s.value for s in Signal)
HARD: frozenset[str] = frozenset(c for c, s in SEVERITY.items() if s == "hard")
# Signals that mean "the message or page asks for PIN/OTP/card" for the hard combo in SRS 6.5.
ASKS_PIN_OTP_CARD: frozenset[str] = frozenset({"CREDENTIAL_REQUEST", "PAGE_ASKS_PIN_OTP_CARD"})
# Trust signals lower the score, so only the deterministic "rules" agent may emit them.
TRUST_ONLY_FROM: frozenset[str] = frozenset({"rules"})

AGENTS: tuple[str, ...] = ("wording", "link", "impersonation", "scamtype", "rules")
