"""Official Channels Registry: seed loading, brand detection, matching and policies.

FR-11 brand detection (aliases), FR-17 entity match, FR-18 domain check (banks must be on
`.bank.in` or a listed legacy domain), FR-19 SMS header + suffix, FR-20 phone numbers,
FR-23 UPI handles, FR-21 `never_does` policies with quote + source URL.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from . import patterns

ENTITY_FIELDS = (
    "name", "aliases", "regulator", "kind", "domains", "legacy_domains", "sms_headers", "call_prefixes",
    "support_numbers", "official_upi_handles", "app_packages", "last_verified", "status",
)
LIST_FIELDS = ("aliases", "domains", "legacy_domains", "sms_headers", "call_prefixes", "support_numbers",
               "official_upi_handles", "app_packages")
GENERIC_TOKENS = {"bank", "india", "life", "insurance", "general", "the", "of", "and", "ltd", "limited", "co", "corp",
                  "online", "netbanking", "www", "health", "assurance", "company", "first", "yes", "new", "star", "max", "union"}

# Detectors for each `never_does` rule_code. Seed policies must use one of these codes.
POLICY_DETECTORS = {
    "NEVER_ASKS_OTP_PIN": patterns.asks_credentials,
    "NEVER_SENDS_KYC_LINK": patterns.kyc_update,
    "NEVER_ASKS_REMOTE_APP": patterns.remote_access,
    "NEVER_ASKS_FEE_FOR_PAYOUT": patterns.fee_for_payout,
    "NEVER_ASKS_UPI_PIN_TO_RECEIVE": patterns.pin_to_receive,
    "NEVER_THREATENS_BLOCK": patterns.threat_block,
    "NEVER_ASKS_PERSONAL_UPI_PAYMENT": patterns.pay_to_upi,
}

SERVICE_CONTENT = re.compile(r"\b(otp|one\s+time\s+password|debited|credited|a/c|acct|account|txn|transaction|balance)\b", re.I)
SENDER_ID_RX = re.compile(r"^(?:[A-Z]{2}-)?([A-Z0-9]{6})(?:-([PSTG]))?$")


class SeedError(ValueError):
    pass


def digits(s: str) -> str:
    return re.sub(r"\D", "", s or "")


def normalize_phone(s: str) -> str:
    d = digits(s)
    if len(d) == 12 and d.startswith("91") and d[2] in "6789":
        return d[2:]
    if len(d) == 11 and d.startswith("0"):
        return d[1:]
    return d


def is_mobile(num: str) -> bool:
    return len(num) == 10 and num[0] in "6789"


def host_matches(host: str, domain: str) -> bool:
    host, domain = host.lower().rstrip("."), domain.lower().rstrip(".")
    return host == domain or host.endswith("." + domain)


def load_seed_dir(seed_dir: str | Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Read registry/seed/{banks,insurers}/*.yaml and playbooks/*.yaml. Raises SeedError on bad data."""
    root = Path(seed_dir)
    entities: list[dict[str, Any]] = []
    for path in sorted(list(root.glob("banks/*.yaml")) + list(root.glob("insurers/*.yaml"))):
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        entities.append(validate_entity(data, path.name))
    playbooks = []
    for path in sorted(root.glob("playbooks/*.yaml")):
        pb = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for key in ("code", "name", "indicators", "advice"):
            if not pb.get(key):
                raise SeedError(f"{path.name}: playbook missing {key}")
        playbooks.append(pb)
    return entities, playbooks


def validate_entity(data: dict[str, Any], origin: str = "?") -> dict[str, Any]:
    if not data.get("name") or data.get("kind") not in ("bank", "insurer", "nbfc", "wallet", "govt"):
        raise SeedError(f"{origin}: name and a valid kind are required")
    ent = {k: data.get(k) for k in ENTITY_FIELDS}
    for k in LIST_FIELDS:
        ent[k] = [str(x) for x in (data.get(k) or [])]
    ent["status"] = data.get("status") or "needs_review"
    ent["sources"] = list(data.get("sources") or [])
    ent["last_verified"] = str(data["last_verified"]) if data.get("last_verified") else None
    policies = []
    for pol in data.get("never_does") or []:
        if not pol.get("quote") or not pol.get("source_url"):
            raise SeedError(f"{origin}: policy {pol.get('rule_code')} needs quote and source_url")
        if pol.get("rule_code") not in POLICY_DETECTORS:
            raise SeedError(f"{origin}: unknown rule_code {pol.get('rule_code')}")
        policies.append({"rule_code": pol["rule_code"], "rule_text": pol.get("rule_text", ""), "quote": pol["quote"],
                         "source_url": pol["source_url"],
                         "last_verified": str(pol["last_verified"]) if pol.get("last_verified") else ent["last_verified"]})
    ent["policies"] = policies
    return ent


@dataclass
class Registry:
    entities: list[dict[str, Any]] = field(default_factory=list)
    include_unreviewed: bool = True

    def __post_init__(self) -> None:
        for i, ent in enumerate(self.entities, start=1):
            ent.setdefault("id", i)
        self._alias_rx = []
        for ent in self.entities:
            for alias in ent.get("aliases", []) + [ent["name"]]:
                rx = re.compile(r"(?<![A-Za-z0-9])" + re.escape(alias) + r"(?![A-Za-z0-9])", re.I)
                self._alias_rx.append((rx, ent))

    # --- lookups -----------------------------------------------------------------------
    def active(self) -> list[dict[str, Any]]:
        ok = {"approved", "needs_review"} if self.include_unreviewed else {"approved"}
        return [e for e in self.entities if e.get("status") in ok]

    def by_id(self, entity_id: int) -> dict[str, Any] | None:
        return next((e for e in self.active() if e["id"] == entity_id), None)

    def by_name(self, name: str) -> dict[str, Any] | None:
        n = (name or "").strip().lower()
        for ent in self.active():
            if ent["name"].lower() == n or n in (a.lower() for a in ent.get("aliases", [])):
                return ent
        return None

    def brand_tokens(self) -> dict[str, str]:
        """Lowercase brand token -> entity name, for URL brand-in-subdomain/lookalike checks."""
        out: dict[str, str] = {}
        for ent in self.active():
            cands = [a for a in ent.get("aliases", []) if re.fullmatch(r"[A-Za-z0-9]+", a)]
            cands += [d.split(".")[0] for d in ent.get("domains", []) + ent.get("legacy_domains", [])]
            for tok in cands:
                tok = tok.lower()
                if len(tok) >= 3 and tok not in GENERIC_TOKENS:
                    out.setdefault(tok, ent["name"])
        return out

    def official_domains(self) -> list[tuple[str, str]]:
        return [(d.lower(), e["name"]) for e in self.active() for d in e.get("domains", []) + e.get("legacy_domains", [])]

    def find_brands(self, text: str) -> list[str]:
        """FR-11: claimed brands from text/OCR using registry aliases."""
        active = {id(e) for e in self.active()}
        spans: list[tuple[int, int, str]] = []
        for rx, ent in self._alias_rx:
            if id(ent) in active:
                spans += [(m.start(), m.end(), ent["name"]) for m in rx.finditer(text or "")]
        # "HDFC" inside "HDFC Life" or "Bank of India" inside "State Bank of India" belongs to the longer match.
        kept = [s for s in spans if not any(o[2] != s[2] and o[0] <= s[0] and s[1] <= o[1] and (o[1] - o[0]) > (s[1] - s[0])
                                            for o in spans)]
        found: list[str] = []
        for _, _, name in sorted(kept):
            if name not in found:
                found.append(name)
        return found

    def entity_for_header(self, header: str) -> dict[str, Any] | None:
        for ent in self.active():
            if header.upper() in (h.upper() for h in ent.get("sms_headers", [])):
                return ent
        return None

    def entity_for_host(self, host: str) -> dict[str, Any] | None:
        for ent in self.active():
            if any(host_matches(host, d) for d in ent.get("domains", []) + ent.get("legacy_domains", [])):
                return ent
        return None

    # --- FR-17..20, FR-23 --------------------------------------------------------------
    def match(self, brands: list[str], urls: list[str], sender_ids: list[str], phones: list[str],
              upi_ids: list[str], text: str = "") -> dict[str, Any]:
        from .url_static import host_of  # local import: url_static depends on registry tokens

        entity = None
        for b in brands:
            entity = self.by_name(b)
            if entity:
                break
        if entity is None:
            for sid in sender_ids:
                m = SENDER_ID_RX.match(sid.upper())
                if m and (entity := self.entity_for_header(m.group(1))):
                    break
        if entity is None:
            for u in urls:
                if (entity := self.entity_for_host(host_of(u))):
                    break

        checks: list[dict[str, str]] = []
        if entity is None:
            checks = [{"field": f, "value": v, "status": "unknown"}
                      for f, vals in (("url", urls), ("sender_id", sender_ids), ("phone", phones), ("upi_id", upi_ids))
                      for v in vals]
            return {"entity": None, "checks": checks}

        official = entity.get("domains", []) + entity.get("legacy_domains", [])
        for u in urls:
            host = host_of(u)
            ok = any(host_matches(host, d) for d in official)
            checks.append({"field": "url", "value": u, "status": "match" if ok else "mismatch"})
        headers = [h.upper() for h in entity.get("sms_headers", [])]
        for sid in sender_ids:
            m = SENDER_ID_RX.match(sid.upper())
            status = "mismatch"
            if m and m.group(1) in headers:
                status = "match"
                if m.group(2) == "P" and SERVICE_CONTENT.search(text or ""):
                    status = "mismatch"  # FR-19: promotional suffix on an OTP/alert
            checks.append({"field": "sender_id", "value": sid, "status": status})
        support = {normalize_phone(n) for n in entity.get("support_numbers", [])}
        prefixes = [digits(p) for p in entity.get("call_prefixes", [])]
        for ph in phones:
            num = normalize_phone(ph)
            if num in support or (prefixes and any(num.startswith(p) for p in prefixes)):
                status = "match"
            elif num == "1930" or len(num) < 7:
                status = "unknown"
            else:
                status = "mismatch"
            checks.append({"field": "phone", "value": ph, "status": status})
        handles = [h.lower().lstrip("@") for h in entity.get("official_upi_handles", [])]
        for uid in upi_ids:
            handle = uid.split("@")[-1].lower()
            checks.append({"field": "upi_id", "value": uid, "status": "match" if handle in handles else "mismatch"})
        return {"entity": public_entity(entity), "checks": checks}

    # --- FR-21 -------------------------------------------------------------------------
    def policy(self, entity_id: int, text: str) -> dict[str, Any]:
        ent = self.by_id(entity_id)
        violations = []
        for pol in (ent or {}).get("policies", []):
            if POLICY_DETECTORS[pol["rule_code"]](text or ""):
                violations.append({"rule_code": pol["rule_code"], "quote": pol["quote"], "source_url": pol["source_url"]})
        return {"violations": violations}


def public_entity(ent: dict[str, Any]) -> dict[str, Any]:
    return {"id": ent["id"], "name": ent["name"], "kind": ent["kind"], "status": ent.get("status"),
            "domains": ent.get("domains", []), "support_numbers": ent.get("support_numbers", []),
            "sources": ent.get("sources", [])}
