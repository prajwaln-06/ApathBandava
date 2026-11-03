"""Scam playbook library search (keyword + fuzzy matching; SRS 6.1 says pgvector is optional)."""
from __future__ import annotations

import re
from typing import Any

from rapidfuzz import fuzz

MATCH_THRESHOLD = 88  # rapidfuzz partial_ratio for multi-word indicators


class Playbooks:
    def __init__(self, items: list[dict[str, Any]]) -> None:
        self.items = items
        self._by_code = {p["code"]: p for p in items}

    def get(self, code: str) -> dict[str, Any] | None:
        return self._by_code.get(code)

    @staticmethod
    def _hit(indicator: str, text: str) -> bool:
        ind = indicator.lower().strip()
        if len(ind) <= 5 or " " not in ind:
            return re.search(r"(?<![a-z0-9])" + re.escape(ind) + r"(?![a-z0-9])", text) is not None
        return fuzz.partial_ratio(ind, text) >= MATCH_THRESHOLD

    def search(self, text: str, limit: int = 3) -> dict[str, Any]:
        low = (text or "").lower()
        matches = []
        for pb in self.items:
            inds = pb.get("indicators") or []
            hits = [i for i in inds if self._hit(i, low)]
            if not hits:
                continue
            score = round(min(1.0, len(hits) / min(3, len(inds))), 2)
            matches.append({"code": pb["code"], "name": pb["name"], "score": score, "matched": hits[:5]})
        matches.sort(key=lambda m: (-m["score"], -len(m["matched"])))
        return {"matches": matches[:limit]}
