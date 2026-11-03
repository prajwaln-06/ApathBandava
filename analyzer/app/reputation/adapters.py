"""Reputation feed adapters (FR-14). Each adapter queries a *lookup service* about a URL or
domain; none of them fetches the user-supplied URL itself (NFR-3).

Every adapter returns None / "unknown" on missing keys or errors; the service applies a
per-feed timeout so one failing feed never blocks a verdict (NFR-8).
"""
from __future__ import annotations

import base64
import time
from datetime import datetime, timezone
from typing import Any, Protocol

import httpx


def _days_since(iso: str) -> int | None:
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return max(0, (datetime.now(timezone.utc) - dt).days)


class AgeAdapter(Protocol):
    name: str

    async def days(self, client: httpx.AsyncClient, domain: str) -> int | None: ...


class FeedAdapter(Protocol):
    name: str

    async def check(self, client: httpx.AsyncClient, url: str) -> str: ...


class RdapAge:
    """Domain age from RDAP registration event (rdap.org bootstrap redirect)."""

    name = "rdap"

    async def days(self, client: httpx.AsyncClient, domain: str) -> int | None:
        r = await client.get(f"https://rdap.org/domain/{domain}", follow_redirects=True,
                             headers={"Accept": "application/rdap+json"})
        if r.status_code != 200:
            return None
        for ev in r.json().get("events", []):
            if ev.get("eventAction") == "registration":
                return _days_since(ev.get("eventDate", ""))
        return None


class CrtshAge:
    """Days since the first certificate seen in CT logs (crt.sh)."""

    name = "crtsh"

    async def days(self, client: httpx.AsyncClient, domain: str) -> int | None:
        r = await client.get("https://crt.sh/", params={"q": domain, "output": "json"})
        if r.status_code != 200:
            return None
        dates = [row.get("not_before") for row in r.json() if row.get("not_before")]
        return _days_since(min(dates)) if dates else None


class SafeBrowsing:
    name = "gsb"

    def __init__(self, key: str) -> None:
        self.key = key

    async def check(self, client: httpx.AsyncClient, url: str) -> str:
        if not self.key:
            return "unknown"
        body = {
            "client": {"clientId": "scamsaathi", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"], "threatEntries": [{"url": url}],
            },
        }
        r = await client.post(f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.key}", json=body)
        if r.status_code != 200:
            return "unknown"
        return "hit" if r.json().get("matches") else "clean"


class URLhaus:
    name = "urlhaus"

    def __init__(self, auth_key: str) -> None:
        self.auth_key = auth_key

    async def check(self, client: httpx.AsyncClient, url: str) -> str:
        if not self.auth_key:
            return "unknown"
        r = await client.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": url},
                              headers={"Auth-Key": self.auth_key})
        if r.status_code != 200:
            return "unknown"
        status = r.json().get("query_status")
        return "hit" if status == "ok" else ("clean" if status == "no_results" else "unknown")


class OpenPhish:
    """Community feed (no key). Fills the SRS `phishtank` slot; PhishTank registration is closed."""

    name = "phishtank"
    FEED = "https://openphish.com/feed.txt"
    TTL = 3600

    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled
        self._urls: set[str] = set()
        self._at = 0.0

    async def check(self, client: httpx.AsyncClient, url: str) -> str:
        if not self.enabled:
            return "unknown"
        if time.time() - self._at > self.TTL:
            r = await client.get(self.FEED)
            if r.status_code != 200:
                return "unknown"
            self._urls = {line.strip().rstrip("/") for line in r.text.splitlines() if line.strip()}
            self._at = time.time()
        return "hit" if url.rstrip("/") in self._urls else "clean"


class VirusTotal:
    name = "vt"

    def __init__(self, key: str) -> None:
        self.key = key

    async def check(self, client: httpx.AsyncClient, url: str) -> str:
        if not self.key:
            return "unknown"
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        r = await client.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers={"x-apikey": self.key})
        if r.status_code == 404:
            return "clean"
        if r.status_code != 200:
            return "unknown"
        stats: dict[str, Any] = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return "hit" if stats.get("malicious", 0) >= 2 else "clean"
