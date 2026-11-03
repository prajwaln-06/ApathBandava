"""Reputation service: runs age + feed adapters concurrently with per-feed timeouts (FR-14, NFR-8)."""
from __future__ import annotations

import asyncio
import logging
import re
import time
from pathlib import Path
from typing import Any, Sequence

import httpx
import yaml

from ..registry import Registry
from ..url_static import analyze, host_of
from .adapters import CrtshAge, OpenPhish, RdapAge, SafeBrowsing, URLhaus, VirusTotal

log = logging.getLogger(__name__)
RESERVED_TLDS = (".example", ".test", ".invalid")
DOMAIN_OK = re.compile(r"^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z0-9-]{2,63}$")
FEED_KEYS = ("gsb", "urlhaus", "phishtank", "vt")


class ReputationService:
    def __init__(self, registry: Registry, *, ages: Sequence[Any] | None = None, feeds: Sequence[Any] | None = None,
                 timeout: float = 5.0, overlay_path: str = "", cache_ttl: int = 3600, settings: Any = None) -> None:
        self.registry = registry
        self.timeout = timeout
        if settings is not None and ages is None:
            ages = ([RdapAge()] if settings.rdap_enabled else []) + ([CrtshAge()] if settings.crtsh_enabled else [])
        if settings is not None and feeds is None:
            feeds = [SafeBrowsing(settings.gsb_api_key), URLhaus(settings.urlhaus_auth_key),
                     OpenPhish(settings.openphish_enabled), VirusTotal(settings.vt_api_key)]
        self.ages = list(ages or [])
        self.feeds = list(feeds or [])
        self.overlay = self._load_overlay(overlay_path)
        self.cache_ttl = cache_ttl
        self._cache: dict[str, tuple[float, dict[str, Any]]] = {}

    @staticmethod
    def _load_overlay(path: str) -> dict[str, Any]:
        if not path or not Path(path).is_file():
            return {}
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        # Only reserved test TLDs may be overlaid, so the overlay can never whitelist a real domain.
        return {k.lower(): v for k, v in data.items() if k.lower().endswith(RESERVED_TLDS)}

    async def _guard(self, coro: Any) -> Any:
        try:
            return await asyncio.wait_for(coro, self.timeout)
        except Exception as exc:  # noqa: BLE001 - NFR-8: any feed failure -> unknown
            log.info("reputation lookup failed: %s", type(exc).__name__)
            return None

    async def lookup(self, url: str) -> dict[str, Any]:
        static = analyze(url, self.registry)
        domain = static["registrable_domain"] or host_of(url)
        if domain in self.overlay:
            return self._result(self.overlay[domain].get("domain_age_days"), self.overlay[domain].get("first_cert_days"),
                                {k: self.overlay[domain].get("feeds", {}).get(k, "unknown") for k in FEED_KEYS})
        if domain.endswith(RESERVED_TLDS):
            return self._result(None, None, {k: "unknown" for k in FEED_KEYS})
        cached = self._cache.get(url)
        if cached and time.time() - cached[0] < self.cache_ttl:
            return cached[1]
        try:
            ascii_domain = domain.encode("idna").decode()
        except UnicodeError:
            ascii_domain = ""
        can_query_domain = bool(DOMAIN_OK.match(ascii_domain)) and not static["ip_host"]
        async with httpx.AsyncClient(timeout=self.timeout, headers={"User-Agent": "ScamSaathi/1.0"}) as client:
            age_tasks = [self._guard(a.days(client, ascii_domain)) for a in self.ages] if can_query_domain else []
            feed_tasks = [self._guard(f.check(client, url)) for f in self.feeds]
            results = await asyncio.gather(*age_tasks, *feed_tasks)
        age_vals = dict(zip([a.name for a in self.ages] if can_query_domain else [], results[: len(age_tasks)]))
        feeds = {k: "unknown" for k in FEED_KEYS}
        for f, res in zip(self.feeds, results[len(age_tasks):]):
            feeds[f.name] = res or "unknown"
        result = self._result(age_vals.get("rdap"), age_vals.get("crtsh"), feeds)
        self._cache[url] = (time.time(), result)
        return result

    @staticmethod
    def _result(age: int | None, cert: int | None, feeds: dict[str, str]) -> dict[str, Any]:
        flags = []
        if any(v == "hit" for v in feeds.values()):
            flags.append("THREAT_FEED_HIT")
        if age is not None and age < 30:
            flags.append("DOMAIN_AGE_LT_30D")
        if cert is not None and cert < 30:
            flags.append("CERT_AGE_LT_30D")
        return {"domain_age_days": age, "first_cert_days": cert, "feeds": feeds, "flags": flags}
