"""Client for the isolated sandbox. All user-URL fetching (expansion and detonation) happens
there, never in the analyzer (NFR-3, FR-13, FR-15, FR-16)."""
from __future__ import annotations

import logging
from typing import Any

import httpx

log = logging.getLogger(__name__)
SENSITIVE_DOWNLOADS = {"apk", "exe", "msi", "bat", "scr", "dex", "jar"}


class SandboxClient:
    def __init__(self, base_url: str, enabled: bool = True, timeout: float = 28.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.enabled = enabled
        self.timeout = timeout

    async def _call(self, url: str, mode: str) -> dict[str, Any] | None:
        if not self.enabled:
            return None
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                r = await client.post(f"{self.base_url}/detonate", json={"url": url, "mode": mode})
            if r.status_code != 200:
                return None
            return r.json()
        except (httpx.HTTPError, ValueError) as exc:
            log.info("sandbox %s failed: %s", mode, type(exc).__name__)
            return None

    async def expand(self, url: str) -> dict[str, Any] | None:
        """FR-13: follow redirects with HEAD requests inside the sandbox (max 5 hops)."""
        return await self._call(url, "expand")

    async def detonate(self, url: str) -> dict[str, Any]:
        res = await self._call(url, "full")
        if res is None:
            return {"final_url": None, "redirects": [], "title": None, "screenshot_path": None,
                    "forms": {"pin": False, "otp": False, "card": False, "password": False},
                    "brand_logos": [], "download": None, "flags": [], "status": "unknown"}
        return with_flags(res)


def with_flags(res: dict[str, Any]) -> dict[str, Any]:
    forms = res.get("forms") or {}
    flags = []
    if forms.get("pin") or forms.get("otp") or forms.get("card"):
        flags.append("PAGE_ASKS_PIN_OTP_CARD")
    dl = res.get("download") or None
    if dl and str(dl.get("type", "")).lower() in SENSITIVE_DOWNLOADS:
        flags.append("APK_DOWNLOAD")
    res["flags"] = flags
    res.setdefault("status", "ok")
    return res
