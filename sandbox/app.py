"""ScamSaathi sandbox: the ONLY component that fetches user-supplied URLs (NFR-3).

POST /detonate {"url": ..., "mode": "expand" | "full"}
  expand: FR-13 — follow redirects with HEAD (GET fallback, body never read), max 5 hops.
  full:   FR-15 — fresh Chromium per request; capture final URL, redirect chain, title,
          screenshot, credential form fields, brand logos, download attempts (FR-16: hashed,
          never opened).

Defences (SRS 3.3.5, NFR-2): iptables egress firewall set by the entrypoint before dropping
root; every hop/request is resolved and must be a public (global) IP; Docker service names and
single-label hosts are refused; 20 s budget; 5 MB response cap; read-only rootfs; no secrets.
"""
from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import logging
import os
import re
import socket
import tempfile
import time
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

log = logging.getLogger("sandbox")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

TOTAL_BUDGET_S = float(os.getenv("SANDBOX_TIMEOUT_S", "20"))
MAX_BYTES = int(os.getenv("SANDBOX_MAX_BYTES", str(5 * 1024 * 1024)))
MAX_HOPS = 5
SHOTS_DIR = os.getenv("SHOTS_DIR", "/shots")
BLOCKED_NAMES = {"localhost", "postgres", "redis", "analyzer", "n8n", "wa-bridge", "sandbox", "llm-gateway",
                 "mock-bridge", "metadata", "metadata.google.internal", "host.docker.internal", "gateway.docker.internal"}
BRANDS = ["sbi", "state bank", "hdfc", "icici", "axis", "kotak", "pnb", "punjab national", "bank of baroda", "canara",
          "union bank", "indusind", "yes bank", "idfc", "federal bank", "idbi", "bank of india", "lic", "sbi life",
          "hdfc life", "icici prudential", "max life", "bajaj", "tata aia", "star health", "new india assurance",
          "icici lombard", "paytm", "phonepe", "google pay", "bhim", "npci", "rbi", "india post"]
FORM_PATTERNS = {
    "pin": re.compile(r"\b(m?pin|upi\s*pin|atm\s*pin)\b", re.I),
    "otp": re.compile(r"\b(otp|one[\s-]?time|verification\s+code)\b", re.I),
    "card": re.compile(r"\b(card\s*(no|number)|cvv|cvc|expiry|valid\s+thru|debit\s+card|credit\s+card)\b", re.I),
    "password": re.compile(r"\bpass(word|code)\b", re.I),
}

app = FastAPI(title="sandbox")


class DetonateIn(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048)
    mode: str = Field("full", pattern="^(expand|full)$")


class Blocked(Exception):
    pass


def _host_allowed(host: str) -> None:
    """Raise Blocked unless every address of `host` is a public, global unicast IP."""
    host = (host or "").strip("[]").lower().rstrip(".")
    if not host or host in BLOCKED_NAMES or "." not in host and not _is_ip(host):
        raise Blocked(f"host not allowed: {host or '(empty)'}")
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise Blocked(f"dns failed for {host}") from exc
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global or ip.is_multicast or str(ip) == "169.254.169.254":
            raise Blocked(f"non-public address for {host}")


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _normalize(url: str) -> str:
    url = url.strip()
    if not re.match(r"^https?://", url, re.I):
        if "://" in url:
            raise Blocked("only http(s) URLs are allowed")
        url = "http://" + url
    parts = urlsplit(url)
    if parts.username or parts.password:
        # userinfo is a classic trick; strip it so the real host is what we check
        url = url.replace(parts.netloc, parts.hostname + (f":{parts.port}" if parts.port else ""), 1)
    return url


async def expand(url: str) -> dict[str, Any]:
    url = _normalize(url)
    redirects: list[str] = []
    deadline = time.monotonic() + TOTAL_BUDGET_S
    async with httpx.AsyncClient(follow_redirects=False, timeout=5.0, trust_env=False,
                                 headers={"User-Agent": "Mozilla/5.0 (ScamSaathi link check)"}) as client:
        for _ in range(MAX_HOPS + 1):
            if time.monotonic() > deadline:
                break
            await asyncio.to_thread(_host_allowed, urlsplit(url).hostname or "")
            try:
                r = await client.head(url)
                if r.status_code in (403, 405, 501):
                    async with client.stream("GET", url) as gr:  # headers only; body is never read
                        r = gr
            except httpx.HTTPError as exc:
                return {"final_url": url, "redirects": redirects, "error": type(exc).__name__}
            loc = r.headers.get("location")
            if r.status_code in (301, 302, 303, 307, 308) and loc and len(redirects) < MAX_HOPS:
                redirects.append(url)
                url = _normalize(urljoin(url, loc))
                continue
            break
    return {"final_url": url, "redirects": redirects}


FORM_JS = """() => Array.from(document.querySelectorAll('input,select,textarea')).slice(0,200).map(e => {
  const lab = e.id ? document.querySelector(`label[for="${CSS.escape(e.id)}"]`) : null;
  return [e.type||'', e.name||'', e.id||'', e.placeholder||'', e.getAttribute('aria-label')||'',
          e.autocomplete||'', lab ? lab.innerText : ''].join(' ');
})"""
IMG_JS = """() => Array.from(document.images).slice(0,100).map(i => (i.alt||'') + ' ' + (i.src||'').split('/').pop())"""


async def detonate(url: str) -> dict[str, Any]:
    from playwright.async_api import async_playwright

    url = _normalize(url)
    await asyncio.to_thread(_host_allowed, urlsplit(url).hostname or "")
    received = {"bytes": 0}
    download: dict[str, Any] | None = None
    allowed_cache: dict[str, bool] = {}

    async def route_guard(route: Any) -> None:
        req_url = route.request.url
        parts = urlsplit(req_url)
        if parts.scheme in ("data", "blob", "about"):
            await route.continue_()
            return
        if parts.scheme not in ("http", "https") or received["bytes"] > MAX_BYTES:
            await route.abort()
            return
        host = parts.hostname or ""
        if host not in allowed_cache:
            try:
                await asyncio.to_thread(_host_allowed, host)
                allowed_cache[host] = True
            except Blocked:
                allowed_cache[host] = False
        if allowed_cache[host]:
            await route.continue_()
        else:
            await route.abort()

    result: dict[str, Any] = {"final_url": None, "redirects": [], "title": None, "screenshot_path": None,
                              "forms": {k: False for k in FORM_PATTERNS}, "brand_logos": [], "download": None}
    with tempfile.TemporaryDirectory(dir="/tmp") as tmp:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(args=["--disable-gpu", "--no-first-run", "--disable-extensions"],
                                               downloads_path=tmp)
            try:
                ctx = await browser.new_context(accept_downloads=True, java_script_enabled=True,
                                                viewport={"width": 412, "height": 915}, service_workers="block",
                                                user_agent="Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/124 Mobile Safari/537.36")
                await ctx.route("**/*", route_guard)
                page = await ctx.new_page()

                def on_response(resp: Any) -> None:
                    try:
                        received["bytes"] += int(resp.headers.get("content-length") or 0)
                    except ValueError:
                        pass

                page.on("response", on_response)
                dl_future: asyncio.Future = asyncio.get_running_loop().create_future()
                page.on("download", lambda d: dl_future.done() or dl_future.set_result(d))
                main_resp = None
                try:
                    main_resp = await page.goto(url, timeout=TOTAL_BUDGET_S * 1000 * 0.7, wait_until="domcontentloaded")
                    await page.wait_for_timeout(1500)
                except Exception as exc:  # noqa: BLE001 - navigation errors are expected for downloads/blocked hosts
                    log.info("navigation ended: %s", type(exc).__name__)
                if dl_future.done():
                    d = dl_future.result()
                    path = await asyncio.wait_for(d.path(), timeout=10)
                    size = os.path.getsize(path) if path and os.path.exists(path) else 0
                    if path and size <= MAX_BYTES:
                        with open(path, "rb") as fh:  # read bytes to hash only; the file is never executed
                            sha = hashlib.sha256(fh.read()).hexdigest()
                    else:
                        sha = None
                    name = d.suggested_filename or ""
                    download = {"sha256": sha, "type": name.rsplit(".", 1)[-1].lower() if "." in name else "unknown",
                                "filename": name[:120]}
                    await d.delete()
                result["final_url"] = page.url if page.url != "about:blank" else url
                chain = []
                req = main_resp.request if main_resp else None
                while req is not None and req.redirected_from is not None:
                    req = req.redirected_from
                    chain.insert(0, req.url)
                result["redirects"] = chain[:MAX_HOPS]
                try:
                    result["title"] = (await page.title())[:200]
                    fields = " | ".join(await page.evaluate(FORM_JS))
                    result["forms"] = {k: bool(rx.search(fields)) for k, rx in FORM_PATTERNS.items()}
                    imgs = " ".join(await page.evaluate(IMG_JS)).lower()
                    result["brand_logos"] = [b for b in BRANDS if b in imgs][:5]
                    name = hashlib.sha256(url.encode()).hexdigest()[:16] + ".png"
                    await page.screenshot(path=os.path.join(SHOTS_DIR, name), timeout=5000)
                    result["screenshot_path"] = f"/shots/{name}"
                except Exception as exc:  # noqa: BLE001
                    log.info("capture incomplete: %s", type(exc).__name__)
            finally:
                await browser.close()
    result["download"] = download
    return result


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/detonate")
async def detonate_ep(body: DetonateIn) -> dict[str, Any]:
    try:
        if body.mode == "expand":
            return await asyncio.wait_for(expand(body.url), TOTAL_BUDGET_S + 2)
        return await asyncio.wait_for(detonate(body.url), TOTAL_BUDGET_S + 5)
    except Blocked as exc:
        raise HTTPException(422, f"blocked: {exc}") from exc
    except asyncio.TimeoutError as exc:
        raise HTTPException(504, "sandbox timeout") from exc
