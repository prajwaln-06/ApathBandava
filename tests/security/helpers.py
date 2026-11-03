"""Shared helpers for the live security suites."""
import os
import time
import uuid

import httpx
import pytest

N8N = os.getenv("N8N_URL", "http://n8n:5678")
MOCK = os.getenv("MOCK_BRIDGE_URL", "http://mock-bridge:8090")
SANDBOX = os.getenv("SANDBOX_URL", "http://sandbox:9000")
ANALYZER = os.getenv("ANALYZER_URL", "http://analyzer:8000")
BRIDGE = "http://wa-bridge:8080"
HEADERS = {"X-Bridge-Token": os.environ.get("BRIDGE_TOKEN", ""), "X-Test-Token": os.environ.get("TEST_TOKEN", "")}


def _up(url: str) -> bool:
    try:
        return httpx.get(url, timeout=3).status_code < 500
    except httpx.HTTPError:
        return False


def new_jid() -> str:
    return f"9188{uuid.uuid4().int % 10**8:08d}@s.whatsapp.net"


def send_check(http: httpx.Client, text: str, jid: str | None = None, **extra) -> tuple[str, str | None, list]:
    """Post a message through the real webhook path; return (jid, final reply, all sends during the check)."""
    jid = jid or new_jid()
    before = len(http.get(f"{MOCK}/sent").json())
    payload = {"msg_id": f"SEC-{uuid.uuid4().hex[:10]}", "sender_jid": jid, "chat_type": "direct", "type": "text",
               "text": text, "forwarded": True, "timestamp": int(time.time())}
    payload.update(extra)
    http.post(f"{N8N}/webhook/wa-inbound", json=payload, headers=HEADERS).raise_for_status()
    end = time.time() + 60
    reply = None
    while time.time() < end:
        mine = http.get(f"{MOCK}/sent", params={"recipient": jid}).json()
        finals = [m["message"] for m in mine if not m["message"].startswith(("Checking", "जाँच"))]
        if finals:
            reply = finals[-1]
            break
        time.sleep(0.3)
    time.sleep(1.5)  # allow any (forbidden) follow-up sends to show up
    sends = http.get(f"{MOCK}/sent").json()[before:]
    return jid, reply, sends
