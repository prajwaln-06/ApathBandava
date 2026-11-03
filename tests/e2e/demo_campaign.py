"""Demo D8 (FR-30): the same link from 5 different senders within 6 h creates one campaign record
and one admin alert; the admin view lists the campaign. Bridge mocked."""
from __future__ import annotations

import os
import sys
import time
import uuid

import httpx

N8N = os.getenv("N8N_URL", "http://n8n:5678")
MOCK = os.getenv("MOCK_BRIDGE_URL", "http://mock-bridge:8090")
ANALYZER = os.getenv("ANALYZER_URL", "http://analyzer:8000")
HEADERS = {"X-Bridge-Token": os.environ["BRIDGE_TOKEN"], "X-Test-Token": os.environ["TEST_TOKEN"]}
ADMIN_JID = os.environ.get("ADMIN_JID", "")


def main() -> int:
    link = f"http://parcel-fee-{uuid.uuid4().hex[:6]}.example/pay"
    text = f"India Post: your parcel is held, pay Rs 25 re-delivery fee within 12 hours: {link}"
    with httpx.Client(timeout=30) as c:
        before = len(c.get(f"{MOCK}/sent").json())
        for i in range(5):
            jid = f"9177{uuid.uuid4().int % 10**8:08d}@s.whatsapp.net"
            c.post(f"{N8N}/webhook/wa-inbound", headers=HEADERS, json={
                "msg_id": uuid.uuid4().hex, "sender_jid": jid, "chat_type": "direct", "type": "text", "text": text,
                "forwarded": True, "timestamp": int(time.time())}).raise_for_status()
            end = time.time() + 60
            while time.time() < end and not [m for m in c.get(f"{MOCK}/sent", params={"recipient": jid}).json()
                                             if not m["message"].startswith("Checking")]:
                time.sleep(0.3)
            print(f"sender {i + 1}/5 checked")
        time.sleep(2)
        sends = c.get(f"{MOCK}/sent").json()[before:]
        alerts = [m for m in sends if m["recipient"] == ADMIN_JID and "campaign" in m["message"].lower()]
        summary = c.get(f"{ANALYZER}/admin/api/summary", headers={"X-Admin-Token": os.environ["ADMIN_TOKEN"]}).json()
        listed = [x for x in summary.get("campaigns_list", []) if link.split("//")[1] in (x.get("sample_value") or "")]
    print("admin alerts:", len(alerts), "| campaign in admin view:", bool(listed))
    for a in alerts:
        print(a["message"])
    ok = len(alerts) == 1 and bool(listed)
    print("D8", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
