"""NFR-7: a cache hit (same artifacts within 24 h) replies in under 2 s. Run after `make eval` has filled the cache.
Each item is sent once to warm the cache (if needed), then again from a new sender; the second reply is timed."""
from __future__ import annotations

import os
import statistics
import sys
import time
import uuid

import httpx
import yaml

N8N = os.getenv("N8N_URL", "http://n8n:5678")
MOCK = os.getenv("MOCK_BRIDGE_URL", "http://mock-bridge:8090")
HEADERS = {"X-Bridge-Token": os.environ["BRIDGE_TOKEN"], "X-Test-Token": os.environ["TEST_TOKEN"]}
IDS = ["S01", "S03", "E01", "E03", "L02", "L05", "S15", "P01"]


def check(c: httpx.Client, text: str) -> float:
    jid = f"9166{uuid.uuid4().int % 10**8:08d}@s.whatsapp.net"
    t0 = time.time()
    c.post(f"{N8N}/webhook/wa-inbound", headers=HEADERS, json={
        "msg_id": uuid.uuid4().hex, "sender_jid": jid, "chat_type": "direct", "type": "text", "text": text,
        "forwarded": True, "timestamp": int(time.time())}).raise_for_status()
    while time.time() - t0 < 60:
        if [m for m in c.get(f"{MOCK}/sent", params={"recipient": jid}).json() if not m["message"].startswith("Checking")]:
            return time.time() - t0
        time.sleep(0.05)
    return 60.0


def main() -> int:
    items = {i["id"]: i for i in yaml.safe_load(open("/repo/tests/fixtures/fixtures.yaml", encoding="utf-8"))}
    lat = []
    with httpx.Client(timeout=30) as c:
        for fid in IDS:
            text = items[fid]["text"]
            first = check(c, text)
            second = check(c, text)
            lat.append(second)
            print(f"{fid}: first {first:.2f}s, cache hit {second:.2f}s")
    p50, worst = statistics.median(lat), max(lat)
    ok = worst < 2.0
    print(f"NFR-7 cache hit: p50 {p50:.2f}s, max {worst:.2f}s -> {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
