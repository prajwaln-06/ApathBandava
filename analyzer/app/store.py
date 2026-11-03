"""Checks, artifacts, verdict cache (FR-29), campaigns (FR-30) and privacy purge (NFR-10)."""
from __future__ import annotations

import hashlib
import uuid
from typing import Any

from psycopg.types.json import Jsonb
from psycopg_pool import AsyncConnectionPool

ARTIFACT_KINDS = (("url", "urls"), ("upi_uri", "upi_uris"), ("upi_id", "upi_ids"), ("phone", "phones"),
                  ("sender_id", "sender_ids"), ("qr", "qr_payloads"))
IGNORED_CAMPAIGN_VALUES = {"1930"}


def sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def sender_hash(jid: str, salt: str) -> str:
    """NFR-10: sender numbers are stored only as salted SHA-256."""
    return sha256(f"{salt}:{(jid or '').strip().lower()}")


def value_hash(kind: str, value: str) -> str:
    return sha256(f"{kind}:{value.strip().lower().rstrip('/')}")


def artifacts_of(extract: dict[str, Any]) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for kind, key in ARTIFACT_KINDS:
        for v in extract.get(key) or []:
            if (kind, v) not in out:
                out.append((kind, str(v)))
    return out


def cache_key(extract: dict[str, Any], text: str = "") -> str:
    """Artifact hash; messages without artifacts are keyed on normalised text."""
    arts = sorted(f"{k}:{v.strip().lower().rstrip('/')}" for k, v in artifacts_of(extract))
    basis = "|".join(arts) if arts else "text:" + " ".join(((text or "") + " " + (extract.get("ocr_text") or "")).lower().split())
    return sha256(basis)


async def cache_lookup(pool: AsyncConnectionPool, key: str, ttl_hours: int) -> dict[str, Any] | None:
    async with pool.connection() as conn:
        row = await (await conn.execute(
            "SELECT result FROM verdict_cache WHERE cache_key=%s AND created_at > now() - make_interval(hours => %s)",
            (key, ttl_hours))).fetchone()
    return row["result"] if row else None


async def record(pool: AsyncConnectionPool, rec: dict[str, Any], threshold: int, window_hours: int) -> dict[str, Any]:
    check_id = str(uuid.uuid4())
    verdict = rec.get("verdict") or {}
    extract = rec.get("extract") or {}
    alerts: list[dict[str, Any]] = []
    async with pool.connection() as conn:
        async with conn.transaction():
            await conn.execute(
                """INSERT INTO checks (id, sender_hash, input_type, raw_text, findings, verdict, score, reply, latency_ms, trace_id)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (check_id, rec.get("sender_hash"), rec.get("input_type"), rec.get("raw_text"),
                 Jsonb(rec.get("findings") or []), verdict.get("verdict"), verdict.get("score"), rec.get("reply"),
                 rec.get("latency_ms"), rec.get("trace_id")))
            arts = artifacts_of(extract)
            for kind, value in arts:
                await conn.execute(
                    "INSERT INTO artifacts (check_id, kind, value, value_hash, verdict) VALUES (%s,%s,%s,%s,%s)",
                    (check_id, kind, value, value_hash(kind, value), verdict.get("verdict")))
            if rec.get("cache_key") and not rec.get("from_cache"):
                await conn.execute(
                    """INSERT INTO verdict_cache (cache_key, result, created_at) VALUES (%s,%s,now())
                       ON CONFLICT (cache_key) DO UPDATE SET result=EXCLUDED.result, created_at=now()""",
                    (rec["cache_key"], Jsonb({"verdict": verdict, "context": rec.get("context") or {}})))
            if verdict.get("verdict") in ("SCAM", "SUSPICIOUS"):
                for kind, value in arts:
                    if value in IGNORED_CAMPAIGN_VALUES or kind == "sender_id":
                        continue
                    alert = await _campaign(conn, kind, value, rec.get("playbook_code"), threshold, window_hours)
                    if alert:
                        alerts.append(alert)
    return {"check_id": check_id, "campaign_alerts": alerts}


async def _campaign(conn: Any, kind: str, value: str, playbook: str | None, threshold: int, window: int) -> dict[str, Any] | None:
    h = value_hash(kind, value)
    row = await (await conn.execute(
        """SELECT count(DISTINCT c.sender_hash) AS n, min(c.created_at) AS first_seen FROM artifacts a
           JOIN checks c ON c.id = a.check_id
           WHERE a.value_hash=%s AND c.created_at > now() - make_interval(hours => %s)""", (h, window))).fetchone()
    if row["n"] < threshold:
        return None
    camp = await (await conn.execute(
        """INSERT INTO campaigns (value_hash, kind, first_seen, sender_count, playbook_code, sample_value)
           VALUES (%s,%s,%s,%s,%s,%s)
           ON CONFLICT (value_hash) DO UPDATE SET sender_count=EXCLUDED.sender_count,
             playbook_code=COALESCE(campaigns.playbook_code, EXCLUDED.playbook_code)
           RETURNING id, alerted""", (h, kind, row["first_seen"], row["n"], playbook, value[:200]))).fetchone()
    if camp["alerted"]:
        return None
    await conn.execute("UPDATE campaigns SET alerted=true WHERE id=%s", (camp["id"],))
    return {"campaign_id": camp["id"], "kind": kind, "value": value[:200], "sender_count": row["n"], "playbook_code": playbook}


async def purge(pool: AsyncConnectionPool, retention_days: int) -> int:
    """NFR-10: raw text is deleted after the retention period."""
    async with pool.connection() as conn:
        cur = await conn.execute(
            "UPDATE checks SET raw_text=NULL WHERE raw_text IS NOT NULL AND created_at < now() - make_interval(days => %s)",
            (retention_days,))
        await conn.execute("DELETE FROM verdict_cache WHERE created_at < now() - interval '7 days'")
        return cur.rowcount


async def recent(pool: AsyncConnectionPool) -> dict[str, Any]:
    async with pool.connection() as conn:
        checks = await (await conn.execute(
            "SELECT id, trace_id, created_at, input_type, verdict, score, latency_ms FROM checks ORDER BY created_at DESC LIMIT 100")).fetchall()
        camps = await (await conn.execute(
            "SELECT id, kind, sample_value, sender_count, playbook_code, first_seen, status FROM campaigns ORDER BY first_seen DESC LIMIT 50")).fetchall()
        queue = await (await conn.execute(
            "SELECT id, entity_id, field, proposed, quote, source_url, status FROM registry_review_queue WHERE status='pending' ORDER BY id LIMIT 100")).fetchall()
        unreviewed = await (await conn.execute(
            "SELECT id, name, kind, status FROM registry_entities WHERE status <> 'approved' ORDER BY name")).fetchall()
    return {"checks": checks, "campaigns": camps, "queue": queue, "unreviewed": unreviewed}
