"""Postgres access: migrations, seed loader (Phase 3) and registry/playbook loading."""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from psycopg.rows import dict_row
from psycopg_pool import AsyncConnectionPool

from .playbooks import Playbooks
from .registry import Registry

log = logging.getLogger(__name__)


async def open_pool(dsn: str) -> AsyncConnectionPool:
    pool = AsyncConnectionPool(dsn, min_size=1, max_size=10, open=False, kwargs={"row_factory": dict_row})
    await pool.open(wait=True, timeout=30)
    return pool


async def migrate(pool: AsyncConnectionPool, migrations_dir: str) -> list[str]:
    applied = []
    async with pool.connection() as conn:
        for path in sorted(Path(migrations_dir).glob("*.sql")):
            await conn.execute(path.read_text(encoding="utf-8"))
            applied.append(path.name)
    return applied


async def seed(pool: AsyncConnectionPool, entities: list[dict[str, Any]], playbooks: list[dict[str, Any]]) -> dict[str, int]:
    """Upsert YAML seeds. Policies of each entity are replaced as a unit."""
    async with pool.connection() as conn:
        async with conn.transaction():
            for e in entities:
                row = await (await conn.execute(
                    """INSERT INTO registry_entities (name, aliases, regulator, kind, domains, legacy_domains, sms_headers,
                         call_prefixes, support_numbers, official_upi_handles, app_packages, last_verified, status, sources)
                       VALUES (%(name)s, %(aliases)s, %(regulator)s, %(kind)s, %(domains)s, %(legacy_domains)s, %(sms_headers)s,
                         %(call_prefixes)s, %(support_numbers)s, %(official_upi_handles)s, %(app_packages)s,
                         %(last_verified)s, %(status)s, %(sources)s)
                       ON CONFLICT (name) DO UPDATE SET aliases=EXCLUDED.aliases, regulator=EXCLUDED.regulator,
                         kind=EXCLUDED.kind, domains=EXCLUDED.domains, legacy_domains=EXCLUDED.legacy_domains,
                         sms_headers=EXCLUDED.sms_headers, call_prefixes=EXCLUDED.call_prefixes,
                         support_numbers=EXCLUDED.support_numbers, official_upi_handles=EXCLUDED.official_upi_handles,
                         app_packages=EXCLUDED.app_packages, last_verified=EXCLUDED.last_verified,
                         status=CASE WHEN registry_entities.status='approved' AND EXCLUDED.status='needs_review'
                                     THEN registry_entities.status ELSE EXCLUDED.status END,
                         sources=EXCLUDED.sources
                       RETURNING id""", e)).fetchone()
                await conn.execute("DELETE FROM registry_policies WHERE entity_id=%s", (row["id"],))
                for p in e["policies"]:
                    await conn.execute(
                        """INSERT INTO registry_policies (entity_id, rule_code, rule_text, quote, source_url, last_verified)
                           VALUES (%s,%s,%s,%s,%s,%s)""",
                        (row["id"], p["rule_code"], p["rule_text"], p["quote"], p["source_url"], p["last_verified"]))
            for pb in playbooks:
                await conn.execute(
                    """INSERT INTO playbooks (code, name, description, indicators, example, advice, advice_hi)
                       VALUES (%s,%s,%s,%s,%s,%s,%s)
                       ON CONFLICT (code) DO UPDATE SET name=EXCLUDED.name, description=EXCLUDED.description,
                         indicators=EXCLUDED.indicators, example=EXCLUDED.example, advice=EXCLUDED.advice,
                         advice_hi=EXCLUDED.advice_hi""",
                    (pb["code"], pb["name"], pb.get("description", ""), pb["indicators"], pb.get("example", ""),
                     pb["advice"], pb.get("advice_hi", "")))
    return {"entities": len(entities), "playbooks": len(playbooks)}


async def load_registry(pool: AsyncConnectionPool, include_unreviewed: bool) -> Registry:
    async with pool.connection() as conn:
        ents = await (await conn.execute("SELECT * FROM registry_entities ORDER BY id")).fetchall()
        pols = await (await conn.execute("SELECT * FROM registry_policies ORDER BY id")).fetchall()
    by_id: dict[int, dict[str, Any]] = {}
    for e in ents:
        e = dict(e)
        for k in ("aliases", "domains", "legacy_domains", "sms_headers", "call_prefixes", "support_numbers",
                  "official_upi_handles", "app_packages", "sources"):
            e[k] = list(e.get(k) or [])
        e["last_verified"] = str(e["last_verified"]) if e.get("last_verified") else None
        e["policies"] = []
        by_id[e["id"]] = e
    for p in pols:
        if p["entity_id"] in by_id:
            by_id[p["entity_id"]]["policies"].append(
                {k: p[k] for k in ("rule_code", "rule_text", "quote", "source_url")})
    return Registry(list(by_id.values()), include_unreviewed=include_unreviewed)


async def load_playbooks(pool: AsyncConnectionPool) -> Playbooks:
    async with pool.connection() as conn:
        rows = await (await conn.execute(
            "SELECT code, name, description, indicators, example, advice, advice_hi FROM playbooks ORDER BY code")).fetchall()
    return Playbooks([dict(r, indicators=list(r["indicators"] or [])) for r in rows])


def jsonb(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str)
