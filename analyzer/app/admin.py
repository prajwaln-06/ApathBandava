"""Minimal admin view (FR-32): last 100 checks, campaigns, registry review queue, bridge health.

Bound to localhost by compose and protected by ADMIN_TOKEN (header X-Admin-Token or ?token=).
Shows hashes and metadata only — never raw sender numbers (NFR-10).
"""
from __future__ import annotations

import hmac
from html import escape
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse

from . import db, store


def _authorized(request: Request, token: str) -> bool:
    got = request.headers.get("x-admin-token") or request.query_params.get("token") or ""
    return bool(token) and hmac.compare_digest(got, token)


def _table(rows: list[dict[str, Any]], cols: list[str]) -> str:
    head = "".join(f"<th>{escape(c)}</th>" for c in cols)
    body = "".join("<tr>" + "".join(f"<td>{escape(str(r.get(c, '')))}</td>" for c in cols) + "</tr>" for r in rows)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body or '<tr><td>none</td></tr>'}</tbody></table>"


async def bridge_health(url: str) -> dict[str, Any]:
    try:
        async with httpx.AsyncClient(timeout=3) as client:
            return (await client.get(url)).json()
    except Exception:  # noqa: BLE001
        return {"status": "unreachable"}


def mount(app: FastAPI, deps: Any) -> None:
    @app.get("/admin", response_class=HTMLResponse)
    async def admin_page(request: Request) -> str:
        if not _authorized(request, deps.settings.admin_token):
            raise HTTPException(403, "admin token required")
        data = await store.recent(deps.pool)
        health = await bridge_health(deps.settings.bridge_health_url)
        css = ("body{font:14px system-ui,sans-serif;margin:24px;color:#1b1b1f}h1{font-size:20px}h2{font-size:16px;margin-top:28px}"
               "table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #ddd;padding:6px 8px;text-align:left;"
               "vertical-align:top}th{background:#f4f4f6}.pill{padding:2px 8px;border-radius:10px;background:#eef}")
        return (f"<!doctype html><html><head><meta charset='utf-8'><title>ScamSaathi admin</title><style>{css}</style></head><body>"
                f"<h1>ScamSaathi admin</h1><p>Bridge: <span class='pill'>{escape(str(health))}</span></p>"
                f"<h2>Campaigns</h2>{_table(data['campaigns'], ['id', 'kind', 'sample_value', 'sender_count', 'playbook_code', 'first_seen', 'status'])}"
                f"<h2>Registry entries awaiting review</h2>{_table(data['unreviewed'], ['id', 'name', 'kind', 'status'])}"
                f"<h2>Registry review queue</h2>{_table(data['queue'], ['id', 'entity_id', 'field', 'proposed', 'quote', 'source_url', 'status'])}"
                f"<h2>Last 100 checks</h2>{_table(data['checks'], ['created_at', 'trace_id', 'input_type', 'verdict', 'score', 'latency_ms'])}"
                "</body></html>")

    @app.get("/admin/api/summary")
    async def admin_summary(request: Request) -> dict[str, Any]:
        if not _authorized(request, deps.settings.admin_token):
            raise HTTPException(403, "admin token required")
        data = await store.recent(deps.pool)
        return {k: len(v) for k, v in data.items()} | {"campaigns_list": data["campaigns"]}

    @app.post("/admin/registry/{entity_id}/approve")
    async def approve(entity_id: int, request: Request) -> dict[str, Any]:
        if not _authorized(request, deps.settings.admin_token):
            raise HTTPException(403, "admin token required")
        async with deps.pool.connection() as conn:
            await conn.execute("UPDATE registry_entities SET status='approved', last_verified=current_date WHERE id=%s", (entity_id,))
        deps.registry = await db.load_registry(deps.pool, deps.settings.registry_include_unreviewed)
        deps.reputation.registry = deps.registry
        return {"approved": entity_id}
