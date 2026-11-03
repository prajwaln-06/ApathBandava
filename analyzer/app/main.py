"""ScamSaathi analyzer API (SRS 6.3). Internal network only; every POST needs X-Internal-Token."""
from __future__ import annotations

import asyncio
import hmac
import logging
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from . import admin, db, intake, reply, rules, store, upi
from .config import Settings, settings as default_settings
from .extract import ImagePathError, extract
from .playbooks import Playbooks
from .registry import Registry, load_seed_dir
from .reputation import ReputationService
from .sandbox_client import SandboxClient
from .schema import validate_agent_output
from .url_static import analyze
from .verdict import decide, load_weights

log = logging.getLogger("analyzer")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

MAX_TEXT = 20000


@dataclass
class Deps:
    settings: Settings
    registry: Registry | None = None
    playbooks: Playbooks | None = None
    reputation: ReputationService | None = None
    sandbox: SandboxClient | None = None
    pool: Any = None
    redis: Any = None
    weights: dict[str, Any] | None = None
    ready: bool = False


# ---- request models ------------------------------------------------------------------
class ExtractIn(BaseModel):
    text: str = Field("", max_length=MAX_TEXT)
    image_path: str | None = Field(None, max_length=512)


class UrlIn(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048)


class UpiIn(BaseModel):
    uri: str = Field(..., max_length=2048)


class MatchIn(BaseModel):
    brands: list[str] = []
    urls: list[str] = []
    sender_ids: list[str] = []
    phones: list[str] = []
    upi_ids: list[str] = []
    text: str = Field("", max_length=MAX_TEXT)


class PolicyIn(BaseModel):
    entity_id: int | None = None
    entity: str | None = Field(None, max_length=200)  # additive: brand name, lets agents call match + policy in parallel
    text: str = Field("", max_length=MAX_TEXT)


class TextIn(BaseModel):
    text: str = Field("", max_length=MAX_TEXT)


class VerdictIn(BaseModel):
    findings: list[Any]


class BaselineIn(BaseModel):
    extract: dict[str, Any]
    text: str = Field("", max_length=MAX_TEXT)


class ContextIn(BaseModel):
    verdict: dict[str, Any]
    extract: dict[str, Any]
    findings: list[Any] = []
    language: str = "en"
    input_type: str = "text"
    text: str = Field("", max_length=MAX_TEXT)


class FinalizeIn(BaseModel):
    text: Any = None
    context: dict[str, Any]


class FindingsIn(BaseModel):
    findings: list[Any]


async def init_deps(deps: Deps) -> None:
    s = deps.settings
    deps.pool = await db.open_pool(s.database_url)
    await db.migrate(deps.pool, s.migrations_dir)
    if s.seed_on_start:
        entities, pbs = load_seed_dir(s.registry_dir)
        counts = await db.seed(deps.pool, entities, pbs)
        log.info("seeded registry: %s", counts)
    deps.registry = await db.load_registry(deps.pool, s.registry_include_unreviewed)
    deps.playbooks = await db.load_playbooks(deps.pool)
    import redis.asyncio as aioredis

    deps.redis = aioredis.from_url(s.redis_url)
    deps.reputation = ReputationService(deps.registry, settings=s, timeout=s.feed_timeout_s, overlay_path=s.reputation_overlay)
    deps.sandbox = SandboxClient(s.sandbox_url, enabled=s.detonate_enabled)
    deps.weights = load_weights()
    deps.ready = True


async def purge_loop(deps: Deps) -> None:  # pragma: no cover - long-running background task
    while True:
        try:
            n = await store.purge(deps.pool, deps.settings.raw_text_retention_days)
            if n:
                log.info("privacy purge cleared raw text of %s checks", n)
        except Exception as exc:  # noqa: BLE001
            log.warning("purge failed: %s", exc)
        await asyncio.sleep(3600)


def create_app(deps: Deps | None = None) -> FastAPI:
    deps = deps or Deps(settings=default_settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI):  # pragma: no cover - exercised by the running container
        task = None
        if not deps.ready:
            await init_deps(deps)
            task = asyncio.create_task(purge_loop(deps))
        yield
        if task:
            task.cancel()
        if deps.pool is not None and hasattr(deps.pool, "close"):
            await deps.pool.close()

    app = FastAPI(title="ScamSaathi analyzer", lifespan=lifespan)
    app.state.deps = deps

    @app.middleware("http")
    async def internal_auth(request: Request, call_next):
        token = deps.settings.internal_token
        if request.method == "POST" and not request.url.path.startswith("/admin") and token:
            if not hmac.compare_digest(request.headers.get("x-internal-token", ""), token):
                return JSONResponse({"detail": "unauthorized"}, status_code=401)
        return await call_next(request)

    @app.get("/health")
    async def health() -> dict[str, Any]:
        return {"status": "ok", "ready": deps.ready,
                "entities": len(deps.registry.entities) if deps.registry else 0,
                "playbooks": len(deps.playbooks.items) if deps.playbooks else 0}

    # ---- SRS 6.3 --------------------------------------------------------------------
    @app.post("/extract")
    async def extract_ep(body: ExtractIn) -> dict[str, Any]:
        try:
            return await asyncio.to_thread(extract, body.text, deps.registry, body.image_path, deps.settings.media_dir)
        except ImagePathError as exc:
            raise HTTPException(400, str(exc)) from exc

    @app.post("/url/static")
    async def url_static_ep(body: UrlIn) -> dict[str, Any]:
        return analyze(body.url, deps.registry)

    @app.post("/url/reputation")
    async def url_reputation_ep(body: UrlIn) -> dict[str, Any]:
        return await deps.reputation.lookup(body.url)

    @app.post("/url/detonate")
    async def url_detonate_ep(body: UrlIn) -> dict[str, Any]:
        return await deps.sandbox.detonate(body.url)

    @app.post("/upi/parse")
    async def upi_parse_ep(body: UpiIn) -> dict[str, Any]:
        return upi.parse(body.uri)

    @app.post("/registry/match")
    async def registry_match_ep(body: MatchIn) -> dict[str, Any]:
        return deps.registry.match(body.brands, body.urls, body.sender_ids, body.phones, body.upi_ids, body.text)

    @app.post("/registry/policy")
    async def registry_policy_ep(body: PolicyIn) -> dict[str, Any]:
        entity_id = body.entity_id
        if not entity_id and body.entity:
            ent = deps.registry.by_name(body.entity)
            entity_id = ent["id"] if ent else None
        if not entity_id:
            return {"violations": []}
        return deps.registry.policy(entity_id, body.text)

    @app.post("/playbooks/search")
    async def playbooks_search_ep(body: TextIn) -> dict[str, Any]:
        return deps.playbooks.search(body.text)

    @app.post("/verdict")
    async def verdict_ep(body: VerdictIn) -> dict[str, Any]:
        return decide(body.findings, deps.weights)

    # ---- pipeline helpers used by n8n ----------------------------------------------
    @app.post("/intake/guard")
    async def guard_ep(payload: dict[str, Any]) -> dict[str, Any]:
        return await intake.guard(deps.redis, payload, deps.settings.sender_salt, deps.settings.rate_limit_per_hour)

    @app.post("/rules/baseline")
    async def baseline_ep(body: BaselineIn) -> dict[str, Any]:
        return await rules.baseline(body.extract, body.text, deps.registry, deps.reputation, deps.playbooks, deps.sandbox)

    @app.post("/findings/validate")
    async def validate_ep(body: FindingsIn) -> dict[str, Any]:
        return {"findings": [validate_agent_output(f) for f in body.findings]}

    @app.post("/cache/lookup")
    async def cache_lookup_ep(body: BaselineIn) -> dict[str, Any]:
        key = store.cache_key(body.extract, body.text)
        hit = await store.cache_lookup(deps.pool, key, deps.settings.cache_ttl_hours)
        return {"hit": hit is not None, "cache_key": key, "result": hit}

    @app.post("/reply/context")
    async def reply_context_ep(body: ContextIn) -> dict[str, Any]:
        return reply.build_context(body.verdict, body.extract, body.findings, body.language, deps.registry,
                                   deps.playbooks, body.input_type, body.text)

    @app.post("/reply/finalize")
    async def reply_finalize_ep(body: FinalizeIn) -> dict[str, Any]:
        return reply.finalize(body.text, body.context)

    @app.post("/checks/record")
    async def record_ep(rec: dict[str, Any]) -> dict[str, Any]:
        return await store.record(deps.pool, rec, deps.settings.campaign_threshold, deps.settings.campaign_window_hours)

    # ---- registry crawler (FR-31), maintenance (NFR-10), campaigns (FR-30) ---------------
    @app.post("/registry/sources")
    async def registry_sources_ep() -> dict[str, Any]:
        """Allowlist for the crawler: only source URLs recorded in the registry seeds."""
        out = []
        for ent in deps.registry.entities:
            for url in ent.get("sources", [])[:3]:
                if url.startswith("https://"):
                    out.append({"entity_id": ent["id"], "entity": ent["name"], "url": url})
        return {"sources": out}

    @app.post("/registry/review")
    async def registry_review_ep(body: dict[str, Any]) -> dict[str, Any]:
        """Queue crawler facts for human review. A fact is kept only if its quote appears verbatim on the page."""
        page = " ".join(str(body.get("page_text") or "").split()).lower()
        allowed = {e["id"] for e in deps.registry.entities}
        sources = {u for e in deps.registry.entities for u in e.get("sources", [])}
        if body.get("entity_id") not in allowed or body.get("source_url") not in sources:
            raise HTTPException(400, "unknown entity or source not allowlisted")
        queued = 0
        async with deps.pool.connection() as conn:
            for fact in (body.get("facts") or [])[:50]:
                quote = " ".join(str(fact.get("quote") or "").split())
                if len(quote) < 8 or quote.lower() not in page:
                    continue
                await conn.execute(
                    "INSERT INTO registry_review_queue (entity_id, field, proposed, quote, source_url) VALUES (%s,%s,%s,%s,%s)",
                    (body["entity_id"], str(fact.get("field"))[:40], db.jsonb({"value": str(fact.get("value"))[:300]}),
                     quote[:500], body["source_url"]))
                queued += 1
        return {"queued": queued}

    @app.post("/maintenance/purge")
    async def purge_ep() -> dict[str, Any]:
        return {"purged": await store.purge(deps.pool, deps.settings.raw_text_retention_days)}

    @app.post("/campaigns/digest")
    async def digest_ep(body: dict[str, Any]) -> dict[str, Any]:
        hours = int(body.get("hours") or 1)
        async with deps.pool.connection() as conn:
            rows = await (await conn.execute(
                "SELECT id, kind, sample_value, sender_count, playbook_code FROM campaigns "
                "WHERE status='open' AND first_seen > now() - make_interval(hours => %s) ORDER BY id", (hours,))).fetchall()
        return {"campaigns": rows}

    # ---- admin (FR-32) ----------------------------------------------------------------
    admin.mount(app, deps)
    return app


app = create_app()
