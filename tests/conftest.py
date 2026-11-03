"""Shared fixtures. Tests run inside the `tests` compose service (analyzer test image) with
real Postgres (database scamsaathi_test) and Redis (db 15); every network feed is mocked."""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
import pytest_asyncio

sys.path.insert(0, "/app")
REPO = Path("/repo")
SEED_DIR = Path(os.getenv("REGISTRY_DIR", "/repo/registry/seed"))
MIGRATIONS = os.getenv("MIGRATIONS_DIR", "/repo/db/migrations")


@pytest.fixture(scope="session")
def seeds():
    from app.registry import load_seed_dir

    return load_seed_dir(SEED_DIR)


@pytest.fixture(scope="session")
def registry(seeds):
    from app.registry import Registry

    entities, _ = seeds
    return Registry([dict(e) for e in entities])


@pytest.fixture(scope="session")
def playbooks(seeds):
    from app.playbooks import Playbooks

    return Playbooks(seeds[1])


@pytest.fixture(scope="session")
def weights():
    from app.verdict import load_weights

    return load_weights()


class FakeAge:
    def __init__(self, name, days):
        self.name, self._days = name, days

    async def days(self, client, domain):
        if isinstance(self._days, Exception):
            raise self._days
        return self._days


class FakeFeed:
    def __init__(self, name, result):
        self.name, self._result = name, result

    async def check(self, client, url):
        return self._result


@pytest.fixture
def fake_reputation(registry):
    from app.reputation import ReputationService

    return ReputationService(registry, ages=[FakeAge("rdap", 400), FakeAge("crtsh", 300)],
                             feeds=[FakeFeed("gsb", "clean"), FakeFeed("urlhaus", "clean")], timeout=1)


class FakeSandbox:
    enabled = True

    def __init__(self, expand_to=None, detonation=None):
        self.expand_to = expand_to
        self.detonation = detonation or {"final_url": None, "redirects": [], "title": None, "screenshot_path": None,
                                         "forms": {"pin": False, "otp": False, "card": False, "password": False},
                                         "brand_logos": [], "download": None}

    async def expand(self, url):
        return {"final_url": self.expand_to, "redirects": [url]} if self.expand_to else None

    async def detonate(self, url):
        from app.sandbox_client import with_flags

        return with_flags(dict(self.detonation))


@pytest.fixture
def fake_sandbox():
    return FakeSandbox()


@pytest_asyncio.fixture(scope="session")
async def pool():
    import psycopg

    from app.db import migrate, open_pool

    admin = os.environ["TEST_DATABASE_ADMIN_URL"]
    async with await psycopg.AsyncConnection.connect(admin, autocommit=True) as conn:
        exists = await (await conn.execute("SELECT 1 FROM pg_database WHERE datname='scamsaathi_test'")).fetchone()
        if not exists:
            await conn.execute("CREATE DATABASE scamsaathi_test")
    p = await open_pool(os.environ["TEST_DATABASE_URL"])
    await migrate(p, MIGRATIONS)
    yield p
    await p.close()


@pytest_asyncio.fixture
async def clean_db(pool, seeds):
    from app.db import seed

    async with pool.connection() as conn:
        await conn.execute("TRUNCATE checks, artifacts, campaigns, verdict_cache, registry_review_queue, "
                           "registry_policies, registry_entities, playbooks RESTART IDENTITY CASCADE")
    await seed(pool, *seeds)
    return pool


@pytest_asyncio.fixture
async def redis():
    import redis.asyncio as aioredis

    r = aioredis.from_url(os.environ["TEST_REDIS_URL"])
    await r.flushdb()
    yield r
    await r.flushdb()
    await r.aclose()


@pytest_asyncio.fixture
async def deps(clean_db, redis, fake_reputation, fake_sandbox, weights):
    from app.config import Settings
    from app.db import load_playbooks, load_registry
    from app.main import Deps

    s = Settings()
    s.internal_token = "test-internal"
    s.admin_token = "test-admin"
    s.media_dir = "/repo/tests/fixtures/images"
    s.bridge_health_url = "http://wa-bridge.invalid/api/health"
    reg = await load_registry(clean_db, True)
    fake_reputation.registry = reg
    return Deps(settings=s, registry=reg, playbooks=await load_playbooks(clean_db), reputation=fake_reputation,
                sandbox=fake_sandbox, pool=clean_db, redis=redis, weights=weights, ready=True)


@pytest_asyncio.fixture
async def client(deps):
    import httpx

    from app.main import create_app

    app = create_app(deps)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://analyzer",
                                 headers={"X-Internal-Token": "test-internal"}) as c:
        yield c
